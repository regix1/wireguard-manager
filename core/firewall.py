"""Firewall management operations."""

import os
import re
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from datetime import datetime

from config.settings import Settings
from core.utils import run_command, validate_ip
from models.firewall_rule import FirewallRule
from models.banned_ip import BannedIP

class FirewallManager:
    """Manages firewall rules and IP banning."""
    
    def __init__(self, settings: Settings):
        """Initialize firewall manager."""
        self.settings = settings
        self.logger = logging.getLogger(__name__)
        self.lock_file = Path("/var/run/wg-firewall.lock")
        
    def get_status(self) -> Dict:
        """Get firewall status."""
        status = {
            'active': self.lock_file.exists(),
            'banned_ips_count': 0,
            'rules_count': {},
            'policies': {},
            'nat_rules': 0
        }
        
        try:
            # Get chain policies
            for chain in ['INPUT', 'FORWARD', 'OUTPUT']:
                result = run_command(['iptables', '-L', chain, '-n'], check=False)
                if result.returncode == 0:
                    first_line = result.stdout.split('\n')[0]
                    if 'policy' in first_line:
                        policy = first_line.split('policy')[1].split(')')[0].strip()
                        status['policies'][chain] = policy
            
            # Count rules
            status['rules_count'] = self._count_rules()
            
            # Count banned IPs
            result = run_command(['iptables', '-L', self.settings.firewall.banned_chain, '-n'], check=False)
            if result.returncode == 0:
                status['banned_ips_count'] = result.stdout.count('DROP')
            
            # Count NAT rules
            result = run_command(['iptables', '-t', 'nat', '-L', '-n'], check=False)
            if result.returncode == 0:
                status['nat_rules'] = result.stdout.count('DNAT') + result.stdout.count('MASQUERADE')
            
        except Exception as e:
            self.logger.error(f"Error getting firewall status: {e}")
        
        return status
    
    def _count_rules(self) -> Dict[str, int]:
        """Count firewall rules by chain."""
        counts = {}
        
        for chain in ['INPUT', 'FORWARD', 'OUTPUT']:
            try:
                result = run_command(['iptables', '-L', chain, '-n', '--line-numbers'], check=False)
                if result.returncode == 0:
                    # Count lines that are actual rules (skip headers)
                    lines = result.stdout.split('\n')
                    count = 0
                    for line in lines:
                        if line and line[0].isdigit():  # Rule lines start with line number
                            count += 1
                    counts[chain] = count
            except:
                counts[chain] = 0
        
        return counts
    
    def start(self, safe_mode: bool = False) -> None:
        """Start firewall."""
        if self.lock_file.exists():
            self.logger.warning("Firewall already running")
            return
        
        self.logger.info(f"Starting firewall (safe_mode={safe_mode})")
        
        # Create lock file
        self.lock_file.touch()
        
        try:
            # Enable IP forwarding
            run_command(['sysctl', '-w', 'net.ipv4.conf.all.forwarding=1'])
            
            # Initialize banned chain
            self._init_banned_chain()
            
            # Clear existing rules
            self._clear_rules()
            
            # Set default policies
            run_command(['iptables', '-P', 'INPUT', 'DROP'])
            run_command(['iptables', '-P', 'FORWARD', 'DROP'])
            run_command(['iptables', '-P', 'OUTPUT', 'ACCEPT'])
            
            # Add essential rules first
            run_command(['iptables', '-A', 'INPUT', '-i', 'lo', '-j', 'ACCEPT'])
            run_command(['iptables', '-A', 'INPUT', '-p', 'tcp', '--dport', '22', '-j', 'ACCEPT'])  # SSH
            run_command(['iptables', '-A', 'INPUT', '-m', 'conntrack', '--ctstate', 'ESTABLISHED,RELATED', '-j', 'ACCEPT'])
            run_command(['iptables', '-A', 'FORWARD', '-m', 'conntrack', '--ctstate', 'ESTABLISHED,RELATED', '-j', 'ACCEPT'])
            
            # Load banned IPs (unless safe mode)
            if not safe_mode:
                self._load_banned_ips()
            
            # Apply rules from file
            self._apply_rules_from_file()
            
            self.logger.info("Firewall started successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to start firewall: {e}")
            self.lock_file.unlink(missing_ok=True)
            raise
    
    def stop(self) -> None:
        """Stop firewall."""
        self.logger.info("Stopping firewall")
        
        # Save banned IPs before stopping
        self._save_banned_ips()
        
        # Clear all rules
        run_command(['iptables', '-F'], check=False)
        run_command(['iptables', '-t', 'nat', '-F'], check=False)
        run_command(['iptables', '-t', 'mangle', '-F'], check=False)
        
        # Reset policies
        run_command(['iptables', '-P', 'INPUT', 'ACCEPT'])
        run_command(['iptables', '-P', 'FORWARD', 'ACCEPT'])
        run_command(['iptables', '-P', 'OUTPUT', 'ACCEPT'])
        
        # Remove lock file
        self.lock_file.unlink(missing_ok=True)
        
        self.logger.info("Firewall stopped")
    
    def restart(self, safe_mode: bool = False) -> None:
        """Restart firewall."""
        self.logger.info("Restarting firewall")
        self.stop()
        self.start(safe_mode)
    
    def _init_banned_chain(self) -> None:
        """Initialize banned IPs chain."""
        chain = self.settings.firewall.banned_chain
        
        # Create chain if it doesn't exist
        result = run_command(['iptables', '-L', chain], check=False)
        if result.returncode != 0:
            run_command(['iptables', '-N', chain])
        
        # Ensure chain is referenced in INPUT and FORWARD
        run_command(['iptables', '-D', 'INPUT', '-j', chain], check=False)
        run_command(['iptables', '-D', 'FORWARD', '-j', chain], check=False)
        
        run_command(['iptables', '-I', 'INPUT', '1', '-j', chain])
        run_command(['iptables', '-I', 'FORWARD', '1', '-j', chain])
    
    def _clear_rules(self) -> None:
        """Clear existing firewall rules."""
        run_command(['iptables', '-F', 'INPUT'], check=False)
        run_command(['iptables', '-F', 'FORWARD'], check=False)
        run_command(['iptables', '-t', 'nat', '-F'], check=False)
        
        # Re-add banned chain references
        chain = self.settings.firewall.banned_chain
        run_command(['iptables', '-I', 'INPUT', '1', '-j', chain])
        run_command(['iptables', '-I', 'FORWARD', '1', '-j', chain])
    
    def _load_banned_ips(self) -> None:
        """Load banned IPs from file."""
        banned_file = Path(self.settings.firewall.banned_ips_file)
        if not banned_file.exists():
            return
        
        chain = self.settings.firewall.banned_chain
        
        # Clear chain first
        run_command(['iptables', '-F', chain], check=False)
        
        # Load IPs
        count = 0
        for line in banned_file.read_text().split('\n'):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            if '|' in line:
                ip, comment = line.split('|', 1)
                ip = ip.strip()
                comment = comment.strip()
                run_command(['iptables', '-A', chain, '-s', ip, '-m', 'comment', '--comment', comment, '-j', 'DROP'], check=False)
            else:
                run_command(['iptables', '-A', chain, '-s', line, '-j', 'DROP'], check=False)
            
            count += 1
        
        self.logger.info(f"Loaded {count} banned IPs")
    
    def _save_banned_ips(self) -> None:
        """Save banned IPs to file."""
        chain = self.settings.firewall.banned_chain
        banned_file = Path(self.settings.firewall.banned_ips_file)
        
        result = run_command(['iptables', '-L', chain, '-n'], check=False)
        if result.returncode != 0:
            return
        
        banned_ips = []
        for line in result.stdout.split('\n'):
            if 'DROP' in line:
                # Extract IP
                parts = line.split()
                if len(parts) >= 4:
                    ip = parts[3]
                    
                    # Extract comment if exists
                    comment_match = re.search(r'/\*(.*?)\*/', line)
                    if comment_match:
                        comment = comment_match.group(1).strip()
                        banned_ips.append(f"{ip}|{comment}")
                    else:
                        banned_ips.append(ip)
        
        banned_file.write_text('\n'.join(banned_ips))
        self.logger.info(f"Saved {len(banned_ips)} banned IPs")
    
    def _apply_rules_from_file(self) -> None:
        """Apply firewall rules from configuration file."""
        rules_file = Path(self.settings.firewall.rules_file)
        
        if not rules_file.exists():
            self._create_default_rules_file()
        
        # Parse and apply rules
        for line in rules_file.read_text().split('\n'):
            line = line.strip()
            
            # Skip comments and empty lines
            if not line or line.startswith('#'):
                continue
            
            # Execute iptables command
            try:
                # Parse the command
                if line.startswith('iptables'):
                    parts = line.split()
                    run_command(parts, check=False)
            except Exception as e:
                self.logger.error(f"Failed to apply rule: {line} - {e}")
    
    def _create_default_rules_file(self) -> None:
        """Create default firewall rules file."""
        rules_file = Path(self.settings.firewall.rules_file)
        
        default_rules = f"""# WireGuard Firewall Rules Configuration
# Generated: {datetime.now()}

# NAT Rules
iptables -t nat -A POSTROUTING -o {self.settings.firewall.external_interface} -s {self.settings.wireguard.default_subnet} -j MASQUERADE

# WireGuard port
iptables -A INPUT -p udp --dport {self.settings.wireguard.default_port} -j ACCEPT

# Allow forwarding
iptables -A FORWARD -i {self.settings.firewall.external_interface} -o {self.settings.wireguard.interface_name} -j ACCEPT
iptables -A FORWARD -i {self.settings.wireguard.interface_name} -j ACCEPT

# DNS for WireGuard clients
iptables -A INPUT -i {self.settings.wireguard.interface_name} -p udp --dport 53 -j ACCEPT
iptables -A INPUT -i {self.settings.wireguard.interface_name} -p tcp --dport 53 -j ACCEPT
"""
        
        rules_file.parent.mkdir(parents=True, exist_ok=True)
        rules_file.write_text(default_rules)
        self.logger.info(f"Created default rules file: {rules_file}")
    
    def ban_ip(self, ip: str, reason: str = "") -> bool:
        """Ban an IP address."""
        if not validate_ip(ip.split('/')[0]):
            raise ValueError(f"Invalid IP address: {ip}")
        
        chain = self.settings.firewall.banned_chain
        
        # Check if already banned
        result = run_command(['iptables', '-L', chain, '-n'], check=False)
        if result.returncode == 0 and ip in result.stdout:
            self.logger.warning(f"IP {ip} is already banned")
            return False
        
        # Add ban
        if reason:
            run_command(['iptables', '-A', chain, '-s', ip, '-m', 'comment', '--comment', reason, '-j', 'DROP'])
        else:
            run_command(['iptables', '-A', chain, '-s', ip, '-j', 'DROP'])
        
        # Save to file
        self._save_banned_ips()
        
        self.logger.info(f"Banned IP: {ip} (reason: {reason})")
        return True
    
    def unban_ip(self, ip: str) -> bool:
        """Unban an IP address."""
        chain = self.settings.firewall.banned_chain
        
        # Get rule numbers for this IP
        result = run_command(['iptables', '-L', chain, '--line-numbers', '-n'], check=False)
        if result.returncode != 0:
            return False
        
        rule_nums = []
        for line in result.stdout.split('\n'):
            if ip in line:
                parts = line.split()
                if parts and parts[0].isdigit():
                    rule_nums.append(int(parts[0]))
        
        # Remove rules (in reverse order to maintain numbering)
        for num in sorted(rule_nums, reverse=True):
            run_command(['iptables', '-D', chain, str(num)], check=False)
        
        # Save to file
        self._save_banned_ips()
        
        self.logger.info(f"Unbanned IP: {ip}")
        return len(rule_nums) > 0
    
    def get_banned_ips(self) -> List[BannedIP]:
        """Get list of banned IPs."""
        banned_ips = []
        chain = self.settings.firewall.banned_chain
        
        result = run_command(['iptables', '-L', chain, '-n'], check=False)
        if result.returncode != 0:
            return banned_ips
        
        for line in result.stdout.split('\n'):
            if 'DROP' in line:
                parts = line.split()
                if len(parts) >= 4:
                    ip = parts[3]
                    
                    # Extract comment
                    comment = ""
                    comment_match = re.search(r'/\*(.*?)\*/', line)
                    if comment_match:
                        comment = comment_match.group(1).strip()
                    
                    banned_ips.append(BannedIP(ip=ip, reason=comment))
        
        return banned_ips
    
    def add_rule(self, rule: FirewallRule) -> None:
        """Add a firewall rule."""
        rules_file = Path(self.settings.firewall.rules_file)
        
        # Append rule to file
        with open(rules_file, 'a') as f:
            f.write(f"\n# {rule.comment}\n")
            
            if rule.type == 'port_forward':
                f.write(f"iptables -t nat -A PREROUTING -i {rule.interface} -p {rule.protocol} ")
                f.write(f"-m multiport --dports {rule.ports} -j DNAT --to-destination {rule.destination}\n")
                f.write(f"iptables -A FORWARD -p {rule.protocol} -d {rule.destination} ")
                f.write(f"-m multiport --dports {rule.ports} -j ACCEPT\n")
            elif rule.type == 'custom':
                f.write(f"{rule.command}\n")
        
        # Apply rule immediately if firewall is active
        if self.lock_file.exists():
            if rule.type == 'port_forward':
                run_command(['iptables', '-t', 'nat', '-A', 'PREROUTING', '-i', rule.interface,
                           '-p', rule.protocol, '-m', 'multiport', '--dports', rule.ports,
                           '-j', 'DNAT', '--to-destination', rule.destination], check=False)
                run_command(['iptables', '-A', 'FORWARD', '-p', rule.protocol, '-d', rule.destination,
                           '-m', 'multiport', '--dports', rule.ports, '-j', 'ACCEPT'], check=False)
            elif rule.type == 'custom':
                parts = rule.command.split()
                run_command(parts, check=False)
        
        self.logger.info(f"Added firewall rule: {rule.comment}")
    
    def get_rules(self) -> List[FirewallRule]:
        """Get list of firewall rules from file."""
        rules = []
        rules_file = Path(self.settings.firewall.rules_file)
        
        if not rules_file.exists():
            return rules
        
        current_comment = ""
        for line in rules_file.read_text().split('\n'):
            line = line.strip()
            
            if line.startswith('# ') and not line.startswith('# ='):
                current_comment = line[2:]
            elif line.startswith('iptables'):
                rule = FirewallRule(
                    type='custom',
                    command=line,
                    comment=current_comment
                )
                rules.append(rule)
                current_comment = ""
        
        return rules
    
    def save_config(self) -> None:
        """Save current configuration."""
        self._save_banned_ips()
        self.settings.save()
        self.logger.info("Firewall configuration saved")