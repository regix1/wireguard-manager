#!/usr/bin/env python3
"""Firewall management for WireGuard."""

import re
from pathlib import Path
from typing import List, Dict, Optional
from datetime import datetime
from models.banned_ip import BannedIP
from models.firewall_rule import FirewallRule
from utils import run_command, pause, print_status, load_defaults
from menu import MenuHandler

class FirewallManager:
    """Manage firewall rules and banned IPs."""
    
    def __init__(self, config_scanner):
        self.scanner = config_scanner
        self.menu = MenuHandler()
        self.defaults = load_defaults()
        self.banned_file = Path("/etc/wireguard/banned_ips.txt")
        self.rules_file = Path("/etc/wireguard/firewall-rules.conf")
        self.banned_chain = "BANNED_IPS"
        
    def manage_firewall(self):
        """Main firewall management menu."""
        while True:
            options = [
                "Show Firewall Status",
                "Start Firewall",
                "Stop Firewall",
                "Restart Firewall",
                "───────────────────",
                "Manage Banned IPs",
                "Manage Port Forwarding",
                "Edit Firewall Rules",
                "View Active Rules",
                "───────────────────",
                "Back to Main Menu"
            ]
            
            choice = self.menu.show_menu(options, "🔥 Firewall Management")
            
            if choice is None or options[choice] == "Back to Main Menu":
                break
            
            if options[choice].startswith("─"):
                continue
                
            actions = {
                "Show Firewall Status": self.show_status,
                "Start Firewall": self.start_firewall,
                "Stop Firewall": self.stop_firewall,
                "Restart Firewall": self.restart_firewall,
                "Manage Banned IPs": self.manage_banned_ips,
                "Manage Port Forwarding": self.manage_port_forwarding,
                "Edit Firewall Rules": self.edit_rules,
                "View Active Rules": self.view_active_rules
            }
            
            action = actions.get(options[choice])
            if action:
                action()
    
    def show_status(self):
        """Show firewall status."""
        print("\n[Firewall Status]")
        print("-" * 50)
        
        # Check if firewall is active
        result = run_command(["iptables", "-L", "-n"], check=False)
        if result.returncode == 0:
            lines = result.stdout.split('\n')
            
            # Count rules
            input_rules = 0
            forward_rules = 0
            output_rules = 0
            
            current_chain = None
            for line in lines:
                if line.startswith("Chain INPUT"):
                    current_chain = "INPUT"
                elif line.startswith("Chain FORWARD"):
                    current_chain = "FORWARD"
                elif line.startswith("Chain OUTPUT"):
                    current_chain = "OUTPUT"
                elif line and not line.startswith("Chain") and not line.startswith("target"):
                    if current_chain == "INPUT":
                        input_rules += 1
                    elif current_chain == "FORWARD":
                        forward_rules += 1
                    elif current_chain == "OUTPUT":
                        output_rules += 1
            
            print(f"✓ Firewall is ACTIVE")
            print(f"  INPUT rules:   {input_rules}")
            print(f"  FORWARD rules: {forward_rules}")
            print(f"  OUTPUT rules:  {output_rules}")
            
            # Check banned IPs
            banned_count = self._count_banned_ips()
            print(f"  Banned IPs:    {banned_count}")
            
            # Check NAT rules
            result = run_command(["iptables", "-t", "nat", "-L", "-n"], check=False)
            if result.returncode == 0:
                nat_rules = result.stdout.count("DNAT") + result.stdout.count("MASQUERADE")
                print(f"  NAT rules:     {nat_rules}")
        else:
            print("✗ Unable to check firewall status")
        
        pause()
    
    def start_firewall(self):
        """Start firewall with rules from file."""
        print("\n[Starting Firewall]")
        print("-" * 50)
        
        if not self.rules_file.exists():
            print("No firewall rules file found.")
            if self.menu.confirm("Create default rules file?"):
                self._create_default_rules()
        
        # Apply rules from file
        self._apply_rules_from_file()
        
        # Load banned IPs
        self._load_banned_ips()
        
        print_status("Firewall started", True)
        pause()
    
    def stop_firewall(self):
        """Stop firewall (flush all rules)."""
        print("\n[Stopping Firewall]")
        print("-" * 50)
        
        if not self.menu.confirm("This will remove all firewall rules. Continue?"):
            return
        
        # Flush all chains
        run_command(["iptables", "-F"], check=False)
        run_command(["iptables", "-t", "nat", "-F"], check=False)
        run_command(["iptables", "-t", "mangle", "-F"], check=False)
        
        # Reset policies
        run_command(["iptables", "-P", "INPUT", "ACCEPT"])
        run_command(["iptables", "-P", "FORWARD", "ACCEPT"])
        run_command(["iptables", "-P", "OUTPUT", "ACCEPT"])
        
        print_status("Firewall stopped", True)
        pause()
    
    def restart_firewall(self):
        """Restart firewall."""
        print("\n[Restarting Firewall]")
        print("-" * 50)
        
        self.stop_firewall()
        self.start_firewall()
    
    def manage_banned_ips(self):
        """Manage banned IPs."""
        while True:
            options = [
                "List Banned IPs",
                "Ban IP Address",
                "Unban IP Address",
                "Import Ban List",
                "Export Ban List",
                "Back"
            ]
            
            choice = self.menu.show_menu(options, "🚫 Banned IP Management")
            
            if choice is None or options[choice] == "Back":
                break
            
            actions = {
                "List Banned IPs": self.list_banned_ips,
                "Ban IP Address": self.ban_ip,
                "Unban IP Address": self.unban_ip,
                "Import Ban List": self.import_ban_list,
                "Export Ban List": self.export_ban_list
            }
            
            action = actions.get(options[choice])
            if action:
                action()
    
    def list_banned_ips(self):
        """List all banned IPs."""
        print("\n[Banned IPs]")
        print("-" * 50)
        
        banned_ips = self._get_banned_ips()
        
        if not banned_ips:
            print("No IPs are currently banned")
        else:
            print(f"Total banned IPs: {len(banned_ips)}\n")
            print(f"{'IP Address':<20} {'Reason':<40}")
            print("-" * 60)
            for banned in banned_ips:
                print(f"{banned.ip:<20} {banned.reason:<40}")
        
        pause()
    
    def ban_ip(self):
        """Ban an IP address."""
        print("\n[Ban IP Address]")
        print("-" * 50)
        
        ip = input("IP address to ban (or CIDR like 192.168.1.0/24): ").strip()
        if not ip:
            return
        
        reason = input("Reason for ban (optional): ").strip()
        
        # Add to iptables
        self._add_banned_ip(ip, reason)
        
        # Save to file
        self._save_banned_ip(ip, reason)
        
        print_status(f"IP {ip} has been banned", True)
        pause()
    
    def unban_ip(self):
        """Unban an IP address."""
        print("\n[Unban IP Address]")
        print("-" * 50)
        
        banned_ips = self._get_banned_ips()
        if not banned_ips:
            print("No IPs are currently banned")
            pause()
            return
        
        # Show list and get selection
        ip_list = [f"{b.ip} - {b.reason}" if b.reason else b.ip for b in banned_ips]
        choice = self.menu.show_menu(ip_list, "Select IP to unban:")
        
        if choice is None:
            return
        
        ip_to_unban = banned_ips[choice].ip
        
        # Remove from iptables
        self._remove_banned_ip(ip_to_unban)
        
        # Remove from file
        self._remove_from_banned_file(ip_to_unban)
        
        print_status(f"IP {ip_to_unban} has been unbanned", True)
        pause()
    
    def manage_port_forwarding(self):
        """Manage port forwarding rules."""
        print("\n[Port Forwarding]")
        print("-" * 50)
        
        options = [
            "Add Port Forward",
            "Remove Port Forward",
            "List Port Forwards",
            "Back"
        ]
        
        choice = self.menu.show_menu(options, "Port Forwarding")
        
        if choice is None or options[choice] == "Back":
            return
        
        if options[choice] == "Add Port Forward":
            self._add_port_forward()
        elif options[choice] == "Remove Port Forward":
            print("Edit firewall-rules.conf to remove port forwards")
            pause()
        elif options[choice] == "List Port Forwards":
            self._list_port_forwards()
    
    def _add_port_forward(self):
        """Add a port forwarding rule."""
        print("\n[Add Port Forward]")
        print("-" * 50)
        
        protocol = input("Protocol (tcp/udp/both) [tcp]: ").strip().lower() or "tcp"
        ports = input("Port(s) (e.g., 80 or 80,443 or 8000:8100): ").strip()
        destination = input("Destination IP: ").strip()
        interface = input("External interface [eno1]: ").strip() or "eno1"
        comment = input("Comment/Description: ").strip()
        
        if not ports or not destination:
            print("Port and destination are required")
            pause()
            return
        
        # Create rule
        rule = FirewallRule(
            type='port_forward',
            protocol=protocol,
            ports=ports,
            destination=destination,
            interface=interface,
            comment=comment
        )
        
        # Add to file
        with open(self.rules_file, 'a') as f:
            f.write(f"\n# {comment}\n")
            f.write(rule.to_iptables() + "\n")
        
        # Apply immediately
        for cmd in rule.to_iptables().split('\n'):
            run_command(cmd.split(), check=False)
        
        print_status("Port forward added", True)
        pause()
    
    def _list_port_forwards(self):
        """List port forwarding rules."""
        print("\n[Active Port Forwards]")
        print("-" * 50)
        
        result = run_command(["iptables", "-t", "nat", "-L", "PREROUTING", "-n"], check=False)
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if 'DNAT' in line:
                    print(f"  • {line}")
        
        pause()
    
    def edit_rules(self):
        """Edit firewall rules file."""
        print("\n[Edit Firewall Rules]")
        print("-" * 50)
        
        print(f"Rules file: {self.rules_file}")
        
        if not self.rules_file.exists():
            if self.menu.confirm("Rules file doesn't exist. Create it?"):
                self._create_default_rules()
        
        print("\nEdit the file manually or use the port forwarding menu")
        print(f"File location: {self.rules_file}")
        pause()
    
    def view_active_rules(self):
        """View all active iptables rules."""
        print("\n[Active Firewall Rules]")
        print("-" * 50)
        
        print("\n[FILTER TABLE]")
        run_command(["iptables", "-L", "-n", "-v"], check=False, print_output=True)
        
        print("\n[NAT TABLE]")
        run_command(["iptables", "-t", "nat", "-L", "-n", "-v"], check=False, print_output=True)
        
        pause()
    
    # Helper methods
    def _create_default_rules(self):
        """Create default firewall rules file."""
        default_content = f"""# WireGuard Firewall Rules Configuration
# Generated: {datetime.now()}
# This file contains iptables commands to be applied

# ========== NAT Rules ==========
# Enable masquerading for WireGuard subnet
iptables -t nat -A POSTROUTING -o eno1 -s {self.defaults['default_subnet']} -j MASQUERADE

# ========== Basic Access Rules ==========
# WireGuard interface
iptables -A INPUT -p udp --dport {self.defaults['default_port']} -j ACCEPT

# Allow forwarding
iptables -A FORWARD -i eno1 -o wg0 -j ACCEPT
iptables -A FORWARD -i wg0 -j ACCEPT

# ========== Port Forwarding Rules ==========
# Add your port forwarding rules here
# Example:
# iptables -t nat -A PREROUTING -i eno1 -p tcp --dport 80 -j DNAT --to-destination 10.0.4.246
# iptables -A FORWARD -p tcp -d 10.0.4.246 --dport 80 -j ACCEPT
"""
        
        self.rules_file.write_text(default_content)
        print_status(f"Created default rules file: {self.rules_file}", True)
    
    def _apply_rules_from_file(self):
        """Apply firewall rules from configuration file."""
        if not self.rules_file.exists():
            return
        
        print("Applying firewall rules...")
        
        for line in self.rules_file.read_text().split('\n'):
            line = line.strip()
            
            # Skip comments and empty lines
            if not line or line.startswith('#'):
                continue
            
            # Execute iptables command
            if line.startswith('iptables'):
                run_command(line.split(), check=False)
        
        print_status("Rules applied", True)
    
    def _init_banned_chain(self):
        """Initialize the banned IPs chain."""
        # Create chain if it doesn't exist
        run_command(["iptables", "-N", self.banned_chain], check=False)
        
        # Add jump rules
        run_command(["iptables", "-D", "INPUT", "-j", self.banned_chain], check=False)
        run_command(["iptables", "-I", "INPUT", "1", "-j", self.banned_chain])
        
        run_command(["iptables", "-D", "FORWARD", "-j", self.banned_chain], check=False)
        run_command(["iptables", "-I", "FORWARD", "1", "-j", self.banned_chain])
    
    def _load_banned_ips(self):
        """Load banned IPs from file."""
        if not self.banned_file.exists():
            return
        
        # Initialize chain
        self._init_banned_chain()
        
        # Clear existing rules in chain
        run_command(["iptables", "-F", self.banned_chain], check=False)
        
        # Load IPs
        count = 0
        for line in self.banned_file.read_text().split('\n'):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            banned = BannedIP.from_file_format(line)
            self._add_banned_ip(banned.ip, banned.reason, save=False)
            count += 1
        
        print(f"Loaded {count} banned IPs")
    
    def _add_banned_ip(self, ip: str, reason: str = "", save: bool = True):
        """Add IP to banned chain."""
        # Initialize chain if needed
        self._init_banned_chain()
        
        # Add rule
        cmd = ["iptables", "-A", self.banned_chain, "-s", ip]
        if reason:
            cmd.extend(["-m", "comment", "--comment", reason])
        cmd.extend(["-j", "DROP"])
        
        run_command(cmd, check=False)
        
        if save:
            self._save_banned_ip(ip, reason)
    
    def _remove_banned_ip(self, ip: str):
        """Remove IP from banned chain."""
        # Find and remove rules
        result = run_command(["iptables", "-L", self.banned_chain, "--line-numbers", "-n"], check=False)
        if result.returncode == 0:
            lines = result.stdout.split('\n')
            for line in reversed(lines):  # Process in reverse to maintain line numbers
                if ip in line and line[0].isdigit():
                    rule_num = line.split()[0]
                    run_command(["iptables", "-D", self.banned_chain, rule_num], check=False)
    
    def _save_banned_ip(self, ip: str, reason: str = ""):
        """Save banned IP to file."""
        banned = BannedIP(ip=ip, reason=reason)
        
        # Append to file
        self.banned_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(self.banned_file, 'a') as f:
            f.write(banned.to_file_format() + '\n')
    
    def _remove_from_banned_file(self, ip: str):
        """Remove IP from banned file."""
        if not self.banned_file.exists():
            return
        
        lines = []
        for line in self.banned_file.read_text().split('\n'):
            if line.strip() and not line.strip().startswith(ip):
                lines.append(line)
        
        self.banned_file.write_text('\n'.join(lines))
    
    def _get_banned_ips(self) -> List[BannedIP]:
        """Get list of banned IPs from file."""
        banned_ips = []
        
        if self.banned_file.exists():
            for line in self.banned_file.read_text().split('\n'):
                line = line.strip()
                if line and not line.startswith('#'):
                    banned_ips.append(BannedIP.from_file_format(line))
        
        return banned_ips
    
    def _count_banned_ips(self) -> int:
        """Count banned IPs."""
        result = run_command(["iptables", "-L", self.banned_chain, "-n"], check=False)
        if result.returncode == 0:
            return result.stdout.count('DROP')
        return 0
    
    def import_ban_list(self):
        """Import a ban list from file."""
        print("\n[Import Ban List]")
        print("-" * 50)
        
        file_path = input("Path to ban list file: ").strip()
        if not file_path:
            return
        
        import_file = Path(file_path)
        if not import_file.exists():
            print(f"File not found: {file_path}")
            pause()
            return
        
        count = 0
        for line in import_file.read_text().split('\n'):
            line = line.strip()
            if line and not line.startswith('#'):
                banned = BannedIP.from_file_format(line)
                self._add_banned_ip(banned.ip, banned.reason)
                count += 1
        
        print_status(f"Imported {count} banned IPs", True)
        pause()
    
    def export_ban_list(self):
        """Export ban list to file."""
        print("\n[Export Ban List]")
        print("-" * 50)
        
        export_path = input("Export path [/tmp/banned_ips_export.txt]: ").strip()
        if not export_path:
            export_path = "/tmp/banned_ips_export.txt"
        
        export_file = Path(export_path)
        
        banned_ips = self._get_banned_ips()
        
        with open(export_file, 'w') as f:
            f.write(f"# Banned IPs exported on {datetime.now()}\n")
            f.write(f"# Format: IP|Reason\n\n")
            for banned in banned_ips:
                f.write(banned.to_file_format() + '\n')
        
        print_status(f"Exported {len(banned_ips)} IPs to {export_file}", True)
        pause()