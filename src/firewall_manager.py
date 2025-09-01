"""Firewall and NAT management for WireGuard."""

import json
import shutil
from pathlib import Path
from typing import List, Dict, Optional
from datetime import datetime
from jinja2 import Template, Environment, FileSystemLoader
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, IntPrompt
from rich.progress import Progress, SpinnerColumn, TextColumn

from .utils import run_command, prompt_yes_no, ensure_directory
from .config_manager import ConfigManager
from .service_manager import ServiceManager

console = Console()

class FirewallManager:
    """Manage firewall rules and NAT."""
    
    def __init__(self):
        """Initialize firewall manager."""
        self.config_manager = ConfigManager()
        self.service_manager = ServiceManager()
        self.firewall_dir = Path("/etc/wireguard/firewall")
        self.rules_file = self.firewall_dir / "rules.conf"
        self.banned_ips_file = self.firewall_dir / "banned_ips.txt"
        self.service_name = "wireguard-firewall"
        self.service_file = Path(f"/etc/systemd/system/{self.service_name}.service")
        self._setup_jinja_env()
        self._ensure_firewall_setup()
    
    def _setup_jinja_env(self):
        """Setup Jinja2 environment for templates."""
        template_dirs = [
            Path(__file__).parent.parent / "data" / "templates",
            Path.home() / "wireguard-manager" / "data" / "templates",
            Path("/opt/wireguard-manager/data/templates"),
        ]
        
        loaders = []
        for path in template_dirs:
            if path.exists():
                loaders.append(FileSystemLoader(str(path)))
        
        if loaders:
            from jinja2 import ChoiceLoader
            self.env = Environment(
                loader=ChoiceLoader(loaders),
                trim_blocks=True,
                lstrip_blocks=True,
            )
        else:
            self.env = Environment()
    
    def _ensure_firewall_setup(self) -> None:
        """Ensure firewall directory and service are properly set up."""
        # Create firewall directory
        ensure_directory(self.firewall_dir, mode=0o755)
        
        # Check for old broken service
        self._cleanup_old_service()
        
        # Setup firewall if not exists
        if not self.service_file.exists() or not (self.firewall_dir / "apply-rules.sh").exists():
            console.print("[yellow]Firewall service not configured. Setting up...[/yellow]")
            self.setup_firewall_service()
    
    def _cleanup_old_service(self) -> None:
        """Clean up old broken wg-quick@firewall-rules service."""
        result = run_command(
            ["systemctl", "status", "wg-quick@firewall-rules.service"],
            check=False
        )
        
        if "loaded" in result.stdout.lower():
            console.print("[yellow]Found old firewall-rules service, cleaning up...[/yellow]")
            run_command(["systemctl", "stop", "wg-quick@firewall-rules.service"], check=False)
            run_command(["systemctl", "disable", "wg-quick@firewall-rules.service"], check=False)
            
            # Move old config if exists
            old_config = Path("/etc/wireguard/firewall-rules.conf")
            if old_config.exists() and not self.rules_file.exists():
                console.print(f"[cyan]Moving existing rules to {self.rules_file}[/cyan]")
                shutil.move(str(old_config), str(self.rules_file))
    
    def setup_firewall_service(self) -> None:
        """Setup the firewall service and scripts from templates."""
        console.print(Panel.fit(
            "[bold cyan]Setup Firewall Service[/bold cyan]",
            border_style="cyan"
        ))
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
        ) as progress:
            task = progress.add_task("Setting up firewall service...", total=None)
            
            # Get configuration
            config = self.config_manager.load_config()
            interfaces = []
            
            # Get all WireGuard interfaces
            for interface_name in self.service_manager.get_interfaces():
                interface_config = Path(f"/etc/wireguard/{interface_name}.conf")
                if interface_config.exists():
                    # Parse config to get subnet and port
                    content = interface_config.read_text()
                    subnet = config.get('server_subnet', '10.0.0.0/24')
                    port = config.get('server_port', 51820)
                    
                    # Try to extract from config
                    for line in content.split('\n'):
                        if line.strip().startswith('Address'):
                            addr = line.split('=')[1].strip()
                            if '/' in addr:
                                # Convert single IP to subnet
                                ip_part = addr.split('/')[0]
                                prefix = addr.split('/')[1]
                                # Create subnet (e.g., 10.0.0.1/24 -> 10.0.0.0/24)
                                octets = ip_part.split('.')
                                if prefix == '24':
                                    subnet = f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"
                                elif prefix == '32':
                                    subnet = addr
                        elif line.strip().startswith('ListenPort'):
                            port = int(line.split('=')[1].strip())
                    
                    interfaces.append({
                        'name': interface_name,
                        'subnet': subnet,
                        'port': port
                    })
            
            if not interfaces:
                # Default interface if none found
                interfaces = [{
                    'name': 'wg0',
                    'subnet': config.get('server_subnet', '10.0.0.0/24'),
                    'port': config.get('server_port', 51820)
                }]
            
            template_data = {
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'firewall_dir': str(self.firewall_dir),
                'rules_file': str(self.rules_file),
                'banned_ips_file': str(self.banned_ips_file),
                'external_interface': config.get('external_interface', 'eth0'),
                'interfaces': interfaces
            }
            
            # Create service file
            progress.update(task, description="Creating service file...")
            try:
                service_template = self.env.get_template('firewall.service.j2')
                service_content = service_template.render(**template_data)
            except:
                # Fallback if template not found
                service_content = f"""[Unit]
Description=WireGuard Firewall Rules
After=network-pre.target
Before=network.target wg-quick@wg0.service
Wants=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart={self.firewall_dir}/apply-rules.sh
ExecStop={self.firewall_dir}/remove-rules.sh
ExecReload={self.firewall_dir}/apply-rules.sh

[Install]
WantedBy=multi-user.target"""
            
            self.service_file.write_text(service_content)
            
            # Create apply script
            progress.update(task, description="Creating apply-rules script...")
            try:
                apply_template = self.env.get_template('apply-rules.sh.j2')
                apply_content = apply_template.render(**template_data)
            except:
                # Fallback script
                apply_content = self._get_default_apply_script(template_data)
            
            apply_script = self.firewall_dir / "apply-rules.sh"
            apply_script.write_text(apply_content)
            apply_script.chmod(0o755)
            
            # Create remove script
            progress.update(task, description="Creating remove-rules script...")
            try:
                remove_template = self.env.get_template('remove-rules.sh.j2')
                remove_content = remove_template.render(**template_data)
            except:
                # Fallback script
                remove_content = self._get_default_remove_script(template_data)
            
            remove_script = self.firewall_dir / "remove-rules.sh"
            remove_script.write_text(remove_content)
            remove_script.chmod(0o755)
            
            # Create default rules file if not exists
            if not self.rules_file.exists():
                progress.update(task, description="Creating default rules file...")
                try:
                    rules_template = self.env.get_template('default-rules.conf.j2')
                    rules_content = rules_template.render(**template_data)
                except:
                    rules_content = self._get_default_rules(template_data)
                
                self.rules_file.write_text(rules_content)
            
            # Reload systemd
            progress.update(task, description="Reloading systemd...")
            run_command(["systemctl", "daemon-reload"], check=False)
            
            # Enable and start service
            progress.update(task, description="Starting firewall service...")
            run_command(["systemctl", "enable", self.service_name], check=False)
            result = run_command(["systemctl", "start", self.service_name], check=False)
            
            progress.update(task, completed=True)
        
        if result.returncode == 0:
            console.print("[green]✓ Firewall service setup complete and started[/green]")
        else:
            console.print("[yellow]⚠ Firewall service created but failed to start[/yellow]")
            console.print("[cyan]Check status with: systemctl status wireguard-firewall[/cyan]")
    
    def _get_default_apply_script(self, data: dict) -> str:
        """Get default apply script if template not found."""
        return f"""#!/bin/bash

# Enable IP forwarding
sysctl -w net.ipv4.ip_forward=1

# Create BANNED_IPS chain if it doesn't exist
iptables -t filter -L BANNED_IPS &>/dev/null || {{
    iptables -N BANNED_IPS
    iptables -I INPUT 1 -j BANNED_IPS
    iptables -I FORWARD 1 -j BANNED_IPS
}}

# Apply rules from config file
RULES_FILE="{data['rules_file']}"

if [ -f "$RULES_FILE" ]; then
    echo "Applying firewall rules from $RULES_FILE"
    
    while IFS= read -r line; do
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ -z "${{line// }}" ]] && continue
        
        eval "$line" 2>/dev/null || echo "Failed: $line"
    done < "$RULES_FILE"
    
    echo "Firewall rules applied successfully"
else
    echo "No rules file found, applying defaults"
    # Default NAT for WireGuard
    iptables -t nat -A POSTROUTING -o {data['external_interface']} -s 10.0.0.0/24 -j MASQUERADE
    iptables -A FORWARD -i wg0 -j ACCEPT
    iptables -A FORWARD -o wg0 -j ACCEPT
fi

exit 0"""
    
    def _get_default_remove_script(self, data: dict) -> str:
        """Get default remove script if template not found."""
        return """#!/bin/bash

# Remove BANNED_IPS chain
iptables -D INPUT -j BANNED_IPS 2>/dev/null
iptables -D FORWARD -j BANNED_IPS 2>/dev/null
iptables -F BANNED_IPS 2>/dev/null
iptables -X BANNED_IPS 2>/dev/null

echo "Firewall rules removed"
exit 0"""
    
    def _get_default_rules(self, data: dict) -> str:
        """Get default rules if template not found."""
        rules = [
            f"# WireGuard Firewall Rules",
            f"# Generated: {data['timestamp']}",
            f"",
            f"# NAT Rules",
        ]
        
        for iface in data['interfaces']:
            rules.append(f"iptables -t nat -A POSTROUTING -o {data['external_interface']} -s {iface['subnet']} -j MASQUERADE")
        
        rules.extend([
            "",
            "# Forward Rules",
        ])
        
        for iface in data['interfaces']:
            rules.append(f"iptables -A FORWARD -i {iface['name']} -j ACCEPT")
            rules.append(f"iptables -A FORWARD -o {iface['name']} -j ACCEPT")
        
        return '\n'.join(rules)
    
    def show_status(self) -> None:
        """Show comprehensive firewall status."""
        console.print(Panel.fit(
            "[bold cyan]Firewall Status[/bold cyan]",
            border_style="cyan"
        ))
        
        # Service status
        self._show_service_status()
        
        # IP forwarding
        self._show_ip_forwarding()
        
        # NAT rules
        self._show_nat_rules()
        
        # Port forwarding
        self._show_port_forwarding()
        
        # Banned IPs
        self._show_banned_ips_summary()
        
        # Rules file
        self._show_rules_file_status()
    
    def _show_service_status(self) -> None:
        """Show firewall service status."""
        console.print("[cyan]Firewall Service:[/cyan]")
        
        result = run_command(["systemctl", "is-active", self.service_name], check=False)
        
        if result.returncode == 0:
            console.print(f"  [green]● {self.service_name} is active[/green]")
            
            # Show last start time
            result = run_command(
                ["systemctl", "show", self.service_name, "--property=ActiveEnterTimestamp"],
                check=False
            )
            if result.returncode == 0 and "=" in result.stdout:
                timestamp = result.stdout.split("=")[1].strip()
                if timestamp:
                    console.print(f"  Started: {timestamp}")
        else:
            console.print(f"  [red]○ {self.service_name} is inactive[/red]")
            console.print("  [yellow]Run 'Firewall & Security → Apply Standard NAT' to setup[/yellow]")
    
    def _show_ip_forwarding(self) -> None:
        """Show IP forwarding status."""
        console.print("\n[cyan]IP Forwarding:[/cyan]")
        with open("/proc/sys/net/ipv4/ip_forward", "r") as f:
            ip_forward = f.read().strip()
        
        if ip_forward == "1":
            console.print("  [green]✓ IPv4 forwarding enabled[/green]")
        else:
            console.print("  [red]✗ IPv4 forwarding disabled[/red]")
    
    def _show_nat_rules(self) -> None:
        """Show NAT rules summary."""
        console.print("\n[cyan]NAT Rules:[/cyan]")
        result = run_command(
            ["iptables", "-t", "nat", "-L", "POSTROUTING", "-n", "--line-numbers"],
            check=False
        )
        
        if result.returncode == 0:
            lines = result.stdout.split('\n')
            masq_count = sum(1 for line in lines if 'MASQUERADE' in line)
            snat_count = sum(1 for line in lines if 'SNAT' in line)
            
            if masq_count > 0 or snat_count > 0:
                console.print(f"  [green]✓ {masq_count} MASQUERADE rule(s)[/green]")
                if snat_count > 0:
                    console.print(f"  [green]✓ {snat_count} SNAT rule(s)[/green]")
            else:
                console.print("  [yellow]No NAT rules configured[/yellow]")
    
    def _show_port_forwarding(self) -> None:
        """Show port forwarding summary."""
        console.print("\n[cyan]Port Forwarding:[/cyan]")
        result = run_command(
            ["iptables", "-t", "nat", "-L", "PREROUTING", "-n", "--line-numbers"],
            check=False
        )
        
        if result.returncode == 0:
            lines = result.stdout.split('\n')
            dnat_count = sum(1 for line in lines if 'DNAT' in line)
            
            if dnat_count > 0:
                console.print(f"  [green]✓ {dnat_count} port forward rule(s)[/green]")
            else:
                console.print("  [yellow]No port forwarding configured[/yellow]")
    
    def _show_banned_ips_summary(self) -> None:
        """Show banned IPs summary."""
        console.print("\n[cyan]Banned IPs:[/cyan]")
        banned_count = self._get_banned_ip_count()
        
        if banned_count > 0:
            console.print(f"  [yellow]⚠ {banned_count} IP(s) banned[/yellow]")
        else:
            console.print("  [green]✓ No banned IPs[/green]")
    
    def _show_rules_file_status(self) -> None:
        """Show rules file status."""
        console.print("\n[cyan]Rules Configuration:[/cyan]")
        
        if self.rules_file.exists():
            lines = self.rules_file.read_text().split('\n')
            rule_count = sum(1 for line in lines if line.strip() and not line.strip().startswith('#'))
            console.print(f"  [green]✓ {rule_count} active rule(s)[/green]")
            console.print(f"  Location: {self.rules_file}")
        else:
            console.print("  [yellow]No rules file configured[/yellow]")
    
    def manage_nat_rules(self) -> None:
        """Manage NAT/Masquerade rules."""
        console.print(Panel.fit(
            "[bold cyan]NAT Rule Management[/bold cyan]",
            border_style="cyan"
        ))
        
        options = [
            "View NAT rules",
            "Add masquerade rule", 
            "Add SNAT rule",
            "Remove NAT rule",
            "Edit rules file",
            "Restart firewall service",  # Added
            "Rebuild firewall service",   # Added
            "Back"
        ]
        
        for i, option in enumerate(options, 1):
            console.print(f"  {i}. {option}")
        
        choice = IntPrompt.ask("Select option", choices=[str(i) for i in range(1, 9)])
        
        if choice == 1:
            self._view_nat_rules()
        elif choice == 2:
            self._add_masquerade_rule()
        elif choice == 3:
            self._add_snat_rule()
        elif choice == 4:
            self._remove_nat_rule()
        elif choice == 5:
            self._edit_rules_file()
        elif choice == 6:
            self.restart_firewall_service()
            console.print("\n[dim]Press Enter to continue...[/dim]")
            input()
        elif choice == 7:
            if prompt_yes_no("Rebuild firewall service from templates?", default=False):
                self.setup_firewall_service()
            console.print("\n[dim]Press Enter to continue...[/dim]")
            input()
    
    def manage_port_forwarding(self) -> None:
        """Manage port forwarding rules."""
        console.print(Panel.fit(
            "[bold cyan]Port Forwarding[/bold cyan]",
            border_style="cyan"
        ))
        
        options = [
            "View current port forwards",
            "Add port forward",
            "Remove port forward",
            "Add range forward",
            "Edit rules file",
            "Back"
        ]
        
        for i, option in enumerate(options, 1):
            console.print(f"  {i}. {option}")
        
        choice = IntPrompt.ask("Select option", choices=[str(i) for i in range(1, 7)])
        
        if choice == 1:
            self._view_port_forwards()
        elif choice == 2:
            self._add_port_forward()
        elif choice == 3:
            self._remove_port_forward()
        elif choice == 4:
            self._add_range_forward()
        elif choice == 5:
            self._edit_rules_file()
    
    def manage_forward_rules(self) -> None:
        """Manage FORWARD chain rules."""
        console.print(Panel.fit(
            "[bold cyan]Forward Rules Management[/bold cyan]",
            border_style="cyan"
        ))
        
        options = [
            "View forward rules",
            "Add accept rule",
            "Add drop rule",
            "Remove forward rule",
            "Edit rules file",
            "Back"
        ]
        
        for i, option in enumerate(options, 1):
            console.print(f"  {i}. {option}")
        
        choice = IntPrompt.ask("Select option", choices=[str(i) for i in range(1, 7)])
        
        if choice == 1:
            self._view_forward_rules()
        elif choice == 2:
            self._add_forward_accept()
        elif choice == 3:
            self._add_forward_drop()
        elif choice == 4:
            self._remove_forward_rule()
        elif choice == 5:
            self._edit_rules_file()
    
    def manage_banned_ips(self) -> None:
        """Manage banned IP addresses."""
        console.print(Panel.fit(
            "[bold cyan]Banned IP Management[/bold cyan]",
            border_style="cyan"
        ))
        
        options = [
            "View banned IPs",
            "Ban an IP",
            "Unban an IP",
            "Ban IP range",
            "Clear all bans",
            "Import ban list",
            "Export ban list",
            "Back"
        ]
        
        for i, option in enumerate(options, 1):
            console.print(f"  {i}. {option}")
        
        choice = IntPrompt.ask("Select option", choices=[str(i) for i in range(1, 9)])
        
        if choice == 1:
            self._view_banned_ips()
        elif choice == 2:
            self._ban_ip()
        elif choice == 3:
            self._unban_ip()
        elif choice == 4:
            self._ban_ip_range()
        elif choice == 5:
            self._clear_all_bans()
        elif choice == 6:
            self._import_ban_list()
        elif choice == 7:
            self._export_ban_list()
    
    def apply_nat_rules(self) -> None:
        """Apply standard NAT rules for WireGuard."""
        console.print(Panel.fit(
            "[bold cyan]Apply Standard NAT Rules[/bold cyan]",
            border_style="cyan"
        ))
        
        # Check if service exists
        if not self.service_file.exists():
            console.print("[yellow]Firewall service not configured. Setting up...[/yellow]")
            self.setup_firewall_service()
        else:
            console.print("[cyan]Restarting firewall service to apply rules...[/cyan]")
            result = run_command(["systemctl", "restart", self.service_name], check=False)
            
            if result.returncode == 0:
                console.print("[green]✓ Firewall rules applied[/green]")
            else:
                console.print("[red]Failed to restart firewall service[/red]")
                console.print("[yellow]Try: systemctl status wireguard-firewall[/yellow]")
    
    def _edit_rules_file(self) -> None:
        """Edit the firewall rules file."""
        console.print(Panel.fit(
            "[bold cyan]Edit Firewall Rules[/bold cyan]",
            border_style="cyan"
        ))
        
        if not self.rules_file.exists():
            console.print("[yellow]Rules file doesn't exist. Creating...[/yellow]")
            self.setup_firewall_service()
        
        console.print(f"[cyan]Current rules file:[/cyan] {self.rules_file}")
        console.print("\n[cyan]Current contents (first 20 lines):[/cyan]")
        console.print("─" * 60)
        
        if self.rules_file.exists():
            lines = self.rules_file.read_text().split('\n')[:20]
            for line in lines:
                console.print(line)
            if len(self.rules_file.read_text().split('\n')) > 20:
                console.print("... (truncated)")
        
        console.print("─" * 60)
        
        console.print("\n[yellow]Options:[/yellow]")
        console.print("  1. Add a new rule")
        console.print("  2. View full file")
        console.print("  3. Reload firewall service")
        console.print("  4. Back")
        
        choice = IntPrompt.ask("Select option", choices=["1", "2", "3", "4"])
        
        if choice == 1:
            self._add_rule_to_file()
        elif choice == 2:
            self._view_full_rules_file()
        elif choice == 3:
            run_command(["systemctl", "reload", self.service_name], check=False)
            console.print("[green]✓ Firewall service reloaded[/green]")
    
    def _add_rule_to_file(self) -> None:
        """Add a new rule to the rules file."""
        console.print("\n[cyan]Add New Rule[/cyan]")
        console.print("[dim]Enter iptables command (without 'sudo')[/dim]")
        console.print("[dim]Example: iptables -A FORWARD -p tcp --dport 80 -j ACCEPT[/dim]")
        
        rule = Prompt.ask("\nEnter rule")
        
        if rule and rule.startswith('iptables'):
            # Add to file
            with open(self.rules_file, 'a') as f:
                f.write(f"\n# Added via manager - {datetime.now():%Y-%m-%d %H:%M}\n")
                f.write(f"{rule}\n")
            
            console.print("[green]✓ Rule added to file[/green]")
            
            if prompt_yes_no("Apply rule now?", default=True):
                result = run_command(rule.split(), check=False)
                if result.returncode == 0:
                    console.print("[green]✓ Rule applied[/green]")
                else:
                    console.print("[red]Failed to apply rule[/red]")
        else:
            console.print("[yellow]Invalid rule format[/yellow]")
    
    def _view_full_rules_file(self) -> None:
        """View the complete rules file."""
        if self.rules_file.exists():
            content = self.rules_file.read_text()
            console.print(content)
        else:
            console.print("[yellow]Rules file not found[/yellow]")
    
    def _view_nat_rules(self) -> None:
        """View detailed NAT rules."""
        console.print("\n[cyan]NAT Table - POSTROUTING Chain:[/cyan]")
        result = run_command(
            ["iptables", "-t", "nat", "-L", "POSTROUTING", "-n", "-v", "--line-numbers"],
            check=False
        )
        if result.returncode == 0:
            console.print(result.stdout)
    
    def _add_masquerade_rule(self) -> None:
        """Add a masquerade rule."""
        console.print("\n[cyan]Add Masquerade Rule[/cyan]")
        
        source = Prompt.ask("Source subnet (e.g., 10.0.0.0/24)")
        interface = Prompt.ask("Output interface (e.g., eth0)")
        
        rule = f"iptables -t nat -A POSTROUTING -s {source} -o {interface} -j MASQUERADE"
        
        console.print(f"\n[yellow]Command:[/yellow] {rule}")
        
        if prompt_yes_no("Add this rule?", default=True):
            # Add to rules file
            with open(self.rules_file, 'a') as f:
                f.write(f"\n# Masquerade rule - {datetime.now():%Y-%m-%d %H:%M}\n")
                f.write(f"{rule}\n")
            
            # Apply immediately
            result = run_command(rule.split(), check=False)
            if result.returncode == 0:
                console.print("[green]✓ Masquerade rule added[/green]")
            else:
                console.print(f"[red]Failed: {result.stderr}[/red]")
    
    def _add_snat_rule(self) -> None:
        """Add an SNAT rule."""
        console.print("\n[cyan]Add SNAT Rule[/cyan]")
        
        source = Prompt.ask("Source subnet (e.g., 10.0.0.0/24)")
        interface = Prompt.ask("Output interface (e.g., eth0)")
        to_source = Prompt.ask("SNAT to IP address")
        
        rule = f"iptables -t nat -A POSTROUTING -s {source} -o {interface} -j SNAT --to-source {to_source}"
        
        console.print(f"\n[yellow]Command:[/yellow] {rule}")
        
        if prompt_yes_no("Add this rule?", default=True):
            # Add to rules file
            with open(self.rules_file, 'a') as f:
                f.write(f"\n# SNAT rule - {datetime.now():%Y-%m-%d %H:%M}\n")
                f.write(f"{rule}\n")
            
            # Apply immediately
            result = run_command(rule.split(), check=False)
            if result.returncode == 0:
                console.print("[green]✓ SNAT rule added[/green]")
            else:
                console.print(f"[red]Failed: {result.stderr}[/red]")
    
    def _remove_nat_rule(self) -> None:
        """Remove a NAT rule by line number."""
        self._view_nat_rules()
        
        line_num = IntPrompt.ask("\nEnter rule number to remove (0 to cancel)")
        if line_num == 0:
            return
        
        cmd = ["iptables", "-t", "nat", "-D", "POSTROUTING", str(line_num)]
        
        if prompt_yes_no(f"Remove rule #{line_num}?", default=False):
            result = run_command(cmd, check=False)
            if result.returncode == 0:
                console.print("[green]✓ Rule removed from active firewall[/green]")
                console.print("[yellow]Note: Update rules file to make permanent[/yellow]")
            else:
                console.print(f"[red]Failed: {result.stderr}[/red]")
    
    def _view_port_forwards(self) -> None:
        """View current port forwarding rules."""
        console.print("\n[cyan]Port Forwarding Rules (PREROUTING):[/cyan]")
        result = run_command(
            ["iptables", "-t", "nat", "-L", "PREROUTING", "-n", "-v", "--line-numbers"],
            check=False
        )
        if result.returncode == 0:
            console.print(result.stdout)
    
    def _add_port_forward(self) -> None:
        """Add a port forwarding rule."""
        console.print("\n[cyan]Add Port Forward[/cyan]")
        
        external_port = IntPrompt.ask("External port")
        internal_ip = Prompt.ask("Internal IP (VPN client)")
        internal_port = IntPrompt.ask("Internal port", default=external_port)
        protocol = Prompt.ask("Protocol", choices=["tcp", "udp", "both"], default="tcp")
        
        config = self.config_manager.load_config()
        external_interface = config.get('external_interface', 'eth0')
        
        rules = []
        if protocol == "both":
            protocols = ["tcp", "udp"]
        else:
            protocols = [protocol]
        
        for proto in protocols:
            rules.append(
                f"iptables -t nat -A PREROUTING -i {external_interface} -p {proto} " +
                f"--dport {external_port} -j DNAT --to-destination {internal_ip}:{internal_port}"
            )
            rules.append(
                f"iptables -A FORWARD -p {proto} -d {internal_ip} --dport {internal_port} -j ACCEPT"
            )
        
        console.print("\n[yellow]Rules to add:[/yellow]")
        for rule in rules:
            console.print(f"  {rule}")
        
        if prompt_yes_no("Add these rules?", default=True):
            # Add to rules file
            with open(self.rules_file, 'a') as f:
                f.write(f"\n# Port forward: {external_port} -> {internal_ip}:{internal_port} ({protocol})\n")
                f.write(f"# Added: {datetime.now():%Y-%m-%d %H:%M}\n")
                for rule in rules:
                    f.write(f"{rule}\n")
            
            # Apply immediately
            for rule in rules:
                run_command(rule.split(), check=False)
            
            console.print(f"[green]✓ Port forward added: {external_port} -> {internal_ip}:{internal_port}[/green]")
    
    def _add_range_forward(self) -> None:
        """Add port range forwarding."""
        console.print("\n[cyan]Add Port Range Forward[/cyan]")
        
        start_port = IntPrompt.ask("Start port")
        end_port = IntPrompt.ask("End port")
        internal_ip = Prompt.ask("Internal IP (VPN client)")
        protocol = Prompt.ask("Protocol", choices=["tcp", "udp", "both"], default="tcp")
        
        config = self.config_manager.load_config()
        external_interface = config.get('external_interface', 'eth0')
        
        rules = []
        if protocol == "both":
            protocols = ["tcp", "udp"]
        else:
            protocols = [protocol]
        
        for proto in protocols:
            rules.append(
                f"iptables -t nat -A PREROUTING -i {external_interface} -p {proto} " +
                f"--dport {start_port}:{end_port} -j DNAT --to-destination {internal_ip}"
            )
            rules.append(
                f"iptables -A FORWARD -p {proto} -d {internal_ip} --dport {start_port}:{end_port} -j ACCEPT"
            )
        
        if prompt_yes_no(f"Add range forward {start_port}-{end_port} to {internal_ip}?", default=True):
            # Add to rules file
            with open(self.rules_file, 'a') as f:
                f.write(f"\n# Port range forward: {start_port}-{end_port} -> {internal_ip} ({protocol})\n")
                for rule in rules:
                    f.write(f"{rule}\n")
            
            # Apply immediately
            for rule in rules:
                run_command(rule.split(), check=False)
            
            console.print(f"[green]✓ Range forward added[/green]")
    
    def _remove_port_forward(self) -> None:
        """Remove port forwarding rule."""
        self._view_port_forwards()
        
        line_num = IntPrompt.ask("\nEnter PREROUTING rule number to remove (0 to cancel)")
        if line_num == 0:
            return
        
        cmd = ["iptables", "-t", "nat", "-D", "PREROUTING", str(line_num)]
        
        if prompt_yes_no(f"Remove port forward rule #{line_num}?", default=False):
            result = run_command(cmd, check=False)
            if result.returncode == 0:
                console.print("[green]✓ Port forward removed[/green]")
                console.print("[yellow]Note: Also remove corresponding FORWARD rule[/yellow]")
            else:
                console.print(f"[red]Failed: {result.stderr}[/red]")
    
    def _view_forward_rules(self) -> None:
        """View FORWARD chain rules."""
        console.print("\n[cyan]FORWARD Chain Rules:[/cyan]")
        result = run_command(
            ["iptables", "-L", "FORWARD", "-n", "-v", "--line-numbers"],
            check=False
        )
        if result.returncode == 0:
            console.print(result.stdout)
    
    def _add_forward_accept(self) -> None:
        """Add ACCEPT rule to FORWARD chain."""
        console.print("\n[cyan]Add Forward Accept Rule[/cyan]")
        
        source = Prompt.ask("Source IP/subnet (leave empty for any)", default="")
        dest = Prompt.ask("Destination IP/subnet (leave empty for any)", default="")
        interface_in = Prompt.ask("Input interface (leave empty for any)", default="")
        interface_out = Prompt.ask("Output interface (leave empty for any)", default="")
        
        cmd_parts = ["iptables", "-A", "FORWARD"]
        
        if source:
            cmd_parts.extend(["-s", source])
        if dest:
            cmd_parts.extend(["-d", dest])
        if interface_in:
            cmd_parts.extend(["-i", interface_in])
        if interface_out:
            cmd_parts.extend(["-o", interface_out])
        
        cmd_parts.extend(["-j", "ACCEPT"])
        rule = " ".join(cmd_parts)
        
        console.print(f"\n[yellow]Command:[/yellow] {rule}")
        
        if prompt_yes_no("Add this rule?", default=True):
            # Add to rules file
            with open(self.rules_file, 'a') as f:
                f.write(f"\n# Forward accept rule - {datetime.now():%Y-%m-%d %H:%M}\n")
                f.write(f"{rule}\n")
            
            result = run_command(cmd_parts, check=False)
            if result.returncode == 0:
                console.print("[green]✓ Forward accept rule added[/green]")
            else:
                console.print(f"[red]Failed: {result.stderr}[/red]")
    
    def _add_forward_drop(self) -> None:
        """Add DROP rule to FORWARD chain."""
        console.print("\n[cyan]Add Forward Drop Rule[/cyan]")
        
        source = Prompt.ask("Source IP/subnet to block")
        dest = Prompt.ask("Destination IP/subnet (leave empty for any)", default="")
        
        cmd_parts = ["iptables", "-A", "FORWARD", "-s", source]
        
        if dest:
            cmd_parts.extend(["-d", dest])
        
        cmd_parts.extend(["-j", "DROP"])
        rule = " ".join(cmd_parts)
        
        console.print(f"\n[yellow]Command:[/yellow] {rule}")
        
        if prompt_yes_no("Add this rule?", default=True):
            # Add to rules file
            with open(self.rules_file, 'a') as f:
                f.write(f"\n# Forward drop rule - {datetime.now():%Y-%m-%d %H:%M}\n")
                f.write(f"{rule}\n")
            
            result = run_command(cmd_parts, check=False)
            if result.returncode == 0:
                console.print("[green]✓ Forward drop rule added[/green]")
            else:
                console.print(f"[red]Failed: {result.stderr}[/red]")
    
    def _remove_forward_rule(self) -> None:
        """Remove FORWARD chain rule."""
        self._view_forward_rules()
        
        line_num = IntPrompt.ask("\nEnter rule number to remove (0 to cancel)")
        if line_num == 0:
            return
        
        cmd = ["iptables", "-D", "FORWARD", str(line_num)]
        
        if prompt_yes_no(f"Remove forward rule #{line_num}?", default=False):
            result = run_command(cmd, check=False)
            if result.returncode == 0:
                console.print("[green]✓ Rule removed[/green]")
            else:
                console.print(f"[red]Failed: {result.stderr}[/red]")
    
    def _view_banned_ips(self) -> None:
        """View banned IP addresses."""
        console.print("\n[cyan]Banned IP Addresses:[/cyan]")
        
        # Check BANNED_IPS chain
        result = run_command(
            ["iptables", "-L", "BANNED_IPS", "-n", "-v", "--line-numbers"],
            check=False
        )
        
        if result.returncode == 0:
            lines = result.stdout.split('\n')
            ban_rules = [line for line in lines if 'DROP' in line]
            
            if ban_rules:
                table = Table(show_header=True, header_style="bold magenta")
                table.add_column("#", width=3)
                table.add_column("IP Address")
                table.add_column("Packets", justify="right")
                table.add_column("Bytes", justify="right")
                
                for rule in ban_rules:
                    parts = rule.split()
                    if len(parts) >= 7:
                        num = parts[0]
                        packets = parts[1]
                        bytes_val = parts[2]
                        
                        # Find IP
                        ip = "unknown"
                        for part in parts[7:]:
                            if '.' in part:
                                ip = part
                                break
                        
                        table.add_row(num, ip, packets, bytes_val)
                
                console.print(table)
            else:
                console.print("[yellow]No banned IPs found[/yellow]")
        else:
            console.print("[yellow]BANNED_IPS chain not found[/yellow]")
            if prompt_yes_no("Create BANNED_IPS chain?", default=True):
                self._ensure_banned_ips_chain()
    
    def _ban_ip(self) -> None:
        """Ban an IP address."""
        console.print("\n[cyan]Ban IP Address[/cyan]")
        
        ip = Prompt.ask("IP address to ban")
        comment = Prompt.ask("Comment/reason (optional)", default="Manual ban")
        
        # Ensure BANNED_IPS chain exists
        self._ensure_banned_ips_chain()
        
        # Add to BANNED_IPS chain
        cmd = ["iptables", "-A", "BANNED_IPS", "-s", ip, "-j", "DROP"]
        
        result = run_command(cmd, check=False)
        if result.returncode == 0:
            console.print(f"[green]✓ IP {ip} banned[/green]")
            
            # Save to file
            ensure_directory(self.firewall_dir)
            with open(self.banned_ips_file, 'a') as f:
                f.write(f"{ip} # {comment} # {datetime.now():%Y-%m-%d %H:%M}\n")
        else:
            console.print(f"[red]Failed to ban IP: {result.stderr}[/red]")
    
    def _unban_ip(self) -> None:
        """Unban an IP address."""
        self._view_banned_ips()
        
        console.print("\n[cyan]Unban IP Address[/cyan]")
        choice = Prompt.ask("Enter IP to unban or rule # to remove")
        
        if choice.isdigit():
            # Remove by rule number
            cmd = ["iptables", "-D", "BANNED_IPS", choice]
        else:
            # Remove by IP
            cmd = ["iptables", "-D", "BANNED_IPS", "-s", choice, "-j", "DROP"]
        
        result = run_command(cmd, check=False)
        if result.returncode == 0:
            console.print(f"[green]✓ IP unbanned[/green]")
            
            # Remove from file
            if self.banned_ips_file.exists():
                lines = self.banned_ips_file.read_text().split('\n')
                new_lines = [line for line in lines if not line.startswith(choice)]
                self.banned_ips_file.write_text('\n'.join(new_lines))
        else:
            console.print(f"[red]Failed to unban: {result.stderr}[/red]")
    
    def _ban_ip_range(self) -> None:
        """Ban an IP range."""
        console.print("\n[cyan]Ban IP Range[/cyan]")
        
        ip_range = Prompt.ask("IP range to ban (e.g., 192.168.1.0/24)")
        comment = Prompt.ask("Comment/reason (optional)", default="Range ban")
        
        self._ensure_banned_ips_chain()
        
        cmd = ["iptables", "-A", "BANNED_IPS", "-s", ip_range, "-j", "DROP"]
        
        result = run_command(cmd, check=False)
        if result.returncode == 0:
            console.print(f"[green]✓ IP range {ip_range} banned[/green]")
            
            with open(self.banned_ips_file, 'a') as f:
                f.write(f"{ip_range} # {comment} # {datetime.now():%Y-%m-%d %H:%M}\n")
        else:
            console.print(f"[red]Failed: {result.stderr}[/red]")
    
    def _clear_all_bans(self) -> None:
        """Clear all banned IPs."""
        if not prompt_yes_no("Remove ALL banned IPs?", default=False):
            return
        
        # Flush BANNED_IPS chain
        run_command(["iptables", "-F", "BANNED_IPS"], check=False)
        
        # Clear file
        if self.banned_ips_file.exists():
            self.banned_ips_file.write_text("")
        
        console.print("[green]✓ All IP bans cleared[/green]")
    
    def _import_ban_list(self) -> None:
        """Import IP ban list from file."""
        console.print("\n[cyan]Import Ban List[/cyan]")
        
        file_path = Prompt.ask("Path to ban list file", default="/tmp/ban_list.txt")
        file_path = Path(file_path)
        
        if not file_path.exists():
            console.print(f"[red]File not found: {file_path}[/red]")
            return
        
        self._ensure_banned_ips_chain()
        
        imported = 0
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    parts = line.split('#', 1)
                    ip = parts[0].strip()
                    comment = parts[1].strip() if len(parts) > 1 else "Imported"
                    
                    cmd = ["iptables", "-A", "BANNED_IPS", "-s", ip, "-j", "DROP"]
                    
                    result = run_command(cmd, check=False)
                    if result.returncode == 0:
                        imported += 1
                        with open(self.banned_ips_file, 'a') as bf:
                            bf.write(f"{ip} # {comment} # {datetime.now():%Y-%m-%d %H:%M}\n")
        
        console.print(f"[green]✓ Imported {imported} IP ban(s)[/green]")
    
    def _export_ban_list(self) -> None:
        """Export IP ban list to file."""
        console.print("\n[cyan]Export Ban List[/cyan]")
        
        file_path = Prompt.ask("Export to file", default="/tmp/ban_list_export.txt")
        
        with open(file_path, 'w') as f:
            f.write(f"# WireGuard Banned IPs - Exported {datetime.now()}\n")
            f.write("# Format: IP_ADDRESS # comment\n\n")
            
            if self.banned_ips_file.exists():
                f.write(self.banned_ips_file.read_text())
        
        console.print(f"[green]✓ Ban list exported to {file_path}[/green]")
    
    def _ensure_banned_ips_chain(self) -> None:
        """Ensure BANNED_IPS chain exists."""
        # Check if chain exists
        result = run_command(["iptables", "-L", "BANNED_IPS"], check=False)
        
        if result.returncode != 0:
            # Create chain
            run_command(["iptables", "-N", "BANNED_IPS"], check=False)
            
            # Add jump rules
            run_command(["iptables", "-I", "INPUT", "1", "-j", "BANNED_IPS"], check=False)
            run_command(["iptables", "-I", "FORWARD", "1", "-j", "BANNED_IPS"], check=False)
            
            console.print("[green]✓ Created BANNED_IPS chain[/green]")
    
    def _get_banned_ip_count(self) -> int:
        """Get count of banned IPs."""
        result = run_command(["iptables", "-L", "BANNED_IPS", "-n"], check=False)
        if result.returncode == 0:
            return result.stdout.count('DROP')
        return 0