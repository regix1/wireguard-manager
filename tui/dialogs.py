"""
TUI Dialog Components for user interactions.
"""

from typing import Optional, Dict, List, Any
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.table import Table
from rich import box
from rich.syntax import Syntax

from core.wireguard import WireGuardManager
from core.firewall import FirewallManager
from models.peer import Peer
from models.firewall_rule import FirewallRule
from core.utils import validate_ip

class AddPeerDialog:
    """Dialog for adding a new peer."""
    
    def __init__(self, wg_manager: WireGuardManager, console: Console):
        self.wg_manager = wg_manager
        self.console = console
    
    def show(self) -> Optional[Dict]:
        """Show the dialog and return peer data."""
        self.console.print(Panel("[bold]Add New Peer[/bold]", style="cyan"))
        
        # Get peer name
        name = Prompt.ask("Peer name", default="")
        if not name:
            self.console.print("[red]Peer name is required[/red]")
            return None
        
        # Check if it's a router
        is_router = Confirm.ask("Is this a router device?", default=False)
        
        routed_networks = []
        if is_router:
            self.console.print("\n[yellow]Router Configuration[/yellow]")
            self.console.print("Enter networks this router will route (one per line, empty to finish):")
            while True:
                network = Prompt.ask("Network (e.g., 192.168.1.0/24)", default="")
                if not network:
                    break
                if '/' not in network:
                    self.console.print("[red]Invalid network format. Use CIDR notation.[/red]")
                    continue
                routed_networks.append(network)
                self.console.print(f"[green]Added: {network}[/green]")
        
        # Keepalive setting
        keepalive = IntPrompt.ask("Persistent keepalive (seconds)", default=25)
        
        # Create peer
        peer = Peer(
            name=name,
            is_router=is_router,
            routed_networks=routed_networks,
            persistent_keepalive=keepalive
        )
        
        try:
            # Add peer
            self.console.print("\n[cyan]Generating keys and configuration...[/cyan]")
            result = self.wg_manager.add_peer(peer)
            
            # Show success message
            self.console.print(Panel(
                f"[green]✓[/green] Peer '{name}' added successfully!\n\n"
                f"[cyan]IP Address:[/cyan] {result['ip_address']}\n"
                f"[cyan]Public Key:[/cyan] {result['public_key']}\n"
                f"[cyan]Config File:[/cyan] {result.get('config_file', 'N/A')}\n"
                f"[cyan]QR Code:[/cyan] {result.get('qr_file', 'N/A')}",
                title="Success",
                border_style="green"
            ))
            
            # Show configuration
            if Confirm.ask("\nShow peer configuration?", default=True):
                self._show_config(name)
            
            return result
            
        except Exception as e:
            self.console.print(f"[red]Failed to add peer: {e}[/red]")
            return None
    
    def _show_config(self, peer_name: str):
        """Show peer configuration."""
        from pathlib import Path
        from core.utils import sanitize_filename
        
        safe_name = sanitize_filename(peer_name)
        config_dir = Path(self.wg_manager.settings.wireguard.config_dir) / "peers"
        config_file = config_dir / f"{safe_name}.conf"
        
        if config_file.exists():
            config_text = config_file.read_text()
            syntax = Syntax(config_text, "ini", theme="monokai", line_numbers=True)
            self.console.print(Panel(syntax, title=f"Configuration for {peer_name}"))
            
            # Offer to show QR code
            if Confirm.ask("\nGenerate QR code for mobile devices?", default=False):
                self._show_qr_code(config_text)
    
    def _show_qr_code(self, config_text: str):
        """Generate and display QR code in terminal."""
        try:
            import qrcode
            qr = qrcode.QRCode()
            qr.add_data(config_text)
            qr.make()
            # Print ASCII QR code
            self.console.print("\n[cyan]QR Code (scan with WireGuard mobile app):[/cyan]")
            qr.print_ascii(invert=True)
        except Exception as e:
            self.console.print(f"[yellow]Could not generate QR code: {e}[/yellow]")


class BanIPDialog:
    """Dialog for banning an IP address."""
    
    def __init__(self, fw_manager: FirewallManager, console: Console):
        self.fw_manager = fw_manager
        self.console = console
    
    def show(self) -> bool:
        """Show the dialog and ban IP."""
        self.console.print(Panel("[bold]Ban IP Address[/bold]", style="red"))
        
        # Get IP address
        ip = Prompt.ask("IP address to ban (e.g., 192.168.1.100 or 10.0.0.0/24)")
        
        # Validate IP
        if '/' in ip:
            # Subnet
            network_part = ip.split('/')[0]
            if not validate_ip(network_part):
                self.console.print(f"[red]Invalid IP address format: {network_part}[/red]")
                return False
        else:
            # Single IP
            if not validate_ip(ip):
                self.console.print(f"[red]Invalid IP address format: {ip}[/red]")
                return False
        
        # Get reason
        reason = Prompt.ask("Reason for ban", default="")
        
        # Confirm
        if not Confirm.ask(f"Ban IP {ip}?", default=True):
            return False
        
        try:
            # Ban the IP
            if self.fw_manager.ban_ip(ip, reason):
                self.console.print(f"[green]✓[/green] IP {ip} has been banned successfully")
                return True
            else:
                self.console.print(f"[yellow]IP {ip} is already banned[/yellow]")
                return False
        except Exception as e:
            self.console.print(f"[red]Failed to ban IP: {e}[/red]")
            return False


class PortForwardDialog:
    """Dialog for adding port forwarding rules."""
    
    def __init__(self, fw_manager: FirewallManager, console: Console):
        self.fw_manager = fw_manager
        self.console = console
    
    def show(self) -> bool:
        """Show the dialog and add port forward."""
        self.console.print(Panel("[bold]Add Port Forwarding Rule[/bold]", style="cyan"))
        
        # Protocol
        protocol = Prompt.ask("Protocol", choices=["tcp", "udp", "both"], default="tcp")
        
        # External interface
        ext_interface = Prompt.ask("External interface", 
                                   default=self.fw_manager.settings.firewall.external_interface)
        
        # External ports
        ports = Prompt.ask("External port(s) (e.g., 80 or 8000:8100 or 80,443)")
        if not ports:
            self.console.print("[red]Ports are required[/red]")
            return False
        
        # Destination IP
        dest_ip = Prompt.ask("Destination IP (e.g., 192.168.1.100)")
        if not validate_ip(dest_ip):
            self.console.print(f"[red]Invalid IP address: {dest_ip}[/red]")
            return False
        
        # Destination port (optional)
        dest_port = Prompt.ask("Destination port (leave empty for same as external)", default="")
        
        # Build destination
        destination = f"{dest_ip}:{dest_port}" if dest_port else dest_ip
        
        # Description
        comment = Prompt.ask("Description", default=f"Port forward {protocol}/{ports} to {destination}")
        
        # Special handling for WebRTC/n.eko
        add_snat = False
        snat_ip = ""
        if protocol in ["udp", "both"]:
            add_snat = Confirm.ask("Add SNAT for WebRTC/n.eko (UDP only)?", default=False)
            if add_snat:
                snat_ip = Prompt.ask("SNAT source IP", default="10.10.20.1")
        
        # Confirm
        self.console.print("\n[cyan]Review Port Forward Rule:[/cyan]")
        table = Table(show_header=False, box=box.SIMPLE)
        table.add_column("Setting", style="cyan")
        table.add_column("Value", style="white")
        
        table.add_row("Protocol", protocol)
        table.add_row("Interface", ext_interface)
        table.add_row("External Ports", ports)
        table.add_row("Destination", destination)
        table.add_row("Description", comment)
        if add_snat:
            table.add_row("SNAT", f"Yes (source: {snat_ip})")
        
        self.console.print(table)
        
        if not Confirm.ask("\nAdd this port forwarding rule?", default=True):
            return False
        
        try:
            # Handle both TCP and UDP if "both" selected
            if protocol == "both":
                # Add TCP rule
                tcp_rule = FirewallRule(
                    type='port_forward',
                    protocol='tcp',
                    interface=ext_interface,
                    ports=ports,
                    destination=destination,
                    comment=f"{comment} (TCP)"
                )
                self.fw_manager.add_rule(tcp_rule)
                
                # Add UDP rule
                udp_rule = FirewallRule(
                    type='port_forward',
                    protocol='udp',
                    interface=ext_interface,
                    ports=ports,
                    destination=destination,
                    comment=f"{comment} (UDP)"
                )
                self.fw_manager.add_rule(udp_rule)
            else:
                # Single protocol rule
                rule = FirewallRule(
                    type='port_forward',
                    protocol=protocol,
                    interface=ext_interface,
                    ports=ports,
                    destination=destination,
                    comment=comment
                )
                self.fw_manager.add_rule(rule)
            
            # Add SNAT if requested
            if add_snat and protocol in ["udp", "both"]:
                snat_command = (f"iptables -t nat -A POSTROUTING -o wg0 -p udp "
                              f"-m multiport --dports {ports} -d {dest_ip} "
                              f"-j SNAT --to-source {snat_ip}")
                
                snat_rule = FirewallRule(
                    type='custom',
                    command=snat_command,
                    comment=f"SNAT for WebRTC/n.eko to {dest_ip}"
                )
                self.fw_manager.add_rule(snat_rule)
            
            self.console.print(f"[green]✓[/green] Port forwarding rule(s) added successfully")
            self.console.print("[yellow]Note: Restart the firewall to apply changes[/yellow]")
            return True
            
        except Exception as e:
            self.console.print(f"[red]Failed to add port forwarding rule: {e}[/red]")
            return False


class RulesEditorDialog:
    """Dialog for editing firewall rules."""
    
    def __init__(self, fw_manager: FirewallManager, console: Console):
        self.fw_manager = fw_manager
        self.console = console
    
    def show(self):
        """Show the rules editor."""
        import tempfile
        import subprocess
        import os
        
        rules_file = Path(self.fw_manager.settings.firewall.rules_file)
        
        # Load current rules
        if rules_file.exists():
            current_rules = rules_file.read_text()
        else:
            current_rules = self._get_default_template()
        
        # Show current rules
        self.console.print(Panel("[bold]Firewall Rules Editor[/bold]", style="cyan"))
        syntax = Syntax(current_rules, "bash", theme="monokai", line_numbers=True)
        self.console.print(Panel(syntax, title="Current Rules"))
        
        # Options
        self.console.print("\n[bold cyan]Options:[/bold cyan]")
        self.console.print("1. Edit rules in external editor")
        self.console.print("2. Add custom rule")
        self.console.print("3. Reset to defaults")
        self.console.print("4. Validate rules")
        self.console.print("B. Back")
        
        choice = Prompt.ask("Select option", choices=["1", "2", "3", "4", "b", "B"], default="b").lower()
        
        if choice == "1":
            self._edit_in_editor(rules_file, current_rules)
        elif choice == "2":
            self._add_custom_rule()
        elif choice == "3":
            self._reset_to_defaults(rules_file)
        elif choice == "4":
            self._validate_rules(current_rules)
    
    def _get_default_template(self) -> str:
        """Get default rules template."""
        from datetime import datetime
        return f"""# WireGuard Firewall Rules Configuration
# Generated: {datetime.now()}
# This file contains ONLY iptables commands - no bash code
# Lines starting with # are comments and will be ignored

# ========== NAT Rules ==========
iptables -t nat -A POSTROUTING -o {self.fw_manager.settings.firewall.external_interface} -s {self.fw_manager.settings.wireguard.default_subnet} -j MASQUERADE

# ========== WireGuard Port ==========
iptables -A INPUT -p udp --dport {self.fw_manager.settings.wireguard.default_port} -j ACCEPT

# ========== Forwarding Rules ==========
iptables -A FORWARD -i {self.fw_manager.settings.firewall.external_interface} -o {self.fw_manager.settings.wireguard.interface_name} -j ACCEPT
iptables -A FORWARD -i {self.fw_manager.settings.wireguard.interface_name} -j ACCEPT

# ========== DNS for WireGuard clients ==========
iptables -A INPUT -i {self.fw_manager.settings.wireguard.interface_name} -p udp --dport 53 -j ACCEPT
iptables -A INPUT -i {self.fw_manager.settings.wireguard.interface_name} -p tcp --dport 53 -j ACCEPT

# ========== Port Forwarding Rules ==========
# Add your port forwarding rules here

# ========== Custom Rules ==========
# Add your custom rules here
"""
    
    def _edit_in_editor(self, rules_file: Path, current_rules: str):
        """Edit rules in external editor."""
        import tempfile
        import subprocess
        import os
        
        # Determine editor
        editor = os.environ.get('EDITOR', 'nano')
        
        # Create temp file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
            f.write(current_rules)
            temp_file = f.name
        
        try:
            # Open in editor
            self.console.print(f"\n[cyan]Opening rules in {editor}...[/cyan]")
            subprocess.call([editor, temp_file])
            
            # Read edited content
            with open(temp_file, 'r') as f:
                new_rules = f.read()
            
            # Validate
            if self._validate_rules(new_rules):
                if Confirm.ask("Save changes?", default=True):
                    rules_file.parent.mkdir(parents=True, exist_ok=True)
                    rules_file.write_text(new_rules)
                    self.console.print("[green]✓[/green] Rules saved successfully")
                    self.console.print("[yellow]Note: Restart the firewall to apply changes[/yellow]")
        finally:
            # Clean up temp file
            if os.path.exists(temp_file):
                os.unlink(temp_file)
    
    def _add_custom_rule(self):
        """Add a custom rule."""
        self.console.print("\n[cyan]Add Custom Rule[/cyan]")
        
        # Get rule type
        self.console.print("Rule type:")
        self.console.print("1. Port forward")
        self.console.print("2. NAT/Masquerade")
        self.console.print("3. Filter rule")
        self.console.print("4. Custom iptables command")
        
        rule_type = Prompt.ask("Select type", choices=["1", "2", "3", "4"])
        
        if rule_type == "1":
            self._add_port_forward_rule()
        elif rule_type == "2":
            self._add_nat_rule()
        elif rule_type == "3":
            self._add_filter_rule()
        elif rule_type == "4":
            self._add_custom_command()
    
    def _add_port_forward_rule(self):
        """Add port forward rule through dialog."""
        dialog = PortForwardDialog(self.fw_manager, self.console)
        dialog.show()
    
    def _add_nat_rule(self):
        """Add NAT rule."""
        source = Prompt.ask("Source network (e.g., 10.0.0.0/24)")
        interface = Prompt.ask("Output interface", default=self.fw_manager.settings.firewall.external_interface)
        nat_type = Prompt.ask("NAT type", choices=["MASQUERADE", "SNAT"], default="MASQUERADE")
        
        if nat_type == "SNAT":
            snat_ip = Prompt.ask("SNAT IP address")
            rule = FirewallRule(
                type='nat',
                source_network=source,
                interface=interface,
                nat_type=nat_type,
                snat_ip=snat_ip,
                comment=f"NAT for {source}"
            )
        else:
            rule = FirewallRule(
                type='nat',
                source_network=source,
                interface=interface,
                nat_type=nat_type,
                comment=f"NAT for {source}"
            )
        
        try:
            self.fw_manager.add_rule(rule)
            self.console.print("[green]✓[/green] NAT rule added successfully")
        except Exception as e:
            self.console.print(f"[red]Failed to add NAT rule: {e}[/red]")
    
    def _add_filter_rule(self):
        """Add filter rule."""
        chain = Prompt.ask("Chain", choices=["INPUT", "FORWARD", "OUTPUT"], default="INPUT")
        protocol = Prompt.ask("Protocol", choices=["all", "tcp", "udp", "icmp"], default="all")
        
        interface = Prompt.ask("Interface (optional)", default="")
        source = Prompt.ask("Source IP/network (optional)", default="")
        destination = Prompt.ask("Destination IP/network (optional)", default="")
        ports = Prompt.ask("Port(s) (optional)", default="")
        
        action = Prompt.ask("Action", choices=["ACCEPT", "DROP", "REJECT"], default="ACCEPT")
        comment = Prompt.ask("Description", default="Filter rule")
        
        rule = FirewallRule(
            type='filter',
            chain=chain,
            protocol=protocol,
            interface=interface,
            source_network=source,
            destination=destination,
            ports=ports,
            action=action,
            comment=comment
        )
        
        try:
            self.fw_manager.add_rule(rule)
            self.console.print("[green]✓[/green] Filter rule added successfully")
        except Exception as e:
            self.console.print(f"[red]Failed to add filter rule: {e}[/red]")
    
    def _add_custom_command(self):
        """Add custom iptables command."""
        self.console.print("\n[cyan]Enter custom iptables command:[/cyan]")
        command = Prompt.ask("Command")
        
        if not command.startswith("iptables"):
            self.console.print("[red]Command must start with 'iptables'[/red]")
            return
        
        comment = Prompt.ask("Description", default="Custom rule")
        
        rule = FirewallRule(
            type='custom',
            command=command,
            comment=comment
        )
        
        try:
            self.fw_manager.add_rule(rule)
            self.console.print("[green]✓[/green] Custom rule added successfully")
        except Exception as e:
            self.console.print(f"[red]Failed to add custom rule: {e}[/red]")
    
    def _reset_to_defaults(self, rules_file: Path):
        """Reset rules to defaults."""
        if Confirm.ask("Reset all rules to defaults? This cannot be undone.", default=False):
            default_rules = self._get_default_template()
            rules_file.parent.mkdir(parents=True, exist_ok=True)
            rules_file.write_text(default_rules)
            self.console.print("[green]✓[/green] Rules reset to defaults")
            self.console.print("[yellow]Note: Restart the firewall to apply changes[/yellow]")
    
    def _validate_rules(self, rules_text: str) -> bool:
        """Validate firewall rules."""
        errors = []
        
        for i, line in enumerate(rules_text.split('\n'), 1):
            line = line.strip()
            if line and not line.startswith('#'):
                if not line.startswith('iptables'):
                    errors.append(f"Line {i}: Must start with 'iptables'")
                # Could add more validation here
        
        if errors:
            self.console.print("[red]Validation errors found:[/red]")
            for error in errors[:10]:  # Show first 10 errors
                self.console.print(f"  • {error}")
            return False
        else:
            self.console.print("[green]✓[/green] Rules are valid")
            return True