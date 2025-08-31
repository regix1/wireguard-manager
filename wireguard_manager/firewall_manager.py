"""Firewall and NAT management for WireGuard."""

from pathlib import Path
from typing import List, Dict
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, IntPrompt

from .utils import run_command, prompt_yes_no
from .config_manager import ConfigManager

console = Console()

class FirewallManager:
    """Manage firewall rules and NAT."""
    
    def __init__(self):
        """Initialize firewall manager."""
        self.config_manager = ConfigManager()
    
    def show_status(self) -> None:
        """Show firewall status."""
        console.print(Panel.fit(
            "[bold cyan]Firewall Status[/bold cyan]",
            border_style="cyan"
        ))
        
        # Check iptables rules
        console.print("[cyan]NAT Rules:[/cyan]")
        result = run_command(
            ["iptables", "-t", "nat", "-L", "POSTROUTING", "-n", "-v"],
            check=False
        )
        
        if result.returncode == 0:
            lines = result.stdout.split('\n')
            nat_rules = [line for line in lines if 'MASQUERADE' in line]
            
            if nat_rules:
                for rule in nat_rules:
                    console.print(f"  {rule.strip()}")
            else:
                console.print("  [yellow]No NAT rules found[/yellow]")
        
        # Check forwarding rules
        console.print("\n[cyan]Forward Rules:[/cyan]")
        result = run_command(
            ["iptables", "-L", "FORWARD", "-n", "-v"],
            check=False
        )
        
        if result.returncode == 0:
            lines = result.stdout.split('\n')
            forward_rules = [line for line in lines if 'wg' in line or 'ACCEPT' in line]
            
            if forward_rules:
                for rule in forward_rules[:5]:  # Show first 5
                    console.print(f"  {rule.strip()}")
            else:
                console.print("  [yellow]No forwarding rules found[/yellow]")
        
        # Check IP forwarding
        console.print("\n[cyan]IP Forwarding:[/cyan]")
        with open("/proc/sys/net/ipv4/ip_forward", "r") as f:
            ip_forward = f.read().strip()
        
        if ip_forward == "1":
            console.print("  [green]✓ Enabled[/green]")
        else:
            console.print("  [red]✗ Disabled[/red]")
    
    def apply_nat_rules(self) -> None:
        """Apply NAT rules for WireGuard."""
        console.print(Panel.fit(
            "[bold cyan]Apply NAT Rules[/bold cyan]",
            border_style="cyan"
        ))
        
        config = self.config_manager.load_config()
        external_interface = config.get('external_interface', 'eth0')
        subnet = config.get('server_subnet', '10.0.0.0/24')
        
        console.print(f"[cyan]External Interface:[/cyan] {external_interface}")
        console.print(f"[cyan]VPN Subnet:[/cyan] {subnet}")
        
        if not prompt_yes_no("\nApply NAT rules?", default=True):
            return
        
        # Enable IP forwarding
        console.print("\n[cyan]Enabling IP forwarding...[/cyan]")
        run_command(["sysctl", "-w", "net.ipv4.ip_forward=1"], check=False)
        
        # Add NAT rule
        console.print("[cyan]Adding NAT rule...[/cyan]")
        run_command([
            "iptables", "-t", "nat", "-A", "POSTROUTING",
            "-s", subnet, "-o", external_interface, "-j", "MASQUERADE"
        ], check=False)
        
        # Add forward rules
        console.print("[cyan]Adding forward rules...[/cyan]")
        run_command([
            "iptables", "-A", "FORWARD", "-i", "wg0", "-j", "ACCEPT"
        ], check=False)
        
        run_command([
            "iptables", "-A", "FORWARD", "-o", "wg0", "-j", "ACCEPT"
        ], check=False)
        
        console.print("\n[green]✓[/green] NAT rules applied")
        console.print("[yellow]Note: These rules are temporary. Add them to your WireGuard config for persistence.[/yellow]")
    
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
            "Back"
        ]
        
        for i, option in enumerate(options, 1):
            console.print(f"  {i}. {option}")
        
        choice = IntPrompt.ask("Select option", choices=["1", "2", "3", "4"])
        
        if choice == 1:
            self._view_port_forwards()
        elif choice == 2:
            self._add_port_forward()
        elif choice == 3:
            self._remove_port_forward()
    
    def _view_port_forwards(self) -> None:
        """View current port forwarding rules."""
        console.print("\n[cyan]Current Port Forwards:[/cyan]")
        
        result = run_command(
            ["iptables", "-t", "nat", "-L", "PREROUTING", "-n", "-v"],
            check=False
        )
        
        if result.returncode == 0:
            lines = result.stdout.split('\n')
            forwards = [line for line in lines if 'DNAT' in line]
            
            if forwards:
                for forward in forwards:
                    console.print(f"  {forward.strip()}")
            else:
                console.print("  [yellow]No port forwards configured[/yellow]")
    
    def _add_port_forward(self) -> None:
        """Add a port forwarding rule."""
        console.print("\n[cyan]Add Port Forward[/cyan]")
        
        external_port = IntPrompt.ask("External port")
        internal_ip = Prompt.ask("Internal IP (VPN client)")
        internal_port = IntPrompt.ask("Internal port", default=external_port)
        protocol = Prompt.ask("Protocol", choices=["tcp", "udp", "both"], default="tcp")
        
        config = self.config_manager.load_config()
        external_interface = config.get('external_interface', 'eth0')
        
        if protocol == "both":
            protocols = ["tcp", "udp"]
        else:
            protocols = [protocol]
        
        for proto in protocols:
            # PREROUTING rule
            run_command([
                "iptables", "-t", "nat", "-A", "PREROUTING",
                "-i", external_interface, "-p", proto,
                "--dport", str(external_port),
                "-j", "DNAT", "--to-destination", f"{internal_ip}:{internal_port}"
            ], check=False)
            
            # FORWARD rule
            run_command([
                "iptables", "-A", "FORWARD",
                "-p", proto, "-d", internal_ip,
                "--dport", str(internal_port),
                "-j", "ACCEPT"
            ], check=False)
        
        console.print(f"[green]✓[/green] Port forward added: {external_port} -> {internal_ip}:{internal_port} ({protocol})")
    
    def _remove_port_forward(self) -> None:
        """Remove port forwarding rule."""
        console.print("\n[yellow]To remove port forwards, use:[/yellow]")
        console.print("  iptables -t nat -D PREROUTING <rule_number>")
        console.print("  iptables -D FORWARD <rule_number>")
        console.print("\nOr flush all rules with:")
        console.print("  iptables -t nat -F PREROUTING")