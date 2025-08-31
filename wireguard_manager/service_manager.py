"""Service management for WireGuard interfaces."""

from pathlib import Path
from typing import List, Dict, Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
import re

from .constants import WIREGUARD_DIR
from .utils import run_command, check_service_status

console = Console()

class ServiceManager:
    """Manage WireGuard services."""
    
    def get_interfaces(self) -> List[str]:
        """Get list of configured interfaces."""
        interfaces = []
        if WIREGUARD_DIR.exists():
            for conf_file in WIREGUARD_DIR.glob("*.conf"):
                # Only match WireGuard interface patterns: wg0, wg1, etc.
                # or any name that doesn't contain special keywords
                filename = conf_file.stem
                
                # Skip non-WireGuard config files
                skip_patterns = [
                    'firewall', 'rules', 'backup', 'peer_', 
                    'client', 'server_peer', 'banned', 'params'
                ]
                
                if any(pattern in filename.lower() for pattern in skip_patterns):
                    continue
                
                # Also skip files that are clearly not interfaces
                if filename.endswith('.bak') or filename.endswith('.old'):
                    continue
                    
                # Check if it looks like a WireGuard interface config
                # by checking if the file contains [Interface] section
                try:
                    content = conf_file.read_text()
                    if '[Interface]' in content:
                        interfaces.append(filename)
                except Exception:
                    # If we can't read the file, skip it
                    continue
                    
        return sorted(interfaces)
    
    def get_active_interfaces(self) -> List[str]:
        """Get list of active interfaces."""
        active = []
        result = run_command(["wg", "show", "interfaces"], check=False)
        if result.returncode == 0 and result.stdout:
            active = result.stdout.strip().split()
        return active
    
    def show_status(self) -> None:
        """Show detailed status of all interfaces."""
        console.clear()
        console.print(Panel.fit(
            "[bold cyan]WireGuard Service Status[/bold cyan]",
            border_style="cyan"
        ))
        
        interfaces = self.get_interfaces()
        active_interfaces = self.get_active_interfaces()
        
        if not interfaces:
            console.print("[yellow]No WireGuard interfaces configured[/yellow]")
            console.print("\n[dim]Press Enter to continue...[/dim]")
            input()
            return
        
        # Summary table
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Interface", style="cyan")
        table.add_column("Status", justify="center")
        table.add_column("Peers")
        table.add_column("Transfer")
        table.add_column("Port")
        
        for interface in interfaces:
            is_active = interface in active_interfaces
            status = "[green]● Active[/green]" if is_active else "[red]○ Inactive[/red]"
            
            peers = "0"
            transfer = "-"
            port = "-"
            
            if is_active:
                # Get interface details
                result = run_command(["wg", "show", interface], check=False)
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    peer_count = sum(1 for line in lines if line.startswith('peer:'))
                    peers = str(peer_count)
                    
                    # Get port
                    for line in lines:
                        if 'listening port:' in line:
                            port = line.split(':')[1].strip()
                            break
                    
                    # Get transfer stats
                    result = run_command(["wg", "show", interface, "transfer"], check=False)
                    if result.returncode == 0:
                        total_rx = 0
                        total_tx = 0
                        for line in result.stdout.split('\n'):
                            parts = line.split('\t')
                            if len(parts) >= 3:
                                try:
                                    total_rx += int(parts[1])
                                    total_tx += int(parts[2])
                                except:
                                    pass
                        
                        if total_rx > 0 or total_tx > 0:
                            rx_mb = total_rx / (1024 * 1024)
                            tx_mb = total_tx / (1024 * 1024)
                            transfer = f"↓{rx_mb:.1f}MB ↑{tx_mb:.1f}MB"
            
            table.add_row(interface, status, peers, transfer, port)
        
        console.print(table)
        
        # Show details for active interfaces
        if active_interfaces:
            console.print("\n[cyan]Active Interface Details:[/cyan]")
            for interface in active_interfaces:
                self._show_interface_summary(interface)
        
        console.print("\n[dim]Press Enter to continue...[/dim]")
        input()
    
    def _show_interface_summary(self, interface: str) -> None:
        """Show summary for an interface."""
        console.print(f"\n[bold]{interface}:[/bold]")
        
        result = run_command(["wg", "show", interface], check=False)
        if result.returncode == 0:
            lines = result.stdout.split('\n')
            
            # Parse and display key information
            for line in lines[:10]:  # Show first 10 lines
                if line.strip() and not line.startswith('private key:'):
                    if line.startswith('peer:'):
                        # Show peer public key (truncated)
                        pubkey = line.split(':')[1].strip()
                        console.print(f"  peer: {pubkey[:20]}...")
                    elif line.startswith('  '):
                        console.print(f"  {line.strip()}")
                    else:
                        console.print(f"  {line}")
    
    def start_interface(self, interface: str) -> None:
        """Start a WireGuard interface."""
        console.print(f"\n[cyan]Starting {interface}...[/cyan]")
        
        result = run_command(
            ["systemctl", "start", f"wg-quick@{interface}"],
            check=False
        )
        
        if result.returncode == 0:
            console.print(f"[green]✓[/green] {interface} started")
            run_command(
                ["systemctl", "enable", f"wg-quick@{interface}"],
                check=False
            )
        else:
            console.print(f"[red]Failed to start {interface}[/red]")
            if result.stderr:
                console.print(f"[red]{result.stderr}[/red]")
    
    def stop_interface(self, interface: str) -> None:
        """Stop a WireGuard interface."""
        console.print(f"\n[cyan]Stopping {interface}...[/cyan]")
        
        result = run_command(
            ["systemctl", "stop", f"wg-quick@{interface}"],
            check=False
        )
        
        if result.returncode == 0:
            console.print(f"[green]✓[/green] {interface} stopped")
        else:
            console.print(f"[red]Failed to stop {interface}[/red]")
    
    def restart_interface(self, interface: str) -> None:
        """Restart a WireGuard interface."""
        console.print(f"\n[cyan]Restarting {interface}...[/cyan]")
        
        result = run_command(
            ["systemctl", "restart", f"wg-quick@{interface}"],
            check=False
        )
        
        if result.returncode == 0:
            console.print(f"[green]✓[/green] {interface} restarted")
        else:
            console.print(f"[red]Failed to restart {interface}[/red]")
    
    def show_interface_details(self, interface: str) -> None:
        """Show detailed information for an interface."""
        console.clear()
        console.print(f"[bold cyan]Interface: {interface}[/bold cyan]")
        console.print("─" * 60)
        
        # Check if active
        if not check_service_status(interface):
            console.print("[red]Interface is not active[/red]")
            console.print("\n[dim]Press Enter to continue...[/dim]")
            input()
            return
        
        # Show full wg show output
        result = run_command(["wg", "show", interface], check=False)
        if result.returncode == 0:
            console.print(result.stdout)
        
        console.print("\n[dim]Press Enter to continue...[/dim]")
        input()