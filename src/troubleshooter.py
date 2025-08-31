"""Troubleshooting tools for WireGuard."""

from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax

from .constants import WIREGUARD_DIR
from .utils import run_command, check_service_status

console = Console()

class Troubleshooter:
    """Troubleshooting tools for WireGuard."""
    
    def run_diagnostics(self) -> None:
        """Run comprehensive diagnostics."""
        console.print(Panel.fit(
            "[bold cyan]WireGuard Diagnostics[/bold cyan]",
            border_style="cyan"
        ))
        
        issues = []
        
        # Check WireGuard installation
        console.print("\n[cyan]Checking installation...[/cyan]")
        result = run_command(["which", "wg"], check=False)
        if result.returncode == 0:
            console.print("[green]✓[/green] WireGuard is installed")
        else:
            issues.append("WireGuard is not installed")
            console.print("[red]✗[/red] WireGuard is not installed")
        
        # Check kernel module
        console.print("\n[cyan]Checking kernel module...[/cyan]")
        result = run_command(["lsmod"], check=False)
        if "wireguard" in result.stdout:
            console.print("[green]✓[/green] WireGuard kernel module loaded")
        else:
            console.print("[yellow]⚠[/yellow] WireGuard kernel module not loaded")
        
        # Check IP forwarding
        console.print("\n[cyan]Checking IP forwarding...[/cyan]")
        with open("/proc/sys/net/ipv4/ip_forward", "r") as f:
            if f.read().strip() == "1":
                console.print("[green]✓[/green] IP forwarding enabled")
            else:
                issues.append("IP forwarding disabled")
                console.print("[red]✗[/red] IP forwarding disabled")
        
        # Check configurations
        console.print("\n[cyan]Checking configurations...[/cyan]")
        if WIREGUARD_DIR.exists():
            configs = list(WIREGUARD_DIR.glob("*.conf"))
            if configs:
                console.print(f"[green]✓[/green] Found {len(configs)} configuration(s)")
            else:
                issues.append("No configurations found")
                console.print("[red]✗[/red] No configurations found")
        else:
            issues.append("Configuration directory missing")
            console.print("[red]✗[/red] Configuration directory missing")
        
        # Summary
        console.print("\n" + "=" * 50)
        if issues:
            console.print(f"[red]Found {len(issues)} issue(s):[/red]")
            for issue in issues:
                console.print(f"  • {issue}")
        else:
            console.print("[green]✓ All diagnostics passed![/green]")
    
    def test_connectivity(self) -> None:
        """Test VPN connectivity."""
        console.print(Panel.fit(
            "[bold cyan]Connectivity Test[/bold cyan]",
            border_style="cyan"
        ))
        
        # Get active interfaces
        result = run_command(["wg", "show", "interfaces"], check=False)
        if result.returncode != 0 or not result.stdout.strip():
            console.print("[yellow]No active WireGuard interfaces[/yellow]")
            return
        
        interfaces = result.stdout.strip().split()
        
        for interface in interfaces:
            console.print(f"\n[cyan]Testing {interface}:[/cyan]")
            
            # Get peers
            result = run_command(["wg", "show", interface, "peers"], check=False)
            if result.returncode == 0 and result.stdout:
                peers = result.stdout.strip().split('\n')
                
                for peer in peers:
                    if peer:
                        # Get endpoint
                        result = run_command(
                            ["wg", "show", interface, "endpoints"],
                            check=False
                        )
                        
                        if result.returncode == 0:
                            console.print(f"  Peer: {peer[:20]}...")
                            
                            # Check handshake
                            result = run_command(
                                ["wg", "show", interface, "latest-handshakes"],
                                check=False
                            )
                            
                            if result.returncode == 0:
                                for line in result.stdout.split('\n'):
                                    if peer in line:
                                        parts = line.split('\t')
                                        if len(parts) >= 2:
                                            timestamp = parts[1]
                                            if timestamp != "0":
                                                console.print("    [green]✓ Handshake successful[/green]")
                                            else:
                                                console.print("    [yellow]⚠ No handshake yet[/yellow]")
            else:
                console.print("  [yellow]No peers configured[/yellow]")
    
    def view_logs(self) -> None:
        """View WireGuard logs."""
        console.print(Panel.fit(
            "[bold cyan]WireGuard Logs[/bold cyan]",
            border_style="cyan"
        ))
        
        # Show kernel messages
        console.print("\n[cyan]Recent kernel messages:[/cyan]")
        result = run_command(
            ["dmesg", "-T"],
            check=False
        )
        
        if result.returncode == 0:
            lines = [line for line in result.stdout.split('\n') if 'wireguard' in line.lower()]
            if lines:
                for line in lines[-10:]:  # Last 10 lines
                    console.print(f"  {line}")
            else:
                console.print("  [yellow]No WireGuard kernel messages[/yellow]")
        
        # Show systemd logs
        console.print("\n[cyan]Recent service logs:[/cyan]")
        result = run_command(
            ["journalctl", "-u", "wg-quick@*", "-n", "20", "--no-pager"],
            check=False
        )
        
        if result.returncode == 0 and result.stdout:
            for line in result.stdout.split('\n')[-20:]:
                if line:
                    console.print(f"  {line[:100]}")
        else:
            console.print("  [yellow]No service logs available[/yellow]")