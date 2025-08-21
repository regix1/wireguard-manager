"""
CLI Mode for quick command execution without TUI.
"""

import sys
from rich.console import Console
from rich.table import Table
from rich import box

from config.settings import Settings
from core.wireguard import WireGuardManager
from core.firewall import FirewallManager
from models.peer import Peer
from core.utils import format_bytes

def handle_cli_command(args, settings: Settings) -> int:
    """Handle CLI commands."""
    console = Console()
    wg_manager = WireGuardManager(settings)
    fw_manager = FirewallManager(settings)
    
    try:
        # Start WireGuard
        if args.start_wg:
            console.print("Starting WireGuard...")
            wg_manager.start()
            console.print("[green]✓[/green] WireGuard started successfully")
            return 0
        
        # Stop WireGuard
        if args.stop_wg:
            console.print("Stopping WireGuard...")
            wg_manager.stop()
            console.print("[green]✓[/green] WireGuard stopped")
            return 0
        
        # Start Firewall
        if args.start_fw:
            console.print("Starting firewall...")
            fw_manager.start()
            console.print("[green]✓[/green] Firewall started successfully")
            return 0
        
        # Stop Firewall
        if args.stop_fw:
            console.print("Stopping firewall...")
            fw_manager.stop()
            console.print("[green]✓[/green] Firewall stopped")
            return 0
        
        # Show status
        if args.status:
            show_status(wg_manager, fw_manager, console)
            return 0
        
        # Add peer
        if args.add_peer:
            add_peer_cli(args.add_peer, wg_manager, console)
            return 0
        
        # Remove peer
        if args.remove_peer:
            remove_peer_cli(args.remove_peer, wg_manager, console)
            return 0
        
        # Ban IP
        if args.ban_ip:
            ban_ip_cli(args.ban_ip, fw_manager, console)
            return 0
        
        # Unban IP
        if args.unban_ip:
            unban_ip_cli(args.unban_ip, fw_manager, console)
            return 0
        
        # Default: show help
        console.print("[yellow]No command specified. Use --help for options.[/yellow]")
        return 1
        
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        return 1

def show_status(wg_manager: WireGuardManager, fw_manager: FirewallManager, console: Console):
    """Show system status."""
    wg_status = wg_manager.get_status()
    fw_status = fw_manager.get_status()
    
    # WireGuard status
    wg_table = Table(title="WireGuard Status", box=box.ROUNDED)
    wg_table.add_column("Property", style="cyan")
    wg_table.add_column("Value", style="white")
    
    wg_active = "Active" if wg_status.get('active') else "Inactive"
    wg_table.add_row("Status", f"[{'green' if wg_status.get('active') else 'red'}]{wg_active}[/]")
    wg_table.add_row("Interface", wg_status.get('interface', 'N/A'))
    wg_table.add_row("Port", str(wg_status.get('listening_port', 'N/A')))
    wg_table.add_row("Active Peers", str(len(wg_status.get('peers', []))))
    
    rx = format_bytes(wg_status.get('total_rx', 0))
    tx = format_bytes(wg_status.get('total_tx', 0))
    wg_table.add_row("Traffic", f"RX: {rx} / TX: {tx}")
    
    console.print(wg_table)
    console.print()
    
    # Firewall status
    fw_table = Table(title="Firewall Status", box=box.ROUNDED)
    fw_table.add_column("Property", style="cyan")
    fw_table.add_column("Value", style="white")
    
    fw_active = "Active" if fw_status.get('active') else "Inactive"
    fw_table.add_row("Status", f"[{'green' if fw_status.get('active') else 'red'}]{fw_active}[/]")
    
    policies = fw_status.get('policies', {})
    if policies:
        fw_table.add_row("Policies", f"IN:{policies.get('INPUT', '?')} FW:{policies.get('FORWARD', '?')} OUT:{policies.get('OUTPUT', '?')}")
    
    rules_count = sum(fw_status.get('rules_count', {}).values())
    fw_table.add_row("Total Rules", str(rules_count))
    fw_table.add_row("Banned IPs", str(fw_status.get('banned_ips_count', 0)))
    fw_table.add_row("NAT Rules", str(fw_status.get('nat_rules', 0)))
    
    console.print(fw_table)
    
    # Peers list
    peers = wg_manager.get_peers()
    if peers:
        console.print()
        peers_table = Table(title=f"Configured Peers ({len(peers)})", box=box.SIMPLE)
        peers_table.add_column("Name", style="cyan")
        peers_table.add_column("IP Address")
        peers_table.add_column("Type", style="yellow")
        peers_table.add_column("Public Key", style="dim")
        
        for peer in peers:
            peer_type = "Router" if peer.is_router else "Client"
            key_display = f"{peer.public_key[:10]}...{peer.public_key[-10:]}" if peer.public_key else "N/A"
            peers_table.add_row(peer.name, peer.ip_address, peer_type, key_display)
        
        console.print(peers_table)

def add_peer_cli(name: str, wg_manager: WireGuardManager, console: Console):
    """Add a peer via CLI."""
    peer = Peer(name=name, is_router=False, persistent_keepalive=25)
    
    try:
        result = wg_manager.add_peer(peer)
        console.print(f"[green]✓[/green] Peer '{name}' added successfully")
        console.print(f"  IP Address: {result['ip_address']}")
        console.print(f"  Public Key: {result['public_key']}")
        
        if result.get('config_file'):
            console.print(f"  Config File: {result['config_file']}")
            
            # Show configuration
            from pathlib import Path
            config_file = Path(result['config_file'])
            if config_file.exists():
                console.print("\n[cyan]Configuration:[/cyan]")
                console.print(config_file.read_text())
                
    except Exception as e:
        console.print(f"[red]Failed to add peer: {e}[/red]")
        sys.exit(1)

def remove_peer_cli(public_key: str, wg_manager: WireGuardManager, console: Console):
    """Remove a peer via CLI."""
    try:
        if wg_manager.remove_peer(public_key):
            console.print(f"[green]✓[/green] Peer removed successfully")
        else:
            console.print(f"[yellow]Peer not found[/yellow]")
            sys.exit(1)
    except Exception as e:
        console.print(f"[red]Failed to remove peer: {e}[/red]")
        sys.exit(1)

def ban_ip_cli(ip: str, fw_manager: FirewallManager, console: Console):
    """Ban an IP via CLI."""
    try:
        if fw_manager.ban_ip(ip, "Banned via CLI"):
            console.print(f"[green]✓[/green] IP {ip} banned successfully")
        else:
            console.print(f"[yellow]IP {ip} is already banned[/yellow]")
    except Exception as e:
        console.print(f"[red]Failed to ban IP: {e}[/red]")
        sys.exit(1)

def unban_ip_cli(ip: str, fw_manager: FirewallManager, console: Console):
    """Unban an IP via CLI."""
    try:
        if fw_manager.unban_ip(ip):
            console.print(f"[green]✓[/green] IP {ip} unbanned successfully")
        else:
            console.print(f"[yellow]IP {ip} was not banned[/yellow]")
    except Exception as e:
        console.print(f"[red]Failed to unban IP: {e}[/red]")
        sys.exit(1)