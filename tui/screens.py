"""
TUI Screen Components for different views.
"""

from typing import Dict, List, Any
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.text import Text
from rich import box
from rich.progress import Progress, BarColumn, TextColumn
from datetime import datetime

from core.wireguard import WireGuardManager
from core.firewall import FirewallManager
from core.utils import format_bytes

class DashboardScreen:
    """Dashboard screen showing system overview."""
    
    def __init__(self, wg_manager: WireGuardManager, fw_manager: FirewallManager, console: Console):
        self.wg_manager = wg_manager
        self.fw_manager = fw_manager
        self.console = console
    
    def display(self):
        """Display the dashboard."""
        # Get status data
        wg_status = self.wg_manager.get_status()
        fw_status = self.fw_manager.get_status()
        
        # Create layout
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="body"),
            Layout(name="footer", size=3)
        )
        
        # Header
        header_text = Text("System Dashboard", style="bold cyan", justify="center")
        layout["header"].update(Panel(header_text, box=box.DOUBLE))
        
        # Body - split into two columns
        layout["body"].split_row(
            Layout(name="left"),
            Layout(name="right")
        )
        
        # Left column - WireGuard status
        wg_table = self._create_wireguard_table(wg_status)
        layout["body"]["left"].update(Panel(wg_table, title="WireGuard Status", border_style="green" if wg_status.get('active') else "red"))
        
        # Right column - Firewall status
        fw_table = self._create_firewall_table(fw_status)
        layout["body"]["right"].update(Panel(fw_table, title="Firewall Status", border_style="green" if fw_status.get('active') else "red"))
        
        # Footer - System info
        footer_text = self._get_system_info()
        layout["footer"].update(Panel(footer_text, box=box.SIMPLE))
        
        self.console.print(layout)
    
    def _create_wireguard_table(self, status: Dict) -> Table:
        """Create WireGuard status table."""
        table = Table(show_header=False, box=None, padding=(0, 1))
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="white")
        
        active_style = "green bold" if status.get('active') else "red bold"
        table.add_row("Status", f"[{active_style}]{'Active' if status.get('active') else 'Inactive'}[/{active_style}]")
        table.add_row("Interface", status.get('interface', 'N/A'))
        table.add_row("Port", str(status.get('listening_port', 'N/A')))
        table.add_row("Active Peers", str(len(status.get('peers', []))))
        
        # Traffic
        rx = format_bytes(status.get('total_rx', 0))
        tx = format_bytes(status.get('total_tx', 0))
        table.add_row("Total Traffic", f"↓ {rx} / ↑ {tx}")
        
        # Server public key (truncated)
        pub_key = status.get('server_public_key', '')
        if pub_key:
            key_display = f"{pub_key[:10]}...{pub_key[-10:]}"
        else:
            key_display = "Not configured"
        table.add_row("Public Key", f"[dim]{key_display}[/dim]")
        
        return table
    
    def _create_firewall_table(self, status: Dict) -> Table:
        """Create Firewall status table."""
        table = Table(show_header=False, box=None, padding=(0, 1))
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="white")
        
        active_style = "green bold" if status.get('active') else "red bold"
        table.add_row("Status", f"[{active_style}]{'Active' if status.get('active') else 'Inactive'}[/{active_style}]")
        
        # Policies
        policies = status.get('policies', {})
        if policies:
            policy_text = f"IN:{policies.get('INPUT', '?')} FW:{policies.get('FORWARD', '?')} OUT:{policies.get('OUTPUT', '?')}"
            table.add_row("Policies", policy_text)
        
        # Rules count
        rules_count = status.get('rules_count', {})
        total_rules = sum(rules_count.values())
        table.add_row("Total Rules", str(total_rules))
        
        # Breakdown
        if rules_count:
            breakdown = f"I:{rules_count.get('INPUT', 0)} F:{rules_count.get('FORWARD', 0)} O:{rules_count.get('OUTPUT', 0)}"
            table.add_row("Breakdown", f"[dim]{breakdown}[/dim]")
        
        table.add_row("Banned IPs", str(status.get('banned_ips_count', 0)))
        table.add_row("NAT Rules", str(status.get('nat_rules', 0)))
        
        return table
    
    def _get_system_info(self) -> Text:
        """Get system information for footer."""
        import psutil
        from core.utils import get_public_ip
        
        text = Text()
        
        # CPU and Memory
        cpu = psutil.cpu_percent(interval=0.1)
        mem = psutil.virtual_memory()
        
        cpu_color = "red" if cpu > 80 else "yellow" if cpu > 50 else "green"
        mem_color = "red" if mem.percent > 80 else "yellow" if mem.percent > 50 else "green"
        
        text.append(f"CPU: [{cpu_color}]{cpu:.1f}%[/{cpu_color}]  ")
        text.append(f"Memory: [{mem_color}]{mem.percent:.1f}%[/{mem_color}]  ")
        
        # IP forwarding
        try:
            with open('/proc/sys/net/ipv4/ip_forward', 'r') as f:
                ip_fwd = f.read().strip() == '1'
                fwd_text = "Enabled" if ip_fwd else "Disabled"
                fwd_color = "green" if ip_fwd else "red"
                text.append(f"IP Forwarding: [{fwd_color}]{fwd_text}[/{fwd_color}]  ")
        except:
            pass
        
        # Uptime
        import uptime
        up = uptime.uptime()
        days = int(up // 86400)
        hours = int((up % 86400) // 3600)
        mins = int((up % 3600) // 60)
        text.append(f"Uptime: {days}d {hours}h {mins}m")
        
        return text


class PeersScreen:
    """Peers management screen."""
    
    def __init__(self, wg_manager: WireGuardManager, console: Console):
        self.wg_manager = wg_manager
        self.console = console
    
    def display(self):
        """Display peers list."""
        status = self.wg_manager.get_status()
        peers = self.wg_manager.get_peers()
        
        if not peers:
            self.console.print(Panel("[yellow]No peers configured[/yellow]\n\nUse option 1 to add a new peer.", 
                                    title="Peers", border_style="yellow"))
            return
        
        # Create active peers map
        active_peers = {}
        for peer_status in status.get('peers', []):
            active_peers[peer_status['public_key']] = peer_status
        
        # Create table
        table = Table(title=f"WireGuard Peers ({len(peers)} configured)", box=box.ROUNDED)
        table.add_column("#", style="dim", width=3)
        table.add_column("Name", style="cyan")
        table.add_column("IP Address", style="white")
        table.add_column("Type", style="yellow")
        table.add_column("Status", style="bold")
        table.add_column("Last Handshake", style="dim")
        table.add_column("Transfer", style="dim")
        
        for i, peer in enumerate(peers, 1):
            active_data = active_peers.get(peer.public_key, {})
            
            # Status
            if peer.public_key in active_peers:
                handshake = active_data.get('latest_handshake', 'Never')
                if handshake != 'Never':
                    status_icon = "[green]●[/green] Connected"
                else:
                    status_icon = "[yellow]●[/yellow] Waiting"
            else:
                status_icon = "[red]●[/red] Offline"
                handshake = "Never"
            
            # Type
            peer_type = "[yellow]Router[/yellow]" if peer.is_router else "Client"
            
            # Traffic
            rx = format_bytes(active_data.get('transfer_rx', 0))
            tx = format_bytes(active_data.get('transfer_tx', 0))
            traffic = f"↓{rx} ↑{tx}" if active_data else "N/A"
            
            table.add_row(
                str(i),
                peer.name,
                peer.ip_address,
                peer_type,
                status_icon,
                handshake,
                traffic
            )
            
            # Add routed networks for routers
            if peer.is_router and peer.routed_networks:
                networks = ", ".join(peer.routed_networks)
                table.add_row("", f"  [dim]Routes: {networks}[/dim]", "", "", "", "", "")
        
        self.console.print(table)
        
        # Summary
        active_count = len([p for p in peers if p.public_key in active_peers])
        summary = f"[green]{active_count}[/green] active, [dim]{len(peers) - active_count}[/dim] inactive"
        self.console.print(f"\nSummary: {summary}")


class FirewallScreen:
    """Firewall management screen."""
    
    def __init__(self, fw_manager: FirewallManager, console: Console):
        self.fw_manager = fw_manager
        self.console = console
    
    def display(self):
        """Display firewall information."""
        status = self.fw_manager.get_status()
        banned_ips = self.fw_manager.get_banned_ips()
        
        # Status panel
        status_text = "[green]Active[/green]" if status.get('active') else "[red]Inactive[/red]"
        status_panel = Panel(f"Firewall Status: {status_text}", border_style="green" if status.get('active') else "red")
        self.console.print(status_panel)
        
        # Statistics table
        stats_table = Table(title="Firewall Statistics", box=box.SIMPLE)
        stats_table.add_column("Chain", style="cyan")
        stats_table.add_column("Policy", style="yellow")
        stats_table.add_column("Rules", style="white")
        
        policies = status.get('policies', {})
        rules_count = status.get('rules_count', {})
        
        for chain in ['INPUT', 'FORWARD', 'OUTPUT']:
            stats_table.add_row(
                chain,
                policies.get(chain, 'N/A'),
                str(rules_count.get(chain, 0))
            )
        
        self.console.print(stats_table)
        self.console.print()
        
        # Banned IPs table
        if banned_ips:
            banned_table = Table(title=f"Banned IPs ({len(banned_ips)} total)", box=box.ROUNDED)
            banned_table.add_column("#", style="dim", width=3)
            banned_table.add_column("IP Address", style="red")
            banned_table.add_column("Reason", style="yellow")
            banned_table.add_column("Banned At", style="dim")
            
            for i, banned in enumerate(banned_ips[:10], 1):  # Show first 10
                banned_at = banned.banned_at.strftime("%Y-%m-%d %H:%M") if banned.banned_at else "Unknown"
                banned_table.add_row(
                    str(i),
                    banned.ip,
                    banned.reason or "No reason specified",
                    banned_at
                )
            
            if len(banned_ips) > 10:
                banned_table.add_row("", f"[dim]... and {len(banned_ips) - 10} more[/dim]", "", "")
            
            self.console.print(banned_table)
        else:
            self.console.print(Panel("[green]No banned IPs[/green]", title="Banned IPs"))
        
        # NAT rules summary
        self.console.print(f"\n[cyan]NAT Rules:[/cyan] {status.get('nat_rules', 0)}")


class ConfigurationScreen:
    """Configuration management screen."""
    
    def __init__(self, settings, console: Console):
        self.settings = settings
        self.console = console
    
    def display(self):
        """Display configuration options."""
        self.console.print(Panel("[bold]Configuration Settings[/bold]", style="cyan"))
        
        # WireGuard settings
        wg_table = Table(title="WireGuard Configuration", box=box.SIMPLE)
        wg_table.add_column("Setting", style="cyan")
        wg_table.add_column("Value", style="white")
        wg_table.add_column("Description", style="dim")
        
        wg_table.add_row("Default Port", str(self.settings.wireguard.default_port), "UDP port for WireGuard")
        wg_table.add_row("Subnet", self.settings.wireguard.default_subnet, "VPN subnet")
        wg_table.add_row("DNS Servers", self.settings.wireguard.default_dns, "DNS for clients")
        wg_table.add_row("Interface", self.settings.wireguard.interface_name, "WireGuard interface name")
        wg_table.add_row("Config Dir", self.settings.wireguard.config_dir, "Configuration directory")
        
        self.console.print(wg_table)
        self.console.print()
        
        # Firewall settings
        fw_table = Table(title="Firewall Configuration", box=box.SIMPLE)
        fw_table.add_column("Setting", style="cyan")
        fw_table.add_column("Value", style="white")
        fw_table.add_column("Description", style="dim")
        
        fw_table.add_row("External Interface", self.settings.firewall.external_interface, "Internet-facing interface")
        fw_table.add_row("Rules File", self.settings.firewall.rules_file, "Firewall rules file")
        fw_table.add_row("Banned IPs File", self.settings.firewall.banned_ips_file, "Banned IPs storage")
        fw_table.add_row("DDoS Protection", str(self.settings.firewall.enable_ddos_protection), "Enable DDoS protection")
        fw_table.add_row("Logging", str(self.settings.firewall.enable_logging), "Enable firewall logging")
        
        self.console.print(fw_table)
        self.console.print()
        
        # Server settings
        srv_table = Table(title="Server Configuration", box=box.SIMPLE)
        srv_table.add_column("Setting", style="cyan")
        srv_table.add_column("Value", style="white")
        
        srv_table.add_row("Public IP", self.settings.server.public_ip or "[yellow]Not configured[/yellow]")
        srv_table.add_row("Hostname", self.settings.server.hostname or "[yellow]Not configured[/yellow]")
        srv_table.add_row("NAT Enabled", str(self.settings.server.nat_enabled))
        srv_table.add_row("IP Forwarding", str(self.settings.server.ip_forwarding))
        srv_table.add_row("Keepalive", f"{self.settings.server.persistent_keepalive} seconds")
        
        self.console.print(srv_table)


class LogsScreen:
    """Logs and diagnostics screen."""
    
    def __init__(self, console: Console):
        self.console = console
    
    def display(self):
        """Display logs and diagnostics."""
        self.console.print(Panel("[bold]Logs & Diagnostics[/bold]", style="cyan"))
        
        # Recent log entries
        self._show_recent_logs()
        
        # System diagnostics
        self._show_diagnostics()
    
    def _show_recent_logs(self):
        """Show recent log entries."""
        from pathlib import Path
        import subprocess
        
        self.console.print("\n[bold cyan]Recent System Logs:[/bold cyan]")
        
        # Try to get recent WireGuard logs
        try:
            result = subprocess.run(
                ["journalctl", "-u", "wg-quick@wg0", "-n", "10", "--no-pager"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0 and result.stdout:
                self.console.print(Panel(result.stdout, title="WireGuard Logs", border_style="dim"))
            else:
                self.console.print("[yellow]No WireGuard logs available[/yellow]")
        except:
            self.console.print("[yellow]Could not retrieve WireGuard logs[/yellow]")
        
        # Application logs
        log_dir = Path.home() / ".wireguard-manager" / "logs"
        if log_dir.exists():
            log_files = sorted(log_dir.glob("*.log"), key=lambda p: p.stat().st_mtime, reverse=True)
            if log_files:
                latest_log = log_files[0]
                with open(latest_log, 'r') as f:
                    lines = f.readlines()[-20:]  # Last 20 lines
                    log_text = "".join(lines)
                    self.console.print(Panel(log_text, title=f"Application Log: {latest_log.name}", border_style="dim"))
    
    def _show_diagnostics(self):
        """Show system diagnostics."""
        import subprocess
        
        self.console.print("\n[bold cyan]System Diagnostics:[/bold cyan]")
        
        diagnostics = Table(box=box.SIMPLE)
        diagnostics.add_column("Check", style="cyan")
        diagnostics.add_column("Status", style="bold")
        diagnostics.add_column("Details", style="dim")
        
        # Check WireGuard kernel module
        try:
            result = subprocess.run(["lsmod"], capture_output=True, text=True)
            if "wireguard" in result.stdout:
                diagnostics.add_row("WireGuard Module", "[green]Loaded[/green]", "Kernel module active")
            else:
                diagnostics.add_row("WireGuard Module", "[red]Not Loaded[/red]", "modprobe wireguard")
        except:
            diagnostics.add_row("WireGuard Module", "[yellow]Unknown[/yellow]", "Could not check")
        
        # Check IP forwarding
        try:
            with open('/proc/sys/net/ipv4/ip_forward', 'r') as f:
                if f.read().strip() == '1':
                    diagnostics.add_row("IP Forwarding", "[green]Enabled[/green]", "Routing enabled")
                else:
                    diagnostics.add_row("IP Forwarding", "[red]Disabled[/red]", "Enable in sysctl")
        except:
            diagnostics.add_row("IP Forwarding", "[yellow]Unknown[/yellow]", "Could not check")
        
        # Check iptables
        try:
            result = subprocess.run(["iptables", "-L", "-n"], capture_output=True, text=True, timeout=2)
            if result.returncode == 0:
                diagnostics.add_row("iptables", "[green]Working[/green]", "Firewall accessible")
            else:
                diagnostics.add_row("iptables", "[red]Error[/red]", "Check permissions")
        except:
            diagnostics.add_row("iptables", "[red]Not Found[/red]", "Install iptables")
        
        # Check DNS resolution
        try:
            import socket
            socket.gethostbyname("google.com")
            diagnostics.add_row("DNS Resolution", "[green]Working[/green]", "External DNS OK")
        except:
            diagnostics.add_row("DNS Resolution", "[red]Failed[/red]", "Check network settings")
        
        self.console.print(diagnostics)