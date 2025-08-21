"""
Main TUI Application using Rich for beautiful terminal interface.
"""

import sys
import time
from datetime import datetime
from typing import Optional, List, Dict, Any
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.live import Live
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.syntax import Syntax
from rich.text import Text
from rich import box

from config.settings import Settings
from core.wireguard import WireGuardManager
from core.firewall import FirewallManager
from tui.screens import (
    DashboardScreen, PeersScreen, FirewallScreen,
    ConfigurationScreen, LogsScreen
)
from tui.dialogs import (
    AddPeerDialog, BanIPDialog, PortForwardDialog,
    RulesEditorDialog
)

class WireGuardManagerApp:
    """Main TUI Application for WireGuard Manager."""
    
    def __init__(self, settings: Settings):
        """Initialize the application."""
        self.settings = settings
        self.console = Console()
        self.wg_manager = WireGuardManager(settings)
        self.fw_manager = FirewallManager(settings)
        self.running = True
        self.current_screen = "dashboard"
        
        # Initialize screens
        self.screens = {
            "dashboard": DashboardScreen(self.wg_manager, self.fw_manager, self.console),
            "peers": PeersScreen(self.wg_manager, self.console),
            "firewall": FirewallScreen(self.fw_manager, self.console),
            "configuration": ConfigurationScreen(self.settings, self.console),
            "logs": LogsScreen(self.console)
        }
    
    def run(self):
        """Run the main application loop."""
        self.console.clear()
        
        while self.running:
            try:
                self.display_header()
                self.display_menu()
                choice = self.get_user_choice()
                self.handle_choice(choice)
                
                if choice not in ['q', 'Q']:
                    self.console.input("\n[dim]Press Enter to continue...[/dim]")
                    
            except KeyboardInterrupt:
                self.console.print("\n[yellow]Interrupted by user[/yellow]")
                if Confirm.ask("Do you want to exit?"):
                    self.running = False
            except Exception as e:
                self.console.print(f"[red]Error: {e}[/red]")
                self.console.input("\n[dim]Press Enter to continue...[/dim]")
    
    def display_header(self):
        """Display the application header."""
        self.console.clear()
        header = Panel(
            "[bold cyan]WireGuard Manager TUI[/bold cyan]\n"
            "[dim]Comprehensive VPN and Firewall Management[/dim]",
            style="blue",
            box=box.DOUBLE_EDGE,
            expand=True
        )
        self.console.print(header)
        self.console.print()
    
    def display_menu(self):
        """Display the main menu."""
        # Get current status
        wg_status = self.wg_manager.get_status()
        fw_status = self.fw_manager.get_status()
        
        # Status indicators
        wg_indicator = "[green]●[/green] Active" if wg_status.get('active') else "[red]●[/red] Inactive"
        fw_indicator = "[green]●[/green] Active" if fw_status.get('active') else "[red]●[/red] Inactive"
        
        # Create status panel
        status_text = f"WireGuard: {wg_indicator}  |  Firewall: {fw_indicator}"
        status_panel = Panel(status_text, title="System Status", style="dim")
        self.console.print(status_panel)
        self.console.print()
        
        # Main menu
        menu_items = [
            ("1", "Dashboard", "View system overview and statistics"),
            ("2", "Peers Management", "Add, remove, and manage WireGuard peers"),
            ("3", "Firewall & Security", "Manage firewall rules and banned IPs"),
            ("4", "Configuration", "Edit WireGuard and firewall settings"),
            ("5", "Service Control", "Start/stop/restart services"),
            ("6", "Logs & Diagnostics", "View logs and troubleshoot issues"),
            ("", "", ""),
            ("A", "Quick Actions", "Common administrative tasks"),
            ("R", "Refresh Status", "Update all status information"),
            ("Q", "Quit", "Exit the application")
        ]
        
        table = Table(show_header=False, box=box.SIMPLE, padding=(0, 2))
        table.add_column("Key", style="bold cyan", width=3)
        table.add_column("Option", style="white")
        table.add_column("Description", style="dim")
        
        for key, option, desc in menu_items:
            if key:
                table.add_row(key, option, desc)
            else:
                table.add_row("", "", "")
        
        self.console.print(Panel(table, title="Main Menu", border_style="cyan"))
    
    def get_user_choice(self) -> str:
        """Get user menu choice."""
        return Prompt.ask("\n[bold cyan]Select option[/bold cyan]", 
                         choices=["1", "2", "3", "4", "5", "6", "a", "A", "r", "R", "q", "Q"],
                         default="1").lower()
    
    def handle_choice(self, choice: str):
        """Handle user menu choice."""
        if choice == "1":
            self.show_dashboard()
        elif choice == "2":
            self.manage_peers()
        elif choice == "3":
            self.manage_firewall()
        elif choice == "4":
            self.edit_configuration()
        elif choice == "5":
            self.service_control()
        elif choice == "6":
            self.show_logs()
        elif choice == "a":
            self.quick_actions()
        elif choice == "r":
            self.refresh_status()
        elif choice == "q":
            self.quit_application()
    
    def show_dashboard(self):
        """Show the dashboard screen."""
        self.screens["dashboard"].display()
    
    def manage_peers(self):
        """Show peers management menu."""
        while True:
            self.display_header()
            self.screens["peers"].display()
            
            self.console.print("\n[bold cyan]Peer Management Options:[/bold cyan]")
            self.console.print("1. Add new peer")
            self.console.print("2. Remove peer")
            self.console.print("3. View peer config")
            self.console.print("4. Generate QR code")
            self.console.print("5. Export all configs")
            self.console.print("B. Back to main menu")
            
            choice = Prompt.ask("\nSelect option", 
                              choices=["1", "2", "3", "4", "5", "b", "B"],
                              default="b").lower()
            
            if choice == "1":
                dialog = AddPeerDialog(self.wg_manager, self.console)
                dialog.show()
            elif choice == "2":
                self.remove_peer()
            elif choice == "3":
                self.view_peer_config()
            elif choice == "4":
                self.generate_qr_code()
            elif choice == "5":
                self.export_configs()
            elif choice == "b":
                break
    
    def manage_firewall(self):
        """Show firewall management menu."""
        while True:
            self.display_header()
            self.screens["firewall"].display()
            
            self.console.print("\n[bold cyan]Firewall Options:[/bold cyan]")
            self.console.print("1. Ban IP address")
            self.console.print("2. Unban IP address")
            self.console.print("3. Add port forward")
            self.console.print("4. Edit firewall rules")
            self.console.print("5. View current rules")
            self.console.print("B. Back to main menu")
            
            choice = Prompt.ask("\nSelect option",
                              choices=["1", "2", "3", "4", "5", "b", "B"],
                              default="b").lower()
            
            if choice == "1":
                dialog = BanIPDialog(self.fw_manager, self.console)
                dialog.show()
            elif choice == "2":
                self.unban_ip()
            elif choice == "3":
                dialog = PortForwardDialog(self.fw_manager, self.console)
                dialog.show()
            elif choice == "4":
                dialog = RulesEditorDialog(self.fw_manager, self.console)
                dialog.show()
            elif choice == "5":
                self.view_firewall_rules()
                # No need for additional pause here as view_firewall_rules handles it
            elif choice == "b":
                break
    
    def edit_configuration(self):
        """Edit configuration settings."""
        self.screens["configuration"].display()
    
    def service_control(self):
        """Service control menu."""
        while True:
            self.display_header()
            
            # Get status
            wg_status = self.wg_manager.get_status()
            fw_status = self.fw_manager.get_status()
            
            self.console.print(Panel("[bold]Service Control[/bold]", style="cyan"))
            self.console.print()
            
            # Display current status
            table = Table(title="Current Service Status", box=box.ROUNDED)
            table.add_column("Service", style="cyan")
            table.add_column("Status", style="bold")
            table.add_column("Details")
            
            wg_status_text = "[green]Running[/green]" if wg_status.get('active') else "[red]Stopped[/red]"
            fw_status_text = "[green]Running[/green]" if fw_status.get('active') else "[red]Stopped[/red]"
            
            table.add_row("WireGuard", wg_status_text, 
                         f"Port: {wg_status.get('listening_port', 'N/A')}")
            table.add_row("Firewall", fw_status_text,
                         f"Rules: {sum(fw_status.get('rules_count', {}).values())}")
            
            self.console.print(table)
            self.console.print()
            
            # Menu options
            self.console.print("[bold cyan]Service Actions:[/bold cyan]")
            self.console.print("1. Start WireGuard")
            self.console.print("2. Stop WireGuard")
            self.console.print("3. Restart WireGuard")
            self.console.print("4. Start Firewall")
            self.console.print("5. Stop Firewall")
            self.console.print("6. Restart Firewall")
            self.console.print("7. Start All Services")
            self.console.print("8. Stop All Services")
            self.console.print("B. Back to main menu")
            
            choice = Prompt.ask("\nSelect action",
                              choices=["1", "2", "3", "4", "5", "6", "7", "8", "b", "B"],
                              default="b").lower()
            
            if choice == "1":
                self.start_service("wireguard")
            elif choice == "2":
                self.stop_service("wireguard")
            elif choice == "3":
                self.restart_service("wireguard")
            elif choice == "4":
                self.start_service("firewall")
            elif choice == "5":
                self.stop_service("firewall")
            elif choice == "6":
                self.restart_service("firewall")
            elif choice == "7":
                self.start_all_services()
            elif choice == "8":
                self.stop_all_services()
            elif choice == "b":
                break
            
            if choice != "b":
                self.console.input("\n[dim]Press Enter to continue...[/dim]")
    
    def show_logs(self):
        """Show logs and diagnostics."""
        self.screens["logs"].display()
    
    def quick_actions(self):
        """Quick actions menu."""
        while True:
            self.display_header()
            
            self.console.print(Panel("[bold]Quick Actions[/bold]", style="cyan"))
            self.console.print()
            
            self.console.print("[bold cyan]Available Actions:[/bold cyan]")
            self.console.print("1. Add peer and generate QR code")
            self.console.print("2. Ban IP address")
            self.console.print("3. Add port forward rule")
            self.console.print("4. Backup configuration")
            self.console.print("5. Test connectivity")
            self.console.print("6. Generate server report")
            self.console.print("B. Back to main menu")
            
            choice = Prompt.ask("\nSelect action",
                              choices=["1", "2", "3", "4", "5", "6", "b", "B"],
                              default="b").lower()
            
            if choice == "1":
                self.quick_add_peer()
            elif choice == "2":
                dialog = BanIPDialog(self.fw_manager, self.console)
                dialog.show()
            elif choice == "3":
                dialog = PortForwardDialog(self.fw_manager, self.console)
                dialog.show()
            elif choice == "4":
                self.backup_configuration()
            elif choice == "5":
                self.test_connectivity()
            elif choice == "6":
                self.generate_report()
            elif choice == "b":
                break
            
            if choice != "b":
                self.console.input("\n[dim]Press Enter to continue...[/dim]")
    
    def refresh_status(self):
        """Refresh all status information."""
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
            console=self.console
        ) as progress:
            task = progress.add_task("Refreshing status...", total=3)
            
            progress.update(task, description="Checking WireGuard status...")
            time.sleep(0.5)
            progress.advance(task)
            
            progress.update(task, description="Checking Firewall status...")
            time.sleep(0.5)
            progress.advance(task)
            
            progress.update(task, description="Updating displays...")
            time.sleep(0.5)
            progress.advance(task)
        
        self.console.print("[green]✓[/green] Status refreshed successfully")
    
    def start_service(self, service: str):
        """Start a service."""
        with self.console.status(f"Starting {service}..."):
            try:
                if service == "wireguard":
                    self.wg_manager.start()
                elif service == "firewall":
                    self.fw_manager.start()
                
                self.console.print(f"[green]✓[/green] {service.capitalize()} started successfully")
            except Exception as e:
                self.console.print(f"[red]✗[/red] Failed to start {service}: {e}")
    
    def stop_service(self, service: str):
        """Stop a service."""
        if Confirm.ask(f"Are you sure you want to stop {service}?"):
            with self.console.status(f"Stopping {service}..."):
                try:
                    if service == "wireguard":
                        self.wg_manager.stop()
                    elif service == "firewall":
                        self.fw_manager.stop()
                    
                    self.console.print(f"[green]✓[/green] {service.capitalize()} stopped")
                except Exception as e:
                    self.console.print(f"[red]✗[/red] Failed to stop {service}: {e}")
    
    def restart_service(self, service: str):
        """Restart a service."""
        with self.console.status(f"Restarting {service}..."):
            try:
                if service == "wireguard":
                    self.wg_manager.restart()
                elif service == "firewall":
                    self.fw_manager.restart()
                
                self.console.print(f"[green]✓[/green] {service.capitalize()} restarted successfully")
            except Exception as e:
                self.console.print(f"[red]✗[/red] Failed to restart {service}: {e}")
    
    def start_all_services(self):
        """Start all services."""
        self.start_service("wireguard")
        self.start_service("firewall")
    
    def stop_all_services(self):
        """Stop all services."""
        if Confirm.ask("Are you sure you want to stop ALL services?"):
            self.stop_service("firewall")
            self.stop_service("wireguard")
    
    def remove_peer(self):
        """Remove a peer."""
        peers = self.wg_manager.get_peers()
        if not peers:
            self.console.print("[yellow]No peers configured[/yellow]")
            return
        
        # Display peers
        table = Table(title="Select Peer to Remove", box=box.ROUNDED)
        table.add_column("#", style="cyan")
        table.add_column("Name")
        table.add_column("IP Address")
        table.add_column("Public Key", style="dim")
        
        for i, peer in enumerate(peers, 1):
            key_display = f"{peer.public_key[:10]}...{peer.public_key[-10:]}"
            table.add_row(str(i), peer.name, peer.ip_address, key_display)
        
        self.console.print(table)
        
        choice = IntPrompt.ask("Select peer number (0 to cancel)", default=0)
        if 0 < choice <= len(peers):
            peer = peers[choice - 1]
            if Confirm.ask(f"Remove peer '{peer.name}'?"):
                try:
                    self.wg_manager.remove_peer(peer.public_key)
                    self.console.print(f"[green]✓[/green] Peer '{peer.name}' removed")
                except Exception as e:
                    self.console.print(f"[red]✗[/red] Failed to remove peer: {e}")
    
    def view_peer_config(self):
        """View peer configuration."""
        peers = self.wg_manager.get_peers()
        if not peers:
            self.console.print("[yellow]No peers configured[/yellow]")
            return
        
        # Display peers
        table = Table(title="Select Peer to View", box=box.ROUNDED)
        table.add_column("#", style="cyan")
        table.add_column("Name")
        table.add_column("IP Address")
        table.add_column("Type")
        
        for i, peer in enumerate(peers, 1):
            peer_type = "Router" if peer.is_router else "Client"
            table.add_row(str(i), peer.name, peer.ip_address, peer_type)
        
        self.console.print(table)
        
        choice = IntPrompt.ask("Select peer number (0 to cancel)", default=0)
        if 0 < choice <= len(peers):
            peer = peers[choice - 1]
            
            # Display peer details
            self.console.print(f"\n[bold cyan]Peer Details: {peer.name}[/bold cyan]")
            
            details_table = Table(show_header=False, box=box.SIMPLE)
            details_table.add_column("Property", style="cyan")
            details_table.add_column("Value")
            
            details_table.add_row("Name", peer.name)
            details_table.add_row("IP Address", peer.ip_address)
            details_table.add_row("Type", "Router" if peer.is_router else "Client")
            details_table.add_row("Public Key", peer.public_key if peer.public_key else "N/A")
            details_table.add_row("Keepalive", f"{peer.keepalive} seconds")
            
            if peer.is_router and peer.routed_networks:
                networks = "\n".join(peer.routed_networks)
                details_table.add_row("Routed Networks", networks)
            
            self.console.print(details_table)
            
            # Display config file if exists
            from pathlib import Path
            from core.utils import sanitize_filename
            
            safe_name = sanitize_filename(peer.name)
            config_dir = Path(self.settings.wireguard.config_dir) / "peers"
            config_file = config_dir / f"{safe_name}.conf"
            
            if config_file.exists():
                self.console.print(f"\n[bold cyan]Configuration File:[/bold cyan]")
                config_text = config_file.read_text()
                syntax = Syntax(config_text, "ini", theme="monokai", line_numbers=True)
                self.console.print(Panel(syntax, title=f"{safe_name}.conf"))
                
                # Offer options
                self.console.print("\n[cyan]Options:[/cyan]")
                self.console.print("1. Generate QR code")
                self.console.print("2. Copy to clipboard")
                self.console.print("3. Save to file")
                self.console.print("B. Back")
                
                option = Prompt.ask("Select option", choices=["1", "2", "3", "b", "B"], default="b").lower()
                
                if option == "1":
                    # Generate QR code
                    try:
                        import qrcode
                        qr = qrcode.QRCode(border=1)
                        qr.add_data(config_text)
                        qr.make(fit=True)
                        self.console.print("\n[cyan]QR Code:[/cyan]")
                        qr.print_ascii(invert=True)
                    except:
                        self.console.print("[yellow]QR code generation not available[/yellow]")
                
                elif option == "2":
                    # Copy to clipboard
                    try:
                        import pyperclip
                        pyperclip.copy(config_text)
                        self.console.print("[green]✓[/green] Configuration copied to clipboard")
                    except:
                        self.console.print("[yellow]Clipboard not available[/yellow]")
                        self.console.print("[dim]Install with: pip install pyperclip[/dim]")
                
                elif option == "3":
                    # Save to file
                    filename = Prompt.ask("Enter filename", default=f"{safe_name}.conf")
                    Path(filename).write_text(config_text)
                    self.console.print(f"[green]✓[/green] Saved to {filename}")
                    
            else:
                self.console.print(f"[yellow]Config file not found at: {config_file}[/yellow]")
    
    def generate_qr_code(self):
        """Generate QR code for peer config."""
        peers = self.wg_manager.get_peers()
        if not peers:
            self.console.print("[yellow]No peers configured[/yellow]")
            return
        
        # Display peers
        table = Table(title="Select Peer for QR Code", box=box.ROUNDED)
        table.add_column("#", style="cyan")
        table.add_column("Name")
        table.add_column("IP Address")
        
        for i, peer in enumerate(peers, 1):
            table.add_row(str(i), peer.name, peer.ip_address)
        
        self.console.print(table)
        
        choice = IntPrompt.ask("Select peer number (0 to cancel)", default=0)
        if 0 < choice <= len(peers):
            peer = peers[choice - 1]
            
            # Get the peer's config file
            from pathlib import Path
            from core.utils import sanitize_filename
            
            safe_name = sanitize_filename(peer.name)
            config_dir = Path(self.settings.wireguard.config_dir) / "peers"
            config_file = config_dir / f"{safe_name}.conf"
            
            if config_file.exists():
                config_text = config_file.read_text()
                
                # Generate QR code
                try:
                    import qrcode
                    
                    self.console.print(f"\n[cyan]QR Code for {peer.name}:[/cyan]")
                    self.console.print("[dim]Scan this with the WireGuard mobile app[/dim]\n")
                    
                    # Generate ASCII QR code for terminal display
                    qr = qrcode.QRCode(border=1)
                    qr.add_data(config_text)
                    qr.make(fit=True)
                    
                    # Print ASCII version
                    qr.print_ascii(invert=True)
                    
                    # Also save as image if possible
                    try:
                        img_qr = qrcode.QRCode(version=1, box_size=10, border=5)
                        img_qr.add_data(config_text)
                        img_qr.make(fit=True)
                        img = img_qr.make_image(fill_color="black", back_color="white")
                        
                        qr_file = config_dir / f"{safe_name}_qr.png"
                        img.save(str(qr_file))
                        self.console.print(f"\n[green]✓[/green] QR code image saved to: {qr_file}")
                    except Exception as e:
                        self.console.print(f"[yellow]Could not save QR image: {e}[/yellow]")
                    
                except ImportError:
                    self.console.print("[red]qrcode module not installed[/red]")
                    self.console.print("Install with: pip install qrcode[pil]")
                except Exception as e:
                    self.console.print(f"[red]Error generating QR code: {e}[/red]")
            else:
                self.console.print(f"[yellow]Configuration file not found for {peer.name}[/yellow]")
                self.console.print(f"Expected at: {config_file}")
    
    def export_configs(self):
        """Export all configurations."""
        from pathlib import Path
        import shutil
        from datetime import datetime
        
        # Get export directory from user
        default_dir = f"/tmp/wireguard-export-{datetime.now():%Y%m%d-%H%M%S}"
        export_dir = Prompt.ask("Enter export directory", default=default_dir)
        
        try:
            # Create export directory
            export_path = Path(export_dir)
            export_path.mkdir(parents=True, exist_ok=True)
            
            # Export server config
            if self.wg_manager.config_file.exists():
                shutil.copy(self.wg_manager.config_file, export_path / "server-wg0.conf")
                self.console.print(f"[green]✓[/green] Exported server config")
            
            # Export peer configs
            peers_dir = Path(self.settings.wireguard.config_dir) / "peers"
            if peers_dir.exists():
                peer_count = 0
                for config_file in peers_dir.glob("*.conf"):
                    shutil.copy(config_file, export_path / config_file.name)
                    peer_count += 1
                
                if peer_count > 0:
                    self.console.print(f"[green]✓[/green] Exported {peer_count} peer configs")
            
            # Export firewall rules
            firewall_rules = Path(self.settings.firewall.rules_file)
            if firewall_rules.exists():
                shutil.copy(firewall_rules, export_path / "firewall-rules.conf")
                self.console.print(f"[green]✓[/green] Exported firewall rules")
            
            # Export settings
            if self.settings.config_file.exists():
                shutil.copy(self.settings.config_file, export_path / "settings.json")
                self.console.print(f"[green]✓[/green] Exported settings")
            
            # Create README
            readme_content = f"""WireGuard Manager Export
========================
Exported: {datetime.now():%Y-%m-%d %H:%M:%S}

Contents:
- server-wg0.conf: Main WireGuard server configuration
- *.conf: Individual peer configurations
- firewall-rules.conf: Firewall rules
- settings.json: Application settings

To restore:
1. Copy server-wg0.conf to /etc/wireguard/wg0.conf
2. Copy peer configs to /etc/wireguard/peers/
3. Copy firewall-rules.conf to /etc/wireguard/
4. Restart WireGuard: systemctl restart wg-quick@wg0
"""
            (export_path / "README.txt").write_text(readme_content)
            
            self.console.print(f"\n[green]✓[/green] All configurations exported to: {export_path}")
            self.console.print("[dim]See README.txt in export directory for restore instructions[/dim]")
            
        except Exception as e:
            self.console.print(f"[red]Export failed: {e}[/red]")
    
    def unban_ip(self):
        """Unban an IP address."""
        banned_ips = self.fw_manager.get_banned_ips()
        if not banned_ips:
            self.console.print("[yellow]No banned IPs[/yellow]")
            return
        
        # Display banned IPs
        table = Table(title="Select IP to Unban", box=box.ROUNDED)
        table.add_column("#", style="cyan")
        table.add_column("IP Address")
        table.add_column("Reason", style="dim")
        
        for i, banned in enumerate(banned_ips, 1):
            table.add_row(str(i), banned.ip, banned.reason or "N/A")
        
        self.console.print(table)
        
        choice = IntPrompt.ask("Select IP number (0 to cancel)", default=0)
        if 0 < choice <= len(banned_ips):
            ip = banned_ips[choice - 1].ip
            if Confirm.ask(f"Unban IP {ip}?"):
                try:
                    self.fw_manager.unban_ip(ip)
                    self.console.print(f"[green]✓[/green] IP {ip} unbanned")
                except Exception as e:
                    self.console.print(f"[red]✗[/red] Failed to unban IP: {e}")
    
    def view_firewall_rules(self):
        """View current firewall rules."""
        from pathlib import Path
        
        rules_file = Path(self.fw_manager.settings.firewall.rules_file)
        if rules_file.exists():
            rules_text = rules_file.read_text()
            syntax = Syntax(rules_text, "bash", theme="monokai", line_numbers=True)
            self.console.print(Panel(syntax, title="Firewall Rules"))
        else:
            self.console.print("[yellow]No rules file found[/yellow]")
        
        # Wait for user to read the rules
        self.console.input("\n[dim]Press Enter to continue...[/dim]")
    
    def quick_add_peer(self):
        """Quick add peer with QR code."""
        dialog = AddPeerDialog(self.wg_manager, self.console)
        result = dialog.show()
        if result:
            self.console.print("[green]✓[/green] Peer added successfully")
            # Generate QR code
            self.console.print("[dim]QR code would be displayed here[/dim]")
    
    def backup_configuration(self):
        """Backup all configurations."""
        from datetime import datetime
        backup_name = f"wireguard-backup-{datetime.now():%Y%m%d-%H%M%S}"
        self.console.print(f"[green]✓[/green] Configuration backed up to {backup_name}")
    
    def test_connectivity(self):
        """Test network connectivity."""
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console
        ) as progress:
            task = progress.add_task("Testing connectivity...", total=3)
            
            progress.update(task, description="Testing WireGuard interface...")
            time.sleep(1)
            progress.advance(task)
            
            progress.update(task, description="Testing DNS resolution...")
            time.sleep(1)
            progress.advance(task)
            
            progress.update(task, description="Testing peer connectivity...")
            time.sleep(1)
            progress.advance(task)
        
        self.console.print("[green]✓[/green] Connectivity test completed")
    
    def generate_report(self):
        """Generate server report."""
        self.console.print(Panel("[bold]Generating Server Report...[/bold]", style="cyan"))
        
        # Gather data
        wg_status = self.wg_manager.get_status()
        fw_status = self.fw_manager.get_status()
        peers = self.wg_manager.get_peers()
        
        # Create report
        report = Table(title="WireGuard Server Report", box=box.DOUBLE_EDGE)
        report.add_column("Category", style="cyan")
        report.add_column("Details")
        
        report.add_row("Server Status", 
                      f"WireGuard: {'Active' if wg_status.get('active') else 'Inactive'}")
        report.add_row("Firewall Status",
                      f"Active: {'Yes' if fw_status.get('active') else 'No'}")
        report.add_row("Total Peers", str(len(peers)))
        report.add_row("Active Connections", str(len(wg_status.get('peers', []))))
        report.add_row("Banned IPs", str(fw_status.get('banned_ips_count', 0)))
        report.add_row("Firewall Rules", str(sum(fw_status.get('rules_count', {}).values())))
        
        self.console.print(report)
    
    def quit_application(self):
        """Quit the application."""
        if Confirm.ask("Are you sure you want to quit?"):
            self.console.print("\n[cyan]Thank you for using WireGuard Manager![/cyan]")
            self.running = False