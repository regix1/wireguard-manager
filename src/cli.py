#!/usr/bin/env python3
"""Main CLI interface for WireGuard Manager."""

import sys
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, IntPrompt
from rich.progress import Progress, SpinnerColumn, TextColumn

from .constants import APP_VERSION
from .utils import check_root, check_wireguard_installed, check_service_status, prompt_yes_no
from .menu_system import InteractiveMenu, MenuItem, MenuCategory
from .config_manager import ConfigManager
from .peer_manager import PeerManager
from .service_manager import ServiceManager
from .firewall_manager import FirewallManager
from .backup import BackupManager
from .installer import WireGuardInstaller
from .troubleshooter import Troubleshooter

console = Console()

class WireGuardManagerCLI:
    """Main CLI class for WireGuard Manager."""
    
    def __init__(self):
        """Initialize the CLI."""
        self.config_manager = ConfigManager()
        self.peer_manager = PeerManager()
        self.service_manager = ServiceManager()
        self.firewall_manager = FirewallManager()
        self.backup_manager = BackupManager()
        self.installer = WireGuardInstaller()
        self.troubleshooter = Troubleshooter()
        self.menu = InteractiveMenu()
        self.setup_menu()
    
    def wrap_action(self, func):
        """Wrap an action to ensure it pauses before returning."""
        def wrapped():
            try:
                result = func()
                console.print("\n[dim]Press Enter to continue...[/dim]")
                input()
                return result
            except KeyboardInterrupt:
                console.print("\n[yellow]Operation cancelled[/yellow]")
                console.print("[dim]Press Enter to continue...[/dim]")
                input()
            except Exception as e:
                console.print(f"\n[red]Error: {e}[/red]")
                console.print("[dim]Press Enter to continue...[/dim]")
                input()
        return wrapped
    
    def show_banner(self) -> None:
        """Display the application banner with status."""
        console.clear()
        
        # Get service status
        interfaces = self.service_manager.get_interfaces()
        active_interfaces = self.service_manager.get_active_interfaces()
        
        # Display header
        console.print("┌" + "─" * 58 + "┐")
        console.print(f"│  [bold cyan]WIREGUARD VPN MANAGER[/bold cyan]  v{APP_VERSION:<25} │")
        console.print("├" + "─" * 58 + "┤")
        
        if active_interfaces:
            console.print(f"│  Status: [green]● Active[/green] ({len(active_interfaces)} interface{'s' if len(active_interfaces) > 1 else ''})                     │")
        else:
            console.print(f"│  Status: [red]○ Inactive[/red]                                  │")
        
        console.print("└" + "─" * 58 + "┘")
        console.print()
    
    def setup_menu(self) -> None:
        """Setup the interactive menu structure."""
        # Check if WireGuard is installed
        if not check_wireguard_installed():
            self.menu.add_item(MenuItem(
                "Install WireGuard",
                self.wrap_action(self.installer.install_wireguard),
                prefix="[I]",
                description="Install WireGuard on this system",
                key="i"
            ))
            self.menu.add_item(MenuItem(
                "Install Manager System-wide",
                self.wrap_action(self.installer.install_manager),
                prefix="[M]",
                description="Install this manager to /usr/local/bin",
                key="m"
            ))
            self.menu.add_item(MenuItem(
                "Exit",
                lambda: False,
                prefix="[Q]",
                description="Exit program",
                key="q",
                style="red"
            ))
            return
        
        # Service Control
        self.menu.add_item(MenuItem(
            "Service Status",
            self.service_manager.show_status,
            prefix="[S]",
            description="View service status",
            key="s"
        ))
        
        self.menu.add_item(MenuItem(
            "Quick Actions",
            self.quick_actions_menu,
            prefix="[Q]",
            description="Start/Stop/Restart",
            key="q"
        ))
        
        # Peer Management
        peer_category = MenuCategory("Peer Management", prefix="[P]")
        peer_category.add_item(MenuItem(
            "Add Peer",
            self.wrap_action(self.peer_manager.add_peer),
            description="Add new VPN client"
        ))
        peer_category.add_item(MenuItem(
            "Remove Peer",
            self.wrap_action(self.peer_manager.remove_peer),
            description="Remove existing peer"
        ))
        peer_category.add_item(MenuItem(
            "List Peers",
            self.wrap_action(self.peer_manager.list_peers),
            description="Show all peers"
        ))
        peer_category.add_item(MenuItem(
            "Show QR Code",
            self.wrap_action(self.peer_manager.show_qr_code),
            description="Generate QR for mobile"
        ))
        self.menu.add_category(peer_category)
        
        # Configuration
        config_category = MenuCategory("Configuration", prefix="[C]")
        config_category.add_item(MenuItem(
            "Create Server Config",
            self.wrap_action(self.config_manager.create_server_config),
            description="Initial server setup"
        ))
        config_category.add_item(MenuItem(
            "Edit Configuration",
            self.wrap_action(self.config_manager.edit_configuration),
            description="Modify settings"
        ))
        config_category.add_item(MenuItem(
            "Network Settings",
            self.wrap_action(self.config_manager.edit_network_settings),
            description="IP ranges and ports"
        ))
        self.menu.add_category(config_category)
        
        # Firewall & Security
        firewall_category = MenuCategory("Firewall & Security", prefix="[F]")
        firewall_category.add_item(MenuItem(
            "Firewall Status",
            self.wrap_action(self.firewall_manager.show_status),
            description="View all firewall rules"
        ))
        firewall_category.add_item(MenuItem(
            "NAT Rules Management",
            self.wrap_action(self.firewall_manager.manage_nat_rules),
            description="Manage NAT/Masquerade rules"
        ))
        firewall_category.add_item(MenuItem(
            "Port Forwarding",
            self.wrap_action(self.firewall_manager.manage_port_forwarding),
            description="Configure port forwards"
        ))
        firewall_category.add_item(MenuItem(
            "Forward Rules",
            self.wrap_action(self.firewall_manager.manage_forward_rules),
            description="Manage FORWARD chain"
        ))
        firewall_category.add_item(MenuItem(
            "Banned IPs",
            self.wrap_action(self.firewall_manager.manage_banned_ips),
            description="Manage IP bans",
            style="yellow"
        ))
        firewall_category.add_item(MenuItem(
            "Apply Standard NAT",
            self.wrap_action(self.firewall_manager.apply_nat_rules),
            description="Quick NAT setup"
        ))
        self.menu.add_category(firewall_category)
        
        # Maintenance
        maintenance_category = MenuCategory("Maintenance", prefix="[M]")
        maintenance_category.add_item(MenuItem(
            "Backup Configuration",
            self.backup_configuration_interactive,
            description="Save current setup"
        ))
        maintenance_category.add_item(MenuItem(
            "Restore Configuration",
            self.wrap_action(self.backup_manager.restore_backup),
            description="Restore from backup"
        ))
        maintenance_category.add_item(MenuItem(
            "Clean Backups",
            self.wrap_action(self.cleanup_old_backups),
            description="Remove old backups"
        ))
        self.menu.add_category(maintenance_category)
        
        # System & Updates
        system_category = MenuCategory("System & Updates", prefix="[U]")
        system_category.add_item(MenuItem(
            "Check for Manager Updates",
            self.wrap_action(self.installer.check_manager_updates),
            description="Check GitHub for updates"
        ))
        system_category.add_item(MenuItem(
            "Update WireGuard",
            self.wrap_action(self.installer.update_wireguard),
            description="Update WireGuard packages"
        ))
        system_category.add_item(MenuItem(
            "Install WireGuard",
            self.wrap_action(self.installer.install_wireguard),
            description="Install WireGuard packages"
        ))
        system_category.add_item(MenuItem(
            "Install Manager System-wide",
            self.wrap_action(self.installer.install_manager),
            description="Install to /usr/local/bin"
        ))
        system_category.add_item(MenuItem(
            "Uninstall WireGuard",
            self.wrap_action(self.installer.uninstall_wireguard),
            description="Remove WireGuard",
            style="yellow"
        ))
        system_category.add_item(MenuItem(
            "Uninstall Manager",
            self.wrap_action(self.installer.uninstall_manager),
            description="Remove this manager",
            style="red"
        ))
        system_category.add_item(MenuItem(
            "Version Info",
            self.installer.show_version_info,
            description="Show version details"
        ))
        self.menu.add_category(system_category)
        
        # Diagnostics
        diagnostic_category = MenuCategory("Diagnostics", prefix="[D]")
        diagnostic_category.add_item(MenuItem(
            "Run Diagnostics",
            self.wrap_action(self.troubleshooter.run_diagnostics),
            description="Check for issues"
        ))
        diagnostic_category.add_item(MenuItem(
            "Test Connectivity",
            self.wrap_action(self.troubleshooter.test_connectivity),
            description="Test VPN tunnel"
        ))
        diagnostic_category.add_item(MenuItem(
            "View Logs",
            self.wrap_action(self.troubleshooter.view_logs),
            description="System logs"
        ))
        self.menu.add_category(diagnostic_category)
        
        # Help and Exit
        self.menu.add_item(MenuItem(
            "Help",
            self.show_help,
            prefix="[H]",
            description="Show help",
            key="h"
        ))
        
        self.menu.add_item(MenuItem(
            "Exit",
            lambda: False,
            prefix="[X]",
            description="Exit program",
            key="x",
            style="red"
        ))
    
    def quick_actions_menu(self) -> None:
        """Quick actions submenu."""
        console.clear()
        console.print("┌" + "─" * 58 + "┐")
        console.print("│                  [bold cyan]QUICK ACTIONS[/bold cyan]                       │")
        console.print("└" + "─" * 58 + "┘")
        console.print()
        
        interfaces = self.service_manager.get_interfaces()
        if not interfaces:
            console.print("[yellow]No WireGuard interfaces configured[/yellow]")
            console.print("\n[dim]Press Enter to continue...[/dim]")
            input()
            return
        
        # Select interface
        if len(interfaces) == 1:
            interface = interfaces[0]
        else:
            console.print("[cyan]Available interfaces:[/cyan]")
            for i, iface in enumerate(interfaces, 1):
                status = "[green]●[/green]" if check_service_status(iface) else "[red]○[/red]"
                console.print(f"  {i}. {status} {iface}")
            
            choice = IntPrompt.ask("Select interface", choices=[str(i) for i in range(1, len(interfaces) + 1)])
            interface = interfaces[choice - 1]
        
        is_active = check_service_status(interface)
        
        console.print(f"\n[cyan]Interface:[/cyan] {interface}")
        console.print(f"[cyan]Status:[/cyan] {'[green]Active[/green]' if is_active else '[red]Inactive[/red]'}")
        console.print()
        
        console.print("  [1] Start")
        console.print("  [2] Stop")
        console.print("  [3] Restart")
        console.print("  [4] Show Details")
        console.print("  [0] Back")
        console.print()
        
        choice = Prompt.ask("Select action", choices=["0", "1", "2", "3", "4"])
        
        if choice == "1":
            self.service_manager.start_interface(interface)
        elif choice == "2":
            self.service_manager.stop_interface(interface)
        elif choice == "3":
            self.service_manager.restart_interface(interface)
        elif choice == "4":
            self.service_manager.show_interface_details(interface)
        
        if choice != "0":
            console.print("\n[dim]Press Enter to continue...[/dim]")
            input()
    
    def backup_configuration_interactive(self) -> None:
        """Interactive backup creation."""
        console.clear()
        console.print("┌" + "─" * 58 + "┐")
        console.print("│                 [bold cyan]CREATE BACKUP[/bold cyan]                         │")
        console.print("└" + "─" * 58 + "┘")
        console.print()
        
        description = Prompt.ask(
            "Enter backup description (optional)",
            default=""
        )
        
        console.print()
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
        ) as progress:
            task = progress.add_task("Creating backup...", total=None)
            backup_path = self.backup_manager.create_backup(description)
            progress.update(task, completed=True)
        
        console.print(f"[green]✓[/green] Backup created: {backup_path.name}")
        console.print("\n[dim]Press Enter to continue...[/dim]")
        input()
    
    def cleanup_old_backups(self) -> None:
        """Clean up old backups."""
        console.clear()
        console.print("┌" + "─" * 58 + "┐")
        console.print("│                 [bold cyan]CLEANUP BACKUPS[/bold cyan]                       │")
        console.print("└" + "─" * 58 + "┘")
        console.print()
        
        backups = self.backup_manager.list_backups()
        console.print(f"Found {len(backups)} backup(s)")
        
        if len(backups) > 10:
            console.print(f"\n[yellow]You have {len(backups)} backups. Recommended to keep only 10.[/yellow]")
            if prompt_yes_no("Clean up old backups?", default=True):
                # Keep only the 10 most recent
                for backup in backups[10:]:
                    console.print(f"[yellow]Removing: {backup.name}[/yellow]")
                    backup.unlink()
                console.print(f"\n[green]✓[/green] Removed {len(backups) - 10} old backup(s)")
        else:
            console.print("\n[green]No cleanup needed[/green]")
    
    def show_help(self) -> None:
        """Show help information."""
        console.clear()
        
        console.print("┌" + "─" * 58 + "┐")
        console.print("│                      [bold cyan]HELP[/bold cyan]                              │")
        console.print("└" + "─" * 58 + "┘")
        console.print()
        
        help_sections = [
            ("[bold]Navigation:[/bold]", [
                "↑/↓ or j/k    Navigate menu",
                "Enter         Select item",
                "ESC or b      Go back",
                "h             Show this help",
                "q             Exit program"
            ]),
            ("[bold]Quick Keys:[/bold]", [
                "s             Service status",
                "q             Quick actions",
                "1-9           Quick select"
            ]),
            ("[bold]Common Tasks:[/bold]", [
                "Service Status     Check VPN status",
                "Add Peer          Add new VPN client",
                "List Peers        Show all clients",
                "Quick Actions     Start/stop VPN",
                "Diagnostics       Troubleshoot issues"
            ])
        ]
        
        for title, items in help_sections:
            console.print(title)
            for item in items:
                console.print(f"  {item}")
            console.print()
        
        console.print("─" * 60)
        console.print("\n[bold]Documentation:[/bold]")
        console.print("  https://github.com/regix1/wireguard-manager")
        console.print("\n[dim]Press Enter to continue...[/dim]")
        input()
    
    def run(self) -> None:
        """Run the main application loop."""
        check_root()
        
        while True:
            self.show_banner()
            
            # Run the interactive menu
            result = self.menu.run()
            
            # Check if we should exit
            if result is False:
                console.print("\n[cyan]Goodbye![/cyan]")
                break

def main():
    """Main entry point for the application."""
    try:
        cli = WireGuardManagerCLI()
        cli.run()
        return 0
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted[/yellow]")
        return 1
    except Exception as e:
        console.print(f"\n[red]Fatal error: {e}[/red]")
        import traceback
        if "--debug" in sys.argv:
            console.print("[dim]" + traceback.format_exc() + "[/dim]")
        return 1

if __name__ == "__main__":
    sys.exit(main())