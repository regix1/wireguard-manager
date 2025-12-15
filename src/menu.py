"""Interactive TUI menu for WireGuard Manager."""

import sys
from typing import List, Tuple

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm

from .config import get_version

console = Console()


def clear_screen():
    """Clear the terminal screen."""
    console.clear()


def print_header():
    """Print the application header."""
    console.print(Panel.fit(
        f"[bold cyan]WireGuard Manager[/bold cyan] [dim]v{get_version()}[/dim]",
        border_style="cyan"
    ))
    console.print()


def show_menu(title: str, options: List[Tuple[str, str]], back: bool = True) -> str:
    """Display a menu and get user selection."""
    console.print(f"[bold yellow]{title}[/bold yellow]\n")

    for key, desc in options:
        console.print(f"  [cyan]{key}[/cyan]) {desc}")

    if back:
        console.print(f"  [dim]b) Back[/dim]")
    console.print(f"  [dim]q) Quit[/dim]")
    console.print()

    valid_keys = [k for k, _ in options] + (['b'] if back else []) + ['q']

    while True:
        choice = Prompt.ask("Select option", default="b" if back else "q").lower()
        if choice in valid_keys:
            return choice
        console.print("[red]Invalid option[/red]")


def pause():
    """Pause and wait for user input."""
    console.print()
    Prompt.ask("[dim]Press Enter to continue[/dim]", default="")


# ============ PEER MENU ============

def menu_peer_add():
    """Add a new peer."""
    from .peers import create

    console.print("\n[bold]Add New Peer[/bold]\n")

    name = Prompt.ask("Peer name")
    if not name:
        return

    is_router = Confirm.ask("Is this a router peer?", default=False)

    if is_router:
        subnets = Prompt.ask("Subnets (comma-separated)", default="")
        if subnets:
            subnet_list = [s.strip() for s in subnets.split(",")]
            create.add_router_peer(name=name, subnets=subnet_list)
        else:
            console.print("[red]Subnets required for router peer[/red]")
    else:
        ip = Prompt.ask("IP address (leave empty for auto)", default="")
        dns = Prompt.ask("DNS servers", default="1.1.1.1, 1.0.0.1")
        create.add_peer(name=name, ip=ip or None, dns=dns)

    pause()


def menu_peer_remove():
    """Remove a peer."""
    from .peers import remove, list as peer_list

    console.print("\n[bold]Remove Peer[/bold]\n")
    peer_list.print_peers()
    console.print()

    name = Prompt.ask("Peer name to remove (or 'cancel')")
    if name and name.lower() != 'cancel':
        if Confirm.ask(f"Remove peer '{name}'?", default=False):
            remove.remove_peer(name)

    pause()


def menu_peer_list():
    """List all peers."""
    from .peers import list as peer_list

    console.print("\n[bold]Peer List[/bold]\n")
    peer_list.print_peers()
    pause()


def menu_peer_show():
    """Show peer details."""
    from .peers import list as peer_list

    console.print("\n[bold]Show Peer Details[/bold]\n")
    name = Prompt.ask("Peer name")
    if name:
        info = peer_list.get_peer_info(name)
        if info:
            for key, value in info.items():
                console.print(f"  {key}: {value}")
        else:
            console.print(f"[red]Peer not found: {name}[/red]")
    pause()


def menu_peer_qr():
    """Show QR code for a peer."""
    from .peers import qrcode

    console.print("\n[bold]Show QR Code[/bold]\n")
    name = Prompt.ask("Peer name")
    if name:
        qrcode.show_qr(name)
    pause()


def menu_peer_config():
    """Show config for a peer."""
    from .peers import qrcode

    console.print("\n[bold]Show Peer Config[/bold]\n")
    name = Prompt.ask("Peer name")
    if name:
        qrcode.show_config(name)
    pause()


def menu_peer_scan():
    """Scan for peer configs."""
    from .peers import list as peer_list

    console.print("\n[bold]Scan for Peer Configs[/bold]\n")
    found = peer_list.scan_for_peer_configs()
    if found:
        console.print(f"Found {len(found)} peer configuration(s):\n")
        console.print(f"{'Name':<30} {'IP':<16} {'Directory'}")
        console.print("-" * 80)
        for p in found:
            console.print(f"{p['name']:<30} {p['ip']:<16} {p['directory']}")
    else:
        console.print("No peer configurations found")
    pause()


def menu_peer_dirs():
    """Manage peer directories submenu."""
    from .peers import list as peer_list

    while True:
        clear_screen()
        print_header()

        choice = show_menu("Peer Directories", [
            ("1", "List directories"),
            ("2", "Add directory"),
            ("3", "Remove directory"),
        ])

        if choice == "1":
            console.print("\n[bold]Configured Directories[/bold]\n")
            dirs = peer_list.load_peer_directories()
            for d in dirs:
                exists = "[green]OK[/green]" if d.exists() else "[red]MISSING[/red]"
                console.print(f"  [{exists}] {d}")
            pause()
        elif choice == "2":
            console.print("\n[bold]Add Directory[/bold]\n")
            directory = Prompt.ask("Directory path")
            if directory:
                peer_list.add_peer_directory(directory)
            pause()
        elif choice == "3":
            console.print("\n[bold]Remove Directory[/bold]\n")
            dirs = peer_list.load_peer_directories()
            for d in dirs:
                console.print(f"  {d}")
            console.print()
            directory = Prompt.ask("Directory to remove")
            if directory:
                peer_list.remove_peer_directory(directory)
            pause()
        elif choice in ("b", "q"):
            break


def menu_peers():
    """Peer management submenu."""
    while True:
        clear_screen()
        print_header()

        choice = show_menu("Peer Management", [
            ("1", "List peers"),
            ("2", "Add peer"),
            ("3", "Remove peer"),
            ("4", "Show peer details"),
            ("5", "Show QR code"),
            ("6", "Show config"),
            ("7", "Scan for configs"),
            ("8", "Manage directories"),
        ])

        if choice == "1":
            menu_peer_list()
        elif choice == "2":
            menu_peer_add()
        elif choice == "3":
            menu_peer_remove()
        elif choice == "4":
            menu_peer_show()
        elif choice == "5":
            menu_peer_qr()
        elif choice == "6":
            menu_peer_config()
        elif choice == "7":
            menu_peer_scan()
        elif choice == "8":
            menu_peer_dirs()
        elif choice in ("b", "q"):
            break


# ============ SERVICE MENU ============

def menu_service():
    """Service control submenu."""
    from .service import control
    from .service.status import status as show_status

    while True:
        clear_screen()
        print_header()

        choice = show_menu("Service Control", [
            ("1", "Show status"),
            ("2", "Start WireGuard"),
            ("3", "Stop WireGuard"),
            ("4", "Restart WireGuard"),
            ("5", "Reload config"),
            ("6", "Enable at boot"),
            ("7", "Disable at boot"),
        ])

        if choice == "1":
            console.print()
            show_status()
            pause()
        elif choice == "2":
            control.start()
            pause()
        elif choice == "3":
            control.stop()
            pause()
        elif choice == "4":
            control.restart()
            pause()
        elif choice == "5":
            control.reload_config()
            pause()
        elif choice == "6":
            control.enable()
            pause()
        elif choice == "7":
            control.disable()
            pause()
        elif choice in ("b", "q"):
            break


# ============ FIREWALL MENU ============

def menu_fw_status():
    """Show firewall status."""
    from .firewall.status import show_status
    console.print()
    show_status()
    pause()


def menu_fw_nat():
    """NAT rules submenu."""
    from .firewall import nat

    while True:
        clear_screen()
        print_header()

        choice = show_menu("NAT Rules", [
            ("1", "List NAT rules"),
            ("2", "Add NAT rule"),
            ("3", "Remove NAT rule"),
        ])

        if choice == "1":
            console.print()
            nat.print_nat()
            pause()
        elif choice == "2":
            console.print("\n[bold]Add NAT Rule[/bold]\n")
            source = Prompt.ask("Source subnet (e.g., 10.0.0.0/24)")
            interface = Prompt.ask("External interface", default="eth0")
            masquerade = Confirm.ask("Use MASQUERADE?", default=True)
            if source:
                nat.add_nat(source, interface, masquerade)
            pause()
        elif choice == "3":
            console.print()
            nat.print_nat()
            console.print()
            source = Prompt.ask("Source subnet to remove")
            interface = Prompt.ask("External interface", default="eth0")
            if source:
                nat.remove_nat(source, interface)
            pause()
        elif choice in ("b", "q"):
            break


def menu_fw_forward():
    """Forward rules submenu."""
    from .firewall import forward

    while True:
        clear_screen()
        print_header()

        choice = show_menu("Forward Rules", [
            ("1", "List FORWARD rules"),
            ("2", "Add FORWARD rule"),
            ("3", "Remove FORWARD rule"),
        ])

        if choice == "1":
            console.print()
            forward.print_forward()
            pause()
        elif choice == "2":
            console.print("\n[bold]Add FORWARD Rule[/bold]\n")
            in_iface = Prompt.ask("Input interface (leave empty for any)", default="")
            out_iface = Prompt.ask("Output interface (leave empty for any)", default="")
            source = Prompt.ask("Source address (leave empty for any)", default="")
            dest = Prompt.ask("Destination address (leave empty for any)", default="")
            protocol = Prompt.ask("Protocol (tcp/udp, leave empty for any)", default="")
            dport = Prompt.ask("Destination port (leave empty for any)", default="")
            forward.add_forward(
                in_interface=in_iface or None,
                out_interface=out_iface or None,
                source=source or None,
                dest=dest or None,
                protocol=protocol or None,
                dport=dport or None,
            )
            pause()
        elif choice == "3":
            console.print()
            forward.print_forward()
            console.print()
            rule_num = Prompt.ask("Rule number to remove")
            if rule_num:
                forward.remove_forward(int(rule_num))
            pause()
        elif choice in ("b", "q"):
            break


def menu_fw_port():
    """Port forwarding submenu."""
    from .firewall import portfwd

    while True:
        clear_screen()
        print_header()

        choice = show_menu("Port Forwarding", [
            ("1", "List port forwards"),
            ("2", "Add port forward"),
            ("3", "Add port forward with SNAT"),
            ("4", "Remove port forward"),
        ])

        if choice == "1":
            console.print()
            portfwd.print_port_forwards()
            pause()
        elif choice == "2":
            console.print("\n[bold]Add Port Forward[/bold]\n")
            ext_port = Prompt.ask("External port")
            int_ip = Prompt.ask("Internal IP")
            int_port = Prompt.ask("Internal port (leave empty for same)", default="")
            protocol = Prompt.ask("Protocol", default="tcp")
            ext_iface = Prompt.ask("External interface", default="eth0")
            if ext_port and int_ip:
                portfwd.add_port_forward(ext_port, int_ip, int_port or None, protocol, ext_iface)
            pause()
        elif choice == "3":
            console.print("\n[bold]Add Port Forward with SNAT[/bold]\n")
            ext_port = Prompt.ask("External port")
            int_ip = Prompt.ask("Internal IP")
            snat_ip = Prompt.ask("SNAT source IP")
            int_port = Prompt.ask("Internal port (leave empty for same)", default="")
            protocol = Prompt.ask("Protocol", default="tcp")
            ext_iface = Prompt.ask("External interface", default="eth0")
            if ext_port and int_ip and snat_ip:
                portfwd.add_port_forward_snat(ext_port, int_ip, snat_ip, int_port or None, protocol, ext_iface)
            pause()
        elif choice == "4":
            console.print()
            portfwd.print_port_forwards()
            console.print()
            ext_port = Prompt.ask("External port to remove")
            int_ip = Prompt.ask("Internal IP")
            protocol = Prompt.ask("Protocol", default="tcp")
            ext_iface = Prompt.ask("External interface", default="eth0")
            if ext_port and int_ip:
                portfwd.remove_port_forward(ext_port, int_ip, protocol, ext_iface)
            pause()
        elif choice in ("b", "q"):
            break


def menu_fw_ban():
    """IP banning submenu."""
    from .firewall import ban

    while True:
        clear_screen()
        print_header()

        choice = show_menu("IP Banning", [
            ("1", "List banned IPs"),
            ("2", "Ban an IP"),
            ("3", "Unban an IP"),
            ("4", "Sync bans to iptables"),
            ("5", "Import ban list"),
            ("6", "Export ban list"),
            ("7", "Migrate old format"),
            ("8", "Scan for ban files"),
        ])

        if choice == "1":
            console.print()
            ban.print_bans()
            pause()
        elif choice == "2":
            console.print("\n[bold]Ban IP[/bold]\n")
            ip = Prompt.ask("IP address to ban")
            reason = Prompt.ask("Reason", default="")
            if ip:
                ban.ban_ip(ip, reason or None)
            pause()
        elif choice == "3":
            console.print()
            ban.print_bans()
            console.print()
            ip = Prompt.ask("IP address to unban")
            if ip:
                ban.unban_ip(ip)
            pause()
        elif choice == "4":
            ban.sync_bans()
            pause()
        elif choice == "5":
            console.print("\n[bold]Import Ban List[/bold]\n")
            filepath = Prompt.ask("File path to import")
            if filepath:
                ban.import_ban_list(filepath)
            pause()
        elif choice == "6":
            console.print("\n[bold]Export Ban List[/bold]\n")
            filepath = Prompt.ask("File path to export to")
            if filepath:
                ban.export_ban_list(filepath)
            pause()
        elif choice == "7":
            ban.migrate_banned_ips()
            pause()
        elif choice == "8":
            console.print("\n[bold]Scan for Ban Files[/bold]\n")
            found = ban.scan_for_ban_files()
            if found:
                console.print("Found ban list files:")
                for f in found:
                    console.print(f"  {f}")
            else:
                console.print("No ban list files found")
            pause()
        elif choice in ("b", "q"):
            break


def menu_fw_rules():
    """Firewall rules submenu."""
    from .firewall import rules

    while True:
        clear_screen()
        print_header()

        choice = show_menu("Firewall Rules Management", [
            ("1", "Show saved rules"),
            ("2", "Apply rules from file"),
            ("3", "Clear all iptables rules"),
            ("4", "Save current rules to scripts"),
        ])

        if choice == "1":
            console.print("\n[bold]Saved Rules[/bold]\n")
            loaded = rules.load_rules()
            if loaded:
                for r in loaded:
                    console.print(f"  {r}")
            else:
                console.print("No rules configured")
            pause()
        elif choice == "2":
            if Confirm.ask("Apply rules from file?", default=False):
                rules.apply_rules()
            pause()
        elif choice == "3":
            if Confirm.ask("[red]Clear ALL iptables rules?[/red]", default=False):
                rules.clear_rules()
            pause()
        elif choice == "4":
            rules.create_apply_script()
            rules.create_remove_script()
            console.print("[green]Rules saved to scripts[/green]")
            pause()
        elif choice in ("b", "q"):
            break


def menu_fw_service():
    """Firewall systemd service submenu."""
    from .firewall import rules

    while True:
        clear_screen()
        print_header()

        choice = show_menu("Firewall Service", [
            ("1", "Show service status"),
            ("2", "Setup firewall service"),
            ("3", "Enable and start service"),
            ("4", "Restart service"),
        ])

        if choice == "1":
            console.print("\n[bold]Firewall Service Status[/bold]\n")
            s = rules.firewall_service_status()
            console.print(f"  Active: {'[green]Yes[/green]' if s['active'] else '[red]No[/red]'}")
            console.print(f"  Enabled: {'[green]Yes[/green]' if s['enabled'] else '[red]No[/red]'}")
            console.print(f"  Service file: {'[green]Exists[/green]' if s['service_exists'] else '[red]Missing[/red]'}")
            console.print(f"  Rules file: {'[green]Exists[/green]' if s['rules_file_exists'] else '[red]Missing[/red]'}")
            pause()
        elif choice == "2":
            console.print("\n[bold]Setup Firewall Service[/bold]\n")
            ext_iface = Prompt.ask("External interface", default="eth0")
            subnets = Prompt.ask("WireGuard subnets (comma-separated)", default="")
            subnet_list = [s.strip() for s in subnets.split(",")] if subnets else None
            rules.setup_firewall_service(ext_iface, subnet_list)
            pause()
        elif choice == "3":
            rules.enable_firewall_service()
            pause()
        elif choice == "4":
            rules.restart_firewall_service()
            pause()
        elif choice in ("b", "q"):
            break


def menu_firewall():
    """Firewall management submenu."""
    while True:
        clear_screen()
        print_header()

        choice = show_menu("Firewall Management", [
            ("1", "Show status"),
            ("2", "NAT rules"),
            ("3", "Forward rules"),
            ("4", "Port forwarding"),
            ("5", "IP banning"),
            ("6", "Rules management"),
            ("7", "Firewall service"),
        ])

        if choice == "1":
            menu_fw_status()
        elif choice == "2":
            menu_fw_nat()
        elif choice == "3":
            menu_fw_forward()
        elif choice == "4":
            menu_fw_port()
        elif choice == "5":
            menu_fw_ban()
        elif choice == "6":
            menu_fw_rules()
        elif choice == "7":
            menu_fw_service()
        elif choice in ("b", "q"):
            break


# ============ BACKUP MENU ============

def menu_backup():
    """Backup management submenu."""
    from .backup import create, restore

    while True:
        clear_screen()
        print_header()

        choice = show_menu("Backup Management", [
            ("1", "List backups"),
            ("2", "Create backup"),
            ("3", "Show backup contents"),
            ("4", "Restore backup"),
            ("5", "Delete backup"),
        ])

        if choice == "1":
            console.print()
            restore.print_backups()
            pause()
        elif choice == "2":
            console.print("\n[bold]Create Backup[/bold]\n")
            name = Prompt.ask("Backup name (leave empty for auto)", default="")
            create.create_backup(name or None)
            pause()
        elif choice == "3":
            console.print()
            restore.print_backups()
            console.print()
            filename = Prompt.ask("Backup file to show")
            if filename:
                restore.show_backup_contents(filename)
            pause()
        elif choice == "4":
            console.print()
            restore.print_backups()
            console.print()
            filename = Prompt.ask("Backup file to restore")
            if filename:
                dry_run = Confirm.ask("Dry run (show what would be restored)?", default=True)
                if dry_run:
                    restore.restore_backup(filename, dry_run=True)
                elif Confirm.ask("Actually restore this backup?", default=False):
                    restore.restore_backup(filename, dry_run=False)
            pause()
        elif choice == "5":
            console.print()
            restore.print_backups()
            console.print()
            filename = Prompt.ask("Backup file to delete")
            if filename:
                if Confirm.ask(f"Delete '{filename}'?", default=False):
                    restore.delete_backup(filename)
            pause()
        elif choice in ("b", "q"):
            break


# ============ DIAGNOSTICS MENU ============

def menu_diagnostics():
    """Diagnostics submenu."""
    from .system import diagnostics

    while True:
        clear_screen()
        print_header()

        choice = show_menu("Diagnostics", [
            ("1", "Run full diagnostics"),
            ("2", "Test connectivity"),
            ("3", "View logs"),
            ("4", "Check config syntax"),
        ])

        if choice == "1":
            console.print()
            diagnostics.run_diagnostics()
            pause()
        elif choice == "2":
            console.print()
            ip = Prompt.ask("IP to test (leave empty for default)", default="")
            diagnostics.test_connectivity(ip or None)
            pause()
        elif choice == "3":
            console.print()
            lines = Prompt.ask("Number of lines", default="50")
            diagnostics.view_logs(int(lines))
            pause()
        elif choice == "4":
            console.print()
            interface = Prompt.ask("Interface", default="wg0")
            diagnostics.check_config_syntax(interface)
            pause()
        elif choice in ("b", "q"):
            break


# ============ INIT/SETUP MENU ============

def menu_init():
    """Init/Setup submenu."""
    from .system import setup, install

    while True:
        clear_screen()
        print_header()

        choice = show_menu("Initialize/Setup", [
            ("1", "Initialize server configuration"),
            ("2", "Install WireGuard"),
        ])

        if choice == "1":
            console.print("\n[bold]Initialize Server Configuration[/bold]\n")
            interface = Prompt.ask("Interface name", default="wg0")
            port = Prompt.ask("Listen port", default="51820")
            subnet = Prompt.ask("Server subnet", default="10.0.0.0/24")
            address = Prompt.ask("Server address", default="10.0.0.1/24")
            dns = Prompt.ask("DNS servers", default="1.1.1.1, 1.0.0.1")
            mtu = Prompt.ask("MTU", default="1420")
            ext_iface = Prompt.ask("External interface", default="eth0")

            if Confirm.ask("Initialize server with these settings?", default=False):
                setup.init_server(
                    interface=interface,
                    port=int(port),
                    subnet=subnet,
                    address=address,
                    dns=dns,
                    mtu=int(mtu),
                    external_interface=ext_iface,
                )
            pause()
        elif choice == "2":
            if Confirm.ask("Install WireGuard?", default=False):
                install.install_wireguard()
            pause()
        elif choice in ("b", "q"):
            break


# ============ MAIN MENU ============

def main_menu():
    """Main application menu."""
    while True:
        clear_screen()
        print_header()

        choice = show_menu("Main Menu", [
            ("1", "Peer Management"),
            ("2", "Service Control"),
            ("3", "Firewall Rules"),
            ("4", "Backup/Restore"),
            ("5", "Diagnostics"),
            ("6", "Initialize/Setup"),
        ], back=False)

        if choice == "1":
            menu_peers()
        elif choice == "2":
            menu_service()
        elif choice == "3":
            menu_firewall()
        elif choice == "4":
            menu_backup()
        elif choice == "5":
            menu_diagnostics()
        elif choice == "6":
            menu_init()
        elif choice == "q":
            console.print("\n[cyan]Goodbye![/cyan]\n")
            sys.exit(0)


def run():
    """Run the interactive menu."""
    try:
        main_menu()
    except KeyboardInterrupt:
        console.print("\n\n[cyan]Goodbye![/cyan]\n")
        sys.exit(0)
