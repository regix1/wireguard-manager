#!/usr/bin/env python3
"""
WireGuard Manager CLI

A simple command-line tool for managing WireGuard VPN servers.

Usage:
    sudo ./wg-manager.py <command> [options]

Examples:
    sudo ./wg-manager.py peer add myphone
    sudo ./wg-manager.py peer add --router openwrt --subnets 10.0.4.0/24,172.16.1.0/24
    sudo ./wg-manager.py peer list
    sudo ./wg-manager.py service status
    sudo ./wg-manager.py fw status
"""

import argparse
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent))

from src.utils import require_root
from src.config import get_version


def cmd_peer(args):
    """Handle peer commands."""
    from src.peers import list as peer_list
    from src.peers import create, remove, qrcode

    if args.peer_action == "add":
        if args.router:
            # Router peer with subnets
            subnets = [s.strip() for s in args.subnets.split(",")]
            create.add_router_peer(
                name=args.name,
                subnets=subnets,
                interface=args.interface,
                ip=args.ip,
                keepalive=args.keepalive or 60,
            )
        else:
            # Standard client peer
            create.add_peer(
                name=args.name,
                interface=args.interface,
                ip=args.ip,
                dns=args.dns,
                keepalive=args.keepalive or 25,
                allowed_ips=args.allowed_ips or "0.0.0.0/0, ::/0",
            )

    elif args.peer_action == "remove":
        remove.remove_peer(args.name, args.interface)

    elif args.peer_action == "list":
        peer_list.print_peers(args.interface)

    elif args.peer_action == "scan":
        # Scan for peer configs in configured directories
        found = peer_list.scan_for_peer_configs()
        if found:
            print(f"\nFound {len(found)} peer configuration(s):\n")
            print(f"{'Name':<30} {'IP':<16} {'Directory'}")
            print("-" * 80)
            for p in found:
                print(f"{p['name']:<30} {p['ip']:<16} {p['directory']}")
        else:
            print("No peer configurations found")

    elif args.peer_action == "dirs":
        # Show/manage peer directories
        if hasattr(args, 'dirs_subaction') and args.dirs_subaction == "add":
            peer_list.add_peer_directory(args.directory)
        elif hasattr(args, 'dirs_subaction') and args.dirs_subaction == "remove":
            peer_list.remove_peer_directory(args.directory)
        else:
            # List directories
            dirs = peer_list.load_peer_directories()
            print("\nConfigured peer directories:")
            for d in dirs:
                exists = "OK" if d.exists() else "MISSING"
                print(f"  [{exists}] {d}")

    elif args.peer_action == "show":
        info = peer_list.get_peer_info(args.name, args.interface)
        if info:
            for key, value in info.items():
                print(f"{key}: {value}")
        else:
            print(f"Peer not found: {args.name}")

    elif args.peer_action == "qr":
        qrcode.show_qr(args.name)

    elif args.peer_action == "config":
        qrcode.show_config(args.name)


def cmd_service(args):
    """Handle service commands."""
    from src.service import control
    from src.service.status import status as show_service_status

    if args.service_action == "start":
        control.start(args.interface)
    elif args.service_action == "stop":
        control.stop(args.interface)
    elif args.service_action == "restart":
        control.restart(args.interface)
    elif args.service_action == "reload":
        control.reload_config(args.interface)
    elif args.service_action == "enable":
        control.enable(args.interface)
    elif args.service_action == "disable":
        control.disable(args.interface)
    elif args.service_action == "status":
        show_service_status(args.interface if args.interface != "wg0" else None)


def cmd_firewall(args):
    """Handle firewall commands."""
    from src.firewall import nat, forward, portfwd, ban, rules
    from src.firewall.status import show_status as show_fw_status

    if args.fw_action == "status":
        show_fw_status()

    elif args.fw_action == "nat":
        if args.fw_subaction == "add":
            nat.add_nat(args.source, args.ext_interface, not args.no_masquerade)
        elif args.fw_subaction == "remove":
            nat.remove_nat(args.source, args.ext_interface)
        elif args.fw_subaction == "list":
            nat.print_nat()

    elif args.fw_action == "forward":
        if args.fw_subaction == "add":
            forward.add_forward(
                in_interface=args.in_interface,
                out_interface=args.out_interface,
                source=args.source,
                dest=args.dest,
                protocol=args.protocol,
                dport=args.dport,
            )
        elif args.fw_subaction == "remove":
            forward.remove_forward(int(args.rule_num))
        elif args.fw_subaction == "list":
            forward.print_forward()

    elif args.fw_action == "port":
        if args.fw_subaction == "add":
            if args.snat:
                portfwd.add_port_forward_snat(
                    args.external_port, args.internal_ip,
                    args.snat, args.internal_port,
                    args.protocol, args.ext_interface
                )
            else:
                portfwd.add_port_forward(
                    args.external_port, args.internal_ip,
                    args.internal_port, args.protocol, args.ext_interface
                )
        elif args.fw_subaction == "remove":
            portfwd.remove_port_forward(
                args.external_port, args.internal_ip,
                args.protocol, args.ext_interface
            )
        elif args.fw_subaction == "list":
            portfwd.print_port_forwards()

    elif args.fw_action == "ban":
        if args.fw_subaction == "add":
            ban.ban_ip(args.ip, args.reason)
        elif args.fw_subaction == "remove":
            ban.unban_ip(args.ip)
        elif args.fw_subaction == "list":
            ban.print_bans()
        elif args.fw_subaction == "sync":
            ban.sync_bans()
        elif args.fw_subaction == "import":
            ban.import_ban_list(args.file)
        elif args.fw_subaction == "export":
            ban.export_ban_list(args.file)
        elif args.fw_subaction == "migrate":
            ban.migrate_banned_ips()
        elif args.fw_subaction == "scan":
            found = ban.scan_for_ban_files()
            if found:
                print("Found ban list files:")
                for f in found:
                    print(f"  {f}")
            else:
                print("No ban list files found")

    elif args.fw_action == "rules":
        if args.fw_subaction == "apply":
            rules.apply_rules()
        elif args.fw_subaction == "clear":
            rules.clear_rules()
        elif args.fw_subaction == "save":
            rules.create_apply_script()
            rules.create_remove_script()
        elif args.fw_subaction == "show":
            loaded = rules.load_rules()
            if loaded:
                print(f"\nRules from {rules.RULES_FILE}:\n")
                for r in loaded:
                    print(f"  {r}")
            else:
                print("No rules configured")

    elif args.fw_action == "service":
        if args.fw_subaction == "setup":
            subnets = args.subnets.split(",") if args.subnets else None
            rules.setup_firewall_service(args.ext_interface, subnets)
        elif args.fw_subaction == "enable":
            rules.enable_firewall_service()
        elif args.fw_subaction == "restart":
            rules.restart_firewall_service()
        elif args.fw_subaction == "status":
            s = rules.firewall_service_status()
            print(f"\nFirewall Service Status:")
            print(f"  Active: {'Yes' if s['active'] else 'No'}")
            print(f"  Enabled: {'Yes' if s['enabled'] else 'No'}")
            print(f"  Service file: {'Exists' if s['service_exists'] else 'Missing'}")
            print(f"  Rules file: {'Exists' if s['rules_file_exists'] else 'Missing'}")


def cmd_backup(args):
    """Handle backup commands."""
    from src.backup import create, restore

    if args.backup_action == "create":
        create.create_backup(args.name)
    elif args.backup_action == "restore":
        restore.restore_backup(args.file, args.dry_run)
    elif args.backup_action == "list":
        restore.print_backups()
    elif args.backup_action == "show":
        restore.show_backup_contents(args.file)
    elif args.backup_action == "delete":
        restore.delete_backup(args.file)


def cmd_init(args):
    """Handle init/setup commands."""
    from src.system import setup, install

    if args.init_action == "server":
        setup.init_server(
            interface=args.interface,
            port=args.port,
            subnet=args.subnet,
            address=args.address,
            dns=args.dns,
            mtu=args.mtu,
            external_interface=args.ext_interface,
        )
    elif args.init_action == "install":
        install.install_wireguard()


def cmd_diagnostics(args):
    """Handle diagnostics commands."""
    from src.system import diagnostics

    if args.diag_action == "run":
        diagnostics.run_diagnostics()
    elif args.diag_action == "test":
        diagnostics.test_connectivity(args.ip)
    elif args.diag_action == "logs":
        diagnostics.view_logs(args.lines)
    elif args.diag_action == "check":
        diagnostics.check_config_syntax(args.interface)


def main():
    parser = argparse.ArgumentParser(
        description="WireGuard Manager CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s peer add myphone
  %(prog)s peer add --router openwrt --subnets 10.0.4.0/24,172.16.1.0/24
  %(prog)s peer list
  %(prog)s peer qr myphone
  %(prog)s service status
  %(prog)s fw nat add --source 10.10.20.0/24
  %(prog)s fw port add --external 80 --internal-ip 10.0.4.246
  %(prog)s backup create
"""
    )

    parser.add_argument("--version", action="version", version=f"wg-manager {get_version()}")

    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # ============ PEER COMMANDS ============
    peer_parser = subparsers.add_parser("peer", help="Manage peers")
    peer_sub = peer_parser.add_subparsers(dest="peer_action")

    # peer add
    peer_add = peer_sub.add_parser("add", help="Add a peer")
    peer_add.add_argument("name", help="Peer name")
    peer_add.add_argument("-i", "--interface", default="wg0", help="WireGuard interface")
    peer_add.add_argument("--ip", help="Assign specific IP")
    peer_add.add_argument("--dns", help="DNS servers for peer")
    peer_add.add_argument("--keepalive", type=int, help="PersistentKeepalive value")
    peer_add.add_argument("--allowed-ips", help="AllowedIPs for peer config")
    peer_add.add_argument("--router", action="store_true", help="Create router peer")
    peer_add.add_argument("--subnets", help="Subnets for router peer (comma-separated)")

    # peer remove
    peer_rm = peer_sub.add_parser("remove", help="Remove a peer")
    peer_rm.add_argument("name", help="Peer name")
    peer_rm.add_argument("-i", "--interface", default="wg0")

    # peer list
    peer_list = peer_sub.add_parser("list", help="List peers")
    peer_list.add_argument("-i", "--interface", default="wg0")

    # peer show
    peer_show = peer_sub.add_parser("show", help="Show peer details")
    peer_show.add_argument("name", help="Peer name")
    peer_show.add_argument("-i", "--interface", default="wg0")

    # peer qr
    peer_qr = peer_sub.add_parser("qr", help="Show QR code for peer")
    peer_qr.add_argument("name", help="Peer name")

    # peer config
    peer_cfg = peer_sub.add_parser("config", help="Show peer configuration")
    peer_cfg.add_argument("name", help="Peer name")

    # peer scan
    peer_sub.add_parser("scan", help="Scan directories for peer configs")

    # peer dirs
    peer_dirs = peer_sub.add_parser("dirs", help="Manage peer directories")
    peer_dirs_sub = peer_dirs.add_subparsers(dest="dirs_subaction")
    peer_dirs_sub.add_parser("list", help="List directories")
    peer_dirs_add = peer_dirs_sub.add_parser("add", help="Add directory")
    peer_dirs_add.add_argument("directory", help="Directory path")
    peer_dirs_rm = peer_dirs_sub.add_parser("remove", help="Remove directory")
    peer_dirs_rm.add_argument("directory", help="Directory path")

    # ============ SERVICE COMMANDS ============
    svc_parser = subparsers.add_parser("service", help="Manage WireGuard service")
    svc_sub = svc_parser.add_subparsers(dest="service_action")

    for action in ["start", "stop", "restart", "reload", "enable", "disable", "status"]:
        p = svc_sub.add_parser(action, help=f"{action.capitalize()} WireGuard")
        p.add_argument("-i", "--interface", default="wg0")

    # ============ FIREWALL COMMANDS ============
    fw_parser = subparsers.add_parser("fw", help="Manage firewall rules")
    fw_sub = fw_parser.add_subparsers(dest="fw_action")

    # fw status
    fw_sub.add_parser("status", help="Show firewall status")

    # fw nat
    fw_nat = fw_sub.add_parser("nat", help="Manage NAT rules")
    fw_nat_sub = fw_nat.add_subparsers(dest="fw_subaction")

    fw_nat_add = fw_nat_sub.add_parser("add", help="Add NAT rule")
    fw_nat_add.add_argument("--source", "-s", required=True, help="Source subnet")
    fw_nat_add.add_argument("--ext-interface", "-o", default="eth0", help="External interface")
    fw_nat_add.add_argument("--no-masquerade", action="store_true", help="Use ACCEPT instead of MASQUERADE")

    fw_nat_rm = fw_nat_sub.add_parser("remove", help="Remove NAT rule")
    fw_nat_rm.add_argument("--source", "-s", required=True)
    fw_nat_rm.add_argument("--ext-interface", "-o", default="eth0")

    fw_nat_sub.add_parser("list", help="List NAT rules")

    # fw forward
    fw_fwd = fw_sub.add_parser("forward", help="Manage FORWARD rules")
    fw_fwd_sub = fw_fwd.add_subparsers(dest="fw_subaction")

    fw_fwd_add = fw_fwd_sub.add_parser("add", help="Add FORWARD rule")
    fw_fwd_add.add_argument("--in-interface", "-i", help="Input interface")
    fw_fwd_add.add_argument("--out-interface", "-o", help="Output interface")
    fw_fwd_add.add_argument("--source", "-s", help="Source address")
    fw_fwd_add.add_argument("--dest", "-d", help="Destination address")
    fw_fwd_add.add_argument("--protocol", "-p", help="Protocol (tcp/udp)")
    fw_fwd_add.add_argument("--dport", help="Destination port(s)")

    fw_fwd_rm = fw_fwd_sub.add_parser("remove", help="Remove FORWARD rule by number")
    fw_fwd_rm.add_argument("rule_num", help="Rule number")

    fw_fwd_sub.add_parser("list", help="List FORWARD rules")

    # fw port
    fw_port = fw_sub.add_parser("port", help="Manage port forwarding")
    fw_port_sub = fw_port.add_subparsers(dest="fw_subaction")

    fw_port_add = fw_port_sub.add_parser("add", help="Add port forward")
    fw_port_add.add_argument("--external", "-e", dest="external_port", required=True, help="External port(s)")
    fw_port_add.add_argument("--internal-ip", "-d", required=True, help="Internal destination IP")
    fw_port_add.add_argument("--internal-port", help="Internal port (defaults to external)")
    fw_port_add.add_argument("--protocol", "-p", default="tcp", help="Protocol (tcp/udp)")
    fw_port_add.add_argument("--ext-interface", "-i", default="eth0", help="External interface")
    fw_port_add.add_argument("--snat", help="SNAT source IP (for WebRTC etc)")

    fw_port_rm = fw_port_sub.add_parser("remove", help="Remove port forward")
    fw_port_rm.add_argument("--external", "-e", dest="external_port", required=True)
    fw_port_rm.add_argument("--internal-ip", "-d", required=True)
    fw_port_rm.add_argument("--protocol", "-p", default="tcp")
    fw_port_rm.add_argument("--ext-interface", "-i", default="eth0")

    fw_port_sub.add_parser("list", help="List port forwards")

    # fw ban
    fw_ban = fw_sub.add_parser("ban", help="Manage banned IPs")
    fw_ban_sub = fw_ban.add_subparsers(dest="fw_subaction")

    fw_ban_add = fw_ban_sub.add_parser("add", help="Ban an IP")
    fw_ban_add.add_argument("ip", help="IP to ban")
    fw_ban_add.add_argument("--reason", "-r", help="Reason for ban")

    fw_ban_rm = fw_ban_sub.add_parser("remove", help="Unban an IP")
    fw_ban_rm.add_argument("ip", help="IP to unban")

    fw_ban_sub.add_parser("list", help="List banned IPs")
    fw_ban_sub.add_parser("sync", help="Sync banned IPs to iptables")
    fw_ban_sub.add_parser("migrate", help="Migrate old banned_ips.txt format")
    fw_ban_sub.add_parser("scan", help="Scan for ban list files")

    fw_ban_import = fw_ban_sub.add_parser("import", help="Import ban list from file")
    fw_ban_import.add_argument("file", help="File to import")

    fw_ban_export = fw_ban_sub.add_parser("export", help="Export ban list to file")
    fw_ban_export.add_argument("file", help="File to export to")

    # fw rules
    fw_rules = fw_sub.add_parser("rules", help="Manage saved rules")
    fw_rules_sub = fw_rules.add_subparsers(dest="fw_subaction")
    fw_rules_sub.add_parser("apply", help="Apply rules from file")
    fw_rules_sub.add_parser("clear", help="Clear all iptables rules")
    fw_rules_sub.add_parser("save", help="Save current rules to scripts")
    fw_rules_sub.add_parser("show", help="Show saved rules")

    # fw service
    fw_svc = fw_sub.add_parser("service", help="Manage firewall systemd service")
    fw_svc_sub = fw_svc.add_subparsers(dest="fw_subaction")

    fw_svc_setup = fw_svc_sub.add_parser("setup", help="Setup firewall service")
    fw_svc_setup.add_argument("--ext-interface", "-o", default="eth0", help="External interface")
    fw_svc_setup.add_argument("--subnets", help="WireGuard subnets (comma-separated)")

    fw_svc_sub.add_parser("enable", help="Enable and start firewall service")
    fw_svc_sub.add_parser("restart", help="Restart firewall service")
    fw_svc_sub.add_parser("status", help="Show firewall service status")

    # ============ BACKUP COMMANDS ============
    bkp_parser = subparsers.add_parser("backup", help="Manage backups")
    bkp_sub = bkp_parser.add_subparsers(dest="backup_action")

    bkp_create = bkp_sub.add_parser("create", help="Create backup")
    bkp_create.add_argument("--name", "-n", help="Backup name")

    bkp_restore = bkp_sub.add_parser("restore", help="Restore backup")
    bkp_restore.add_argument("file", nargs="?", help="Backup file")
    bkp_restore.add_argument("--dry-run", action="store_true", help="Show what would be restored")

    bkp_sub.add_parser("list", help="List backups")

    bkp_show = bkp_sub.add_parser("show", help="Show backup contents")
    bkp_show.add_argument("file", help="Backup file")

    bkp_del = bkp_sub.add_parser("delete", help="Delete backup")
    bkp_del.add_argument("file", help="Backup file")

    # ============ INIT COMMANDS ============
    init_parser = subparsers.add_parser("init", help="Initialize/setup")
    init_sub = init_parser.add_subparsers(dest="init_action")

    init_srv = init_sub.add_parser("server", help="Initialize server configuration")
    init_srv.add_argument("-i", "--interface", default="wg0")
    init_srv.add_argument("--port", type=int, help="Listen port")
    init_srv.add_argument("--subnet", help="Server subnet")
    init_srv.add_argument("--address", help="Server address")
    init_srv.add_argument("--dns", help="DNS servers")
    init_srv.add_argument("--mtu", type=int, help="MTU")
    init_srv.add_argument("--ext-interface", default="eth0", help="External interface")

    init_sub.add_parser("install", help="Install WireGuard")

    # ============ DIAGNOSTICS COMMANDS ============
    diag_parser = subparsers.add_parser("diag", help="Diagnostics")
    diag_sub = diag_parser.add_subparsers(dest="diag_action")

    diag_sub.add_parser("run", help="Run diagnostics")

    diag_test = diag_sub.add_parser("test", help="Test connectivity")
    diag_test.add_argument("--ip", help="Specific IP to test")

    diag_logs = diag_sub.add_parser("logs", help="View logs")
    diag_logs.add_argument("--lines", "-n", type=int, default=50, help="Number of lines")

    diag_check = diag_sub.add_parser("check", help="Check config syntax")
    diag_check.add_argument("-i", "--interface", default="wg0")

    # Parse arguments
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    # Most commands need root
    if args.command not in ["--help", "-h"]:
        require_root()

    # Dispatch to command handler
    handlers = {
        "peer": cmd_peer,
        "service": cmd_service,
        "fw": cmd_firewall,
        "backup": cmd_backup,
        "init": cmd_init,
        "diag": cmd_diagnostics,
    }

    handler = handlers.get(args.command)
    if handler:
        handler(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
