#!/usr/bin/env python3
"""
WireGuard Manager TUI - Main Entry Point
A comprehensive terminal UI tool for managing WireGuard VPN and firewall rules.
"""

import sys
import os
import argparse
import logging
from pathlib import Path

# Add the project root to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from tui.main_app import WireGuardManagerApp
from config.settings import Settings
from core.utils import check_root, setup_logging

def check_requirements():
    """Check if all system requirements are met."""
    errors = []
    
    # Check for root/sudo
    if not check_root():
        errors.append("This application must be run as root (sudo)")
    
    # Check for WireGuard
    if not os.path.exists('/usr/bin/wg'):
        errors.append("WireGuard tools not found. Install with: apt install wireguard-tools")
    
    # Check for iptables
    if not os.path.exists('/sbin/iptables'):
        errors.append("iptables not found. Install with: apt install iptables")
    
    return errors

def main():
    """Main application entry point."""
    parser = argparse.ArgumentParser(description='WireGuard Manager - Terminal UI Management Tool')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    parser.add_argument('--config-dir', type=str, help='Custom configuration directory')
    parser.add_argument('--no-check', action='store_true', help='Skip requirements check')
    parser.add_argument('--cli', action='store_true', help='Use simple CLI mode instead of TUI')
    
    # Quick actions for CLI mode
    parser.add_argument('--start-wg', action='store_true', help='Start WireGuard service')
    parser.add_argument('--stop-wg', action='store_true', help='Stop WireGuard service')
    parser.add_argument('--start-fw', action='store_true', help='Start firewall')
    parser.add_argument('--stop-fw', action='store_true', help='Stop firewall')
    parser.add_argument('--status', action='store_true', help='Show status')
    parser.add_argument('--add-peer', type=str, metavar='NAME', help='Add a new peer')
    parser.add_argument('--remove-peer', type=str, metavar='KEY', help='Remove a peer by public key')
    parser.add_argument('--ban-ip', type=str, metavar='IP', help='Ban an IP address')
    parser.add_argument('--unban-ip', type=str, metavar='IP', help='Unban an IP address')
    
    args = parser.parse_args()
    
    # Setup logging
    log_level = logging.DEBUG if args.debug else logging.INFO
    setup_logging(log_level)
    logger = logging.getLogger(__name__)
    
    # Load settings
    settings = Settings(config_dir=args.config_dir)
    
    # Check requirements unless skipped
    if not args.no_check:
        errors = check_requirements()
        if errors:
            from rich.console import Console
            console = Console()
            console.print("[bold red]Requirements Error:[/bold red]")
            for error in errors:
                console.print(f"  • {error}", style="red")
            sys.exit(1)
    
    try:
        # Handle CLI quick actions
        if args.cli or any([args.start_wg, args.stop_wg, args.start_fw, args.stop_fw, 
                            args.status, args.add_peer, args.remove_peer, 
                            args.ban_ip, args.unban_ip]):
            from tui.cli_mode import handle_cli_command
            return handle_cli_command(args, settings)
        
        # Run the TUI application
        logger.info("Starting WireGuard Manager TUI...")
        app = WireGuardManagerApp(settings)
        app.run()
        
    except KeyboardInterrupt:
        logger.info("Application interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        from rich.console import Console
        console = Console()
        console.print(f"[bold red]Fatal Error:[/bold red] {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    main()