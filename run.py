#!/usr/bin/env python3
"""
WireGuard Manager - Main Entry Point
A comprehensive GUI tool for managing WireGuard VPN and firewall rules.
"""

import sys
import os
import argparse
import logging
from pathlib import Path

# Add the project root to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from PyQt6.QtWidgets import QApplication, QMessageBox
from PyQt6.QtCore import Qt
from gui.main_window import MainWindow
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
    parser = argparse.ArgumentParser(description='WireGuard Manager - GUI Management Tool')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    parser.add_argument('--config-dir', type=str, help='Custom configuration directory')
    parser.add_argument('--no-check', action='store_true', help='Skip requirements check')
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
            app = QApplication(sys.argv)
            QMessageBox.critical(None, "Requirements Error", 
                               "The following requirements are not met:\n\n" + 
                               "\n".join(f"• {error}" for error in errors))
            sys.exit(1)
    
    # Create Qt application
    app = QApplication(sys.argv)
    app.setApplicationName("WireGuard Manager")
    app.setOrganizationName("WireGuard Tools")
    
    # Set application style
    app.setStyle('Fusion')
    
    # Enable high DPI support
    app.setAttribute(Qt.ApplicationAttribute.AA_UseHighDpiPixmaps, True)
    
    try:
        # Create and show main window
        logger.info("Starting WireGuard Manager...")
        window = MainWindow(settings)
        window.show()
        
        # Run the application
        sys.exit(app.exec())
        
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        QMessageBox.critical(None, "Fatal Error", 
                           f"An unexpected error occurred:\n{str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    main()