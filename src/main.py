#!/usr/bin/env python3
"""
Main WireGuard Manager Application
"""

from menu import MenuHandler
from config_scanner import ConfigScanner
from installer import Installer
from service import ServiceManager
from peer_manager import PeerManager
from version_manager import VersionManager
from utils import clear_screen, print_header

class WireGuardManager:
    """Main application class"""
    
    def __init__(self):
        self.scanner = ConfigScanner()
        self.installer = Installer()
        self.service = ServiceManager(self.scanner)
        self.peers = PeerManager(self.scanner)
        self.version = VersionManager()
        self.menu = MenuHandler()
        
    def run(self):
        """Main application loop"""
        while True:
            clear_screen()
            print_header()
            
            # Show version in header
            print(f"Version {self.version.version}")
            print()
            
            # Check installation status
            if not self.installer.is_installed():
                options = [
                    "Install WireGuard",
                    "Install This Manager", 
                    "Exit"
                ]
            else:
                options = [
                    "Show Status",
                    "Start WireGuard",
                    "Stop WireGuard", 
                    "Restart WireGuard",
                    "───────────────────",  # Separator
                    "Add Peer",
                    "Remove Peer",
                    "List Peers",
                    "───────────────────",  # Separator
                    "Backup Configuration",
                    "Restore Configuration",
                    "───────────────────",  # Separator
                    "Install WireGuard",
                    "Uninstall WireGuard",
                    "───────────────────",  # Separator
                    "Check for Updates",
                    "Install This Manager",
                    "Uninstall This Manager",
                    "Version Info",
                    "───────────────────",  # Separator
                    "Exit"
                ]
            
            choice = self.menu.show_menu(options, "WireGuard Manager")
            
            if choice is None or options[choice] == "Exit":
                print("\nGoodbye!")
                break
            
            # Skip separators
            if options[choice].startswith("─"):
                continue
            
            self._handle_choice(options[choice])
    
    def _handle_choice(self, choice: str):
        """Handle menu choice"""
        actions = {
            # WireGuard Management
            "Install WireGuard": self.installer.install,
            "Uninstall WireGuard": self.installer.uninstall,
            "Show Status": self.service.show_status,
            "Start WireGuard": self.service.start,
            "Stop WireGuard": self.service.stop,
            "Restart WireGuard": self.service.restart,
            
            # Peer Management
            "Add Peer": self.peers.add_peer,
            "Remove Peer": self.peers.remove_peer,
            "List Peers": self.peers.list_peers,
            
            # Configuration Management
            "Backup Configuration": self.peers.backup_config,
            "Restore Configuration": self.peers.restore_config,
            
            # Manager Management
            "Check for Updates": self.version.check_for_updates,
            "Install This Manager": self.version.install_manager,
            "Uninstall This Manager": self.version.uninstall_manager,
            "Version Info": self.version.show_version_info
        }
        
        action = actions.get(choice)
        if action:
            action()