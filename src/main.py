#!/usr/bin/env python3
"""Main WireGuard Manager Application"""

from menu import MenuHandler
from config_scanner import ConfigScanner
from installer import Installer
from service import ServiceManager
from peer_manager import PeerManager
from version_manager import VersionManager
from firewall_manager import FirewallManager
from utils import clear_screen, print_header
import sys

class WireGuardManager:
    """Main application class"""
    
    def __init__(self):
        self.scanner = ConfigScanner()
        self.installer = Installer()
        self.service = ServiceManager(self.scanner)
        self.peers = PeerManager(self.scanner)
        self.version = VersionManager()
        self.firewall = FirewallManager(self.scanner)
        self.menu = MenuHandler()
        
    def run(self):
        """Main application loop"""
        while True:
            clear_screen()
            self._show_header()
            
            # Check installation status
            if not self.installer.is_installed():
                options = [
                    "📦 Install WireGuard",
                    "🔧 Install This Manager", 
                    "❌ Exit"
                ]
            else:
                # Get current status
                status = self.service.get_status()
                active_interfaces = status.get('active_interfaces', [])
                
                options = [
                    f"📊 Show Status {self._status_indicator(active_interfaces)}",
                    "▶️  Start WireGuard",
                    "⏹️  Stop WireGuard", 
                    "🔄 Restart WireGuard",
                    "───────────────────",  # Service separator
                    "👥 Peer Management →",
                    "🔥 Firewall Management →",
                    "───────────────────",  # Management separator
                    "💾 Backup Configuration",
                    "📂 Restore Configuration",
                    "───────────────────",  # Config separator
                    "🔧 System & Updates →",
                    "───────────────────",  # System separator
                    "❌ Exit"
                ]
            
            choice = self.menu.show_menu(options, "🔐 WireGuard Manager v" + self.version.version)
            
            if choice is None or "Exit" in options[choice]:
                print("\n👋 Goodbye!")
                sys.exit(0)
            
            # Skip separators
            if options[choice].startswith("─"):
                continue
            
            self._handle_choice(options[choice])
    
    def _show_header(self):
        """Show enhanced header with status info."""
        print("=" * 60)
        print("       🔐 WireGuard VPN Manager")
        print("=" * 60)
        
        # Quick status line
        status = self.service.get_status()
        active = status.get('active_interfaces', [])
        if active:
            print(f"✅ Active: {', '.join(active)}")
        else:
            print("⚠️  No active interfaces")
        print("=" * 60)
    
    def _status_indicator(self, active_interfaces):
        """Get status indicator for menu."""
        if active_interfaces:
            return f"[✅ {len(active_interfaces)} active]"
        return "[⚠️  inactive]"
    
    def _handle_choice(self, choice: str):
        """Handle menu choice."""
        # Clean up the choice string
        choice_text = choice.split('[')[0].strip()
        
        if "Show Status" in choice_text:
            self.service.show_status()
        elif "Start WireGuard" in choice_text:
            self.service.start()
        elif "Stop WireGuard" in choice_text:
            self.service.stop()
        elif "Restart WireGuard" in choice_text:
            self.service.restart()
        elif "Peer Management" in choice_text:
            self._peer_management_menu()
        elif "Firewall Management" in choice_text:
            self.firewall.manage_firewall()
        elif "Backup Configuration" in choice_text:
            self.peers.backup_config()
        elif "Restore Configuration" in choice_text:
            self.peers.restore_config()
        elif "System & Updates" in choice_text:
            self._system_menu()
        elif "Install WireGuard" in choice_text:
            self.installer.install()
        elif "Install This Manager" in choice_text:
            self.version.install_manager()
    
    def _peer_management_menu(self):
        """Peer management submenu."""
        while True:
            clear_screen()
            print("=" * 60)
            print("       👥 Peer Management")
            print("=" * 60)
            
            options = [
                "➕ Add New Peer",
                "➖ Remove Peer",
                "📋 List All Peers",
                "🔑 Show Peer Config",
                "📱 Generate QR Code",
                "───────────────────",
                "◀️  Back to Main Menu"
            ]
            
            choice = self.menu.show_menu(options, "👥 Peer Management")
            
            if choice is None or "Back" in options[choice]:
                break
            
            if options[choice].startswith("─"):
                continue
            
            if "Add New Peer" in options[choice]:
                self.peers.add_peer()
            elif "Remove Peer" in options[choice]:
                self.peers.remove_peer()
            elif "List All Peers" in options[choice]:
                self.peers.list_peers()
            elif "Show Peer Config" in options[choice]:
                self.peers.show_peer_config()
            elif "Generate QR Code" in options[choice]:
                self.peers.generate_qr_code()
    
    def _system_menu(self):
        """System and updates submenu."""
        while True:
            clear_screen()
            print("=" * 60)
            print("       🔧 System & Updates")
            print("=" * 60)
            
            options = [
                "🔄 Check for Updates",
                "📦 Install WireGuard",
                "🗑️  Uninstall WireGuard",
                "───────────────────",
                "🔧 Install This Manager",
                "🗑️  Uninstall This Manager",
                "ℹ️  Version Info",
                "───────────────────",
                "◀️  Back to Main Menu"
            ]
            
            choice = self.menu.show_menu(options, "🔧 System & Updates")
            
            if choice is None or "Back" in options[choice]:
                break
            
            if options[choice].startswith("─"):
                continue
            
            if "Check for Updates" in options[choice]:
                self.version.check_for_updates()
            elif "Install WireGuard" in options[choice]:
                self.installer.install()
            elif "Uninstall WireGuard" in options[choice]:
                self.installer.uninstall()
            elif "Install This Manager" in options[choice]:
                self.version.install_manager()
            elif "Uninstall This Manager" in options[choice]:
                self.version.uninstall_manager()
            elif "Version Info" in options[choice]:
                self.version.show_version_info()

if __name__ == "__main__":
    # Check for root
    import os
    if os.geteuid() != 0:
        print("❌ This script must be run as root (use sudo)")
        sys.exit(1)
    
    # Run the manager
    manager = WireGuardManager()
    manager.run()