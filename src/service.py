#!/usr/bin/env python3
"""
WireGuard Service Manager
"""

from typing import List, Dict
from menu import MenuHandler
from utils import run_command, pause, print_status

class ServiceManager:
    """Manage WireGuard services"""
    
    def __init__(self, config_scanner):
        self.scanner = config_scanner
        self.menu = MenuHandler()
    
    def get_status(self) -> Dict:
        """Get service status"""
        status = {
            "interfaces": self.scanner.get_interfaces(),
            "active_interfaces": []
        }
        
        # Get active interfaces
        result = run_command(["wg", "show", "interfaces"], check=False)
        if result.returncode == 0:
            status["active_interfaces"] = result.stdout.strip().split()
        
        return status
    
    def show_status(self):
        """Show detailed status"""
        print("\n[WireGuard Status]")
        print("-" * 50)
        
        status = self.get_status()
        
        # Show detected config directories
        if self.scanner.detected_paths:
            print("\nConfig Directories Found:")
            for path in self.scanner.detected_paths:
                print(f"  • {path}")
        
        # Show interfaces
        print(f"\nConfigured Interfaces: {', '.join(status['interfaces']) if status['interfaces'] else 'None'}")
        print(f"Active Interfaces: {', '.join(status['active_interfaces']) if status['active_interfaces'] else 'None'}")
        
        # Show detailed info for active interfaces
        if status["active_interfaces"]:
            print("\n[Interface Details]")
            for interface in status["active_interfaces"]:
                self._show_interface_details(interface)
        
        # System info
        self._show_system_info()
        
        pause()
    
    def start(self):
        """Start WireGuard interface"""
        interfaces = self.scanner.get_interfaces()
        
        if not interfaces:
            print("\nNo WireGuard interfaces configured!")
            print("Please configure an interface first.")
            pause()
            return
        
        # Select interface
        interface = self._select_interface(interfaces, "Select interface to start:")
        if not interface:
            return
        
        print(f"\nStarting {interface}...")
        result = run_command(["systemctl", "start", f"wg-quick@{interface}"])
        
        if result.returncode == 0:
            print_status(f"{interface} started", True)
            run_command(["systemctl", "enable", f"wg-quick@{interface}"], check=False)
        else:
            print_status(f"Failed to start {interface}", False)
        
        pause()
    
    def stop(self):
        """Stop WireGuard interface"""
        status = self.get_status()
        
        if not status["active_interfaces"]:
            print("\nNo active WireGuard interfaces")
            pause()
            return
        
        # Select interface
        interface = self._select_interface(status["active_interfaces"], "Select interface to stop:")
        if not interface:
            return
        
        print(f"\nStopping {interface}...")
        result = run_command(["systemctl", "stop", f"wg-quick@{interface}"])
        
        if result.returncode == 0:
            print_status(f"{interface} stopped", True)
        else:
            print_status(f"Failed to stop {interface}", False)
        
        pause()
    
    def restart(self):
        """Restart WireGuard interface"""
        interfaces = self.scanner.get_interfaces()
        
        if not interfaces:
            print("\nNo WireGuard interfaces configured!")
            pause()
            return
        
        # Select interface
        interface = self._select_interface(interfaces, "Select interface to restart:")
        if not interface:
            return
        
        print(f"\nRestarting {interface}...")
        result = run_command(["systemctl", "restart", f"wg-quick@{interface}"])
        
        if result.returncode == 0:
            print_status(f"{interface} restarted", True)
        else:
            print_status(f"Failed to restart {interface}", False)
        
        pause()
    
    def _select_interface(self, interfaces: List[str], title: str) -> str:
        """Select an interface from list"""
        if len(interfaces) == 1:
            return interfaces[0]
        
        choice = self.menu.show_menu(interfaces, title)
        if choice is None:
            return None
        
        return interfaces[choice]
    
    def _show_interface_details(self, interface: str):
        """Show details for a specific interface"""
        print(f"\n{interface}:")
        
        result = run_command(["wg", "show", interface], check=False)
        if result.returncode == 0:
            lines = result.stdout.strip().split('\n')
            for line in lines[:8]:  # Show first 8 lines
                if line.strip() and not line.startswith("private key"):
                    print(f"  {line}")
    
    def _show_system_info(self):
        """Show system information"""
        print("\n[System Info]")
        
        # IP forwarding
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "r") as f:
                ip_forward = f.read().strip()
            print(f"IP Forwarding: {'Enabled' if ip_forward == '1' else 'Disabled'}")
        except:
            pass
        
        # Firewall rules count
        result = run_command(["iptables", "-L", "-n"], check=False)
        if result.returncode == 0:
            rule_count = len(result.stdout.strip().split('\n'))
            print(f"Firewall Rules: {rule_count} lines")