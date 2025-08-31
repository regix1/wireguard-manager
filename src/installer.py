#!/usr/bin/env python3
"""
WireGuard Installer/Uninstaller
"""

import os
import shutil
import subprocess
from pathlib import Path
from datetime import datetime
from utils import run_command, pause

class Installer:
    """Handle WireGuard installation and removal"""
    
    def is_installed(self) -> bool:
        """Check if WireGuard is installed"""
        return shutil.which("wg") is not None
    
    def install(self):
        """Install WireGuard"""
        print("\n[Installing WireGuard]")
        print("-" * 50)
        
        if self.is_installed():
            print("WireGuard is already installed!")
            pause()
            return
        
        # Detect OS
        os_type = self._detect_os()
        
        if os_type == "debian":
            self._install_debian()
        elif os_type == "redhat":
            self._install_redhat()
        else:
            print("Unsupported OS. Please install WireGuard manually.")
            print("Visit: https://www.wireguard.com/install/")
            pause()
    
    def uninstall(self):
        """Uninstall WireGuard"""
        print("\n[Uninstalling WireGuard]")
        print("-" * 50)
        
        if not self.is_installed():
            print("WireGuard is not installed!")
            pause()
            return
        
        # Confirm
        confirm = input("This will remove WireGuard. Are you sure? (yes/N): ")
        if confirm.lower() != "yes":
            print("Cancelled")
            pause()
            return
        
        # Stop all interfaces
        self._stop_all_interfaces()
        
        # Backup configurations
        self._backup_configs()
        
        # Remove packages
        os_type = self._detect_os()
        if os_type == "debian":
            self._uninstall_debian()
        elif os_type == "redhat":
            self._uninstall_redhat()
        
        print("✓ WireGuard uninstalled successfully")
        pause()
    
    def _detect_os(self) -> str:
        """Detect operating system type"""
        if os.path.exists("/etc/debian_version"):
            return "debian"
        elif os.path.exists("/etc/redhat-release"):
            return "redhat"
        else:
            return "unknown"
    
    def _install_debian(self):
        """Install on Debian/Ubuntu"""
        print("Detected Debian/Ubuntu system")
        
        print("Updating package lists...")
        run_command(["apt-get", "update"])
        
        print("Installing WireGuard...")
        run_command(["apt-get", "install", "-y", "wireguard", "wireguard-tools", "qrencode"])
        
        self._configure_system()
        print("✓ WireGuard installed successfully")
    
    def _install_redhat(self):
        """Install on RedHat/CentOS"""
        print("Detected RedHat/CentOS system")
        
        print("Installing EPEL repository...")
        run_command(["yum", "install", "-y", "epel-release"])
        
        print("Installing WireGuard...")
        run_command(["yum", "install", "-y", "wireguard-tools", "qrencode"])
        
        self._configure_system()
        print("✓ WireGuard installed successfully")
    
    def _configure_system(self):
        """Configure system settings"""
        print("Configuring system...")
        
        # Enable IP forwarding
        sysctl_conf = "/etc/sysctl.conf"
        with open(sysctl_conf, "r") as f:
            content = f.read()
        
        if "net.ipv4.ip_forward=1" not in content:
            with open(sysctl_conf, "a") as f:
                f.write("\n# Enable IP forwarding for WireGuard\n")
                f.write("net.ipv4.ip_forward=1\n")
        
        run_command(["sysctl", "-p"], check=False)
        
        # Create config directory
        config_dir = Path("/etc/wireguard")
        config_dir.mkdir(parents=True, exist_ok=True)
        
        print("✓ System configured")
    
    def _stop_all_interfaces(self):
        """Stop all WireGuard interfaces"""
        print("Stopping WireGuard interfaces...")
        
        result = run_command(["wg", "show", "interfaces"], check=False)
        if result.returncode == 0:
            interfaces = result.stdout.strip().split()
            for interface in interfaces:
                run_command(["systemctl", "stop", f"wg-quick@{interface}"], check=False)
                run_command(["systemctl", "disable", f"wg-quick@{interface}"], check=False)
    
    def _backup_configs(self):
        """Backup configurations before uninstall"""
        config_dir = Path("/etc/wireguard")
        if config_dir.exists() and list(config_dir.glob("*.conf")):
            backup_dir = Path.home() / f"wireguard-backup-{datetime.now():%Y%m%d-%H%M%S}"
            print(f"Backing up configs to {backup_dir}...")
            shutil.copytree(config_dir, backup_dir)
            print(f"✓ Configs backed up to {backup_dir}")
    
    def _uninstall_debian(self):
        """Uninstall from Debian/Ubuntu"""
        print("Removing WireGuard packages...")
        run_command(["apt-get", "remove", "-y", "wireguard", "wireguard-tools"])
        run_command(["apt-get", "autoremove", "-y"])
    
    def _uninstall_redhat(self):
        """Uninstall from RedHat/CentOS"""
        print("Removing WireGuard packages...")
        run_command(["yum", "remove", "-y", "wireguard-tools"])