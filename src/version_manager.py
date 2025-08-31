#!/usr/bin/env python3
"""
Version and Update Manager for WireGuard Manager
"""

import os
import sys
import subprocess
import shutil
import tempfile
import json
from pathlib import Path
from datetime import datetime
from menu import MenuHandler
from utils import run_command, pause, print_status, clear_screen, print_header

class VersionManager:
    """Manage versions and updates for WireGuard Manager"""
    
    def __init__(self):
        self.menu = MenuHandler()
        self.version = self._get_current_version()
        self.install_dir = self._find_install_dir()
        self.repo_url = "https://github.com/regix1/wireguard-manager.git"
    
    def _get_current_version(self) -> str:
        """Get current version from VERSION file"""
        version_file = Path(__file__).parent.parent / "VERSION"
        if version_file.exists():
            return version_file.read_text().strip()
        return "unknown"
    
    def _find_install_dir(self) -> Path:
        """Find where the manager is installed"""
        # Check common locations
        locations = [
            Path.home() / "wireguard-manager",
            Path("/opt/wireguard-manager"),
            Path("/usr/local/wireguard-manager"),
            Path.cwd()
        ]
        
        for loc in locations:
            if loc.exists() and (loc / "run.py").exists():
                return loc
        
        # Default to current directory
        return Path.cwd()
    
    def check_for_updates(self):
        """Check if updates are available"""
        print("\n[Checking for Updates]")
        print("-" * 50)
        print(f"Current version: {self.version}")
        
        try:
            # Try to fetch latest version from GitHub
            print("\nChecking GitHub for updates...")
            
            # Get latest version tag
            result = run_command([
                "git", "ls-remote", "--tags", self.repo_url
            ], check=False)
            
            if result.returncode == 0:
                tags = result.stdout.strip().split('\n')
                versions = []
                for tag in tags:
                    if 'refs/tags/v' in tag:
                        version = tag.split('refs/tags/v')[-1]
                        versions.append(version)
                
                if versions:
                    latest = sorted(versions)[-1]
                    print(f"Latest version:  {latest}")
                    
                    if latest != self.version:
                        print("\n✓ Update available!")
                        if self.menu.confirm("Update now?"):
                            self.update_manager()
                    else:
                        print("\n✓ Already up to date")
                else:
                    print("Could not determine latest version")
            else:
                print("Could not connect to GitHub")
        
        except Exception as e:
            print(f"Error checking for updates: {e}")
        
        pause()
    
    def update_manager(self):
        """Update WireGuard Manager to latest version"""
        print("\n[Updating WireGuard Manager]")
        print("-" * 50)
        
        # Check if we're in a git repository
        if (self.install_dir / ".git").exists():
            self._update_from_git()
        else:
            self._update_from_download()
    
    def _update_from_git(self):
        """Update using git pull"""
        print("Updating from git repository...")
        
        try:
            # Stash any local changes
            run_command(["git", "stash"], cwd=self.install_dir, check=False)
            
            # Pull latest changes
            result = run_command(["git", "pull", "origin", "main"], 
                               cwd=self.install_dir, check=False)
            
            if result.returncode != 0:
                # Try master branch
                result = run_command(["git", "pull", "origin", "master"], 
                                   cwd=self.install_dir, check=False)
            
            if result.returncode == 0:
                print_status("Update successful", True)
                
                # Update dependencies
                print("\nUpdating dependencies...")
                run_command([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"], 
                          cwd=self.install_dir)
                
                print_status("Dependencies updated", True)
                print("\nPlease restart the application for changes to take effect.")
            else:
                print_status("Update failed", False)
                print("Please update manually or reinstall.")
        
        except Exception as e:
            print(f"Error updating: {e}")
        
        pause()
    
    def _update_from_download(self):
        """Update by downloading fresh copy"""
        print("Downloading latest version...")
        
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            
            try:
                # Clone repository to temp directory
                result = run_command([
                    "git", "clone", self.repo_url, str(tmp_path / "wireguard-manager")
                ])
                
                if result.returncode == 0:
                    # Backup current installation
                    backup_dir = self.install_dir.parent / f"wireguard-manager-backup-{datetime.now():%Y%m%d-%H%M%S}"
                    print(f"\nBacking up to {backup_dir}")
                    shutil.copytree(self.install_dir, backup_dir)
                    
                    # Copy new files
                    new_dir = tmp_path / "wireguard-manager"
                    
                    # Preserve user data
                    preserved_files = ["data/defaults.json"]
                    for file in preserved_files:
                        src = self.install_dir / file
                        if src.exists():
                            dst = new_dir / file
                            dst.parent.mkdir(parents=True, exist_ok=True)
                            shutil.copy2(src, dst)
                    
                    # Replace installation
                    shutil.rmtree(self.install_dir)
                    shutil.copytree(new_dir, self.install_dir)
                    
                    print_status("Update successful", True)
                    print("\nPlease restart the application.")
                else:
                    print_status("Download failed", False)
            
            except Exception as e:
                print(f"Error: {e}")
        
        pause()
    
    def install_manager(self):
        """Install WireGuard Manager system-wide"""
        print("\n[Installing WireGuard Manager]")
        print("-" * 50)
        
        # Create installation script
        install_script = """#!/bin/bash
# WireGuard Manager Installation

INSTALL_DIR="/opt/wireguard-manager"
BIN_PATH="/usr/local/bin/wg-manager"

echo "Installing WireGuard Manager..."

# Copy files
if [ -d "$INSTALL_DIR" ]; then
    echo "Backing up existing installation..."
    mv "$INSTALL_DIR" "${INSTALL_DIR}.backup.$(date +%Y%m%d-%H%M%S)"
fi

cp -r . "$INSTALL_DIR"

# Create executable
cat > "$BIN_PATH" << 'EOF'
#!/bin/bash
cd /opt/wireguard-manager
python3 run.py "$@"
EOF

chmod +x "$BIN_PATH"

# Install dependencies
pip3 install -r "$INSTALL_DIR/requirements.txt"

echo "✓ Installation complete!"
echo "Run 'wg-manager' to start"
"""
        
        try:
            # Write and execute install script
            script_file = Path("/tmp/install_wg_manager.sh")
            script_file.write_text(install_script)
            script_file.chmod(0o755)
            
            run_command(["bash", str(script_file)])
            
            print_status("Installation complete", True)
            print("\nYou can now run 'wg-manager' from anywhere")
        
        except Exception as e:
            print(f"Installation failed: {e}")
        
        pause()
    
    def uninstall_manager(self):
        """Uninstall WireGuard Manager"""
        print("\n[Uninstall WireGuard Manager]")
        print("-" * 50)
        print("\nThis will remove WireGuard Manager from your system.")
        print("Your WireGuard configurations will be preserved.")
        
        if not self.menu.confirm("Are you sure you want to uninstall?"):
            print("Uninstall cancelled")
            pause()
            return
        
        try:
            # Remove system-wide installation
            if Path("/opt/wireguard-manager").exists():
                shutil.rmtree("/opt/wireguard-manager")
                print("✓ Removed /opt/wireguard-manager")
            
            if Path("/usr/local/bin/wg-manager").exists():
                Path("/usr/local/bin/wg-manager").unlink()
                print("✓ Removed /usr/local/bin/wg-manager")
            
            # Ask about local installation
            if self.install_dir.exists() and self.install_dir != Path("/opt/wireguard-manager"):
                if self.menu.confirm(f"Remove local installation at {self.install_dir}?"):
                    shutil.rmtree(self.install_dir)
                    print(f"✓ Removed {self.install_dir}")
            
            print_status("Uninstall complete", True)
            print("\nWireGuard Manager has been removed.")
            print("Your WireGuard configurations are still in /etc/wireguard/")
            
            pause()
            sys.exit(0)
        
        except Exception as e:
            print(f"Uninstall failed: {e}")
            pause()
    
    def show_version_info(self):
        """Show version and system information"""
        clear_screen()
        print_header()
        
        print("[Version Information]")
        print("-" * 50)
        print(f"WireGuard Manager Version: {self.version}")
        print(f"Installation Directory: {self.install_dir}")
        print(f"Python Version: {sys.version.split()[0]}")
        
        # Check WireGuard version
        result = run_command(["wg", "--version"], check=False)
        if result.returncode == 0:
            wg_version = result.stdout.strip()
            print(f"WireGuard Version: {wg_version}")
        
        print("\n[System Information]")
        print("-" * 50)
        
        # OS information
        if Path("/etc/os-release").exists():
            with open("/etc/os-release") as f:
                for line in f:
                    if line.startswith("PRETTY_NAME"):
                        os_name = line.split("=")[1].strip().strip('"')
                        print(f"Operating System: {os_name}")
                        break
        
        # Kernel version
        result = run_command(["uname", "-r"], check=False)
        if result.returncode == 0:
            print(f"Kernel: {result.stdout.strip()}")
        
        pause()