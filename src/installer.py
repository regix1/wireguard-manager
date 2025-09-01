"""WireGuard and Manager installation/updates."""

import os
import sys
import shutil
import subprocess
import tempfile
import requests
from pathlib import Path
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.prompt import Prompt

from .constants import APP_VERSION, WIREGUARD_DIR, BACKUP_DIR
from .utils import run_command, check_wireguard_installed, enable_ip_forwarding, prompt_yes_no

console = Console()

class WireGuardInstaller:
    """Handle WireGuard and Manager installation."""
    
    def __init__(self):
        """Initialize installer."""
        self.install_dir = self._find_install_dir()
        self.repo_url = "https://github.com/regix1/wireguard-manager"
        self.version_url = "https://raw.githubusercontent.com/regix1/wireguard-manager/refs/heads/main/VERSION"
    
    def _find_install_dir(self) -> Path:
        """Find where the manager is installed."""
        locations = [
            Path(__file__).parent.parent,
            Path.home() / "wireguard-manager",
            Path("/opt/wireguard-manager"),
            Path("/usr/local/wireguard-manager"),
            Path("/etc/wireguard/wireguard-manager"),
        ]
        
        for loc in locations:
            if loc.exists() and ((loc / "setup.py").exists() or (loc / "src").exists()):
                return loc
        
        return Path(__file__).parent.parent
    
    def install_wireguard(self) -> None:
        """Install WireGuard on the system."""
        console.print(Panel.fit(
            "[bold cyan]Install WireGuard[/bold cyan]",
            border_style="cyan"
        ))
        
        if check_wireguard_installed():
            console.print("[yellow]WireGuard is already installed![/yellow]")
            
            # Check version
            result = run_command(["wg", "--version"], check=False)
            if result.returncode == 0:
                console.print(f"Current version: {result.stdout.strip()}")
            
            if not prompt_yes_no("Reinstall WireGuard?", default=False):
                return
        
        # Detect OS
        if Path("/etc/debian_version").exists():
            self._install_debian()
        elif Path("/etc/redhat-release").exists():
            self._install_redhat()
        else:
            console.print("[red]Unsupported OS[/red]")
            console.print("Please install WireGuard manually:")
            console.print("https://www.wireguard.com/install/")
            return
        
        # Create directories
        from .utils import ensure_directory
        ensure_directory(WIREGUARD_DIR)
        ensure_directory(BACKUP_DIR)
        
        console.print("\n[green]✓[/green] WireGuard installation complete!")
    
    def _install_debian(self) -> None:
        """Install on Debian/Ubuntu."""
        console.print("Detected Debian/Ubuntu")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
        ) as progress:
            task = progress.add_task("Updating package lists...", total=None)
            run_command(["apt-get", "update"])
            
            progress.update(task, description="Installing WireGuard...")
            run_command(["apt-get", "install", "-y", "wireguard", "wireguard-tools", "qrencode", "iptables"])
            
            progress.update(task, completed=True)
        
        enable_ip_forwarding()
        console.print("[green]✓[/green] WireGuard packages installed")
    
    def _install_redhat(self) -> None:
        """Install on RedHat/CentOS."""
        console.print("Detected RedHat/CentOS")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
        ) as progress:
            task = progress.add_task("Installing EPEL...", total=None)
            run_command(["yum", "install", "-y", "epel-release", "elrepo-release"])
            
            progress.update(task, description="Installing WireGuard...")
            run_command(["yum", "install", "-y", "kmod-wireguard", "wireguard-tools", "qrencode", "iptables"])
            
            progress.update(task, completed=True)
        
        enable_ip_forwarding()
        console.print("[green]✓[/green] WireGuard packages installed")
    
    def uninstall_wireguard(self) -> None:
        """Uninstall WireGuard from the system."""
        console.print(Panel.fit(
            "[bold red]Uninstall WireGuard[/bold red]",
            border_style="red"
        ))
        
        console.print("[yellow]Warning: This will remove WireGuard from your system.[/yellow]")
        console.print("Your configurations will be backed up.")
        
        if not prompt_yes_no("Are you sure you want to uninstall WireGuard?", default=False):
            return
        
        # Backup configurations first
        from .backup import BackupManager
        backup_mgr = BackupManager()
        backup_path = backup_mgr.create_backup("before_uninstall")
        console.print(f"[green]✓[/green] Configurations backed up to: {backup_path}")
        
        # Stop all interfaces
        from .service_manager import ServiceManager
        service_mgr = ServiceManager()
        for interface in service_mgr.get_active_interfaces():
            console.print(f"Stopping {interface}...")
            run_command(["systemctl", "stop", f"wg-quick@{interface}"], check=False)
            run_command(["systemctl", "disable", f"wg-quick@{interface}"], check=False)
        
        # Uninstall packages
        if Path("/etc/debian_version").exists():
            console.print("Removing WireGuard packages...")
            run_command(["apt-get", "remove", "-y", "wireguard", "wireguard-tools"])
            run_command(["apt-get", "autoremove", "-y"])
        elif Path("/etc/redhat-release").exists():
            console.print("Removing WireGuard packages...")
            run_command(["yum", "remove", "-y", "kmod-wireguard", "wireguard-tools"])
        
        console.print(f"\n[green]✓[/green] WireGuard uninstalled")
        console.print(f"[cyan]Backup location:[/cyan] {backup_path}")
    
    def update_wireguard(self) -> None:
        """Update WireGuard to latest version."""
        console.print(Panel.fit(
            "[bold cyan]Update WireGuard[/bold cyan]",
            border_style="cyan"
        ))
        
        console.print("Checking for WireGuard updates...")
        
        if Path("/etc/debian_version").exists():
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                transient=True,
            ) as progress:
                task = progress.add_task("Updating package lists...", total=None)
                run_command(["apt-get", "update"])
                
                progress.update(task, description="Upgrading WireGuard...")
                result = run_command(
                    ["apt-get", "upgrade", "-y", "wireguard", "wireguard-tools"],
                    check=False
                )
                progress.update(task, completed=True)
                
        elif Path("/etc/redhat-release").exists():
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                transient=True,
            ) as progress:
                task = progress.add_task("Updating packages...", total=None)
                result = run_command(
                    ["yum", "update", "-y", "kmod-wireguard", "wireguard-tools"],
                    check=False
                )
                progress.update(task, completed=True)
        
        # Check new version
        result = run_command(["wg", "--version"], check=False)
        if result.returncode == 0:
            console.print(f"[green]✓[/green] Current version: {result.stdout.strip()}")
        else:
            console.print("[green]✓[/green] WireGuard updated")
    
    def check_manager_updates(self) -> None:
        """Check for manager updates from GitHub."""
        console.print(Panel.fit(
            "[bold cyan]Check for Updates[/bold cyan]",
            border_style="cyan"
        ))
        
        console.print(f"Current version: {APP_VERSION}")
        console.print("Checking GitHub for updates...")
        
        try:
            # Fetch version from GitHub
            response = requests.get(self.version_url, timeout=10)
            
            if response.status_code == 200:
                remote_version = response.text.strip()
                console.print(f"Latest version: {remote_version}")
                
                # Compare versions
                if self._compare_versions(remote_version, APP_VERSION) > 0:
                    console.print("\n[yellow]🔄 New version available![/yellow]")
                    console.print(f"[cyan]Current:[/cyan] {APP_VERSION}")
                    console.print(f"[cyan]Latest:[/cyan] {remote_version}")
                    console.print(f"\n[cyan]View changes:[/cyan] {self.repo_url}/releases")
                    
                    if prompt_yes_no("\nDownload and install update?", default=True):
                        self.update_manager()
                else:
                    console.print(f"\n[green]✓ You are running the latest version ({APP_VERSION})[/green]")
            else:
                console.print(f"[yellow]Could not fetch version from GitHub (status: {response.status_code})[/yellow]")
                
        except requests.exceptions.Timeout:
            console.print("[yellow]Connection timeout - GitHub may be unavailable[/yellow]")
        except requests.exceptions.ConnectionError:
            console.print("[yellow]Connection error - check your internet connection[/yellow]")
        except Exception as e:
            console.print(f"[yellow]Update check failed: {e}[/yellow]")
    
    def update_manager(self) -> None:
        """Update the WireGuard Manager from GitHub."""
        console.print(Panel.fit(
            "[bold cyan]Update WireGuard Manager[/bold cyan]",
            border_style="cyan"
        ))
        
        console.print("Downloading latest version from GitHub...")
        
        try:
            # Backup current installation
            from .backup import BackupManager
            backup_mgr = BackupManager()
            backup_path = backup_mgr.create_backup("before_update")
            console.print(f"[green]✓[/green] Backup created: {backup_path}")
            
            with tempfile.TemporaryDirectory() as tmpdir:
                tmpdir_path = Path(tmpdir)
                
                # Download repository as archive
                archive_url = f"{self.repo_url}/archive/refs/heads/main.zip"
                console.print(f"Downloading from: {archive_url}")
                
                response = requests.get(archive_url, timeout=30, stream=True)
                if response.status_code != 200:
                    console.print(f"[red]Failed to download (status: {response.status_code})[/red]")
                    return
                
                # Save archive
                archive_path = tmpdir_path / "update.zip"
                with open(archive_path, 'wb') as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        f.write(chunk)
                
                console.print("[green]✓[/green] Download complete")
                
                # Extract archive
                console.print("Extracting files...")
                import zipfile
                with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                    zip_ref.extractall(tmpdir_path)
                
                # Find extracted directory
                extracted_dir = tmpdir_path / "wireguard-manager-main"
                if not extracted_dir.exists():
                    # Try to find any extracted directory
                    for item in tmpdir_path.iterdir():
                        if item.is_dir() and item.name != "update.zip":
                            extracted_dir = item
                            break
                
                if not extracted_dir.exists():
                    console.print("[red]Failed to extract update[/red]")
                    return
                
                # Update files
                console.print("Installing update...")
                
                # Update src directory
                if (extracted_dir / "src").exists():
                    src_dest = self.install_dir / "src"
                    if src_dest.exists():
                        shutil.rmtree(src_dest)
                    shutil.copytree(extracted_dir / "src", src_dest)
                    console.print("[green]✓[/green] Updated src directory")
                
                # Update VERSION file
                if (extracted_dir / "VERSION").exists():
                    shutil.copy2(extracted_dir / "VERSION", self.install_dir / "VERSION")
                    new_version = (extracted_dir / "VERSION").read_text().strip()
                    console.print(f"[green]✓[/green] Updated to version {new_version}")
                
                # Update other files
                for file in ["requirements.txt", "setup.py", "auto_install.sh", "uninstall.sh"]:
                    if (extracted_dir / file).exists():
                        shutil.copy2(extracted_dir / file, self.install_dir / file)
                        console.print(f"[green]✓[/green] Updated {file}")
                
                # Update data directory
                if (extracted_dir / "data").exists():
                    data_dest = self.install_dir / "data"
                    if data_dest.exists():
                        shutil.rmtree(data_dest)
                    shutil.copytree(extracted_dir / "data", data_dest)
                    console.print("[green]✓[/green] Updated data directory")
                
                # Update dependencies
                if (self.install_dir / "requirements.txt").exists():
                    console.print("Updating dependencies...")
                    run_command([
                        sys.executable, "-m", "pip", "install", "-r",
                        str(self.install_dir / "requirements.txt"), "-q"
                    ])
                    console.print("[green]✓[/green] Dependencies updated")
                
                console.print("\n[green]✓[/green] Update complete!")
                console.print("[yellow]Please restart the application to use the new version[/yellow]")
                
        except Exception as e:
            console.print(f"[red]Update failed: {e}[/red]")
            console.print(f"[yellow]Backup available at: {backup_path}[/yellow]")
    
    def _compare_versions(self, version1: str, version2: str) -> int:
        """Compare two version strings.
        Returns: 1 if version1 > version2, -1 if version1 < version2, 0 if equal."""
        try:
            v1_parts = [int(x) for x in version1.split('.')]
            v2_parts = [int(x) for x in version2.split('.')]
            
            # Pad with zeros if needed
            max_len = max(len(v1_parts), len(v2_parts))
            v1_parts.extend([0] * (max_len - len(v1_parts)))
            v2_parts.extend([0] * (max_len - len(v2_parts)))
            
            for i in range(max_len):
                if v1_parts[i] > v2_parts[i]:
                    return 1
                elif v1_parts[i] < v2_parts[i]:
                    return -1
            
            return 0
        except:
            # Fallback to string comparison
            if version1 > version2:
                return 1
            elif version1 < version2:
                return -1
            return 0
    
    def install_manager(self) -> None:
        """Install WireGuard Manager system-wide."""
        console.print(Panel.fit(
            "[bold cyan]Install WireGuard Manager[/bold cyan]",
            border_style="cyan"
        ))
        
        install_dir = Path("/opt/wireguard-manager")
        bin_path = Path("/usr/local/bin/wg-manager")
        
        console.print("Installing WireGuard Manager system-wide...")
        
        # Copy files to /opt
        if install_dir.exists():
            console.print("Backing up existing installation...")
            backup = install_dir.parent / f"wireguard-manager.backup.{datetime.now():%Y%m%d-%H%M%S}"
            shutil.move(str(install_dir), str(backup))
        
        console.print(f"Copying files to {install_dir}...")
        shutil.copytree(self.install_dir, install_dir)
        
        # Create executable
        console.print(f"Creating executable at {bin_path}...")
        
        # Determine if using src or wireguard_manager directory
        if (install_dir / "src").exists():
            module_name = "src"
        else:
            module_name = "wireguard_manager"
        
        bin_content = f"""#!/bin/bash
cd {install_dir}
if [ -d "venv" ]; then
    source venv/bin/activate
fi
export PYTHONPATH="{install_dir}/{module_name}:$PYTHONPATH"
{sys.executable} -m {module_name} "$@"
"""
        bin_path.write_text(bin_content)
        bin_path.chmod(0o755)
        
        # Install dependencies
        console.print("Installing dependencies...")
        if (install_dir / "requirements.txt").exists():
            run_command([
                sys.executable, "-m", "pip", "install", "-r",
                str(install_dir / "requirements.txt")
            ])
        
        console.print("\n[green]✓[/green] Installation complete!")
        console.print("You can now run 'wg-manager' from anywhere")
    
    def uninstall_manager(self) -> None:
        """Uninstall WireGuard Manager."""
        console.print(Panel.fit(
            "[bold red]Uninstall WireGuard Manager[/bold red]",
            border_style="red"
        ))
        
        console.print("[yellow]This will remove WireGuard Manager from your system.[/yellow]")
        console.print("Your WireGuard configurations will be preserved.")
        
        if not prompt_yes_no("Are you sure you want to uninstall?", default=False):
            return
        
        # Remove system-wide installation
        install_paths = [
            Path("/opt/wireguard-manager"),
            Path("/usr/local/bin/wg-manager"),
            Path("/usr/local/bin/wireguard-manager"),
        ]
        
        for path in install_paths:
            if path.exists():
                console.print(f"Removing {path}...")
                if path.is_dir():
                    shutil.rmtree(path)
                else:
                    path.unlink()
        
        # Clean pip packages
        for pip_cmd in ["pip", "pip3"]:
            try:
                run_command([pip_cmd, "uninstall", "-y", "wireguard-manager"], check=False)
            except:
                pass
        
        console.print("\n[green]✓[/green] WireGuard Manager uninstalled")
        console.print(f"[cyan]WireGuard configurations remain in:[/cyan] {WIREGUARD_DIR}")
        
        # Exit after uninstall
        sys.exit(0)
    
    def show_version_info(self) -> None:
        """Show version information."""
        console.clear()
        console.print(Panel.fit(
            "[bold cyan]Version Information[/bold cyan]",
            border_style="cyan"
        ))
        
        console.print(f"[cyan]WireGuard Manager:[/cyan] {APP_VERSION}")
        console.print(f"[cyan]Install Directory:[/cyan] {self.install_dir}")
        console.print(f"[cyan]Python Version:[/cyan] {sys.version.split()[0]}")
        
        # WireGuard version
        result = run_command(["wg", "--version"], check=False)
        if result.returncode == 0:
            console.print(f"[cyan]WireGuard Version:[/cyan] {result.stdout.strip()}")
        
        # Kernel module
        result = run_command(["modinfo", "wireguard"], check=False)
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if line.startswith('version:'):
                    kernel_version = line.split(':')[1].strip()
                    console.print(f"[cyan]Kernel Module:[/cyan] {kernel_version}")
                    break
        
        # OS information
        if Path("/etc/os-release").exists():
            with open("/etc/os-release") as f:
                for line in f:
                    if line.startswith("PRETTY_NAME"):
                        os_name = line.split("=")[1].strip().strip('"')
                        console.print(f"[cyan]Operating System:[/cyan] {os_name}")
                        break
        
        # Check for updates
        console.print("\n[cyan]Update Status:[/cyan]")
        console.print(f"  Repository: {self.repo_url}")
        console.print(f"  Version URL: {self.version_url}")
        
        console.print("\n[dim]Press Enter to continue...[/dim]")
        input()