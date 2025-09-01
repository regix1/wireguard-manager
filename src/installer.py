"""WireGuard and Manager installation/updates."""

import os
import sys
import shutil
import subprocess
import tempfile
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
        self.repo_url = "https://github.com/regix1/wireguard-manager"  # Update when available
    
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
        """Check for manager updates."""
        console.print(Panel.fit(
            "[bold cyan]Check for Updates[/bold cyan]",
            border_style="cyan"
        ))
        
        console.print(f"Current version: {APP_VERSION}")
        
        if self.repo_url:
            console.print("Checking for updates...")
            try:
                # Check GitHub releases
                import requests
                api_url = self.repo_url.replace("github.com", "api.github.com/repos") + "/releases/latest"
                response = requests.get(api_url, timeout=5)
                
                if response.status_code == 200:
                    latest = response.json()
                    latest_version = latest.get("tag_name", "").lstrip("v")
                    
                    if latest_version and latest_version != APP_VERSION:
                        console.print(f"[yellow]New version available: {latest_version}[/yellow]")
                        console.print(f"Download: {latest.get('html_url', self.repo_url)}")
                        
                        if prompt_yes_no("Download and install update?", default=False):
                            self.update_manager()
                    else:
                        console.print(f"[green]✓[/green] You are running the latest version {APP_VERSION}")
                else:
                    console.print("[yellow]Could not check for updates[/yellow]")
            except Exception as e:
                console.print(f"[yellow]Update check failed: {e}[/yellow]")
        else:
            console.print("[yellow]Update checking is not configured[/yellow]")
            console.print("This is a local installation")
            console.print(f"\n[green]✓[/green] You are running version {APP_VERSION}")
    
    def update_manager(self) -> None:
        """Update the WireGuard Manager."""
        console.print(Panel.fit(
            "[bold cyan]Update WireGuard Manager[/bold cyan]",
            border_style="cyan"
        ))
        
        if not self.repo_url:
            console.print("[yellow]No update repository configured[/yellow]")
            return
        
        console.print("Downloading latest version...")
        
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                # Clone repository
                result = run_command([
                    "git", "clone", "--depth", "1", 
                    self.repo_url, tmpdir
                ], check=False)
                
                if result.returncode != 0:
                    console.print("[red]Failed to download update[/red]")
                    return
                
                # Backup current installation
                from .backup import BackupManager
                backup_mgr = BackupManager()
                backup_path = backup_mgr.create_backup("before_update")
                
                # Copy new files
                tmpdir_path = Path(tmpdir)
                if (tmpdir_path / "src").exists():
                    shutil.rmtree(self.install_dir / "src", ignore_errors=True)
                    shutil.copytree(tmpdir_path / "src", self.install_dir / "src")
                
                if (tmpdir_path / "VERSION").exists():
                    shutil.copy2(tmpdir_path / "VERSION", self.install_dir / "VERSION")
                
                # Update dependencies
                if (tmpdir_path / "requirements.txt").exists():
                    shutil.copy2(tmpdir_path / "requirements.txt", self.install_dir / "requirements.txt")
                    run_command([
                        sys.executable, "-m", "pip", "install", "-r",
                        str(self.install_dir / "requirements.txt")
                    ])
                
                console.print("[green]✓[/green] Update complete!")
                console.print("Please restart the application")
                
        except Exception as e:
            console.print(f"[red]Update failed: {e}[/red]")
    
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
        
        console.print("\n[dim]Press Enter to continue...[/dim]")
        input()