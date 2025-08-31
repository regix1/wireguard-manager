"""Backup and restore functionality for WireGuard."""

import shutil
import tarfile
from datetime import datetime
from pathlib import Path
from typing import List
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import IntPrompt

from .constants import WIREGUARD_DIR, BACKUP_DIR
from .utils import ensure_directory, prompt_yes_no

console = Console()

class BackupManager:
    """Manage WireGuard configuration backups."""
    
    def __init__(self):
        """Initialize backup manager."""
        ensure_directory(BACKUP_DIR)
    
    def create_backup(self, description: str = "") -> Path:
        """Create a backup of current configuration."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_name = f"wireguard_backup_{timestamp}"
        
        if description:
            backup_name += f"_{description.replace(' ', '_')}"
        
        backup_path = BACKUP_DIR / f"{backup_name}.tar.gz"
        
        console.print(f"[cyan]Creating backup: {backup_path.name}[/cyan]")
        
        with tarfile.open(backup_path, "w:gz") as tar:
            for item in WIREGUARD_DIR.iterdir():
                if item.name != "backups":
                    tar.add(item, arcname=item.name)
        
        console.print(f"[green]✓[/green] Backup created: {backup_path}")
        return backup_path
    
    def list_backups(self) -> List[Path]:
        """List available backups."""
        backups = sorted(BACKUP_DIR.glob("*.tar.gz"), reverse=True)
        return backups
    
    def restore_backup(self) -> None:
        """Interactive backup restoration."""
        console.print(Panel.fit(
            "[bold cyan]Restore Configuration Backup[/bold cyan]",
            border_style="cyan"
        ))
        
        backups = self.list_backups()
        
        if not backups:
            console.print("[yellow]No backups found[/yellow]")
            return
        
        # Display available backups
        table = Table(title="Available Backups", title_style="bold cyan")
        table.add_column("#", style="cyan", width=3)
        table.add_column("Filename")
        table.add_column("Date", justify="center")
        table.add_column("Size", justify="right")
        
        for i, backup in enumerate(backups[:10], 1):
            stats = backup.stat()
            date = datetime.fromtimestamp(stats.st_mtime).strftime("%Y-%m-%d %H:%M")
            size = self._format_size(stats.st_size)
            table.add_row(str(i), backup.name, date, size)
        
        console.print(table)
        
        choice = IntPrompt.ask(
            "Select backup to restore (0 to cancel)",
            choices=[str(i) for i in range(0, min(len(backups), 10) + 1)]
        )
        
        if choice == 0:
            return
        
        selected_backup = backups[choice - 1]
        
        if not prompt_yes_no(f"Restore from {selected_backup.name}?", default=False):
            return
        
        # Create backup of current config
        console.print("[cyan]Creating backup of current configuration...[/cyan]")
        self.create_backup("before_restore")
        
        # Restore
        self.restore_specific_backup(selected_backup)
    
    def restore_specific_backup(self, backup_path: Path) -> bool:
        """Restore a specific backup."""
        console.print(f"[cyan]Restoring from {backup_path.name}...[/cyan]")
        
        try:
            temp_dir = BACKUP_DIR / "temp_restore"
            temp_dir.mkdir(exist_ok=True)
            
            with tarfile.open(backup_path, "r:gz") as tar:
                tar.extractall(temp_dir)
            
            for item in temp_dir.iterdir():
                target = WIREGUARD_DIR / item.name
                
                if target.exists():
                    if target.is_dir():
                        shutil.rmtree(target)
                    else:
                        target.unlink()
                
                shutil.move(str(item), str(target))
            
            shutil.rmtree(temp_dir)
            
            console.print(f"[green]✓[/green] Backup restored successfully")
            return True
            
        except Exception as e:
            console.print(f"[red]Restore failed: {e}[/red]")
            return False
    
    def _format_size(self, size: int) -> str:
        """Format file size."""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} TB"