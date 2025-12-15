"""Restore WireGuard configuration backups."""

import tarfile
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional

from ..config import WIREGUARD_DIR, BACKUP_DIR


def list_backups() -> List[Dict]:
    """
    List available backups.

    Returns:
        List of backup dicts with name, date, size
    """
    if not BACKUP_DIR.exists():
        return []

    backups = []
    for backup_file in sorted(BACKUP_DIR.glob("wg_backup_*.tar.gz"), reverse=True):
        stat = backup_file.stat()
        backups.append({
            "name": backup_file.name,
            "path": str(backup_file),
            "size": stat.st_size,
            "date": datetime.fromtimestamp(stat.st_mtime),
        })

    return backups


def print_backups() -> None:
    """Print formatted list of backups."""
    backups = list_backups()

    if not backups:
        print("No backups found")
        return

    print(f"\n{'Name':<45} {'Date':<20} {'Size'}")
    print("-" * 80)

    for backup in backups:
        name = backup['name'][:45]
        date = backup['date'].strftime("%Y-%m-%d %H:%M")
        size = f"{backup['size'] / 1024:.1f} KB"
        print(f"{name:<45} {date:<20} {size}")

    print()


def restore_backup(
    backup_path: Optional[str] = None,
    dry_run: bool = False,
) -> bool:
    """
    Restore configuration from a backup.

    Args:
        backup_path: Path to backup file (or None to show list)
        dry_run: If True, only show what would be restored

    Returns:
        True if successful
    """
    if backup_path is None:
        # Show available backups
        print_backups()
        return False

    backup_file = Path(backup_path)
    if not backup_file.exists():
        # Try finding in backup dir
        backup_file = BACKUP_DIR / backup_path
        if not backup_file.exists():
            print(f"Backup not found: {backup_path}")
            return False

    try:
        with tarfile.open(backup_file, "r:gz") as tar:
            members = tar.getmembers()

            if dry_run:
                print(f"Would restore from: {backup_file.name}")
                print(f"Files to restore:")
                for member in members:
                    print(f"  {member.name}")
                return True

            # Create backup of current config before restore
            from .create import create_backup
            print("Creating backup of current config...")
            create_backup(name="pre_restore")

            # Extract to wireguard dir
            tar.extractall(path=WIREGUARD_DIR)

            print(f"Restored from: {backup_file.name}")
            print(f"  Files: {len(members)}")
            print("\nRestart WireGuard to apply changes:")
            print("  wg-manager service restart")

            return True

    except Exception as e:
        print(f"Failed to restore backup: {e}")
        return False


def show_backup_contents(backup_path: str) -> None:
    """
    Show contents of a backup file.

    Args:
        backup_path: Path to backup file
    """
    backup_file = Path(backup_path)
    if not backup_file.exists():
        backup_file = BACKUP_DIR / backup_path
        if not backup_file.exists():
            print(f"Backup not found: {backup_path}")
            return

    try:
        with tarfile.open(backup_file, "r:gz") as tar:
            print(f"\nContents of {backup_file.name}:")
            print("-" * 50)
            for member in tar.getmembers():
                size = f"{member.size / 1024:.1f} KB" if member.size > 0 else "dir"
                print(f"  {member.name:<40} {size}")
            print()

    except Exception as e:
        print(f"Failed to read backup: {e}")


def delete_backup(backup_path: str) -> bool:
    """
    Delete a backup file.

    Args:
        backup_path: Path or name of backup to delete

    Returns:
        True if deleted
    """
    backup_file = Path(backup_path)
    if not backup_file.exists():
        backup_file = BACKUP_DIR / backup_path
        if not backup_file.exists():
            print(f"Backup not found: {backup_path}")
            return False

    backup_file.unlink()
    print(f"Deleted: {backup_file.name}")
    return True
