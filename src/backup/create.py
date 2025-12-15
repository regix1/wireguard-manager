"""Create WireGuard configuration backups."""

import tarfile
from datetime import datetime
from pathlib import Path
from typing import Optional, List

from ..config import WIREGUARD_DIR, BACKUP_DIR, FIREWALL_DIR, PEERS_DIR


def create_backup(
    name: Optional[str] = None,
    include_keys: bool = True,
    max_backups: int = 10,
) -> Optional[Path]:
    """
    Create a backup of WireGuard configuration.

    Args:
        name: Optional backup name (defaults to timestamp)
        include_keys: Include private keys in backup
        max_backups: Maximum number of backups to keep

    Returns:
        Path to backup file or None on failure
    """
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)

    # Generate backup filename
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    if name:
        backup_name = f"wg_backup_{name}_{timestamp}.tar.gz"
    else:
        backup_name = f"wg_backup_{timestamp}.tar.gz"

    backup_path = BACKUP_DIR / backup_name

    # Files to backup
    files_to_backup = []

    # Main config files
    for conf in WIREGUARD_DIR.glob("*.conf"):
        files_to_backup.append(conf)

    # Keys directory
    keys_dir = WIREGUARD_DIR / "keys"
    if include_keys and keys_dir.exists():
        for key_file in keys_dir.glob("*"):
            files_to_backup.append(key_file)

    # Peers directory
    if PEERS_DIR.exists():
        for peer_file in PEERS_DIR.glob("*.conf"):
            files_to_backup.append(peer_file)

    # Firewall directory
    if FIREWALL_DIR.exists():
        for fw_file in FIREWALL_DIR.glob("*"):
            if fw_file.is_file():
                files_to_backup.append(fw_file)

    # Config yaml
    config_yaml = WIREGUARD_DIR / "config.yaml"
    if config_yaml.exists():
        files_to_backup.append(config_yaml)

    if not files_to_backup:
        print("No files to backup")
        return None

    try:
        with tarfile.open(backup_path, "w:gz") as tar:
            for file_path in files_to_backup:
                # Use relative path from WIREGUARD_DIR
                arcname = file_path.relative_to(WIREGUARD_DIR)
                tar.add(file_path, arcname=arcname)

        backup_path.chmod(0o600)
        print(f"Backup created: {backup_path}")
        print(f"  Files: {len(files_to_backup)}")
        print(f"  Size: {backup_path.stat().st_size / 1024:.1f} KB")

        # Cleanup old backups
        _cleanup_old_backups(max_backups)

        return backup_path

    except Exception as e:
        print(f"Failed to create backup: {e}")
        return None


def _cleanup_old_backups(max_backups: int) -> None:
    """Remove old backups exceeding max count."""
    backups = sorted(BACKUP_DIR.glob("wg_backup_*.tar.gz"), key=lambda p: p.stat().st_mtime, reverse=True)

    if len(backups) > max_backups:
        for old_backup in backups[max_backups:]:
            old_backup.unlink()
            print(f"Removed old backup: {old_backup.name}")


def quick_backup() -> Optional[Path]:
    """Create a quick backup with default settings."""
    return create_backup()
