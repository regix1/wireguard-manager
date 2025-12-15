"""IP banning management."""

import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional

from ..config import WIREGUARD_DIR, FIREWALL_DIR
from ..utils import run

BANNED_FILE = FIREWALL_DIR / "banned_ips.json"
BANNED_TXT = FIREWALL_DIR / "banned_ips.txt"
OLD_BANNED_FILE = WIREGUARD_DIR / "banned_ips.txt"


def migrate_banned_ips() -> int:
    """
    Migrate old banned IPs file to new JSON format.

    Returns:
        Number of IPs migrated
    """
    if not OLD_BANNED_FILE.exists():
        return 0

    if BANNED_FILE.exists():
        print("New banned IPs file already exists, skipping migration")
        return 0

    banned = {}
    migrated = 0

    try:
        with open(OLD_BANNED_FILE, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue

                # Handle different delimiters: | or #
                if '|' in line:
                    parts = line.split('|', 1)
                    ip = parts[0].strip()
                    reason = parts[1].strip() if len(parts) > 1 else ""
                elif '#' in line:
                    parts = line.split('#', 1)
                    ip = parts[0].strip()
                    reason = parts[1].strip() if len(parts) > 1 else ""
                else:
                    ip = line
                    reason = "Migrated from old format"

                if ip:
                    banned[ip] = {
                        "reason": reason,
                        "banned_at": datetime.now().isoformat(),
                    }
                    migrated += 1

        if banned:
            _save_banned(banned)
            sync_bans()
            print(f"Migrated {migrated} banned IPs from {OLD_BANNED_FILE}")

    except Exception as e:
        print(f"Migration failed: {e}")

    return migrated


def import_ban_list(file_path: str) -> int:
    """
    Import banned IPs from a file.

    Supports formats:
    - One IP per line
    - IP|reason
    - IP # reason

    Args:
        file_path: Path to file to import

    Returns:
        Number of IPs imported
    """
    path = Path(file_path)
    if not path.exists():
        print(f"File not found: {file_path}")
        return 0

    banned = _load_banned()
    imported = 0

    with open(path, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            # Parse line
            if '|' in line:
                parts = line.split('|', 1)
                ip = parts[0].strip()
                reason = parts[1].strip() if len(parts) > 1 else "Imported"
            elif '#' in line and not line.startswith('#'):
                parts = line.split('#', 1)
                ip = parts[0].strip()
                reason = parts[1].strip() if len(parts) > 1 else "Imported"
            else:
                ip = line
                reason = f"Imported from {path.name}"

            if ip and ip not in banned:
                banned[ip] = {
                    "reason": reason,
                    "banned_at": datetime.now().isoformat(),
                }
                imported += 1

    if imported > 0:
        _save_banned(banned)
        sync_bans()
        print(f"Imported {imported} IPs from {file_path}")

    return imported


def export_ban_list(file_path: str) -> int:
    """
    Export banned IPs to a file.

    Args:
        file_path: Path to export to

    Returns:
        Number of IPs exported
    """
    banned = _load_banned()

    with open(file_path, 'w') as f:
        f.write(f"# WireGuard Banned IPs - Exported {datetime.now()}\n")
        f.write("# Format: IP|reason\n\n")

        for ip, info in banned.items():
            reason = info.get('reason', '')
            f.write(f"{ip}|{reason}\n")

    print(f"Exported {len(banned)} IPs to {file_path}")
    return len(banned)


def scan_for_ban_files() -> List[str]:
    """
    Scan for existing banned IP files.

    Returns:
        List of found file paths
    """
    search_paths = [
        WIREGUARD_DIR / "banned_ips.txt",
        WIREGUARD_DIR / "banned_ips.conf",
        FIREWALL_DIR / "banned_ips.txt",
        Path("/root/banned_ips.txt"),
    ]

    # Also check home directories
    home = Path("/home")
    if home.exists():
        for user_dir in home.iterdir():
            if user_dir.is_dir():
                search_paths.append(user_dir / "banned_ips.txt")

    found = []
    for path in search_paths:
        if path.exists() and path != BANNED_FILE:
            found.append(str(path))

    return found


def _load_banned() -> Dict[str, Dict]:
    """Load banned IPs from JSON file."""
    if BANNED_FILE.exists():
        try:
            return json.loads(BANNED_FILE.read_text())
        except Exception:
            pass
    return {}


def _save_banned(banned: Dict[str, Dict]) -> None:
    """Save banned IPs to JSON file."""
    FIREWALL_DIR.mkdir(parents=True, exist_ok=True)
    BANNED_FILE.write_text(json.dumps(banned, indent=2))


def _ensure_chain() -> None:
    """Ensure BANNED_IPS chain exists."""
    # Check if chain exists
    result = run(["iptables", "-L", "BANNED_IPS", "-n"], check=False)
    if result.returncode != 0:
        # Create chain
        run(["iptables", "-N", "BANNED_IPS"])
        # Add jump to BANNED_IPS from INPUT
        run(["iptables", "-I", "INPUT", "1", "-j", "BANNED_IPS"])


def ban_ip(ip: str, reason: Optional[str] = None) -> bool:
    """
    Ban an IP address.

    Args:
        ip: IP address to ban
        reason: Optional reason for the ban

    Returns:
        True if successful
    """
    _ensure_chain()

    banned = _load_banned()

    if ip in banned:
        print(f"IP {ip} is already banned")
        return False

    # Add iptables rule
    cmd = ["iptables", "-A", "BANNED_IPS", "-s", ip, "-j", "DROP"]
    if reason:
        cmd.extend(["-m", "comment", "--comment", reason[:256]])

    try:
        run(cmd)
    except Exception as e:
        print(f"Failed to ban IP: {e}")
        return False

    # Save to file
    banned[ip] = {
        "reason": reason or "No reason provided",
        "banned_at": datetime.now().isoformat(),
    }
    _save_banned(banned)

    print(f"Banned IP: {ip}")
    if reason:
        print(f"  Reason: {reason}")
    return True


def unban_ip(ip: str) -> bool:
    """
    Unban an IP address.

    Args:
        ip: IP address to unban

    Returns:
        True if successful
    """
    banned = _load_banned()

    if ip not in banned:
        print(f"IP {ip} is not banned")
        return False

    # Remove iptables rule
    try:
        run(["iptables", "-D", "BANNED_IPS", "-s", ip, "-j", "DROP"], check=False)
    except Exception:
        pass

    # Remove from file
    del banned[ip]
    _save_banned(banned)

    print(f"Unbanned IP: {ip}")
    return True


def list_bans() -> List[Dict]:
    """
    List all banned IPs.

    Returns:
        List of banned IP dicts
    """
    banned = _load_banned()
    return [
        {"ip": ip, **info}
        for ip, info in banned.items()
    ]


def print_bans() -> None:
    """Print formatted list of banned IPs."""
    bans = list_bans()

    if not bans:
        print("No banned IPs")
        return

    print(f"\n{'IP Address':<20} {'Banned At':<22} {'Reason'}")
    print("-" * 80)

    for ban in bans:
        ip = ban['ip'][:20]
        banned_at = ban.get('banned_at', 'Unknown')[:22]
        reason = ban.get('reason', 'No reason')[:40]
        print(f"{ip:<20} {banned_at:<22} {reason}")

    print()


def sync_bans() -> None:
    """Sync banned IPs from file to iptables."""
    _ensure_chain()

    # Flush existing rules
    run(["iptables", "-F", "BANNED_IPS"], check=False)

    # Re-add all banned IPs
    banned = _load_banned()
    for ip, info in banned.items():
        reason = info.get('reason', '')
        cmd = ["iptables", "-A", "BANNED_IPS", "-s", ip, "-j", "DROP"]
        if reason:
            cmd.extend(["-m", "comment", "--comment", reason[:256]])
        run(cmd, check=False)

    print(f"Synced {len(banned)} banned IPs to iptables")
