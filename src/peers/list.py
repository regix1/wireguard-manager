"""List and query WireGuard peers."""

import json
import re
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Set

from ..config import WIREGUARD_DIR, PEERS_DIR, get_interface_path
from ..utils import run


# Default directories to scan for peer configs
DEFAULT_PEER_DIRS = [
    PEERS_DIR,
    WIREGUARD_DIR,
    Path("/home"),
    Path("/root"),
]


def load_peer_directories() -> List[Path]:
    """Load configured peer directories."""
    config_file = WIREGUARD_DIR / "peer_directories.json"

    if config_file.exists():
        try:
            with open(config_file, 'r') as f:
                data = json.load(f)
                return [Path(d) for d in data.get('directories', [])]
        except Exception:
            pass

    return DEFAULT_PEER_DIRS.copy()


def save_peer_directories(directories: List[Path]) -> None:
    """Save peer directories configuration."""
    config_file = WIREGUARD_DIR / "peer_directories.json"

    data = {
        'directories': [str(d) for d in directories],
        'updated': datetime.now().isoformat()
    }

    config_file.parent.mkdir(parents=True, exist_ok=True)
    with open(config_file, 'w') as f:
        json.dump(data, f, indent=2)

    print(f"Saved peer directories configuration")


def add_peer_directory(directory: str) -> bool:
    """Add a directory to scan for peer configs."""
    path = Path(directory).expanduser().resolve()
    dirs = load_peer_directories()

    if path in dirs:
        print(f"Directory already in list: {path}")
        return False

    dirs.append(path)
    save_peer_directories(dirs)
    print(f"Added directory: {path}")
    return True


def remove_peer_directory(directory: str) -> bool:
    """Remove a directory from the scan list."""
    path = Path(directory).expanduser().resolve()
    dirs = load_peer_directories()

    if path not in dirs:
        print(f"Directory not in list: {path}")
        return False

    dirs.remove(path)
    save_peer_directories(dirs)
    print(f"Removed directory: {path}")
    return True


def scan_for_peer_configs() -> List[Dict]:
    """Scan all configured directories for peer configurations."""
    dirs = load_peer_directories()
    found = []

    for directory in dirs:
        if not directory.exists():
            continue

        # Recursively search for .conf files
        for conf_file in directory.rglob("*.conf"):
            # Skip non-peer configs
            skip_patterns = ['firewall', 'rules', 'banned', 'server', 'params']
            if any(skip in conf_file.name.lower() for skip in skip_patterns):
                continue

            # Skip main interface configs
            if conf_file.parent == WIREGUARD_DIR and conf_file.stem in ['wg0', 'wg1', 'wg2']:
                continue

            try:
                content = conf_file.read_text()
                # Check if it's a peer config (has both [Interface] and [Peer])
                if '[Interface]' in content and '[Peer]' in content:
                    # Extract IP
                    ip = "unknown"
                    ip_match = re.search(r'Address\s*=\s*([^/\n]+)', content)
                    if ip_match:
                        ip = ip_match.group(1).strip()

                    found.append({
                        'file': str(conf_file),
                        'name': conf_file.stem,
                        'directory': str(conf_file.parent),
                        'ip': ip,
                    })
            except Exception:
                continue

    return found


def list_peers(interface: str = "wg0", show_live: bool = True) -> List[Dict]:
    """
    List all peers for an interface.

    Args:
        interface: WireGuard interface name
        show_live: Include live connection stats

    Returns:
        List of peer dicts with name, ip, public_key, etc.
    """
    config_path = get_interface_path(interface)
    if not config_path.exists():
        print(f"Interface {interface} not configured")
        return []

    peers = _parse_peers_from_config(config_path)

    # Get live stats if requested
    if show_live:
        live_stats = _get_live_stats(interface)
        for peer in peers:
            if peer['public_key'] in live_stats:
                peer.update(live_stats[peer['public_key']])

    return peers


def _parse_peers_from_config(config_path: Path) -> List[Dict]:
    """Parse peer information from config file."""
    content = config_path.read_text()
    lines = content.split('\n')
    peers = []
    current_peer = None

    for line in lines:
        stripped = line.strip()

        # Peer comment with name
        if stripped.startswith('# Peer:'):
            match = re.match(r'# Peer:\s*(\S+)(?:\s*\((\w+)\))?', stripped)
            if match:
                current_peer = {
                    'name': match.group(1),
                    'type': match.group(2) or 'client',
                    'public_key': '',
                    'allowed_ips': '',
                    'keepalive': 0,
                    'added': '',
                }

        # Added date comment
        elif stripped.startswith('# Added:') and current_peer:
            current_peer['added'] = stripped.replace('# Added:', '').strip()

        # Routes comment (for router peers)
        elif stripped.startswith('# Routes:') and current_peer:
            current_peer['routes'] = stripped.replace('# Routes:', '').strip()

        # Start of peer block
        elif stripped == '[Peer]':
            if current_peer is None:
                current_peer = {
                    'name': 'unknown',
                    'type': 'client',
                    'public_key': '',
                    'allowed_ips': '',
                    'keepalive': 0,
                }

        # Peer settings
        elif current_peer and '=' in stripped:
            key, value = stripped.split('=', 1)
            key = key.strip()
            value = value.strip()

            if key == 'PublicKey':
                current_peer['public_key'] = value
            elif key == 'AllowedIPs':
                current_peer['allowed_ips'] = value
                # Extract primary IP
                ips = [ip.strip() for ip in value.split(',')]
                for ip in ips:
                    if '/32' in ip:
                        current_peer['ip'] = ip.replace('/32', '')
                        break
            elif key == 'PersistentKeepalive':
                current_peer['keepalive'] = int(value)

        # End of peer block (next section or end)
        elif stripped.startswith('[') and current_peer and current_peer.get('public_key'):
            peers.append(current_peer)
            current_peer = None

    # Don't forget last peer
    if current_peer and current_peer.get('public_key'):
        peers.append(current_peer)

    return peers


def _get_live_stats(interface: str) -> Dict[str, Dict]:
    """Get live connection stats from wg show."""
    stats = {}

    try:
        result = run(["wg", "show", interface, "dump"], check=False)
        if result.returncode != 0:
            return stats

        lines = result.stdout.strip().split('\n')
        # Skip first line (interface info)
        for line in lines[1:]:
            parts = line.split('\t')
            if len(parts) >= 5:
                public_key = parts[0]
                endpoint = parts[2] if parts[2] != '(none)' else None
                latest_handshake = int(parts[4]) if parts[4] != '0' else None
                rx_bytes = int(parts[5]) if len(parts) > 5 else 0
                tx_bytes = int(parts[6]) if len(parts) > 6 else 0

                stats[public_key] = {
                    'endpoint': endpoint,
                    'last_handshake': latest_handshake,
                    'rx_bytes': rx_bytes,
                    'tx_bytes': tx_bytes,
                    'online': latest_handshake is not None and (
                        datetime.now().timestamp() - latest_handshake < 180
                    ),
                }

    except Exception:
        pass

    return stats


def get_peer_info(name: str, interface: str = "wg0") -> Optional[Dict]:
    """Get info for a specific peer."""
    peers = list_peers(interface, show_live=True)
    for peer in peers:
        if peer['name'] == name:
            return peer
    return None


def print_peers(interface: str = "wg0") -> None:
    """Print formatted peer list."""
    peers = list_peers(interface, show_live=True)

    if not peers:
        print("No peers configured")
        return

    print(f"\n{'Name':<20} {'IP':<16} {'Type':<10} {'Status':<10} {'Last Seen'}")
    print("-" * 75)

    for peer in peers:
        name = peer.get('name', 'unknown')[:20]
        ip = peer.get('ip', 'N/A')[:16]
        ptype = peer.get('type', 'client')[:10]

        online = peer.get('online', False)
        status = 'online' if online else 'offline'

        last_seen = 'never'
        if peer.get('last_handshake'):
            ts = datetime.fromtimestamp(peer['last_handshake'])
            last_seen = ts.strftime('%Y-%m-%d %H:%M')

        print(f"{name:<20} {ip:<16} {ptype:<10} {status:<10} {last_seen}")

    print()
