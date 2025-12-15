"""Remove WireGuard peers."""

import re
from pathlib import Path
from typing import Optional

from ..config import PEERS_DIR, get_interface_path
from ..utils import run


def remove_peer(name: str, interface: str = "wg0") -> bool:
    """
    Remove a peer from the WireGuard configuration.

    Args:
        name: Peer name to remove
        interface: WireGuard interface name

    Returns:
        True if peer was removed, False if not found
    """
    config_path = get_interface_path(interface)
    if not config_path.exists():
        raise FileNotFoundError(f"Interface {interface} not configured")

    content = config_path.read_text()
    lines = content.split('\n')

    # Find and remove peer block
    new_lines = []
    skip_until_next_peer = False
    peer_found = False
    public_key = None

    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        # Check for peer comment with name
        if stripped.startswith(f'# Peer: {name}'):
            peer_found = True
            skip_until_next_peer = True
            # Skip until we find [Peer] then capture public key
            while i < len(lines) and not lines[i].strip().startswith('[Peer]'):
                i += 1
            i += 1  # Skip [Peer] line
            # Get public key
            while i < len(lines):
                l = lines[i].strip()
                if l.startswith('PublicKey'):
                    public_key = l.split('=')[1].strip()
                    break
                if l.startswith('['):
                    break
                i += 1
            continue

        if skip_until_next_peer:
            # Skip until next section or empty line followed by comment
            if stripped.startswith('[') or (stripped == '' and i + 1 < len(lines) and lines[i + 1].strip().startswith('#')):
                skip_until_next_peer = False
                if stripped.startswith('['):
                    new_lines.append(line)
            i += 1
            continue

        new_lines.append(line)
        i += 1

    if not peer_found:
        # Try finding by just scanning for name in comments
        new_lines = []
        in_peer_block = False
        skip_block = False

        for i, line in enumerate(lines):
            stripped = line.strip()

            if stripped.startswith('# Peer:') and name in stripped:
                skip_block = True
                peer_found = True
                continue

            if stripped.startswith('[Peer]') and skip_block:
                in_peer_block = True
                continue

            if in_peer_block:
                if stripped.startswith('PublicKey') and public_key is None:
                    public_key = stripped.split('=')[1].strip()
                if stripped.startswith('[') or (stripped == '' and i + 1 < len(lines) and lines[i + 1].strip().startswith('[Peer]')):
                    in_peer_block = False
                    skip_block = False
                    if stripped.startswith('['):
                        new_lines.append(line)
                continue

            if skip_block:
                continue

            new_lines.append(line)

    if not peer_found:
        print(f"Peer '{name}' not found")
        return False

    # Clean up multiple blank lines
    cleaned = []
    prev_blank = False
    for line in new_lines:
        if line.strip() == '':
            if not prev_blank:
                cleaned.append(line)
            prev_blank = True
        else:
            cleaned.append(line)
            prev_blank = False

    # Write updated config
    config_path.write_text('\n'.join(cleaned))

    # Remove from live interface if we have the public key
    if public_key:
        try:
            run(["wg", "set", interface, "peer", public_key, "remove"], check=False)
        except Exception:
            pass

    # Remove peer config file
    peer_file = PEERS_DIR / f"{name}.conf"
    if peer_file.exists():
        peer_file.unlink()

    print(f"Peer '{name}' removed successfully")
    return True


def remove_peer_by_ip(ip: str, interface: str = "wg0") -> bool:
    """
    Remove a peer by its IP address.

    Args:
        ip: IP address of peer to remove
        interface: WireGuard interface name

    Returns:
        True if peer was removed
    """
    config_path = get_interface_path(interface)
    if not config_path.exists():
        raise FileNotFoundError(f"Interface {interface} not configured")

    content = config_path.read_text()

    # Find peer name by IP
    lines = content.split('\n')
    peer_name = None

    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith('AllowedIPs') and ip in stripped:
            # Look backwards for peer name
            for j in range(i - 1, -1, -1):
                if lines[j].strip().startswith('# Peer:'):
                    match = re.match(r'# Peer:\s*(\S+)', lines[j].strip())
                    if match:
                        peer_name = match.group(1)
                        break
                if lines[j].strip().startswith('[Interface]'):
                    break
            break

    if peer_name:
        return remove_peer(peer_name, interface)

    print(f"No peer found with IP {ip}")
    return False
