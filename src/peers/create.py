"""Create WireGuard peers."""

import re
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from ..config import WIREGUARD_DIR, PEERS_DIR, KEYS_DIR, DEFAULTS, get_interface_path
from ..utils import generate_keypair, generate_psk, get_public_ip, get_next_ip, run


def get_used_ips(interface: str = "wg0") -> List[str]:
    """Get list of IPs already in use."""
    config_path = get_interface_path(interface)
    used = []

    if config_path.exists():
        content = config_path.read_text()
        # Get server address
        for line in content.split('\n'):
            if line.strip().startswith('Address'):
                addrs = line.split('=')[1].strip()
                for addr in addrs.split(','):
                    addr = addr.strip()
                    if '/' in addr:
                        used.append(addr.split('/')[0])
                    else:
                        used.append(addr)
            # Get peer AllowedIPs
            if line.strip().startswith('AllowedIPs'):
                ips = line.split('=')[1].strip()
                for ip in ips.split(','):
                    ip = ip.strip()
                    if '/32' in ip:
                        used.append(ip.split('/')[0])

    return used


def get_server_info(interface: str = "wg0") -> dict:
    """Get server configuration info."""
    config_path = get_interface_path(interface)
    info = {
        "endpoint": get_public_ip(),
        "port": DEFAULTS["server_port"],
        "subnet": DEFAULTS["server_subnet"],
        "dns": DEFAULTS["dns_servers"],
        "mtu": DEFAULTS["mtu"],
        "public_key": "",
    }

    if config_path.exists():
        content = config_path.read_text()
        for line in content.split('\n'):
            line = line.strip()
            if line.startswith('ListenPort'):
                info["port"] = int(line.split('=')[1].strip())
            elif line.startswith('DNS'):
                info["dns"] = line.split('=')[1].strip()
            elif line.startswith('MTU'):
                info["mtu"] = int(line.split('=')[1].strip())
            elif line.startswith('Address'):
                # Extract subnet from first address
                addr = line.split('=')[1].strip().split(',')[0].strip()
                if '/' in addr:
                    parts = addr.rsplit('.', 1)
                    info["subnet"] = f"{parts[0]}.0/{addr.split('/')[1]}"

    # Get public key from private key
    keys_file = KEYS_DIR / f"{interface}_private.key"
    if keys_file.exists():
        result = run(["wg", "pubkey"], input_text=keys_file.read_text().strip())
        info["public_key"] = result.stdout.strip()
    else:
        # Try to get from wg show
        try:
            result = run(["wg", "show", interface, "public-key"], check=False)
            if result.returncode == 0:
                info["public_key"] = result.stdout.strip()
        except Exception:
            pass

    return info


def add_peer(
    name: str,
    interface: str = "wg0",
    ip: Optional[str] = None,
    dns: Optional[str] = None,
    keepalive: int = 25,
    allowed_ips: str = "0.0.0.0/0, ::/0",
) -> dict:
    """
    Add a standard client peer.

    Args:
        name: Peer name (alphanumeric and dashes only)
        interface: WireGuard interface name
        ip: Specific IP to assign (auto if None)
        dns: DNS servers for peer
        keepalive: PersistentKeepalive value
        allowed_ips: AllowedIPs for peer config (what the peer routes)

    Returns:
        dict with peer info and config paths
    """
    # Validate name
    if not re.match(r'^[a-zA-Z0-9_-]+$', name):
        raise ValueError("Peer name must be alphanumeric (dashes/underscores allowed)")

    config_path = get_interface_path(interface)
    if not config_path.exists():
        raise FileNotFoundError(f"Interface {interface} not configured")

    # Get server info
    server = get_server_info(interface)

    # Generate keys
    private_key, public_key = generate_keypair()
    psk = generate_psk()

    # Assign IP
    if ip is None:
        used_ips = get_used_ips(interface)
        ip = get_next_ip(server["subnet"], used_ips)

    peer_ip = f"{ip}/32"

    # Use server DNS if not specified
    if dns is None:
        dns = server["dns"]

    # Create peer config (for the client)
    peer_config = f"""[Interface]
PrivateKey = {private_key}
Address = {ip}/24
DNS = {dns}
MTU = {server['mtu']}

[Peer]
PublicKey = {server['public_key']}
PresharedKey = {psk}
Endpoint = {server['endpoint']}:{server['port']}
AllowedIPs = {allowed_ips}
PersistentKeepalive = {keepalive}
"""

    # Save peer config
    PEERS_DIR.mkdir(parents=True, exist_ok=True)
    peer_file = PEERS_DIR / f"{name}.conf"
    peer_file.write_text(peer_config)
    peer_file.chmod(0o600)

    # Add to server config
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    server_peer_block = f"""
# Peer: {name}
# Added: {timestamp}
[Peer]
PublicKey = {public_key}
PresharedKey = {psk}
AllowedIPs = {peer_ip}
PersistentKeepalive = {keepalive}
"""

    with open(config_path, 'a') as f:
        f.write(server_peer_block)

    # Sync to live interface
    try:
        run(["wg", "syncconf", interface, "/dev/stdin"],
            input_text=_get_wg_syncconf(config_path))
    except Exception:
        pass  # Interface might not be up

    print(f"Peer '{name}' added successfully")
    print(f"  IP: {ip}")
    print(f"  Config: {peer_file}")

    return {
        "name": name,
        "ip": ip,
        "public_key": public_key,
        "config_path": str(peer_file),
    }


def add_router_peer(
    name: str,
    subnets: List[str],
    interface: str = "wg0",
    ip: Optional[str] = None,
    keepalive: int = 60,
) -> dict:
    """
    Add a router peer that routes entire subnets.

    This is for peers like OpenWRT that provide access to local networks.

    Args:
        name: Peer name
        subnets: List of subnets this peer routes (e.g., ["10.0.4.0/24", "172.16.1.0/24"])
        interface: WireGuard interface name
        ip: Specific IP to assign (auto if None)
        keepalive: PersistentKeepalive value (higher for routers)

    Returns:
        dict with peer info
    """
    if not re.match(r'^[a-zA-Z0-9_-]+$', name):
        raise ValueError("Peer name must be alphanumeric (dashes/underscores allowed)")

    config_path = get_interface_path(interface)
    if not config_path.exists():
        raise FileNotFoundError(f"Interface {interface} not configured")

    server = get_server_info(interface)

    # Generate keys
    private_key, public_key = generate_keypair()
    psk = generate_psk()

    # Assign IP
    if ip is None:
        used_ips = get_used_ips(interface)
        ip = get_next_ip(server["subnet"], used_ips)

    # Build AllowedIPs for server config (include all subnets)
    # Also include the WireGuard subnet so this peer can talk to other peers
    allowed_ips = subnets.copy()
    allowed_ips.append(server["subnet"])
    allowed_ips_str = ",".join(allowed_ips)

    # Create peer config (for the router device)
    # Router uses the WireGuard subnet for allowed IPs since it routes to server
    peer_config = f"""[Interface]
PrivateKey = {private_key}
Address = {ip}/24
MTU = {server['mtu']}

[Peer]
PublicKey = {server['public_key']}
PresharedKey = {psk}
Endpoint = {server['endpoint']}:{server['port']}
AllowedIPs = {server['subnet']}
PersistentKeepalive = {keepalive}
"""

    # Save peer config
    PEERS_DIR.mkdir(parents=True, exist_ok=True)
    peer_file = PEERS_DIR / f"{name}.conf"
    peer_file.write_text(peer_config)
    peer_file.chmod(0o600)

    # Add to server config
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    server_peer_block = f"""
# Peer: {name} (router)
# Added: {timestamp}
# Routes: {', '.join(subnets)}
[Peer]
PublicKey = {public_key}
PresharedKey = {psk}
AllowedIPs = {allowed_ips_str}
PersistentKeepalive = {keepalive}
"""

    with open(config_path, 'a') as f:
        f.write(server_peer_block)

    # Sync to live interface
    try:
        run(["wg", "syncconf", interface, "/dev/stdin"],
            input_text=_get_wg_syncconf(config_path))
    except Exception:
        pass

    print(f"Router peer '{name}' added successfully")
    print(f"  IP: {ip}")
    print(f"  Routes: {', '.join(subnets)}")
    print(f"  Config: {peer_file}")

    return {
        "name": name,
        "ip": ip,
        "public_key": public_key,
        "subnets": subnets,
        "config_path": str(peer_file),
    }


def _get_wg_syncconf(config_path: Path) -> str:
    """Extract peer sections for wg syncconf."""
    content = config_path.read_text()
    lines = []
    in_peer = False

    for line in content.split('\n'):
        stripped = line.strip()
        if stripped.startswith('[Peer]'):
            in_peer = True
        if in_peer:
            # Skip comments
            if not stripped.startswith('#'):
                lines.append(line)

    return '\n'.join(lines)
