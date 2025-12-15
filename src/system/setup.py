"""Initial WireGuard server setup."""

from pathlib import Path
from typing import Optional

from ..config import (
    WIREGUARD_DIR, KEYS_DIR, PEERS_DIR, FIREWALL_DIR,
    DEFAULTS, get_interface_path, ensure_dirs
)
from ..utils import generate_keypair, get_public_ip, enable_ip_forwarding, run


def init_server(
    interface: str = "wg0",
    port: int = None,
    subnet: str = None,
    address: str = None,
    dns: str = None,
    mtu: int = None,
    external_interface: str = None,
) -> bool:
    """
    Initialize WireGuard server with default configuration.

    Args:
        interface: Interface name
        port: Listen port
        subnet: Server subnet
        address: Server address
        dns: DNS servers
        mtu: MTU value
        external_interface: External network interface

    Returns:
        True if successful
    """
    # Use defaults if not specified
    port = port or DEFAULTS["server_port"]
    subnet = subnet or DEFAULTS["server_subnet"]
    address = address or DEFAULTS["server_address"]
    dns = dns or DEFAULTS["dns_servers"]
    mtu = mtu or DEFAULTS["mtu"]
    external_interface = external_interface or DEFAULTS["external_interface"]

    # Ensure directories exist
    ensure_dirs()

    config_path = get_interface_path(interface)
    if config_path.exists():
        print(f"Configuration already exists: {config_path}")
        print("Use --force to overwrite")
        return False

    # Generate keys
    private_key, public_key = generate_keypair()

    # Save keys
    KEYS_DIR.mkdir(parents=True, exist_ok=True)
    private_key_file = KEYS_DIR / f"{interface}_private.key"
    public_key_file = KEYS_DIR / f"{interface}_public.key"

    private_key_file.write_text(private_key)
    private_key_file.chmod(0o600)

    public_key_file.write_text(public_key)
    public_key_file.chmod(0o644)

    # Create server config
    config = f"""[Interface]
Address = {address}
ListenPort = {port}
PrivateKey = {private_key}
DNS = {dns}
MTU = {mtu}

# Enable IP forwarding on start
PreUp = sysctl -w net.ipv4.conf.all.forwarding=1

# Add NAT rules on start
PostUp = iptables -t nat -A POSTROUTING -o {external_interface} -s {subnet} -j MASQUERADE
PostUp = iptables -A FORWARD -i {interface} -j ACCEPT
PostUp = iptables -A FORWARD -i {external_interface} -o {interface} -j ACCEPT

# Remove NAT rules on stop
PostDown = iptables -t nat -D POSTROUTING -o {external_interface} -s {subnet} -j MASQUERADE
PostDown = iptables -D FORWARD -i {interface} -j ACCEPT
PostDown = iptables -D FORWARD -i {external_interface} -o {interface} -j ACCEPT
"""

    config_path.write_text(config)
    config_path.chmod(0o600)

    # Enable IP forwarding
    enable_ip_forwarding()

    print(f"Server initialized: {config_path}")
    print(f"  Address: {address}")
    print(f"  Port: {port}")
    print(f"  Public Key: {public_key}")
    print()
    print("Start the server with:")
    print(f"  wg-manager service start {interface}")

    return True


def create_server_config(
    interface: str = "wg0",
    port: int = None,
    address: str = None,
    dns: str = None,
    mtu: int = None,
    private_key: str = None,
    extra_addresses: list = None,
    post_up: list = None,
    post_down: list = None,
) -> bool:
    """
    Create a custom server configuration.

    This is for advanced setups like the hub-and-spoke topology.

    Args:
        interface: Interface name
        port: Listen port
        address: Primary server address
        dns: DNS servers
        mtu: MTU value
        private_key: Existing private key (generates new if None)
        extra_addresses: Additional addresses for the interface
        post_up: Custom PostUp commands
        post_down: Custom PostDown commands

    Returns:
        True if successful
    """
    ensure_dirs()

    config_path = get_interface_path(interface)

    # Use defaults
    port = port or DEFAULTS["server_port"]
    address = address or DEFAULTS["server_address"]
    dns = dns or DEFAULTS["dns_servers"]
    mtu = mtu or DEFAULTS["mtu"]

    # Generate or use provided key
    if private_key:
        priv_key = private_key
        # Generate public key from private
        result = run(["wg", "pubkey"], input_text=priv_key)
        pub_key = result.stdout.strip()
    else:
        priv_key, pub_key = generate_keypair()

    # Build address line
    addresses = [address]
    if extra_addresses:
        addresses.extend(extra_addresses)
    address_line = ", ".join(addresses)

    # Build config
    lines = [
        "[Interface]",
        f"Address = {address_line}",
        f"ListenPort = {port}",
        f"PrivateKey = {priv_key}",
        f"DNS = {dns}",
        f"MTU = {mtu}",
    ]

    # Add PreUp for IP forwarding
    lines.append("PreUp = sysctl -w net.ipv4.conf.all.forwarding=1")

    # Add custom PostUp
    if post_up:
        for cmd in post_up:
            lines.append(f"PostUp = {cmd}")

    # Add custom PostDown
    if post_down:
        for cmd in post_down:
            lines.append(f"PostDown = {cmd}")

    config = "\n".join(lines) + "\n"

    config_path.write_text(config)
    config_path.chmod(0o600)

    # Save keys
    KEYS_DIR.mkdir(parents=True, exist_ok=True)
    (KEYS_DIR / f"{interface}_private.key").write_text(priv_key)
    (KEYS_DIR / f"{interface}_public.key").write_text(pub_key)

    print(f"Created configuration: {config_path}")
    print(f"  Public Key: {pub_key}")

    return True


def get_endpoint() -> str:
    """Get server endpoint (public IP)."""
    return get_public_ip()
