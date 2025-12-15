"""Configuration and constants for WireGuard Manager."""

import json
import yaml
from pathlib import Path
from typing import Dict, Any, Optional

# Paths
WIREGUARD_DIR = Path("/etc/wireguard")
BACKUP_DIR = WIREGUARD_DIR / "backups"
PEERS_DIR = WIREGUARD_DIR / "peers"
FIREWALL_DIR = WIREGUARD_DIR / "firewall"
KEYS_DIR = WIREGUARD_DIR / "keys"

# Default interface
DEFAULT_INTERFACE = "wg0"

# Default network settings
DEFAULTS = {
    "server_port": 51820,
    "server_subnet": "10.10.20.0/24",
    "server_address": "10.10.20.1/24",
    "dns_servers": "10.10.20.1",
    "keepalive": 25,
    "mtu": 1320,
    "external_interface": "eth0",
    "allowed_ips": "0.0.0.0/0, ::/0",
}


def get_version() -> str:
    """Get application version."""
    version_file = Path(__file__).parent.parent / "VERSION"
    if version_file.exists():
        return version_file.read_text().strip()
    return "3.0.0"


def load_config(path: Optional[Path] = None) -> Dict[str, Any]:
    """Load configuration from YAML file."""
    if path is None:
        path = WIREGUARD_DIR / "config.yaml"

    if path.exists():
        with open(path, 'r') as f:
            return yaml.safe_load(f) or {}
    return {}


def save_config(config: Dict[str, Any], path: Optional[Path] = None) -> None:
    """Save configuration to YAML file."""
    if path is None:
        path = WIREGUARD_DIR / "config.yaml"

    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, 'w') as f:
        yaml.dump(config, f, default_flow_style=False)


def get_interface_path(interface: str = DEFAULT_INTERFACE) -> Path:
    """Get path to interface config file."""
    return WIREGUARD_DIR / f"{interface}.conf"


def ensure_dirs() -> None:
    """Ensure all required directories exist."""
    for d in [WIREGUARD_DIR, BACKUP_DIR, PEERS_DIR, FIREWALL_DIR, KEYS_DIR]:
        d.mkdir(parents=True, exist_ok=True)
        d.chmod(0o700)
