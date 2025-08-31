"""Constants used throughout the application."""

import os
import json
from pathlib import Path

def get_app_version():
    """Get application version from VERSION file."""
    version_paths = [
        Path(__file__).parent.parent / "VERSION",
        Path.home() / "wireguard-manager" / "VERSION",
        Path("/etc/wireguard/wireguard-manager/VERSION"),
    ]
    
    for version_path in version_paths:
        if version_path.exists():
            return version_path.read_text().strip()
    
    return "2.0.0"

def load_defaults():
    """Load default configuration from JSON file."""
    defaults_paths = [
        Path(__file__).parent.parent / "data" / "defaults.json",
        Path.home() / "wireguard-manager" / "data" / "defaults.json",
        Path("/opt/wireguard-manager/data/defaults.json"),
        Path("/etc/wireguard/wireguard-manager/data/defaults.json"),
        Path("/etc/wireguard/defaults.json"),
    ]
    
    for defaults_path in defaults_paths:
        if defaults_path.exists():
            try:
                with open(defaults_path, 'r') as f:
                    return json.load(f)
            except Exception:
                pass
    
    # Return hardcoded defaults if file not found
    return {
        "server_port": 51820,
        "server_subnet": "10.0.0.0/24",
        "server_address": "10.0.0.1/24",
        "dns_servers": "1.1.1.1, 1.0.0.1",
        "keepalive": 25,
        "mtu": 1420,
        "external_interface": "eth0",
        "save_config": False,
        "allowed_ips": "0.0.0.0/0, ::/0",
        "public_ip": "auto",
        "backup_count": 10,
        "log_level": 1
    }

# Version
APP_VERSION = get_app_version()

# Paths
WIREGUARD_DIR = Path("/etc/wireguard")
BACKUP_DIR = WIREGUARD_DIR / "backups"
PEERS_DIR = WIREGUARD_DIR / "peers"
CONFIGS_DIR = WIREGUARD_DIR / "configs"

# Config files
DEFAULT_INTERFACE = "wg0"
SERVER_CONFIG = WIREGUARD_DIR / f"{DEFAULT_INTERFACE}.conf"

# System
SYSTEMD_SERVICE = "wg-quick@{interface}"

# Load defaults
DEFAULT_CONFIG = load_defaults()

# Network defaults (from loaded config or fallback)
ALLOWED_IPS = DEFAULT_CONFIG.get("allowed_ips", "0.0.0.0/0, ::/0")
DEFAULT_PORT = DEFAULT_CONFIG.get("server_port", 51820)
DEFAULT_SUBNET = DEFAULT_CONFIG.get("server_subnet", "10.0.0.0/24")
DEFAULT_DNS = DEFAULT_CONFIG.get("dns_servers", "1.1.1.1, 1.0.0.1")