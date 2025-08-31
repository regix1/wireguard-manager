#!/usr/bin/env python3
"""
Utility Functions
"""

import os
import json
import subprocess
from pathlib import Path
from typing import Dict, List
from jinja2 import Template

def clear_screen():
    """Clear the terminal screen"""
    os.system('clear' if os.name == 'posix' else 'cls')

def print_header():
    """Print application header"""
    print("=" * 50)
    print("       WireGuard Manager")
    print("=" * 50)

def pause():
    """Pause for user input"""
    input("\nPress Enter to continue...")

def print_status(message: str, success: bool = True):
    """Print status message with indicator"""
    indicator = "✓" if success else "✗"
    print(f"{indicator} {message}")

def run_command(cmd: List[str], check: bool = True, cwd: Path = None) -> subprocess.CompletedProcess:
    """Run a system command"""
    try:
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=check,
            cwd=cwd
        )
    except subprocess.CalledProcessError as e:
        if check:
            print(f"Error running command: {' '.join(cmd)}")
            if e.stderr:
                print(f"Error: {e.stderr}")
        return e

def load_template(template_name: str) -> Template:
    """Load a Jinja2 template"""
    template_dir = Path(__file__).parent.parent / "templates"
    template_file = template_dir / template_name
    
    if not template_file.exists():
        # Create default template if it doesn't exist
        create_default_templates()
        
    with open(template_file, "r") as f:
        return Template(f.read())

def load_defaults() -> Dict:
    """Load default configuration values"""
    defaults_file = Path(__file__).parent.parent / "data" / "defaults.json"
    
    if not defaults_file.exists():
        # Create default values
        defaults = {
            "default_port": "51820",
            "default_subnet": "10.10.20.0/24",
            "default_peer_ip": "10.10.20.2",
            "default_endpoint": "YOUR_SERVER_IP",
            "dns_servers": "1.1.1.1, 1.0.0.1",
            "keepalive": 25,
            "interface": "wg0",
            "external_interface": "eth0"
        }
        
        defaults_file.parent.mkdir(parents=True, exist_ok=True)
        with open(defaults_file, "w") as f:
            json.dump(defaults, f, indent=2)
        
        return defaults
    
    with open(defaults_file, "r") as f:
        return json.load(f)

def create_default_templates():
    """Create default Jinja2 templates"""
    template_dir = Path(__file__).parent.parent / "templates"
    template_dir.mkdir(parents=True, exist_ok=True)
    
    # Server configuration template
    server_template = """[Interface]
# WireGuard Server Configuration
PrivateKey = {{ private_key }}
Address = {{ address }}
ListenPort = {{ port }}
SaveConfig = false

# Post-up and post-down scripts
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o {{ external_interface }} -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o {{ external_interface }} -j MASQUERADE
"""
    
    # Peer configuration template
    peer_template = """[Interface]
# Name: {{ peer_name }}
PrivateKey = {{ private_key }}
Address = {{ address }}
DNS = {{ dns }}

[Peer]
PublicKey = {{ server_public_key }}
PresharedKey = {{ preshared_key }}
AllowedIPs = 0.0.0.0/0
Endpoint = {{ endpoint }}
PersistentKeepalive = {{ keepalive }}
"""
    
    # Server peer section template
    server_peer_template = """
# Peer: {{ peer_name }}
[Peer]
PublicKey = {{ public_key }}
PresharedKey = {{ preshared_key }}
AllowedIPs = {{ allowed_ips }}
PersistentKeepalive = {{ keepalive }}
"""
    
    # Interface template
    interface_template = """[Interface]
PrivateKey = {{ private_key }}
Address = {{ address }}
ListenPort = {{ port }}
"""
    
    # Save templates
    (template_dir / "server.conf.j2").write_text(server_template)
    (template_dir / "peer.conf.j2").write_text(peer_template)
    (template_dir / "server_peer.conf.j2").write_text(server_peer_template)
    (template_dir / "interface.conf.j2").write_text(interface_template)

def get_version() -> str:
    """Get current version from VERSION file"""
    version_file = Path(__file__).parent.parent / "VERSION"
    if version_file.exists():
        return version_file.read_text().strip()
    return "unknown"