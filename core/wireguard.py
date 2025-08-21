"""WireGuard management operations."""

import os
import subprocess
import logging
import ipaddress
import qrcode
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from datetime import datetime

from config.settings import Settings
from core.utils import run_command, validate_ip, validate_subnet, sanitize_filename
from models.peer import Peer

class WireGuardManager:
    """Manages WireGuard configuration and operations."""
    
    def __init__(self, settings: Settings):
        """Initialize WireGuard manager."""
        self.settings = settings
        self.logger = logging.getLogger(__name__)
        self.config_file = Path(self.settings.wireguard.config_dir) / f"{self.settings.wireguard.interface_name}.conf"
        
    def get_status(self) -> Dict:
        """Get WireGuard status."""
        status = {
            'active': False,
            'interface': self.settings.wireguard.interface_name,
            'peers': [],
            'server_public_key': '',
            'server_ip': '',
            'listening_port': 0,
            'total_rx': 0,
            'total_tx': 0
        }
        
        try:
            # Check if service is active
            result = run_command(['systemctl', 'is-active', f'wg-quick@{self.settings.wireguard.interface_name}'], check=False)
            status['active'] = result.stdout.strip() == 'active'
            
            if status['active']:
                # Get interface details
                result = run_command(['wg', 'show', self.settings.wireguard.interface_name], check=False)
                if result.returncode == 0:
                    self._parse_wg_show(result.stdout, status)
            
            # Get server public key if exists
            server_pubkey_file = Path(self.settings.wireguard.keys_dir) / "server.public"
            if server_pubkey_file.exists():
                status['server_public_key'] = server_pubkey_file.read_text().strip()
            
        except Exception as e:
            self.logger.error(f"Error getting WireGuard status: {e}")
        
        return status
    
    def _parse_wg_show(self, output: str, status: Dict) -> None:
        """Parse wg show output."""
        lines = output.strip().split('\n')
        current_peer = None
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            if line.startswith('interface:'):
                continue
            elif line.startswith('public key:'):
                if current_peer is None:
                    status['server_public_key'] = line.split(':', 1)[1].strip()
                else:
                    current_peer['public_key'] = line.split(':', 1)[1].strip()
            elif line.startswith('private key:'):
                continue  # Don't expose private key
            elif line.startswith('listening port:'):
                try:
                    status['listening_port'] = int(line.split(':', 1)[1].strip())
                except ValueError:
                    status['listening_port'] = 0
            elif line.startswith('peer:'):
                if current_peer:
                    status['peers'].append(current_peer)
                current_peer = {
                    'public_key': line.split(':', 1)[1].strip(),
                    'endpoint': '',
                    'allowed_ips': [],
                    'latest_handshake': '',
                    'transfer_rx': 0,
                    'transfer_tx': 0,
                    'persistent_keepalive': 0
                }
            elif line.startswith('endpoint:') and current_peer:
                current_peer['endpoint'] = line.split(':', 1)[1].strip()
            elif line.startswith('allowed ips:') and current_peer:
                ips = line.split(':', 1)[1].strip()
                current_peer['allowed_ips'] = [ip.strip() for ip in ips.split(',')]
            elif line.startswith('latest handshake:') and current_peer:
                current_peer['latest_handshake'] = line.split(':', 1)[1].strip()
            elif line.startswith('transfer:') and current_peer:
                parts = line.split(':', 1)[1].strip().split(',')
                for part in parts:
                    if 'received' in part:
                        current_peer['transfer_rx'] = self._parse_bytes(part)
                        status['total_rx'] += current_peer['transfer_rx']
                    elif 'sent' in part:
                        current_peer['transfer_tx'] = self._parse_bytes(part)
                        status['total_tx'] += current_peer['transfer_tx']
            elif line.startswith('persistent keepalive:') and current_peer:
                try:
                    keepalive_str = line.split(':', 1)[1].strip().split()[0]
                    if keepalive_str.lower() not in ['every', 'off', 'none']:
                        current_peer['persistent_keepalive'] = int(keepalive_str)
                    else:
                        current_peer['persistent_keepalive'] = 0
                except (ValueError, IndexError):
                    current_peer['persistent_keepalive'] = 0
        
        if current_peer:
            status['peers'].append(current_peer)
    
    def _parse_bytes(self, text: str) -> int:
        """Parse byte string to integer."""
        import re
        match = re.search(r'([\d.]+)\s*([KMGT]?i?B)', text)
        if match:
            value = float(match.group(1))
            unit = match.group(2)
            multipliers = {
                'B': 1, 'KB': 1024, 'KiB': 1024,
                'MB': 1024**2, 'MiB': 1024**2,
                'GB': 1024**3, 'GiB': 1024**3,
                'TB': 1024**4, 'TiB': 1024**4
            }
            return int(value * multipliers.get(unit, 1))
        return 0
    
    def start(self) -> None:
        """Start WireGuard service."""
        self.logger.info("Starting WireGuard...")
        run_command(['systemctl', 'start', f'wg-quick@{self.settings.wireguard.interface_name}'])
        run_command(['systemctl', 'enable', f'wg-quick@{self.settings.wireguard.interface_name}'])
    
    def stop(self) -> None:
        """Stop WireGuard service."""
        self.logger.info("Stopping WireGuard...")
        run_command(['systemctl', 'stop', f'wg-quick@{self.settings.wireguard.interface_name}'])
    
    def restart(self) -> None:
        """Restart WireGuard service."""
        self.logger.info("Restarting WireGuard...")
        run_command(['systemctl', 'restart', f'wg-quick@{self.settings.wireguard.interface_name}'])
    
    def generate_keys(self) -> Dict[str, str]:
        """Generate WireGuard key pair."""
        # Generate private key
        private_key_proc = run_command(['wg', 'genkey'])
        private_key = private_key_proc.stdout.strip()
        
        # Generate public key
        public_key_proc = run_command(['wg', 'pubkey'], input=private_key)
        public_key = public_key_proc.stdout.strip()
        
        # Generate preshared key
        preshared_proc = run_command(['wg', 'genpsk'])
        preshared_key = preshared_proc.stdout.strip()
        
        return {
            'private': private_key,
            'public': public_key,
            'preshared': preshared_key
        }
    
    def generate_server_config(self, port: int, subnet: str, dns: str, public_ip: str) -> str:
        """Generate server configuration."""
        keys = self.generate_keys()
        
        # Save keys
        keys_dir = Path(self.settings.wireguard.keys_dir)
        keys_dir.mkdir(parents=True, exist_ok=True)
        
        (keys_dir / "server.private").write_text(keys['private'])
        (keys_dir / "server.public").write_text(keys['public'])
        (keys_dir / "preshared.key").write_text(keys['preshared'])
        
        # Update server settings
        self.settings.server.public_ip = public_ip
        self.settings.wireguard.default_port = port
        self.settings.wireguard.default_subnet = subnet
        self.settings.wireguard.default_dns = dns
        self.settings.save()
        
        # Generate config
        config = f"""# WireGuard Server Configuration
# Generated: {datetime.now()}

[Interface]
PrivateKey = {keys['private']}
ListenPort = {port}
Address = {subnet}

# Enable NAT
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o {self.settings.firewall.external_interface} -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o {self.settings.firewall.external_interface} -j MASQUERADE

# Enable IP forwarding
PreUp = sysctl -w net.ipv4.conf.all.forwarding=1

"""
        return config
    
    def add_peer(self, peer: Peer) -> Dict:
        """Add a new peer."""
        # Generate keys for peer
        keys = self.generate_keys()
        peer.private_key = keys['private']
        peer.public_key = keys['public']
        
        # Get next available IP
        peer.ip_address = self._get_next_peer_ip()
        
        # Add to server config
        self._add_peer_to_server_config(peer, keys['preshared'])
        
        # Generate peer config
        peer_config = self._generate_peer_config(peer, keys['preshared'])
        
        # Save peer config
        config_dir = Path(self.settings.wireguard.config_dir) / "peers"
        config_dir.mkdir(parents=True, exist_ok=True)
        
        safe_name = sanitize_filename(peer.name)
        config_file = config_dir / f"{safe_name}.conf"
        config_file.write_text(peer_config)
        
        # Generate QR code if possible
        qr_file = None
        try:
            qr = qrcode.QRCode(version=1, box_size=10, border=5)
            qr.add_data(peer_config)
            qr.make(fit=True)
            img = qr.make_image(fill_color="black", back_color="white")
            qr_file = config_dir / f"{safe_name}.png"
            img.save(str(qr_file))
        except Exception as e:
            self.logger.warning(f"Failed to generate QR code: {e}")
        
        # Reload WireGuard if active
        status = self.get_status()
        if status['active']:
            self.restart()
        
        return {
            'config_file': str(config_file),
            'qr_file': str(qr_file) if qr_file else None,
            'public_key': peer.public_key,
            'ip_address': peer.ip_address
        }
    
    def _get_next_peer_ip(self) -> str:
        """Get next available peer IP address."""
        subnet = ipaddress.ip_network(self.settings.wireguard.default_subnet, strict=False)
        used_ips = set()
        
        # Get server IP
        server_ip = str(list(subnet.hosts())[0])
        used_ips.add(server_ip)
        
        # Get existing peer IPs
        if self.config_file.exists():
            config_text = self.config_file.read_text()
            for line in config_text.split('\n'):
                if 'AllowedIPs' in line:
                    ips = line.split('=', 1)[1].strip()
                    for ip in ips.split(','):
                        ip = ip.strip().split('/')[0]
                        if ip:
                            used_ips.add(ip)
        
        # Find next available
        for ip in subnet.hosts():
            if str(ip) not in used_ips:
                return str(ip)
        
        raise ValueError("No available IPs in subnet")
    
    def _add_peer_to_server_config(self, peer: Peer, preshared_key: str) -> None:
        """Add peer to server configuration."""
        peer_config = f"""
# Peer - {peer.name}
[Peer]
PublicKey = {peer.public_key}
PresharedKey = {preshared_key}
AllowedIPs = {peer.ip_address}/32"""
        
        if peer.is_router and peer.routed_networks:
            peer_config = f"""
# Peer - {peer.name} (Router)
[Peer]
PublicKey = {peer.public_key}
PresharedKey = {preshared_key}
AllowedIPs = {peer.ip_address}/32,{','.join(peer.routed_networks)}"""
        
        peer_config += f"""
PersistentKeepalive = {self.settings.server.persistent_keepalive}
"""
        
        # Append to server config
        if self.config_file.exists():
            with open(self.config_file, 'a') as f:
                f.write(peer_config)
        else:
            self.logger.warning("Server config file doesn't exist")
    
    def _generate_peer_config(self, peer: Peer, preshared_key: str) -> str:
        """Generate peer configuration file."""
        if peer.is_router:
            return self._generate_router_config(peer, preshared_key)
        
        # Get server public key
        server_pubkey_file = Path(self.settings.wireguard.keys_dir) / "server.public"
        server_pubkey = server_pubkey_file.read_text().strip() if server_pubkey_file.exists() else ""
        
        config = f"""[Interface]
# {peer.name}
PrivateKey = {peer.private_key}
Address = {peer.ip_address}/24
DNS = {self.settings.wireguard.default_dns}

[Peer]
PublicKey = {server_pubkey}
PresharedKey = {preshared_key}
AllowedIPs = 0.0.0.0/0
Endpoint = {self.settings.server.public_ip}:{self.settings.wireguard.default_port}
PersistentKeepalive = {self.settings.server.persistent_keepalive}
"""
        return config
    
    def _generate_router_config(self, peer: Peer, preshared_key: str) -> str:
        """Generate router configuration."""
        server_pubkey_file = Path(self.settings.wireguard.keys_dir) / "server.public"
        server_pubkey = server_pubkey_file.read_text().strip() if server_pubkey_file.exists() else ""
        
        config = f"""# Router Configuration for {peer.name}
# Generated: {datetime.now()}

## Router Details
- Name: {peer.name}
- VPN IP: {peer.ip_address}/24
- Routed Networks: {','.join(peer.routed_networks) if peer.routed_networks else 'None'}

## WireGuard Configuration

[Interface]
PrivateKey = {peer.private_key}
Address = {peer.ip_address}/24

[Peer]
PublicKey = {server_pubkey}
PresharedKey = {preshared_key}
AllowedIPs = 0.0.0.0/0
Endpoint = {self.settings.server.public_ip}:{self.settings.wireguard.default_port}
PersistentKeepalive = {self.settings.server.persistent_keepalive}
"""
        return config
    
    def remove_peer(self, public_key: str) -> bool:
        """Remove a peer from configuration."""
        if not self.config_file.exists():
            return False
        
        # Read current config
        lines = self.config_file.read_text().split('\n')
        new_lines = []
        skip_peer = False
        
        for line in lines:
            if line.strip().startswith('[Peer]'):
                skip_peer = False
            
            if f"PublicKey = {public_key}" in line:
                skip_peer = True
                # Remove the [Peer] line and comment before it
                if new_lines and '[Peer]' in new_lines[-1]:
                    new_lines.pop()
                if new_lines and new_lines[-1].startswith('#'):
                    new_lines.pop()
                continue
            
            if not skip_peer:
                new_lines.append(line)
            elif line.strip() and not line.strip().startswith(('PublicKey', 'PresharedKey', 'AllowedIPs', 'PersistentKeepalive', 'Endpoint')):
                skip_peer = False
                new_lines.append(line)
        
        # Write updated config
        self.config_file.write_text('\n'.join(new_lines))
        
        # Reload if active
        status = self.get_status()
        if status['active']:
            self.restart()
        
        return True
    
    def get_peers(self) -> List[Peer]:
        """Get list of configured peers."""
        peers = []
        
        if not self.config_file.exists():
            return peers
        
        config_text = self.config_file.read_text()
        lines = config_text.split('\n')
        
        current_peer = None
        for line in lines:
            line = line.strip()
            
            if line.startswith('# Peer -'):
                name = line.replace('# Peer -', '').strip()
                if '(Router)' in name:
                    name = name.replace('(Router)', '').strip()
                    current_peer = Peer(name=name, is_router=True)
                else:
                    current_peer = Peer(name=name)
            elif line.startswith('[Peer]') and current_peer is None:
                current_peer = Peer(name="Unknown")
            elif line.startswith('PublicKey =') and current_peer:
                current_peer.public_key = line.split('=', 1)[1].strip()
            elif line.startswith('AllowedIPs =') and current_peer:
                ips = line.split('=', 1)[1].strip()
                ip_list = [ip.strip() for ip in ips.split(',')]
                if ip_list:
                    # First IP is the peer's IP
                    current_peer.ip_address = ip_list[0].split('/')[0]
                    if len(ip_list) > 1:
                        current_peer.routed_networks = ip_list[1:]
            elif line.startswith('PersistentKeepalive =') and current_peer:
                try:
                    keepalive_val = line.split('=', 1)[1].strip()
                    if keepalive_val.lower() not in ['every', 'off', 'none']:
                        current_peer.keepalive = int(keepalive_val)
                    else:
                        current_peer.keepalive = 25
                except (ValueError, IndexError):
                    current_peer.keepalive = 25
                peers.append(current_peer)
                current_peer = None
        
        return peers
    
    def save_config(self) -> None:
        """Save current configuration."""
        self.settings.save()
        self.logger.info("Configuration saved")
    
    def load_config(self, config_file: str) -> None:
        """Load configuration from file."""
        source = Path(config_file)
        if source.exists():
            dest = Path(self.settings.wireguard.config_dir) / f"{self.settings.wireguard.interface_name}.conf"
            dest.write_text(source.read_text())
            self.logger.info(f"Configuration loaded from {config_file}")