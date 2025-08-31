"""Peer management for WireGuard."""

import ipaddress
import json
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional
from jinja2 import Template
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, IntPrompt

from .constants import WIREGUARD_DIR, PEERS_DIR, ALLOWED_IPS
from .utils import (
    generate_key_pair, generate_preshared_key,
    get_next_available_ip, ensure_directory, run_command
)
from .config_manager import ConfigManager

console = Console()

class PeerManager:
    """Manage WireGuard peers."""
    
    def __init__(self):
        """Initialize peer manager."""
        self.config_manager = ConfigManager()
        ensure_directory(PEERS_DIR, mode=0o700)
    
    def add_peer(self) -> None:
        """Add a new peer."""
        console.print(Panel.fit(
            "[bold cyan]Add New Peer[/bold cyan]",
            border_style="cyan"
        ))
        
        interfaces = self._get_interfaces()
        if not interfaces:
            console.print("[red]No WireGuard interfaces configured![/red]")
            console.print("[yellow]Please create a server configuration first.[/yellow]")
            return
        
        if len(interfaces) == 1:
            interface = interfaces[0]
        else:
            console.print("[cyan]Available interfaces:[/cyan]")
            for i, iface in enumerate(interfaces, 1):
                console.print(f"  {i}. {iface}")
            
            choice = IntPrompt.ask(
                "Select interface",
                choices=[str(i) for i in range(1, len(interfaces) + 1)]
            )
            interface = interfaces[choice - 1]
        
        console.print(f"[cyan]Adding peer to interface:[/cyan] {interface}")
        
        peer_name = Prompt.ask("\nPeer name (e.g., john-laptop)")
        if not peer_name:
            console.print("[yellow]Cancelled[/yellow]")
            return
        
        peer_config = PEERS_DIR / f"{peer_name}.conf"
        if peer_config.exists():
            console.print(f"[red]Peer '{peer_name}' already exists![/red]")
            return
        
        config = self.config_manager.load_config()
        server_config_file = WIREGUARD_DIR / f"{interface}.conf"
        
        if not server_config_file.exists():
            console.print(f"[red]Server configuration not found for {interface}![/red]")
            return
        
        console.print("\n[cyan]Generating keys...[/cyan]")
        private_key, public_key = generate_key_pair()
        preshared_key = generate_preshared_key()
        
        server_public_key = self._get_server_public_key(interface)
        if not server_public_key:
            console.print("[red]Could not retrieve server public key![/red]")
            return
        
        used_ips = self._get_used_ips(server_config_file)
        subnet = config.get('server_subnet', '10.0.0.0/24')
        
        try:
            peer_ip = get_next_available_ip(subnet, used_ips)
        except ValueError as e:
            console.print(f"[red]Error: {e}[/red]")
            return
        
        endpoint_ip = config.get('public_ip', 'YOUR_SERVER_IP')
        endpoint_port = config.get('server_port', 51820)
        endpoint = f"{endpoint_ip}:{endpoint_port}"
        
        peer_config_content = self._generate_peer_config(
            peer_name=peer_name,
            private_key=private_key,
            peer_ip=peer_ip,
            dns=config.get('dns_servers', '1.1.1.1, 1.0.0.1'),
            server_public_key=server_public_key,
            preshared_key=preshared_key,
            endpoint=endpoint,
            keepalive=config.get('keepalive', 25),
            mtu=config.get('mtu', 1420)
        )
        
        peer_config.write_text(peer_config_content)
        peer_config.chmod(0o600)
        
        self._add_peer_to_server(
            server_config_file,
            peer_name,
            public_key,
            preshared_key,
            peer_ip
        )
        
        self._save_peer_metadata(peer_name, {
            'interface': interface,
            'ip': peer_ip,
            'public_key': public_key,
            'created': datetime.now().isoformat()
        })
        
        console.print(f"\n[green]✓[/green] Peer '{peer_name}' added successfully!")
        console.print(f"[cyan]IP Address:[/cyan] {peer_ip}")
        console.print(f"[cyan]Config file:[/cyan] {peer_config}")
        
        if Prompt.ask("\nGenerate QR code for mobile?", choices=["y", "n"], default="n") == "y":
            self._show_qr_code(peer_config_content)
        
        console.print("\n[yellow]Note: Restart the WireGuard interface to apply changes[/yellow]")
    
    def remove_peer(self) -> None:
        """Remove a peer."""
        console.print(Panel.fit(
            "[bold cyan]Remove Peer[/bold cyan]",
            border_style="cyan"
        ))
        
        peers = self._get_all_peers()
        if not peers:
            console.print("[yellow]No peers configured[/yellow]")
            return
        
        console.print("[cyan]Configured peers:[/cyan]")
        peer_list = []
        for i, (name, info) in enumerate(peers.items(), 1):
            console.print(f"  {i}. {name} ({info.get('ip', 'unknown')})")
            peer_list.append(name)
        
        choice = IntPrompt.ask(
            "\nSelect peer to remove (0 to cancel)",
            choices=[str(i) for i in range(0, len(peer_list) + 1)]
        )
        
        if choice == 0:
            return
        
        peer_name = peer_list[choice - 1]
        
        if not Prompt.ask(
            f"[red]Remove peer '{peer_name}'?[/red]",
            choices=["y", "n"],
            default="n"
        ) == "y":
            return
        
        peer_info = peers[peer_name]
        interface = peer_info.get('interface', 'wg0')
        server_config = WIREGUARD_DIR / f"{interface}.conf"
        
        if server_config.exists():
            self._remove_peer_from_server(server_config, peer_name)
        
        peer_config = PEERS_DIR / f"{peer_name}.conf"
        if peer_config.exists():
            peer_config.unlink()
        
        metadata_file = PEERS_DIR / f"{peer_name}.json"
        if metadata_file.exists():
            metadata_file.unlink()
        
        console.print(f"[green]✓[/green] Peer '{peer_name}' removed")
    
    def list_peers(self) -> None:
        """List all configured peers."""
        console.print(Panel.fit(
            "[bold cyan]Configured Peers[/bold cyan]",
            border_style="cyan"
        ))
        
        peers = self._get_all_peers()
        
        if not peers:
            console.print("[yellow]No peers configured[/yellow]")
            return
        
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("#", style="cyan", width=3)
        table.add_column("Name", style="cyan")
        table.add_column("IP Address")
        table.add_column("Interface")
        table.add_column("Created")
        
        for i, (name, info) in enumerate(peers.items(), 1):
            created = info.get('created', 'unknown')
            if created != 'unknown':
                try:
                    dt = datetime.fromisoformat(created)
                    created = dt.strftime("%Y-%m-%d %H:%M")
                except:
                    pass
            
            table.add_row(
                str(i),
                name,
                info.get('ip', 'unknown'),
                info.get('interface', 'unknown'),
                created
            )
        
        console.print(table)
    
    def show_qr_code(self) -> None:
        """Show QR code for a peer configuration."""
        console.print(Panel.fit(
            "[bold cyan]Generate QR Code[/bold cyan]",
            border_style="cyan"
        ))
        
        peer_configs = list(PEERS_DIR.glob("*.conf"))
        if not peer_configs:
            console.print("[yellow]No peer configurations found[/yellow]")
            return
        
        console.print("[cyan]Available peer configurations:[/cyan]")
        for i, config in enumerate(peer_configs, 1):
            console.print(f"  {i}. {config.stem}")
        
        choice = IntPrompt.ask(
            "Select peer",
            choices=[str(i) for i in range(1, len(peer_configs) + 1)]
        )
        
        peer_config = peer_configs[choice - 1]
        config_content = peer_config.read_text()
        
        console.print(f"\n[cyan]QR Code for {peer_config.stem}:[/cyan]")
        self._show_qr_code(config_content)
    
    def _get_interfaces(self) -> List[str]:
        """Get list of WireGuard interfaces."""
        interfaces = []
        
        # Skip patterns for non-interface config files
        skip_patterns = [
            'firewall', 'rules', 'backup', 'peer_', 
            'client', 'server_peer', 'banned', 'params'
        ]
        
        for conf_file in WIREGUARD_DIR.glob("*.conf"):
            filename = conf_file.stem
            
            # Skip non-WireGuard config files
            if any(pattern in filename.lower() for pattern in skip_patterns):
                continue
            
            # Skip backup files
            if filename.endswith('.bak') or filename.endswith('.old') or filename.endswith('.snat'):
                continue
            
            # Check if file contains [Interface] section
            try:
                content = conf_file.read_text()
                if '[Interface]' in content:
                    interfaces.append(filename)
            except Exception:
                continue
                
        return sorted(interfaces)
    
    def _get_server_public_key(self, interface: str) -> Optional[str]:
        """Get server public key."""
        key_file = WIREGUARD_DIR / "keys" / f"{interface}.pub"
        if key_file.exists():
            return key_file.read_text().strip()
        
        config_file = WIREGUARD_DIR / f"{interface}.conf"
        if config_file.exists():
            for line in config_file.read_text().split('\n'):
                if line.strip().startswith('PrivateKey'):
                    private_key = line.split('=')[1].strip()
                    result = run_command(
                        ["wg", "pubkey"],
                        input=private_key,
                        text=True,
                        capture_output=True,
                        check=False
                    )
                    if result.returncode == 0:
                        return result.stdout.strip()
        return None
    
    def _get_used_ips(self, config_file: Path) -> List[str]:
        """Get list of used IP addresses."""
        used_ips = []
        
        if config_file.exists():
            content = config_file.read_text()
            
            for line in content.split('\n'):
                if line.strip().startswith('Address'):
                    addr = line.split('=')[1].strip()
                    if '/' in addr:
                        addr = addr.split('/')[0]
                    used_ips.append(addr)
                
                if line.strip().startswith('AllowedIPs'):
                    ips = line.split('=')[1].strip()
                    for ip in ips.split(','):
                        ip = ip.strip()
                        if '/' in ip:
                            ip = ip.split('/')[0]
                        if ip and not ip.startswith('0.0.0.0'):
                            used_ips.append(ip)
        
        return used_ips
    
    def _generate_peer_config(self, **kwargs) -> str:
        """Generate peer configuration."""
        template = """[Interface]
# {{ peer_name }} - WireGuard Client Configuration
# Generated: {{ datetime.now().strftime('%Y-%m-%d %H:%M:%S') }}
PrivateKey = {{ private_key }}
Address = {{ peer_ip }}/32
DNS = {{ dns }}
{% if mtu %}MTU = {{ mtu }}{% endif %}

[Peer]
# Server
PublicKey = {{ server_public_key }}
PresharedKey = {{ preshared_key }}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = {{ endpoint }}
PersistentKeepalive = {{ keepalive }}"""
        
        from jinja2 import Template
        return Template(template).render(datetime=datetime, **kwargs)
    
    def _add_peer_to_server(self, config_file: Path, peer_name: str,
                           public_key: str, preshared_key: str, peer_ip: str) -> None:
        """Add peer to server configuration."""
        peer_section = f"""

# Peer: {peer_name}
# Added: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
[Peer]
PublicKey = {public_key}
PresharedKey = {preshared_key}
AllowedIPs = {peer_ip}/32"""
        
        with open(config_file, 'a') as f:
            f.write(peer_section)
    
    def _remove_peer_from_server(self, config_file: Path, peer_name: str) -> None:
        """Remove peer from server configuration."""
        lines = config_file.read_text().split('\n')
        new_lines = []
        skip = False
        
        for i, line in enumerate(lines):
            if f"# Peer: {peer_name}" in line:
                skip = True
                continue
            elif skip:
                if line.strip().startswith('[') and i > 0:
                    skip = False
                elif not line.strip():
                    for j in range(i + 1, len(lines)):
                        if lines[j].strip():
                            if lines[j].strip().startswith('[') or lines[j].strip().startswith('#'):
                                skip = False
                            break
            
            if not skip:
                new_lines.append(line)
        
        cleaned_lines = []
        prev_blank = False
        for line in new_lines:
            if not line.strip():
                if not prev_blank:
                    cleaned_lines.append(line)
                prev_blank = True
            else:
                cleaned_lines.append(line)
                prev_blank = False
        
        config_file.write_text('\n'.join(cleaned_lines))
    
    def _save_peer_metadata(self, peer_name: str, metadata: Dict) -> None:
        """Save peer metadata."""
        metadata_file = PEERS_DIR / f"{peer_name}.json"
        with open(metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2)
    
    def _get_all_peers(self) -> Dict[str, Dict]:
        """Get all peer information."""
        peers = {}
        
        for metadata_file in PEERS_DIR.glob("*.json"):
            peer_name = metadata_file.stem
            try:
                with open(metadata_file, 'r') as f:
                    peers[peer_name] = json.load(f)
            except:
                config_file = PEERS_DIR / f"{peer_name}.conf"
                if config_file.exists():
                    peers[peer_name] = {'interface': 'unknown', 'ip': 'unknown'}
        
        return peers
    
    def _show_qr_code(self, config_content: str) -> None:
        """Display QR code in terminal."""
        try:
            import qrcode
            qr = qrcode.QRCode()
            qr.add_data(config_content)
            qr.make()
            qr.print_ascii(invert=True)
        except ImportError:
            console.print("[yellow]qrcode library not installed[/yellow]")
            console.print("Install with: pip install qrcode[pil]")