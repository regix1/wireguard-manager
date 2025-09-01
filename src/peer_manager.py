"""Peer management for WireGuard."""

import ipaddress
import json
import re
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional, Set
from jinja2 import Template
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, IntPrompt

from .constants import WIREGUARD_DIR, PEERS_DIR, ALLOWED_IPS
from .utils import (
    generate_key_pair, generate_preshared_key,
    get_next_available_ip, ensure_directory, run_command, prompt_yes_no
)
from .config_manager import ConfigManager

console = Console()

class PeerManager:
    """Manage WireGuard peers."""
    
    def __init__(self):
        """Initialize peer manager."""
        self.config_manager = ConfigManager()
        ensure_directory(PEERS_DIR, mode=0o700)
        self.peer_dirs_config = WIREGUARD_DIR / "peer_directories.json"
        self.peer_directories = self._load_peer_directories()
    
    def _load_peer_directories(self) -> List[Path]:
        """Load configured peer directories from JSON."""
        default_dirs = [
            PEERS_DIR,
            Path("/home"),
            Path("/root"),
            WIREGUARD_DIR
        ]
        
        if self.peer_dirs_config.exists():
            try:
                with open(self.peer_dirs_config, 'r') as f:
                    data = json.load(f)
                    dirs = [Path(d) for d in data.get('directories', [])]
                    return dirs if dirs else default_dirs
            except Exception as e:
                console.print(f"[yellow]Warning: Could not load peer directories config: {e}[/yellow]")
        
        return default_dirs
    
    def _save_peer_directories(self, directories: List[Path]) -> None:
        """Save peer directories configuration."""
        data = {
            'directories': [str(d) for d in directories],
            'updated': datetime.now().isoformat()
        }
        
        try:
            with open(self.peer_dirs_config, 'w') as f:
                json.dump(data, f, indent=2)
            console.print(f"[green]✓ Saved peer directories configuration[/green]")
        except Exception as e:
            console.print(f"[red]Failed to save directories config: {e}[/red]")
    
    def configure_peer_directories(self) -> None:
        """Configure directories to scan for peer configurations."""
        console.print(Panel.fit(
            "[bold cyan]Configure Peer Directories[/bold cyan]",
            border_style="cyan"
        ))
        
        console.print("[cyan]Current directories being scanned:[/cyan]")
        for i, dir_path in enumerate(self.peer_directories, 1):
            exists = "✓" if dir_path.exists() else "✗"
            console.print(f"  {i}. [{exists}] {dir_path}")
        
        console.print("\n[cyan]Options:[/cyan]")
        console.print("  1. Add directory")
        console.print("  2. Remove directory")
        console.print("  3. Reset to defaults")
        console.print("  4. Scan for peer configs")
        console.print("  5. Back")
        
        choice = IntPrompt.ask("Select option", choices=["1", "2", "3", "4", "5"])
        
        if choice == 1:
            self._add_peer_directory()
        elif choice == 2:
            self._remove_peer_directory()
        elif choice == 3:
            self._reset_peer_directories()
        elif choice == 4:
            self._scan_for_configs()
    
    def _add_peer_directory(self) -> None:
        """Add a directory to scan for peer configs."""
        console.print("\n[cyan]Add Peer Directory[/cyan]")
        
        dir_path = Prompt.ask("Enter directory path to scan for peer configs")
        dir_path = Path(dir_path).expanduser().resolve()
        
        if not dir_path.exists():
            if prompt_yes_no(f"Directory {dir_path} doesn't exist. Create it?", default=False):
                try:
                    dir_path.mkdir(parents=True, exist_ok=True)
                    console.print(f"[green]✓ Created directory {dir_path}[/green]")
                except Exception as e:
                    console.print(f"[red]Failed to create directory: {e}[/red]")
                    return
            else:
                console.print("[yellow]Directory not added[/yellow]")
                return
        
        if dir_path not in self.peer_directories:
            self.peer_directories.append(dir_path)
            self._save_peer_directories(self.peer_directories)
            console.print(f"[green]✓ Added {dir_path} to peer directories[/green]")
        else:
            console.print(f"[yellow]Directory {dir_path} already in list[/yellow]")
    
    def _remove_peer_directory(self) -> None:
        """Remove a directory from the scan list."""
        if not self.peer_directories:
            console.print("[yellow]No directories configured[/yellow]")
            return
        
        console.print("\n[cyan]Remove Peer Directory[/cyan]")
        for i, dir_path in enumerate(self.peer_directories, 1):
            console.print(f"  {i}. {dir_path}")
        
        choice = IntPrompt.ask("Select directory to remove (0 to cancel)")
        if choice == 0:
            return
        
        if 1 <= choice <= len(self.peer_directories):
            removed = self.peer_directories.pop(choice - 1)
            self._save_peer_directories(self.peer_directories)
            console.print(f"[green]✓ Removed {removed}[/green]")
    
    def _reset_peer_directories(self) -> None:
        """Reset to default directories."""
        default_dirs = [
            PEERS_DIR,
            WIREGUARD_DIR
        ]
        
        self.peer_directories = default_dirs
        self._save_peer_directories(self.peer_directories)
        console.print("[green]✓ Reset to default directories[/green]")
    
    def _scan_for_configs(self) -> None:
        """Scan directories for peer configurations."""
        console.print("\n[cyan]Scanning for peer configurations...[/cyan]")
        
        found_configs = []
        
        for directory in self.peer_directories:
            if not directory.exists():
                continue
            
            # Recursively search for .conf files
            for conf_file in directory.rglob("*.conf"):
                # Skip server configs and special files
                if any(skip in conf_file.name.lower() for skip in 
                       ['firewall', 'rules', 'banned', 'server', 'params']):
                    continue
                
                # Skip main interface configs (wg0.conf, etc)
                if conf_file.parent == WIREGUARD_DIR and conf_file.stem in ['wg0', 'wg1', 'wg2']:
                    continue
                
                # Check if it's a peer config (has [Interface] and [Peer] sections)
                try:
                    content = conf_file.read_text()
                    if '[Interface]' in content and '[Peer]' in content:
                        # This looks like a peer config
                        found_configs.append(conf_file)
                except:
                    continue
        
        if found_configs:
            console.print(f"\n[green]Found {len(found_configs)} peer configuration(s):[/green]")
            
            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("#", width=3)
            table.add_column("File Name")
            table.add_column("Location")
            table.add_column("IP Address")
            
            for i, conf in enumerate(found_configs, 1):
                # Try to extract IP
                ip = "unknown"
                try:
                    content = conf.read_text()
                    ip_match = re.search(r'Address\s*=\s*([^/\n]+)', content)
                    if ip_match:
                        ip = ip_match.group(1).strip()
                except:
                    pass
                
                table.add_row(
                    str(i),
                    conf.name,
                    str(conf.parent),
                    ip
                )
            
            console.print(table)
            
            if prompt_yes_no("\nAdd these directories to the scan list?", default=True):
                new_dirs = set(self.peer_directories)
                for conf in found_configs:
                    new_dirs.add(conf.parent)
                
                self.peer_directories = list(new_dirs)
                self._save_peer_directories(self.peer_directories)
                console.print("[green]✓ Updated peer directories[/green]")
        else:
            console.print("[yellow]No peer configurations found[/yellow]")
    
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
        
        # Sanitize peer name
        peer_name = re.sub(r'[^a-zA-Z0-9\-_]', '-', peer_name)
        
        # Ask where to save the peer config
        console.print("\n[cyan]Where to save peer configuration?[/cyan]")
        console.print(f"  1. Default location ({PEERS_DIR})")
        console.print("  2. Custom location")
        
        location_choice = IntPrompt.ask("Select location", choices=["1", "2"])
        
        if location_choice == 1:
            peer_dir = PEERS_DIR
        else:
            custom_path = Prompt.ask("Enter directory path", default=str(Path.home()))
            peer_dir = Path(custom_path).expanduser().resolve()
            
            if not peer_dir.exists():
                if prompt_yes_no(f"Create directory {peer_dir}?", default=True):
                    peer_dir.mkdir(parents=True, exist_ok=True)
                else:
                    console.print("[yellow]Cancelled[/yellow]")
                    return
            
            # Add to scan directories if not already there
            if peer_dir not in self.peer_directories:
                if prompt_yes_no(f"Add {peer_dir} to peer directories list?", default=True):
                    self.peer_directories.append(peer_dir)
                    self._save_peer_directories(self.peer_directories)
        
        peer_config = peer_dir / f"{interface}-client-{peer_name}.conf"
        
        if peer_config.exists():
            console.print(f"[red]Peer configuration already exists: {peer_config}[/red]")
            if not prompt_yes_no("Overwrite?", default=False):
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
            'config_path': str(peer_config),
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
        
        peers = self._get_all_peers_comprehensive()
        if not peers:
            console.print("[yellow]No peers configured[/yellow]")
            return
        
        console.print("[cyan]Configured peers:[/cyan]")
        peer_list = []
        for i, (name, info) in enumerate(peers.items(), 1):
            location = info.get('location', info.get('config_file', 'unknown'))
            console.print(f"  {i}. {name} ({info.get('ip', 'unknown')}) - {location}")
            peer_list.append((name, info))
        
        choice = IntPrompt.ask(
            "\nSelect peer to remove (0 to cancel)",
            choices=[str(i) for i in range(0, len(peer_list) + 1)]
        )
        
        if choice == 0:
            return
        
        peer_name, peer_info = peer_list[choice - 1]
        
        if not prompt_yes_no(f"Remove peer '{peer_name}'?", default=False):
            return
        
        # Remove from server config
        interface = peer_info.get('interface', 'wg0')
        server_config = WIREGUARD_DIR / f"{interface}.conf"
        
        if server_config.exists():
            self._remove_peer_from_server(server_config, peer_name)
        
        # Remove config file if exists
        if 'config_file' in peer_info:
            config_path = Path(peer_info['config_file'])
            if config_path.exists():
                config_path.unlink()
                console.print(f"[green]✓[/green] Removed config file: {config_path}")
        
        # Remove metadata
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
        
        # Get peers from all sources
        all_peers = self._get_all_peers_comprehensive()
        
        if not all_peers:
            console.print("[yellow]No peers configured[/yellow]")
            console.print("\n[cyan]Tips:[/cyan]")
            console.print("  1. Configure peer directories: Peer Management → Configure Directories")
            console.print("  2. Add a new peer: Peer Management → Add Peer")
            console.print("  3. Check /home/<user>/ directories for existing configs")
            return
        
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("#", style="cyan", width=3)
        table.add_column("Name", style="cyan")
        table.add_column("IP Address")
        table.add_column("Interface")
        table.add_column("Location")
        table.add_column("Status")
        
        # Get active peers
        active_peers = self._get_active_peers()
        
        for i, (name, info) in enumerate(all_peers.items(), 1):
            # Check if peer is active
            pub_key = info.get('public_key', '')
            status = "[green]Active[/green]" if pub_key in active_peers else "[red]Inactive[/red]"
            
            # Shorten location path for display
            location = info.get('location', 'unknown')
            if location != 'unknown' and len(location) > 30:
                location = "..." + location[-27:]
            
            table.add_row(
                str(i),
                name,
                info.get('ip', 'unknown'),
                info.get('interface', 'unknown'),
                location,
                status
            )
        
        console.print(table)
        console.print(f"\n[cyan]Total peers found:[/cyan] {len(all_peers)}")
    
    def show_qr_code(self) -> None:
        """Show QR code for a peer configuration."""
        console.print(Panel.fit(
            "[bold cyan]Generate QR Code[/bold cyan]",
            border_style="cyan"
        ))
        
        # Get all peer configs
        peers = self._get_all_peers_comprehensive()
        
        if not peers:
            console.print("[yellow]No peer configurations found[/yellow]")
            return
        
        console.print("[cyan]Available peer configurations:[/cyan]")
        peer_list = []
        for i, (name, info) in enumerate(peers.items(), 1):
            config_file = info.get('config_file', 'unknown')
            console.print(f"  {i}. {name} - {config_file}")
            peer_list.append((name, info))
        
        choice = IntPrompt.ask(
            "Select peer",
            choices=[str(i) for i in range(1, len(peer_list) + 1)]
        )
        
        peer_name, peer_info = peer_list[choice - 1]
        
        if 'config_file' in peer_info:
            config_path = Path(peer_info['config_file'])
            if config_path.exists():
                config_content = config_path.read_text()
                console.print(f"\n[cyan]QR Code for {peer_name}:[/cyan]")
                self._show_qr_code(config_content)
            else:
                console.print(f"[red]Config file not found: {config_path}[/red]")
        else:
            console.print(f"[red]No config file path for {peer_name}[/red]")
    
    def _get_interfaces(self) -> List[str]:
        """Get list of WireGuard interfaces."""
        interfaces = []
        
        skip_patterns = [
            'firewall', 'rules', 'backup', 'peer_', 
            'client', 'server_peer', 'banned', 'params'
        ]
        
        for conf_file in WIREGUARD_DIR.glob("*.conf"):
            filename = conf_file.stem
            
            if any(pattern in filename.lower() for pattern in skip_patterns):
                continue
            
            if filename.endswith('.bak') or filename.endswith('.old') or filename.endswith('.snat') or filename.endswith('.working'):
                continue
            
            try:
                content = conf_file.read_text()
                if '[Interface]' in content:
                    interfaces.append(filename)
            except Exception:
                continue
                
        return sorted(interfaces)
    
    def _get_server_public_key(self, interface: str) -> Optional[str]:
        """Get server public key - extract from config, not from pre-made files."""
        # Try to get from running interface first
        result = run_command(["wg", "show", interface, "public-key"], check=False)
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
        
        # Extract private key from config and generate public key
        config_file = WIREGUARD_DIR / f"{interface}.conf"
        if config_file.exists():
            try:
                content = config_file.read_text()
                
                for line in content.split('\n'):
                    line = line.strip()
                    if line.startswith('PrivateKey'):
                        if '=' in line:
                            private_key = line.split('=', 1)[1].strip()
                            
                            if private_key:
                                # Generate public key from private key
                                result = run_command(
                                    ["wg", "pubkey"],
                                    input=private_key + '\n',
                                    text=True,
                                    capture_output=True,
                                    check=False
                                )
                                
                                if result.returncode == 0:
                                    return result.stdout.strip()
            except Exception as e:
                console.print(f"[red]Error reading config: {e}[/red]")
        
        console.print(f"[red]Could not find public key for {interface}[/red]")
        console.print("[yellow]Make sure the interface is configured with a PrivateKey[/yellow]")
        
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
                        if ip and not ip.startswith('0.0.0.0') and not ip.startswith('::'):
                            used_ips.append(ip)
        
        return used_ips
    
    def _get_all_peers_comprehensive(self) -> Dict[str, Dict]:
        """Get all peers from all configured directories."""
        all_peers = {}
        
        # Scan all configured directories
        for directory in self.peer_directories:
            if not directory.exists():
                continue
            
            # Look for .conf files
            for conf_file in directory.rglob("*.conf"):
                # Skip non-peer configs
                if any(skip in conf_file.name.lower() for skip in 
                       ['firewall', 'rules', 'banned', 'server', 'params']):
                    continue
                
                # Skip main server configs
                if conf_file.parent == WIREGUARD_DIR and conf_file.stem in ['wg0', 'wg1', 'wg2']:
                    continue
                
                try:
                    content = conf_file.read_text()
                    
                    # Check if it's a peer config
                    if '[Interface]' in content and '[Peer]' in content:
                        # Extract info
                        peer_name = conf_file.stem
                        
                        # Clean up common naming patterns
                        for pattern in ['wg0-client-', 'wg1-client-', 'client-', '-client']:
                            peer_name = peer_name.replace(pattern, '')
                        
                        # Extract IP
                        ip = "unknown"
                        ip_match = re.search(r'Address\s*=\s*([^/\n]+)', content)
                        if ip_match:
                            ip = ip_match.group(1).strip()
                        
                        # Extract public key if possible
                        pub_key = ""
                        if 'PrivateKey' in content:
                            priv_match = re.search(r'PrivateKey\s*=\s*([^\n]+)', content)
                            if priv_match:
                                private_key = priv_match.group(1).strip()
                                # Generate public key
                                result = run_command(
                                    ["wg", "pubkey"],
                                    input=private_key + '\n',
                                    text=True,
                                    capture_output=True,
                                    check=False
                                )
                                if result.returncode == 0:
                                    pub_key = result.stdout.strip()
                        
                        # Determine interface
                        interface = "unknown"
                        if 'wg0' in conf_file.name:
                            interface = "wg0"
                        elif 'wg1' in conf_file.name:
                            interface = "wg1"
                        
                        all_peers[peer_name] = {
                            'ip': ip,
                            'interface': interface,
                            'location': str(conf_file.parent),
                            'config_file': str(conf_file),
                            'public_key': pub_key
                        }
                        
                except Exception:
                    continue
        
        # Also check metadata files
        for metadata_file in PEERS_DIR.glob("*.json"):
            peer_name = metadata_file.stem
            try:
                with open(metadata_file, 'r') as f:
                    data = json.load(f)
                    if peer_name not in all_peers:
                        all_peers[peer_name] = data
            except:
                pass
        
        # Also scan server configs for peers
        server_peers = self._get_peers_from_server_configs()
        for name, info in server_peers.items():
            if name not in all_peers:
                all_peers[name] = info
        
        return all_peers
    
    def _get_peers_from_server_configs(self) -> Dict[str, Dict]:
        """Extract peer information from server configuration files."""
        peers = {}
        
        for interface_file in self._get_interfaces():
            config_file = WIREGUARD_DIR / f"{interface_file}.conf"
            if not config_file.exists():
                continue
            
            content = config_file.read_text()
            
            peer_pattern = r'#\s*Peer:\s*(.+?)\n.*?\[Peer\].*?AllowedIPs\s*=\s*([^\n]+)'
            matches = re.finditer(peer_pattern, content, re.DOTALL)
            
            for match in matches:
                peer_name = match.group(1).strip()
                allowed_ips = match.group(2).strip()
                
                ip = allowed_ips.split('/')[0] if '/' in allowed_ips else allowed_ips
                
                peers[peer_name] = {
                    'interface': interface_file,
                    'ip': ip,
                    'location': 'server_config',
                    'source': 'config'
                }
        
        return peers
    
    def _get_active_peers(self) -> List[str]:
        """Get list of active peer public keys."""
        active = []
        
        result = run_command(["wg", "show", "all", "peers"], check=False)
        if result.returncode == 0 and result.stdout:
            active = result.stdout.strip().split('\n')
        
        return active
    
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