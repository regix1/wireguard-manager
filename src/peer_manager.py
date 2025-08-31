#!/usr/bin/env python3
"""
Peer Management
"""

import json
import subprocess
import shutil
import ipaddress
from pathlib import Path
from datetime import datetime
from jinja2 import Template
from menu import MenuHandler
from utils import run_command, pause, print_status, load_template, load_defaults

class PeerManager:
    """Manage WireGuard peers"""
    
    def __init__(self, config_scanner):
        self.scanner = config_scanner
        self.menu = MenuHandler()
        self.defaults = load_defaults()
    
    def add_peer(self):
        """Add a new peer"""
        print("\n[Add New Peer]")
        print("-" * 50)
        
        # Select interface
        interfaces = self.scanner.get_interfaces()
        if not interfaces:
            print("No WireGuard interfaces configured!")
            print("Please create a server configuration first.")
            pause()
            return
        
        interface = self._select_interface(interfaces)
        if not interface:
            return
        
        # Get peer details
        peer_name = input("\nPeer name: ").strip()
        if not peer_name:
            print("Cancelled")
            return
        
        # Generate keys
        print("\nGenerating keys...")
        keys = self._generate_keys()
        
        # Get next available IP
        config_file = self.scanner.get_config_file(interface)
        peer_ip = self._get_next_ip(config_file)
        
        # Get server details
        server_details = self._get_server_details(config_file)
        
        # Create peer config from template
        peer_config = self._generate_peer_config(
            peer_name=peer_name,
            peer_ip=peer_ip,
            keys=keys,
            server_details=server_details
        )
        
        # Save peer config
        peer_dir = self.scanner.get_config_dir() / "peers"
        peer_dir.mkdir(exist_ok=True)
        
        peer_file = peer_dir / f"{peer_name}.conf"
        peer_file.write_text(peer_config)
        
        # Add peer to server config
        self._add_peer_to_server(config_file, peer_name, peer_ip, keys)
        
        print(f"\n✓ Peer '{peer_name}' added successfully!")
        print(f"  IP: {peer_ip}/32")
        print(f"  Config: {peer_file}")
        
        # Restart interface if active
        if self._is_interface_active(interface):
            if self.menu.confirm("Restart interface to apply changes?"):
                run_command(["systemctl", "restart", f"wg-quick@{interface}"])
        
        pause()
    
    def remove_peer(self):
        """Remove a peer"""
        print("\n[Remove Peer]")
        print("-" * 50)
        
        # Get all peers
        peers = self._get_all_peers()
        
        if not peers:
            print("No peers configured")
            pause()
            return
        
        # Select peer
        peer_names = list(peers.keys())
        choice = self.menu.show_menu(peer_names, "Select peer to remove:")
        
        if choice is None:
            return
        
        peer_name = peer_names[choice]
        
        # Confirm
        if not self.menu.confirm(f"Remove peer '{peer_name}'?"):
            return
        
        # Remove from server config
        for interface, peer_list in peers.items():
            if peer_name in [p['name'] for p in peer_list]:
                config_file = self.scanner.get_config_file(interface)
                self._remove_peer_from_server(config_file, peer_name)
                
                # Restart interface if active
                if self._is_interface_active(interface):
                    run_command(["systemctl", "restart", f"wg-quick@{interface}"])
        
        # Remove peer config file
        peer_file = self.scanner.get_config_dir() / "peers" / f"{peer_name}.conf"
        if peer_file.exists():
            peer_file.unlink()
        
        print_status(f"Peer '{peer_name}' removed", True)
        pause()
    
    def list_peers(self):
        """List all configured peers"""
        print("\n[Configured Peers]")
        print("-" * 50)
        
        peers = self._get_all_peers()
        
        if not peers:
            print("No peers configured")
        else:
            for interface, peer_list in peers.items():
                print(f"\nInterface: {interface}")
                for peer in peer_list:
                    print(f"  • {peer['name']}: {peer['ip']}")
        
        pause()
    
    def backup_config(self):
        """Backup all configurations"""
        print("\n[Backup Configuration]")
        print("-" * 50)
        
        backup_dir = Path.home() / f"wireguard-backup-{datetime.now():%Y%m%d-%H%M%S}"
        config_dir = self.scanner.get_config_dir()
        
        if not config_dir.exists():
            print("No configuration to backup")
            pause()
            return
        
        print(f"Backing up to: {backup_dir}")
        shutil.copytree(config_dir, backup_dir)
        
        print_status("Backup completed", True)
        print(f"Location: {backup_dir}")
        pause()
    
    def restore_config(self):
        """Restore configuration from backup"""
        print("\n[Restore Configuration]")
        print("-" * 50)
        
        # Find backup directories
        backups = sorted(Path.home().glob("wireguard-backup-*"))
        
        if not backups:
            print("No backups found")
            pause()
            return
        
        # Select backup
        backup_names = [b.name for b in backups]
        choice = self.menu.show_menu(backup_names, "Select backup to restore:")
        
        if choice is None:
            return
        
        backup_dir = backups[choice]
        
        # Confirm
        if not self.menu.confirm(f"Restore from {backup_dir.name}?"):
            return
        
        # Stop all interfaces
        for interface in self.scanner.get_interfaces():
            run_command(["systemctl", "stop", f"wg-quick@{interface}"], check=False)
        
        # Restore
        config_dir = self.scanner.get_config_dir()
        if config_dir.exists():
            shutil.rmtree(config_dir)
        
        shutil.copytree(backup_dir, config_dir)
        
        print_status("Configuration restored", True)
        pause()
    
    def _select_interface(self, interfaces):
        """Select an interface"""
        if len(interfaces) == 1:
            return interfaces[0]
        
        choice = self.menu.show_menu(interfaces, "Select interface:")
        if choice is None:
            return None
        
        return interfaces[choice]
    
    def _generate_keys(self):
        """Generate WireGuard keys"""
        private_key = subprocess.check_output(["wg", "genkey"]).decode().strip()
        public_key = subprocess.check_output(["wg", "pubkey"], input=private_key.encode()).decode().strip()
        preshared_key = subprocess.check_output(["wg", "genpsk"]).decode().strip()
        
        return {
            "private": private_key,
            "public": public_key,
            "preshared": preshared_key
        }
    
    def _get_next_ip(self, config_file):
        """Get next available IP address"""
        if not config_file or not config_file.exists():
            return self.defaults["default_peer_ip"]
        
        config_text = config_file.read_text()
        
        # Find subnet
        subnet = None
        for line in config_text.split('\n'):
            if line.strip().startswith("Address"):
                addr = line.split('=')[1].strip()
                subnet = ipaddress.ip_network(addr, strict=False)
                break
        
        if not subnet:
            subnet = ipaddress.ip_network(self.defaults["default_subnet"])
        
        # Find used IPs
        used_ips = {str(list(subnet.hosts())[0])}  # Server IP
        
        for line in config_text.split('\n'):
            if "AllowedIPs" in line:
                ips = line.split('=')[1].strip()
                for ip in ips.split(','):
                    ip = ip.strip().split('/')[0]
                    if ip:
                        used_ips.add(ip)
        
        # Find next available
        for ip in subnet.hosts():
            if str(ip) not in used_ips:
                return str(ip)
        
        return str(list(subnet.hosts())[100])  # Fallback
    
    def _get_server_details(self, config_file):
        """Extract server details from config"""
        details = {
            "public_key": "",
            "endpoint": "",
            "port": self.defaults["default_port"]
        }
        
        if config_file and config_file.exists():
            config_text = config_file.read_text()
            
            # Extract public key
            for line in config_text.split('\n'):
                if line.strip().startswith("PrivateKey"):
                    private_key = line.split('=')[1].strip()
                    result = subprocess.run(
                        ["wg", "pubkey"],
                        input=private_key.encode(),
                        capture_output=True
                    )
                    details["public_key"] = result.stdout.decode().strip()
                    break
            
            # Extract port
            for line in config_text.split('\n'):
                if line.strip().startswith("ListenPort"):
                    details["port"] = line.split('=')[1].strip()
                    break
        
        # Get endpoint
        endpoint_ip = input("Server endpoint IP: ").strip()
        if not endpoint_ip:
            endpoint_ip = self.defaults["default_endpoint"]
        
        details["endpoint"] = f"{endpoint_ip}:{details['port']}"
        
        return details
    
    def _generate_peer_config(self, peer_name, peer_ip, keys, server_details):
        """Generate peer configuration from template"""
        template = load_template("peer.conf.j2")
        
        return template.render(
            peer_name=peer_name,
            private_key=keys["private"],
            address=f"{peer_ip}/24",
            dns=self.defaults["dns_servers"],
            server_public_key=server_details["public_key"],
            preshared_key=keys["preshared"],
            endpoint=server_details["endpoint"],
            keepalive=self.defaults["keepalive"]
        )
    
    def _add_peer_to_server(self, config_file, peer_name, peer_ip, keys):
        """Add peer to server configuration"""
        if not config_file or not config_file.exists():
            return
        
        template = load_template("server_peer.conf.j2")
        
        peer_section = template.render(
            peer_name=peer_name,
            public_key=keys["public"],
            preshared_key=keys["preshared"],
            allowed_ips=f"{peer_ip}/32",
            keepalive=self.defaults["keepalive"]
        )
        
        with open(config_file, "a") as f:
            f.write(f"\n{peer_section}")
    
    def _remove_peer_from_server(self, config_file, peer_name):
        """Remove peer from server configuration"""
        if not config_file or not config_file.exists():
            return
        
        lines = config_file.read_text().split('\n')
        new_lines = []
        skip = False
        
        for i, line in enumerate(lines):
            if f"# Peer: {peer_name}" in line:
                skip = True
                continue
            elif skip and line.strip().startswith("["):
                skip = False
            
            if not skip:
                new_lines.append(line)
        
        config_file.write_text('\n'.join(new_lines))
    
    def _is_interface_active(self, interface):
        """Check if interface is active"""
        result = run_command(["systemctl", "is-active", f"wg-quick@{interface}"], check=False)
        return result.stdout.strip() == "active"
    
    def _get_all_peers(self):
        """Get all configured peers"""
        peers = {}
        
        for interface in self.scanner.get_interfaces():
            config_file = self.scanner.get_config_file(interface)
            if config_file and config_file.exists():
                interface_peers = []
                config_text = config_file.read_text()
                
                for line in config_text.split('\n'):
                    if line.startswith("# Peer:"):
                        peer_name = line.replace("# Peer:", "").strip()
                        interface_peers.append({"name": peer_name, "ip": "unknown"})
                
                if interface_peers:
                    peers[interface] = interface_peers
        
        return peers
    
    def show_peer_config(self):
        """Show configuration for a specific peer."""
        print("\n[Show Peer Config]")
        print("-" * 50)
        
        peer_dir = self.scanner.get_config_dir() / "peers"
        if not peer_dir.exists():
            print("No peers configured")
            pause()
            return
        
        peer_files = list(peer_dir.glob("*.conf"))
        if not peer_files:
            print("No peer configurations found")
            pause()
            return
        
        peer_names = [f.stem for f in peer_files]
        choice = self.menu.show_menu(peer_names, "Select peer:")
        
        if choice is None:
            return
        
        peer_file = peer_files[choice]
        print(f"\nConfiguration for {peer_names[choice]}:")
        print("-" * 50)
        print(peer_file.read_text())
        pause()

    def generate_qr_code(self):
        """Generate QR code for peer configuration."""
        print("\n[Generate QR Code]")
        print("-" * 50)
        
        peer_dir = self.scanner.get_config_dir() / "peers"
        if not peer_dir.exists():
            print("No peers configured")
            pause()
            return
        
        peer_files = list(peer_dir.glob("*.conf"))
        if not peer_files:
            print("No peer configurations found")
            pause()
            return
        
        peer_names = [f.stem for f in peer_files]
        choice = self.menu.show_menu(peer_names, "Select peer for QR code:")
        
        if choice is None:
            return
        
        peer_file = peer_files[choice]
        
        # Check if qrencode is installed
        if shutil.which("qrencode") is None:
            print("qrencode is not installed!")
            if self.menu.confirm("Install qrencode?"):
                run_command(["apt-get", "install", "-y", "qrencode"], check=False)
        
        # Generate QR code
        print(f"\nQR Code for {peer_names[choice]}:")
        print("-" * 50)
        
        result = run_command(["qrencode", "-t", "ansiutf8"], 
                            input=peer_file.read_text(), 
                            check=False)
        
        if result.returncode == 0:
            print(result.stdout)
        else:
            print("Failed to generate QR code")
        
        pause()