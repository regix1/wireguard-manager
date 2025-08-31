"""Configuration management for WireGuard."""

import ipaddress
from pathlib import Path
from typing import Dict, Any, Optional
import yaml
from jinja2 import Template, Environment, FileSystemLoader
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, IntPrompt, Confirm
from rich.table import Table

from .constants import WIREGUARD_DIR, DEFAULT_CONFIG, DEFAULT_INTERFACE
from .utils import (
    ensure_directory, generate_key_pair, generate_preshared_key,
    get_server_ip, get_network_interfaces, prompt_yes_no
)

console = Console()

class ConfigManager:
    """Manage WireGuard configuration files."""
    
    def __init__(self):
        """Initialize the configuration manager."""
        self.setup_jinja_env()
    
    def setup_jinja_env(self):
        """Setup Jinja2 environment."""
        template_dirs = [
            Path(__file__).parent.parent / "data" / "templates",
            Path.home() / "wireguard-manager" / "data" / "templates",
        ]
        
        loaders = []
        for path in template_dirs:
            if path.exists():
                loaders.append(FileSystemLoader(str(path)))
        
        if loaders:
            from jinja2 import ChoiceLoader
            self.env = Environment(
                loader=ChoiceLoader(loaders),
                trim_blocks=True,
                lstrip_blocks=True,
            )
        else:
            # Create templates in memory if files don't exist
            self.env = Environment()
            self._create_default_templates()
    
    def _create_default_templates(self):
        """Create default templates in memory."""
        # Server template
        server_template = """[Interface]
# WireGuard Server Configuration
PrivateKey = {{ private_key }}
Address = {{ address }}
ListenPort = {{ port }}
SaveConfig = {{ save_config }}

PostUp = sysctl -w net.ipv4.ip_forward=1
PostUp = iptables -A FORWARD -i %i -j ACCEPT
PostUp = iptables -t nat -A POSTROUTING -o {{ external_interface }} -j MASQUERADE

PostDown = iptables -D FORWARD -i %i -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o {{ external_interface }} -j MASQUERADE"""
        
        self.env.from_string(server_template)
    
    def load_config(self) -> Dict[str, Any]:
        """Load current configuration or defaults."""
        config_file = WIREGUARD_DIR / "config.yaml"
        
        if config_file.exists():
            with open(config_file, 'r') as f:
                return yaml.safe_load(f) or DEFAULT_CONFIG.copy()
        
        return DEFAULT_CONFIG.copy()
    
    def save_config(self, config: Dict[str, Any]) -> None:
        """Save configuration to YAML file."""
        ensure_directory(WIREGUARD_DIR)
        config_file = WIREGUARD_DIR / "config.yaml"
        
        with open(config_file, 'w') as f:
            yaml.dump(config, f, default_flow_style=False)
    
    def create_server_config(self) -> None:
        """Create initial server configuration."""
        console.print(Panel.fit(
            "[bold cyan]Create WireGuard Server Configuration[/bold cyan]",
            border_style="cyan"
        ))
        
        # Check if config already exists
        interface = Prompt.ask("Interface name", default=DEFAULT_INTERFACE)
        config_file = WIREGUARD_DIR / f"{interface}.conf"
        
        if config_file.exists():
            if not prompt_yes_no(f"Configuration for {interface} already exists. Overwrite?", default=False):
                return
        
        config = self.load_config()
        
        # Get network configuration
        console.print("\n[cyan]Network Configuration[/cyan]")
        
        # Server IP
        public_ip = get_server_ip()
        config['public_ip'] = Prompt.ask("Server public IP", default=public_ip)
        
        # Port
        config['server_port'] = IntPrompt.ask(
            "WireGuard port",
            default=config.get('server_port', 51820)
        )
        
        # Subnet
        config['server_subnet'] = Prompt.ask(
            "VPN subnet (CIDR)",
            default=config.get('server_subnet', '10.0.0.0/24')
        )
        
        # Server address in the VPN
        network = ipaddress.ip_network(config['server_subnet'], strict=False)
        first_ip = str(list(network.hosts())[0])
        config['server_address'] = f"{first_ip}/{network.prefixlen}"
        
        # External interface
        interfaces = get_network_interfaces()
        console.print("\n[cyan]Available network interfaces:[/cyan]")
        for i, iface in enumerate(interfaces, 1):
            console.print(f"  {i}. {iface}")
        
        if len(interfaces) == 1:
            config['external_interface'] = interfaces[0]
        else:
            choice = IntPrompt.ask(
                "Select external interface",
                choices=[str(i) for i in range(1, len(interfaces) + 1)]
            )
            config['external_interface'] = interfaces[choice - 1]
        
        # DNS servers
        config['dns_servers'] = Prompt.ask(
            "DNS servers (comma-separated)",
            default=config.get('dns_servers', '1.1.1.1, 1.0.0.1')
        )
        
        # Generate keys
        console.print("\n[cyan]Generating keys...[/cyan]")
        private_key, public_key = generate_key_pair()
        
        # Save keys
        keys_dir = WIREGUARD_DIR / "keys"
        ensure_directory(keys_dir, mode=0o700)
        
        (keys_dir / f"{interface}.key").write_text(private_key)
        (keys_dir / f"{interface}.pub").write_text(public_key)
        
        # Create configuration from template
        try:
            template = self.env.get_template("server.conf.j2")
        except:
            template = self.env.from_string(self._get_server_template())
        
        server_config = template.render(
            version="2.0.0",
            private_key=private_key,
            address=config['server_address'],
            port=config['server_port'],
            external_interface=config['external_interface'],
            save_config="false",
            mtu=config.get('mtu', 1420)
        )
        
        # Write configuration
        config_file.write_text(server_config)
        config_file.chmod(0o600)
        
        # Save config
        self.save_config(config)
        
        console.print(f"\n[green]✓[/green] Server configuration created: {config_file}")
        console.print(f"[green]✓[/green] Server public key: {public_key}")
        console.print("\n[yellow]Next steps:[/yellow]")
        console.print("  1. Start the interface: systemctl start wg-quick@{interface}")
        console.print("  2. Enable on boot: systemctl enable wg-quick@{interface}")
        console.print("  3. Add peers using the Peer Management menu")
    
    def _get_server_template(self) -> str:
        """Get server template string."""
        return """[Interface]
PrivateKey = {{ private_key }}
Address = {{ address }}
ListenPort = {{ port }}
SaveConfig = {{ save_config }}

PostUp = sysctl -w net.ipv4.ip_forward=1
PostUp = iptables -A FORWARD -i %i -j ACCEPT
PostUp = iptables -t nat -A POSTROUTING -o {{ external_interface }} -j MASQUERADE

PostDown = iptables -D FORWARD -i %i -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o {{ external_interface }} -j MASQUERADE"""
    
    def edit_configuration(self) -> None:
        """Edit existing configuration."""
        console.print(Panel.fit(
            "[bold cyan]Edit Configuration[/bold cyan]",
            border_style="cyan"
        ))
        
        # List available configurations
        configs = list(WIREGUARD_DIR.glob("*.conf"))
        if not configs:
            console.print("[yellow]No configurations found[/yellow]")
            return
        
        console.print("[cyan]Available configurations:[/cyan]")
        for i, config in enumerate(configs, 1):
            console.print(f"  {i}. {config.stem}")
        
        choice = IntPrompt.ask(
            "Select configuration to edit",
            choices=[str(i) for i in range(1, len(configs) + 1)]
        )
        
        config_file = configs[choice - 1]
        
        # Read current configuration
        content = config_file.read_text()
        
        console.print(f"\n[cyan]Current configuration ({config_file.name}):[/cyan]")
        console.print("─" * 60)
        
        # Show first 20 lines
        lines = content.split('\n')[:20]
        for line in lines:
            if "PrivateKey" in line:
                console.print("PrivateKey = [HIDDEN]")
            else:
                console.print(line)
        
        if len(content.split('\n')) > 20:
            console.print("... (truncated)")
        
        console.print("─" * 60)
        
        console.print("\n[yellow]Note: Direct file editing not implemented in this demo[/yellow]")
        console.print("Use 'sudo nano {config_file}' to edit manually")
    
    def edit_network_settings(self) -> None:
        """Edit network settings."""
        console.print(Panel.fit(
            "[bold cyan]Network Settings[/bold cyan]",
            border_style="cyan"
        ))
        
        config = self.load_config()
        
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Setting", style="cyan", width=25)
        table.add_column("Current Value", style="yellow")
        
        table.add_row("Server Port", str(config.get('server_port', 51820)))
        table.add_row("VPN Subnet", config.get('server_subnet', '10.0.0.0/24'))
        table.add_row("Server Address", config.get('server_address', '10.0.0.1/24'))
        table.add_row("External Interface", config.get('external_interface', 'eth0'))
        table.add_row("DNS Servers", config.get('dns_servers', '1.1.1.1, 1.0.0.1'))
        table.add_row("MTU", str(config.get('mtu', 1420)))
        table.add_row("Keepalive", str(config.get('keepalive', 25)))
        
        console.print(table)
        
        if prompt_yes_no("\nModify settings?", default=False):
            # Port
            config['server_port'] = IntPrompt.ask(
                "Server port",
                default=config.get('server_port', 51820)
            )
            
            # MTU
            config['mtu'] = IntPrompt.ask(
                "MTU size",
                default=config.get('mtu', 1420)
            )
            
            # Keepalive
            config['keepalive'] = IntPrompt.ask(
                "Keepalive interval (seconds)",
                default=config.get('keepalive', 25)
            )
            
            # DNS
            config['dns_servers'] = Prompt.ask(
                "DNS servers",
                default=config.get('dns_servers', '1.1.1.1, 1.0.0.1')
            )
            
            self.save_config(config)
            console.print("\n[green]✓[/green] Settings updated")