"""Application settings and configuration management."""

import os
import json
import yaml
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional

@dataclass
class WireGuardConfig:
    """WireGuard configuration settings."""
    default_port: int = 51821
    default_subnet: str = "10.10.20.0/24"
    default_dns: str = "1.1.1.1,1.0.0.1"
    interface_name: str = "wg0"
    config_dir: str = "/etc/wireguard"
    keys_dir: str = "/etc/wireguard/keys"

@dataclass
class FirewallConfig:
    """Firewall configuration settings."""
    rules_file: str = "/etc/wireguard/firewall-rules.conf"
    banned_ips_file: str = "/etc/wireguard/banned_ips.txt"
    banned_chain: str = "BANNED_IPS"
    external_interface: str = "eno1"
    enable_ddos_protection: bool = True
    enable_logging: bool = True
    log_prefix: str = "WGCONNECTION: "

@dataclass
class ServerConfig:
    """Server configuration settings."""
    public_ip: str = ""
    hostname: str = ""
    nat_enabled: bool = True
    ip_forwarding: bool = True
    persistent_keepalive: int = 25

class Settings:
    """Application settings manager."""
    
    def __init__(self, config_dir: Optional[str] = None):
        """Initialize settings."""
        self.config_dir = Path(config_dir or os.path.expanduser("~/.wireguard-manager"))
        self.config_file = self.config_dir / "settings.json"
        self.rules_template = self.config_dir / "rules_template.yaml"
        
        # Create directories
        self.config_dir.mkdir(parents=True, exist_ok=True)
        (self.config_dir / "configs").mkdir(exist_ok=True)
        (self.config_dir / "keys").mkdir(exist_ok=True)
        (self.config_dir / "logs").mkdir(exist_ok=True)
        
        # Initialize configurations
        self.wireguard = WireGuardConfig()
        self.firewall = FirewallConfig()
        self.server = ServerConfig()
        
        # Load settings
        self.load()
        
        # Create default rules template if it doesn't exist
        if not self.rules_template.exists():
            self.create_default_rules_template()
    
    def load(self) -> None:
        """Load settings from file."""
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    data = json.load(f)
                
                # Load WireGuard config
                if 'wireguard' in data:
                    self.wireguard = WireGuardConfig(**data['wireguard'])
                
                # Load Firewall config
                if 'firewall' in data:
                    self.firewall = FirewallConfig(**data['firewall'])
                
                # Load Server config
                if 'server' in data:
                    self.server = ServerConfig(**data['server'])
                    
            except Exception as e:
                print(f"Error loading settings: {e}")
    
    def save(self) -> None:
        """Save settings to file."""
        data = {
            'wireguard': asdict(self.wireguard),
            'firewall': asdict(self.firewall),
            'server': asdict(self.server)
        }
        
        with open(self.config_file, 'w') as f:
            json.dump(data, f, indent=2)
    
    def create_default_rules_template(self) -> None:
        """Create default firewall rules template."""
        template = {
            'version': '2.0',
            'rules': {
                'nat': [
                    {
                        'comment': 'Enable masquerading for WireGuard subnets',
                        'rules': [
                            'iptables -t nat -A POSTROUTING -o {ext_if} -s 10.0.4.0/24 -j ACCEPT',
                            'iptables -t nat -A POSTROUTING -o {ext_if} -s 10.10.20.0/24 -j MASQUERADE',
                            'iptables -t nat -A POSTROUTING -o {ext_if} -s 172.16.1.225 -j MASQUERADE'
                        ]
                    }
                ],
                'input': [
                    {
                        'comment': 'WireGuard interface with rate limiting',
                        'rule': 'iptables -A INPUT -p udp --dport {wg_port} -m hashlimit --hashlimit-name wg --hashlimit-upto 20/sec --hashlimit-burst 50 --hashlimit-mode srcip -j ACCEPT'
                    },
                    {
                        'comment': 'SSH access',
                        'rule': 'iptables -A INPUT -p tcp --dport 22 -j ACCEPT'
                    }
                ],
                'forward': [
                    {
                        'comment': 'Allow forwarding between interfaces',
                        'rules': [
                            'iptables -A FORWARD -i {ext_if} -o {wg_if} -j ACCEPT',
                            'iptables -A FORWARD -i {wg_if} -j ACCEPT'
                        ]
                    }
                ],
                'port_forwarding': [],
                'security': {
                    'ddos_protection': [
                        'iptables -A INPUT -p tcp --syn -m limit --limit 1/s --limit-burst 4 -j ACCEPT',
                        'iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s --limit-burst 4 -j ACCEPT'
                    ],
                    'anti_spoofing': [
                        'iptables -A INPUT -i {ext_if} -s 10.0.4.0/24 -j DROP',
                        'iptables -A INPUT -i {ext_if} -s 10.10.20.0/24 -j DROP',
                        'iptables -A INPUT -i {ext_if} -s 172.16.0.0/16 -j DROP',
                        'iptables -A INPUT -i {ext_if} -s 127.0.0.0/8 -j DROP'
                    ]
                }
            }
        }
        
        with open(self.rules_template, 'w') as f:
            yaml.dump(template, f, default_flow_style=False)
    
    def get_data_dir(self) -> Path:
        """Get the data directory path."""
        return self.config_dir
    
    def get_configs_dir(self) -> Path:
        """Get the configs directory path."""
        return self.config_dir / "configs"
    
    def get_keys_dir(self) -> Path:
        """Get the keys directory path."""
        return self.config_dir / "keys"
    
    def get_logs_dir(self) -> Path:
        """Get the logs directory path."""
        return self.config_dir / "logs"