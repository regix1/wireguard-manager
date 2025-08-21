"""Utility functions for the WireGuard Manager."""

import os
import sys
import subprocess
import logging
import socket
import ipaddress
import netifaces
import requests
from pathlib import Path
from typing import Optional, List, Tuple, Dict
from datetime import datetime

def check_root() -> bool:
    """Check if running as root."""
    return os.geteuid() == 0

def setup_logging(level: int = logging.INFO) -> None:
    """Setup application logging."""
    log_dir = Path.home() / ".wireguard-manager" / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    
    log_file = log_dir / f"wireguard-manager-{datetime.now():%Y%m%d}.log"
    
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout)
        ]
    )

def run_command(cmd: List[str], check: bool = True, capture: bool = True) -> subprocess.CompletedProcess:
    """Run a system command."""
    logger = logging.getLogger(__name__)
    logger.debug(f"Running command: {' '.join(cmd)}")
    
    try:
        result = subprocess.run(
            cmd,
            check=check,
            capture_output=capture,
            text=True
        )
        return result
    except subprocess.CalledProcessError as e:
        logger.error(f"Command failed: {e.cmd}")
        logger.error(f"Error output: {e.stderr}")
        raise

def validate_ip(ip: str) -> bool:
    """Validate IP address format."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def validate_subnet(subnet: str) -> bool:
    """Validate subnet format (e.g., 10.0.0.0/24)."""
    try:
        ipaddress.ip_network(subnet, strict=False)
        return True
    except ValueError:
        return False

def validate_port(port: int) -> bool:
    """Validate port number."""
    return 1 <= port <= 65535

def get_public_ip() -> Optional[str]:
    """Detect public IP address."""
    services = [
        "https://ifconfig.me",
        "https://ipinfo.io/ip",
        "https://icanhazip.com"
    ]
    
    for service in services:
        try:
            response = requests.get(service, timeout=3)
            if response.status_code == 200:
                ip = response.text.strip()
                if validate_ip(ip):
                    return ip
        except:
            continue
    
    # Fallback to local IP
    return get_local_ip()

def get_local_ip() -> Optional[str]:
    """Get local IP address."""
    try:
        # Get all network interfaces
        interfaces = netifaces.interfaces()
        
        for iface in interfaces:
            if iface == 'lo':
                continue
            
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET in addrs:
                for addr in addrs[netifaces.AF_INET]:
                    ip = addr['addr']
                    if not ip.startswith('127.'):
                        return ip
    except:
        pass
    
    return None

def get_network_interfaces() -> List[str]:
    """Get list of network interfaces."""
    try:
        interfaces = netifaces.interfaces()
        # Filter out loopback
        return [iface for iface in interfaces if iface != 'lo']
    except:
        return []

def check_port_available(port: int) -> bool:
    """Check if a port is available."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('', port))
            return True
    except:
        return False

def find_available_port(start_port: int = 51820) -> int:
    """Find next available port starting from start_port."""
    port = start_port
    while port < 65535:
        if check_port_available(port):
            return port
        port += 1
    return start_port

def check_wireguard_installed() -> bool:
    """Check if WireGuard is installed."""
    return os.path.exists('/usr/bin/wg')

def check_iptables_installed() -> bool:
    """Check if iptables is installed."""
    return os.path.exists('/sbin/iptables')

def check_qrencode_installed() -> bool:
    """Check if qrencode is installed."""
    return os.path.exists('/usr/bin/qrencode')

def get_wireguard_status() -> Dict:
    """Get WireGuard status information."""
    status = {
        'installed': check_wireguard_installed(),
        'interfaces': [],
        'service_active': False
    }
    
    if not status['installed']:
        return status
    
    try:
        # Check service status
        result = run_command(['systemctl', 'is-active', 'wg-quick@wg0'], check=False)
        status['service_active'] = result.stdout.strip() == 'active'
        
        # Get interface info
        result = run_command(['wg', 'show'], check=False)
        if result.returncode == 0 and result.stdout:
            # Parse output for interface names
            for line in result.stdout.split('\n'):
                if line.startswith('interface:'):
                    iface = line.split(':')[1].strip()
                    status['interfaces'].append(iface)
    except:
        pass
    
    return status

def get_iptables_rules_count() -> Dict[str, int]:
    """Get count of iptables rules by chain."""
    counts = {
        'INPUT': 0,
        'FORWARD': 0,
        'OUTPUT': 0,
        'NAT_PREROUTING': 0,
        'NAT_POSTROUTING': 0
    }
    
    try:
        # Count INPUT/FORWARD/OUTPUT rules
        for chain in ['INPUT', 'FORWARD', 'OUTPUT']:
            result = run_command(['iptables', '-L', chain, '-n'], check=False)
            if result.returncode == 0:
                # Count lines that are rules (skip headers)
                lines = result.stdout.split('\n')
                counts[chain] = len([l for l in lines if l and not l.startswith('Chain') and not l.startswith('target')])
        
        # Count NAT rules
        result = run_command(['iptables', '-t', 'nat', '-L', 'PREROUTING', '-n'], check=False)
        if result.returncode == 0:
            lines = result.stdout.split('\n')
            counts['NAT_PREROUTING'] = len([l for l in lines if 'DNAT' in l])
        
        result = run_command(['iptables', '-t', 'nat', '-L', 'POSTROUTING', '-n'], check=False)
        if result.returncode == 0:
            lines = result.stdout.split('\n')
            counts['NAT_POSTROUTING'] = len([l for l in lines if 'MASQUERADE' in l or 'SNAT' in l])
    except:
        pass
    
    return counts

def sanitize_filename(name: str) -> str:
    """Sanitize a string for use as a filename."""
    # Replace spaces with underscores
    name = name.replace(' ', '_')
    # Keep only alphanumeric, underscore, dash, and dot
    return ''.join(c for c in name if c.isalnum() or c in '._-')

def format_bytes(bytes: int) -> str:
    """Format bytes to human readable string."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes < 1024.0:
            return f"{bytes:.2f} {unit}"
        bytes /= 1024.0
    return f"{bytes:.2f} PB"

def parse_time_duration(duration: str) -> int:
    """Parse time duration string to seconds."""
    units = {
        's': 1,
        'm': 60,
        'h': 3600,
        'd': 86400,
        'w': 604800
    }
    
    if duration[-1] in units:
        try:
            value = int(duration[:-1])
            return value * units[duration[-1]]
        except:
            pass
    
    try:
        return int(duration)
    except:
        return 0