"""Utility functions for WireGuard Manager."""

import os
import sys
import subprocess
import socket
import ipaddress
from pathlib import Path
from typing import Optional, List, Tuple


def check_root() -> bool:
    """Check if running as root."""
    return os.geteuid() == 0


def require_root() -> None:
    """Exit if not running as root."""
    if not check_root():
        print("Error: This command must be run as root")
        sys.exit(1)


def run(
    cmd: List[str],
    check: bool = True,
    capture: bool = True,
    timeout: int = 30,
    input_text: Optional[str] = None,
) -> subprocess.CompletedProcess:
    """Run a shell command."""
    try:
        return subprocess.run(
            cmd,
            input=input_text,
            capture_output=capture,
            text=True,
            timeout=timeout,
            check=check,
        )
    except subprocess.CalledProcessError as e:
        if check:
            print(f"Command failed: {' '.join(cmd)}")
            if e.stderr:
                print(f"Error: {e.stderr}")
        raise
    except subprocess.TimeoutExpired:
        print(f"Command timed out: {' '.join(cmd)}")
        raise


def run_silent(cmd: List[str], timeout: int = 30) -> Tuple[bool, str]:
    """Run command silently, return (success, output)."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        return result.returncode == 0, result.stdout
    except Exception as e:
        return False, str(e)


def generate_keypair() -> Tuple[str, str]:
    """Generate WireGuard private and public key pair."""
    result = run(["wg", "genkey"])
    private_key = result.stdout.strip()

    result = run(["wg", "pubkey"], input_text=private_key)
    public_key = result.stdout.strip()

    return private_key, public_key


def generate_psk() -> str:
    """Generate WireGuard preshared key."""
    result = run(["wg", "genpsk"])
    return result.stdout.strip()


def get_public_ip() -> str:
    """Get the server's public IP address."""
    try:
        result = run(["curl", "-s", "https://api.ipify.org"], check=False, timeout=5)
        if result.returncode == 0 and result.stdout:
            return result.stdout.strip()
    except Exception:
        pass

    # Fallback to local IP detection
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "YOUR_SERVER_IP"


def get_next_ip(subnet: str, used_ips: List[str]) -> str:
    """Get next available IP in subnet."""
    network = ipaddress.ip_network(subnet, strict=False)

    used_set = set()
    for ip in used_ips:
        if '/' in ip:
            ip = ip.split('/')[0]
        used_set.add(ip)

    # Skip .0 (network) and .1 (usually server)
    for ip in network.hosts():
        ip_str = str(ip)
        if ip_str not in used_set and not ip_str.endswith('.1'):
            return ip_str

    raise ValueError("No available IP addresses in subnet")


def validate_ip(ip: str) -> bool:
    """Validate an IP address or CIDR."""
    try:
        if '/' in ip:
            ipaddress.ip_network(ip, strict=False)
        else:
            ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def is_wireguard_installed() -> bool:
    """Check if WireGuard is installed."""
    success, _ = run_silent(["which", "wg"])
    return success


def get_interfaces() -> List[str]:
    """Get list of network interfaces."""
    try:
        result = run(["ip", "-o", "link", "show"], check=False)
        interfaces = []
        for line in result.stdout.strip().split('\n'):
            if ':' in line:
                parts = line.split(':')
                if len(parts) >= 2:
                    iface = parts[1].strip().split('@')[0]
                    if iface not in ['lo']:
                        interfaces.append(iface)
        return sorted(set(interfaces))
    except Exception:
        return []


def enable_ip_forwarding() -> None:
    """Enable IP forwarding."""
    run(["sysctl", "-w", "net.ipv4.ip_forward=1"], check=False)
    run(["sysctl", "-w", "net.ipv6.conf.all.forwarding=1"], check=False)

    # Make permanent
    sysctl_conf = Path("/etc/sysctl.conf")
    if sysctl_conf.exists():
        content = sysctl_conf.read_text()
        if "net.ipv4.ip_forward=1" not in content:
            with open(sysctl_conf, "a") as f:
                f.write("\n# WireGuard IP Forwarding\n")
                f.write("net.ipv4.ip_forward=1\n")
                f.write("net.ipv6.conf.all.forwarding=1\n")

    print("IP forwarding enabled")
