"""Utility functions for WireGuard Manager."""

import os
import sys
import subprocess
import socket
import ipaddress
from pathlib import Path
from typing import Optional, List, Tuple
import psutil
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()

def check_root() -> None:
    """Check if the script is running as root."""
    if os.geteuid() != 0:
        console.print("[red]✗ This application must be run as root[/red]")
        sys.exit(1)

def run_command(
    command: List[str],
    check: bool = True,
    capture_output: bool = True,
    text: bool = True,
    timeout: Optional[int] = 30,
    cwd: Optional[Path] = None,
    input: Optional[str] = None,
) -> subprocess.CompletedProcess:
    """Run a shell command and return the result."""
    try:
        if input is not None:
            result = subprocess.run(
                command,
                input=input,
                capture_output=capture_output,
                text=text,
                timeout=timeout,
                cwd=cwd,
                check=check,
            )
        else:
            result = subprocess.run(
                command,
                check=check,
                capture_output=capture_output,
                text=text,
                timeout=timeout,
                cwd=cwd,
            )
        return result
    except subprocess.TimeoutExpired:
        console.print(f"[red]Command timed out: {' '.join(command)}[/red]")
        raise
    except subprocess.CalledProcessError as e:
        if check:
            console.print(f"[red]Command failed: {' '.join(command)}[/red]")
            if e.stderr:
                console.print(f"[red]Error: {e.stderr}[/red]")
        raise

def check_service_status(interface: str) -> bool:
    """Check if a WireGuard interface is active."""
    try:
        result = run_command(
            ["systemctl", "is-active", "--quiet", f"wg-quick@{interface}"],
            check=False,
        )
        return result.returncode == 0
    except Exception:
        return False

def get_server_ip() -> str:
    """Get the server's public IP address."""
    try:
        # Try external service first
        result = run_command(
            ["curl", "-s", "https://api.ipify.org"],
            check=False,
            timeout=5
        )
        if result.returncode == 0 and result.stdout:
            return result.stdout.strip()
    except Exception:
        pass
    
    # Fallback to local IP
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "YOUR_SERVER_IP"

def get_network_interfaces() -> List[str]:
    """Get list of network interfaces."""
    interfaces = []
    for interface, addrs in psutil.net_if_addrs().items():
        if interface != "lo":  # Skip loopback
            interfaces.append(interface)
    return sorted(interfaces)

def prompt_yes_no(question: str, default: bool = True) -> bool:
    """Prompt the user for a yes/no answer."""
    from rich.prompt import Confirm
    return Confirm.ask(question, default=default)

def generate_key_pair() -> Tuple[str, str]:
    """Generate WireGuard private and public key pair."""
    # Generate private key
    result = run_command(["wg", "genkey"])
    private_key = result.stdout.strip()
    
    # Generate public key
    result = run_command(
        ["wg", "pubkey"],
        input=private_key,
        text=True,
        capture_output=True
    )
    public_key = result.stdout.strip()
    
    return private_key, public_key

def generate_preshared_key() -> str:
    """Generate WireGuard preshared key."""
    result = run_command(["wg", "genpsk"])
    return result.stdout.strip()

def get_next_available_ip(subnet: str, used_ips: List[str]) -> str:
    """Get the next available IP address in a subnet."""
    network = ipaddress.ip_network(subnet, strict=False)
    
    # Convert used IPs to set for faster lookup
    used_set = set()
    for ip in used_ips:
        if '/' in ip:
            ip = ip.split('/')[0]
        used_set.add(ip)
    
    # Find next available IP (skip .0 and .1)
    for ip in network.hosts():
        if str(ip) not in used_set and not str(ip).endswith('.0') and not str(ip).endswith('.1'):
            return str(ip)
    
    raise ValueError("No available IP addresses in subnet")

def validate_ip_address(ip: str) -> bool:
    """Validate an IP address."""
    try:
        if '/' in ip:
            ipaddress.ip_network(ip, strict=False)
        else:
            ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def ensure_directory(path: Path, mode: int = 0o755) -> None:
    """Ensure a directory exists with proper permissions."""
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(mode)

def check_wireguard_installed() -> bool:
    """Check if WireGuard is installed."""
    try:
        result = run_command(["which", "wg"], check=False)
        return result.returncode == 0
    except Exception:
        return False

def enable_ip_forwarding() -> None:
    """Enable IP forwarding."""
    try:
        # Enable temporarily
        run_command(["sysctl", "-w", "net.ipv4.ip_forward=1"], check=False)
        run_command(["sysctl", "-w", "net.ipv6.conf.all.forwarding=1"], check=False)
        
        # Enable permanently
        sysctl_conf = Path("/etc/sysctl.conf")
        content = sysctl_conf.read_text() if sysctl_conf.exists() else ""
        
        if "net.ipv4.ip_forward=1" not in content:
            with open(sysctl_conf, "a") as f:
                f.write("\n# WireGuard IP Forwarding\n")
                f.write("net.ipv4.ip_forward=1\n")
                f.write("net.ipv6.conf.all.forwarding=1\n")
        
        console.print("[green]✓[/green] IP forwarding enabled")
    except Exception as e:
        console.print(f"[yellow]Warning: Could not enable IP forwarding: {e}[/yellow]")