"""WireGuard service status."""

from pathlib import Path
from typing import List, Dict, Optional

from ..config import WIREGUARD_DIR, DEFAULT_INTERFACE
from ..utils import run


def is_active(interface: str = DEFAULT_INTERFACE) -> bool:
    """
    Check if WireGuard interface is active.

    Args:
        interface: Interface name

    Returns:
        True if active
    """
    result = run(
        ["systemctl", "is-active", "--quiet", f"wg-quick@{interface}"],
        check=False
    )
    return result.returncode == 0


def is_enabled(interface: str = DEFAULT_INTERFACE) -> bool:
    """
    Check if WireGuard interface is enabled at boot.

    Args:
        interface: Interface name

    Returns:
        True if enabled
    """
    result = run(
        ["systemctl", "is-enabled", "--quiet", f"wg-quick@{interface}"],
        check=False
    )
    return result.returncode == 0


def list_interfaces() -> List[str]:
    """
    List all configured WireGuard interfaces.

    Returns:
        List of interface names
    """
    interfaces = []

    if not WIREGUARD_DIR.exists():
        return interfaces

    for conf in WIREGUARD_DIR.glob("*.conf"):
        if conf.stem not in ['params']:  # Exclude non-interface configs
            interfaces.append(conf.stem)

    return sorted(interfaces)


def get_interface_info(interface: str = DEFAULT_INTERFACE) -> Optional[Dict]:
    """
    Get detailed information about an interface.

    Args:
        interface: Interface name

    Returns:
        Dict with interface info or None
    """
    info = {
        "name": interface,
        "active": is_active(interface),
        "enabled": is_enabled(interface),
        "config_exists": (WIREGUARD_DIR / f"{interface}.conf").exists(),
    }

    # Get wg show info if active
    if info["active"]:
        result = run(["wg", "show", interface], check=False)
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                line = line.strip()
                if line.startswith('public key:'):
                    info['public_key'] = line.split(':', 1)[1].strip()
                elif line.startswith('listening port:'):
                    info['port'] = int(line.split(':', 1)[1].strip())
                elif line.startswith('fwmark:'):
                    info['fwmark'] = line.split(':', 1)[1].strip()

        # Get transfer stats
        result = run(["wg", "show", interface, "transfer"], check=False)
        if result.returncode == 0:
            rx_total = 0
            tx_total = 0
            for line in result.stdout.strip().split('\n'):
                if line:
                    parts = line.split('\t')
                    if len(parts) >= 3:
                        rx_total += int(parts[1])
                        tx_total += int(parts[2])
            info['rx_bytes'] = rx_total
            info['tx_bytes'] = tx_total

    return info


def status(interface: str = None) -> None:
    """
    Print status of WireGuard interface(s).

    Args:
        interface: Specific interface or None for all
    """
    if interface:
        interfaces = [interface]
    else:
        interfaces = list_interfaces()

    if not interfaces:
        print("No WireGuard interfaces configured")
        return

    for iface in interfaces:
        info = get_interface_info(iface)
        if not info:
            continue

        active = "ACTIVE" if info['active'] else "INACTIVE"
        enabled = "enabled" if info['enabled'] else "disabled"

        print(f"\n{iface}: {active} ({enabled})")
        print("-" * 40)

        if not info['config_exists']:
            print("  Config file missing!")
            continue

        if info['active']:
            if 'port' in info:
                print(f"  Port: {info['port']}")
            if 'public_key' in info:
                print(f"  Public Key: {info['public_key'][:20]}...")
            if 'rx_bytes' in info:
                rx = _format_bytes(info['rx_bytes'])
                tx = _format_bytes(info['tx_bytes'])
                print(f"  Transfer: RX {rx}, TX {tx}")

            # Show connected peers
            result = run(["wg", "show", iface, "dump"], check=False)
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                peer_count = len(lines) - 1 if len(lines) > 1 else 0
                print(f"  Peers: {peer_count}")
        else:
            print("  Interface not active")

    print()


def show_detailed(interface: str = DEFAULT_INTERFACE) -> None:
    """
    Show detailed WireGuard status output.

    Args:
        interface: Interface name
    """
    if not is_active(interface):
        print(f"Interface {interface} is not active")
        return

    result = run(["wg", "show", interface], check=False)
    if result.returncode == 0:
        print(result.stdout)
    else:
        print(f"Failed to get status for {interface}")


def _format_bytes(b: int) -> str:
    """Format bytes as human-readable string."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if b < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} PB"
