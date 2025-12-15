"""WireGuard service control."""

from ..config import DEFAULT_INTERFACE
from ..utils import run


def start(interface: str = DEFAULT_INTERFACE) -> bool:
    """
    Start WireGuard interface.

    Args:
        interface: Interface name (e.g., "wg0")

    Returns:
        True if successful
    """
    try:
        run(["systemctl", "start", f"wg-quick@{interface}"])
        print(f"Started {interface}")
        return True
    except Exception as e:
        print(f"Failed to start {interface}: {e}")
        return False


def stop(interface: str = DEFAULT_INTERFACE) -> bool:
    """
    Stop WireGuard interface.

    Args:
        interface: Interface name

    Returns:
        True if successful
    """
    try:
        run(["systemctl", "stop", f"wg-quick@{interface}"])
        print(f"Stopped {interface}")
        return True
    except Exception as e:
        print(f"Failed to stop {interface}: {e}")
        return False


def restart(interface: str = DEFAULT_INTERFACE) -> bool:
    """
    Restart WireGuard interface.

    Args:
        interface: Interface name

    Returns:
        True if successful
    """
    try:
        run(["systemctl", "restart", f"wg-quick@{interface}"])
        print(f"Restarted {interface}")
        return True
    except Exception as e:
        print(f"Failed to restart {interface}: {e}")
        return False


def reload_config(interface: str = DEFAULT_INTERFACE) -> bool:
    """
    Reload WireGuard configuration without disrupting connections.

    Uses wg syncconf to apply changes without restarting.

    Args:
        interface: Interface name

    Returns:
        True if successful
    """
    from ..config import get_interface_path

    config_path = get_interface_path(interface)
    if not config_path.exists():
        print(f"Configuration not found: {config_path}")
        return False

    # Extract peer sections for syncconf
    content = config_path.read_text()
    peer_config = []
    in_peer = False

    for line in content.split('\n'):
        stripped = line.strip()
        if stripped.startswith('[Peer]'):
            in_peer = True
        if in_peer and not stripped.startswith('#'):
            peer_config.append(line)

    try:
        run(["wg", "syncconf", interface, "/dev/stdin"],
            input_text='\n'.join(peer_config))
        print(f"Reloaded configuration for {interface}")
        return True
    except Exception as e:
        print(f"Failed to reload {interface}: {e}")
        return False


def enable(interface: str = DEFAULT_INTERFACE) -> bool:
    """
    Enable WireGuard interface at boot.

    Args:
        interface: Interface name

    Returns:
        True if successful
    """
    try:
        run(["systemctl", "enable", f"wg-quick@{interface}"])
        print(f"Enabled {interface} at boot")
        return True
    except Exception as e:
        print(f"Failed to enable {interface}: {e}")
        return False


def disable(interface: str = DEFAULT_INTERFACE) -> bool:
    """
    Disable WireGuard interface at boot.

    Args:
        interface: Interface name

    Returns:
        True if successful
    """
    try:
        run(["systemctl", "disable", f"wg-quick@{interface}"])
        print(f"Disabled {interface} at boot")
        return True
    except Exception as e:
        print(f"Failed to disable {interface}: {e}")
        return False


def quick_up(interface: str = DEFAULT_INTERFACE) -> bool:
    """
    Bring up interface using wg-quick directly.

    Args:
        interface: Interface name

    Returns:
        True if successful
    """
    try:
        run(["wg-quick", "up", interface])
        print(f"Interface {interface} is up")
        return True
    except Exception as e:
        print(f"Failed to bring up {interface}: {e}")
        return False


def quick_down(interface: str = DEFAULT_INTERFACE) -> bool:
    """
    Bring down interface using wg-quick directly.

    Args:
        interface: Interface name

    Returns:
        True if successful
    """
    try:
        run(["wg-quick", "down", interface])
        print(f"Interface {interface} is down")
        return True
    except Exception as e:
        print(f"Failed to bring down {interface}: {e}")
        return False
