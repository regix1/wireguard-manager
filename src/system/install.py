"""WireGuard installation utilities."""

from pathlib import Path
from typing import Optional

from ..utils import run, run_silent


def is_installed() -> bool:
    """Check if WireGuard is installed."""
    success, _ = run_silent(["which", "wg"])
    return success


def get_os_type() -> str:
    """Detect OS type (debian/redhat/unknown)."""
    if Path("/etc/debian_version").exists():
        return "debian"
    if Path("/etc/redhat-release").exists():
        return "redhat"
    if Path("/etc/arch-release").exists():
        return "arch"
    return "unknown"


def install_wireguard() -> bool:
    """
    Install WireGuard based on OS type.

    Returns:
        True if successful
    """
    if is_installed():
        print("WireGuard is already installed")
        return True

    os_type = get_os_type()
    print(f"Detected OS: {os_type}")

    try:
        if os_type == "debian":
            run(["apt-get", "update"])
            run(["apt-get", "install", "-y", "wireguard", "wireguard-tools", "qrencode"])
        elif os_type == "redhat":
            run(["dnf", "install", "-y", "wireguard-tools", "qrencode"])
        elif os_type == "arch":
            run(["pacman", "-S", "--noconfirm", "wireguard-tools", "qrencode"])
        else:
            print("Unknown OS. Please install WireGuard manually.")
            return False

        if is_installed():
            print("WireGuard installed successfully")
            return True
        else:
            print("Installation completed but WireGuard not found")
            return False

    except Exception as e:
        print(f"Failed to install WireGuard: {e}")
        return False


def install_dependencies() -> bool:
    """Install Python dependencies."""
    try:
        run(["pip3", "install", "pyyaml", "qrcode"])
        return True
    except Exception as e:
        print(f"Failed to install dependencies: {e}")
        return False


def check_kernel_module() -> bool:
    """Check if WireGuard kernel module is loaded."""
    result = run(["lsmod"], check=False)
    return "wireguard" in result.stdout.lower()


def load_kernel_module() -> bool:
    """Load WireGuard kernel module."""
    try:
        run(["modprobe", "wireguard"])
        return True
    except Exception:
        return False


def get_version() -> Optional[str]:
    """Get WireGuard version."""
    if not is_installed():
        return None

    result = run(["wg", "--version"], check=False)
    if result.returncode == 0:
        return result.stdout.strip()
    return None
