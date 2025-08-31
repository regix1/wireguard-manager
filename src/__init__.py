"""WireGuard Manager - A modern VPN management tool."""

from pathlib import Path

# Try to read version from VERSION file
try:
    version_file = Path(__file__).parent.parent / "VERSION"
    if version_file.exists():
        __version__ = version_file.read_text().strip()
    else:
        __version__ = "2.0.0"
except Exception:
    __version__ = "2.0.0"

__author__ = "Regix"

# Import main entry point
from .cli import main

__all__ = ["main", "__version__", "__author__"]