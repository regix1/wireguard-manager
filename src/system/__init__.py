"""System management modules."""

from .install import install_wireguard, is_installed
from .diagnostics import run_diagnostics, test_connectivity
from .setup import create_server_config, init_server
