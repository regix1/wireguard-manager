"""TUI package for WireGuard Manager."""

from .main_app import WireGuardManagerApp
from .screens import (
    DashboardScreen,
    PeersScreen,
    FirewallScreen,
    ConfigurationScreen,
    LogsScreen
)
from .dialogs import (
    AddPeerDialog,
    BanIPDialog,
    PortForwardDialog,
    RulesEditorDialog
)
from .cli_mode import handle_cli_command

__all__ = [
    'WireGuardManagerApp',
    'DashboardScreen',
    'PeersScreen',
    'FirewallScreen',
    'ConfigurationScreen',
    'LogsScreen',
    'AddPeerDialog',
    'BanIPDialog',
    'PortForwardDialog',
    'RulesEditorDialog',
    'handle_cli_command'
]