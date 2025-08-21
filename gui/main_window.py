"""Main application window for WireGuard Manager."""

import logging
from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTabWidget, QMenuBar, QMenu, QStatusBar, QToolBar,
    QMessageBox, QSplitter, QLabel
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QAction, QIcon, QPixmap

from config.settings import Settings
from gui.widgets.status_widget import StatusWidget
from gui.widgets.peers_widget import PeersWidget
from gui.widgets.firewall_widget import FirewallWidget
from gui.dialogs.peer_dialog import AddPeerDialog
from gui.dialogs.ban_dialog import BanIPDialog
from gui.dialogs.rules_dialog import RulesEditorDialog
from core.wireguard import WireGuardManager
from core.firewall import FirewallManager

class MainWindow(QMainWindow):
    """Main application window."""
    
    # Signals
    status_updated = pyqtSignal(dict)
    
    def __init__(self, settings: Settings):
        """Initialize the main window."""
        super().__init__()
        self.settings = settings
        self.logger = logging.getLogger(__name__)
        
        # Initialize managers
        self.wg_manager = WireGuardManager(settings)
        self.fw_manager = FirewallManager(settings)
        
        # Setup UI
        self.setup_ui()
        self.setup_menu()
        self.setup_toolbar()
        self.setup_statusbar()
        
        # Setup auto-refresh timer
        self.refresh_timer = QTimer()
        self.refresh_timer.timeout.connect(self.refresh_status)
        self.refresh_timer.start(5000)  # Refresh every 5 seconds
        
        # Initial refresh
        self.refresh_status()
    
    def setup_ui(self):
        """Setup the main UI."""
        self.setWindowTitle("WireGuard Manager")
        self.setGeometry(100, 100, 1200, 800)
        
        # Create central widget
        central = QWidget()
        self.setCentralWidget(central)
        
        # Main layout
        layout = QVBoxLayout(central)
        
        # Create splitter for status and tabs
        splitter = QSplitter(Qt.Orientation.Vertical)
        layout.addWidget(splitter)
        
        # Status widget (top)
        self.status_widget = StatusWidget()
        splitter.addWidget(self.status_widget)
        
        # Tab widget (bottom)
        self.tabs = QTabWidget()
        splitter.addWidget(self.tabs)
        
        # Create tabs
        self.peers_widget = PeersWidget(self.wg_manager)
        self.firewall_widget = FirewallWidget(self.fw_manager)
        
        self.tabs.addTab(self.peers_widget, "Peers & Configuration")
        self.tabs.addTab(self.firewall_widget, "Firewall & Security")
        
        # Set splitter sizes (30% status, 70% tabs)
        splitter.setSizes([240, 560])
        
        # Connect signals
        self.peers_widget.refresh_requested.connect(self.refresh_status)
        self.firewall_widget.refresh_requested.connect(self.refresh_status)
    
    def setup_menu(self):
        """Setup menu bar."""
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu("&File")
        
        new_config = QAction("&New Configuration", self)
        new_config.setShortcut("Ctrl+N")
        new_config.triggered.connect(self.new_configuration)
        file_menu.addAction(new_config)
        
        open_config = QAction("&Open Configuration", self)
        open_config.setShortcut("Ctrl+O")
        open_config.triggered.connect(self.open_configuration)
        file_menu.addAction(open_config)
        
        file_menu.addSeparator()
        
        save_config = QAction("&Save Configuration", self)
        save_config.setShortcut("Ctrl+S")
        save_config.triggered.connect(self.save_configuration)
        file_menu.addAction(save_config)
        
        file_menu.addSeparator()
        
        settings_action = QAction("&Settings", self)
        settings_action.setShortcut("Ctrl+,")
        settings_action.triggered.connect(self.show_settings)
        file_menu.addAction(settings_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction("E&xit", self)
        exit_action.setShortcut("Ctrl+Q")
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # WireGuard menu
        wg_menu = menubar.addMenu("&WireGuard")
        
        start_wg = QAction("&Start WireGuard", self)
        start_wg.triggered.connect(self.start_wireguard)
        wg_menu.addAction(start_wg)
        
        stop_wg = QAction("S&top WireGuard", self)
        stop_wg.triggered.connect(self.stop_wireguard)
        wg_menu.addAction(stop_wg)
        
        restart_wg = QAction("&Restart WireGuard", self)
        restart_wg.triggered.connect(self.restart_wireguard)
        wg_menu.addAction(restart_wg)
        
        wg_menu.addSeparator()
        
        add_peer = QAction("&Add Peer", self)
        add_peer.setShortcut("Ctrl+P")
        add_peer.triggered.connect(self.add_peer)
        wg_menu.addAction(add_peer)
        
        generate_keys = QAction("&Generate Keys", self)
        generate_keys.triggered.connect(self.generate_keys)
        wg_menu.addAction(generate_keys)
        
        # Firewall menu
        fw_menu = menubar.addMenu("&Firewall")
        
        start_fw = QAction("&Start Firewall", self)
        start_fw.triggered.connect(self.start_firewall)
        fw_menu.addAction(start_fw)
        
        stop_fw = QAction("S&top Firewall", self)
        stop_fw.triggered.connect(self.stop_firewall)
        fw_menu.addAction(stop_fw)
        
        restart_fw = QAction("&Restart Firewall", self)
        restart_fw.triggered.connect(self.restart_firewall)
        fw_menu.addAction(restart_fw)
        
        fw_menu.addSeparator()
        
        edit_rules = QAction("&Edit Rules", self)
        edit_rules.setShortcut("Ctrl+R")
        edit_rules.triggered.connect(self.edit_rules)
        fw_menu.addAction(edit_rules)
        
        ban_ip = QAction("&Ban IP", self)
        ban_ip.setShortcut("Ctrl+B")
        ban_ip.triggered.connect(self.ban_ip)
        fw_menu.addAction(ban_ip)
        
        # Tools menu
        tools_menu = menubar.addMenu("&Tools")
        
        check_status = QAction("&Check Status", self)
        check_status.setShortcut("F5")
        check_status.triggered.connect(self.refresh_status)
        tools_menu.addAction(check_status)
        
        view_logs = QAction("&View Logs", self)
        view_logs.setShortcut("Ctrl+L")
        view_logs.triggered.connect(self.view_logs)
        tools_menu.addAction(view_logs)
        
        tools_menu.addSeparator()
        
        export_config = QAction("&Export Configuration", self)
        export_config.triggered.connect(self.export_configuration)
        tools_menu.addAction(export_config)
        
        import_config = QAction("&Import Configuration", self)
        import_config.triggered.connect(self.import_configuration)
        tools_menu.addAction(import_config)
        
        # Help menu
        help_menu = menubar.addMenu("&Help")
        
        documentation = QAction("&Documentation", self)
        documentation.setShortcut("F1")
        documentation.triggered.connect(self.show_documentation)
        help_menu.addAction(documentation)
        
        about = QAction("&About", self)
        about.triggered.connect(self.show_about)
        help_menu.addAction(about)
    
    def setup_toolbar(self):
        """Setup toolbar."""
        toolbar = QToolBar("Main Toolbar")
        toolbar.setMovable(False)
        self.addToolBar(toolbar)
        
        # Add actions
        start_all = QAction("Start All", self)
        start_all.setToolTip("Start WireGuard and Firewall")
        start_all.triggered.connect(self.start_all)
        toolbar.addAction(start_all)
        
        stop_all = QAction("Stop All", self)
        stop_all.setToolTip("Stop WireGuard and Firewall")
        stop_all.triggered.connect(self.stop_all)
        toolbar.addAction(stop_all)
        
        toolbar.addSeparator()
        
        add_peer = QAction("Add Peer", self)
        add_peer.setToolTip("Add new peer")
        add_peer.triggered.connect(self.add_peer)
        toolbar.addAction(add_peer)
        
        edit_rules = QAction("Edit Rules", self)
        edit_rules.setToolTip("Edit firewall rules")
        edit_rules.triggered.connect(self.edit_rules)
        toolbar.addAction(edit_rules)
        
        toolbar.addSeparator()
        
        refresh = QAction("Refresh", self)
        refresh.setToolTip("Refresh status")
        refresh.triggered.connect(self.refresh_status)
        toolbar.addAction(refresh)
    
    def setup_statusbar(self):
        """Setup status bar."""
        self.statusbar = QStatusBar()
        self.setStatusBar(self.statusbar)
        
        # Add permanent widgets
        self.status_label = QLabel("Ready")
        self.statusbar.addWidget(self.status_label)
        
        self.wg_status_label = QLabel("WireGuard: Unknown")
        self.statusbar.addPermanentWidget(self.wg_status_label)
        
        self.fw_status_label = QLabel("Firewall: Unknown")
        self.statusbar.addPermanentWidget(self.fw_status_label)
    
    def refresh_status(self):
        """Refresh all status information."""
        try:
            # Get WireGuard status
            wg_status = self.wg_manager.get_status()
            
            # Get Firewall status
            fw_status = self.fw_manager.get_status()
            
            # Update status widget
            self.status_widget.update_status(wg_status, fw_status)
            
            # Update status bar
            wg_text = "WireGuard: Active" if wg_status.get('active') else "WireGuard: Inactive"
            fw_text = "Firewall: Active" if fw_status.get('active') else "Firewall: Inactive"
            
            self.wg_status_label.setText(wg_text)
            self.fw_status_label.setText(fw_text)
            
            # Update other widgets
            self.peers_widget.refresh()
            self.firewall_widget.refresh()
            
            self.status_label.setText("Status updated")
            
        except Exception as e:
            self.logger.error(f"Error refreshing status: {e}")
            self.status_label.setText(f"Error: {str(e)}")
    
    # Action handlers
    def new_configuration(self):
        """Create new configuration."""
        # Implementation for new configuration wizard
        QMessageBox.information(self, "New Configuration", 
                              "New configuration wizard will be implemented here")
    
    def open_configuration(self):
        """Open existing configuration."""
        # Implementation for opening configuration
        QMessageBox.information(self, "Open Configuration", 
                              "Open configuration dialog will be implemented here")
    
    def save_configuration(self):
        """Save current configuration."""
        try:
            self.wg_manager.save_config()
            self.fw_manager.save_config()
            QMessageBox.information(self, "Success", "Configuration saved successfully")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save configuration: {str(e)}")
    
    def show_settings(self):
        """Show settings dialog."""
        # Implementation for settings dialog
        QMessageBox.information(self, "Settings", 
                              "Settings dialog will be implemented here")
    
    def start_wireguard(self):
        """Start WireGuard service."""
        try:
            self.wg_manager.start()
            self.refresh_status()
            QMessageBox.information(self, "Success", "WireGuard started successfully")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to start WireGuard: {str(e)}")
    
    def stop_wireguard(self):
        """Stop WireGuard service."""
        try:
            self.wg_manager.stop()
            self.refresh_status()
            QMessageBox.information(self, "Success", "WireGuard stopped successfully")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to stop WireGuard: {str(e)}")
    
    def restart_wireguard(self):
        """Restart WireGuard service."""
        try:
            self.wg_manager.restart()
            self.refresh_status()
            QMessageBox.information(self, "Success", "WireGuard restarted successfully")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to restart WireGuard: {str(e)}")
    
    def add_peer(self):
        """Add new peer."""
        dialog = AddPeerDialog(self.wg_manager, self)
        if dialog.exec():
            self.refresh_status()
    
    def generate_keys(self):
        """Generate new keys."""
        try:
            keys = self.wg_manager.generate_keys()
            QMessageBox.information(self, "Keys Generated", 
                                  f"Private Key: {keys['private'][:20]}...\n"
                                  f"Public Key: {keys['public']}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to generate keys: {str(e)}")
    
    def start_firewall(self):
        """Start firewall."""
        try:
            self.fw_manager.start()
            self.refresh_status()
            QMessageBox.information(self, "Success", "Firewall started successfully")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to start firewall: {str(e)}")
    
    def stop_firewall(self):
        """Stop firewall."""
        try:
            self.fw_manager.stop()
            self.refresh_status()
            QMessageBox.information(self, "Success", "Firewall stopped successfully")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to stop firewall: {str(e)}")
    
    def restart_firewall(self):
        """Restart firewall."""
        try:
            self.fw_manager.restart()
            self.refresh_status()
            QMessageBox.information(self, "Success", "Firewall restarted successfully")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to restart firewall: {str(e)}")
    
    def edit_rules(self):
        """Edit firewall rules."""
        dialog = RulesEditorDialog(self.fw_manager, self)
        if dialog.exec():
            self.refresh_status()
    
    def ban_ip(self):
        """Ban IP address."""
        dialog = BanIPDialog(self.fw_manager, self)
        if dialog.exec():
            self.refresh_status()
    
    def start_all(self):
        """Start both WireGuard and Firewall."""
        try:
            self.wg_manager.start()
            self.fw_manager.start()
            self.refresh_status()
            QMessageBox.information(self, "Success", 
                                  "WireGuard and Firewall started successfully")
        except Exception as e:
            QMessageBox.critical(self, "Error", 
                               f"Failed to start services: {str(e)}")
    
    def stop_all(self):
        """Stop both WireGuard and Firewall."""
        try:
            self.fw_manager.stop()
            self.wg_manager.stop()
            self.refresh_status()
            QMessageBox.information(self, "Success", 
                                  "WireGuard and Firewall stopped successfully")
        except Exception as e:
            QMessageBox.critical(self, "Error", 
                               f"Failed to stop services: {str(e)}")
    
    def view_logs(self):
        """View application logs."""
        # Implementation for log viewer
        QMessageBox.information(self, "View Logs", 
                              "Log viewer will be implemented here")
    
    def export_configuration(self):
        """Export configuration."""
        # Implementation for export
        QMessageBox.information(self, "Export", 
                              "Export functionality will be implemented here")
    
    def import_configuration(self):
        """Import configuration."""
        # Implementation for import
        QMessageBox.information(self, "Import", 
                              "Import functionality will be implemented here")
    
    def show_documentation(self):
        """Show documentation."""
        QMessageBox.information(self, "Documentation", 
                              "WireGuard Manager Documentation\n\n"
                              "This tool provides a comprehensive GUI for managing:\n"
                              "• WireGuard VPN configurations\n"
                              "• Firewall rules and security\n"
                              "• Peer management\n"
                              "• Key generation\n\n"
                              "For more information, visit the GitHub repository.")
    
    def show_about(self):
        """Show about dialog."""
        QMessageBox.about(self, "About WireGuard Manager",
                         "WireGuard Manager v2.0\n\n"
                         "A comprehensive GUI tool for managing WireGuard VPN "
                         "and firewall rules.\n\n"
                         "Features:\n"
                         "• Complete WireGuard configuration\n"
                         "• Firewall management\n"
                         "• Peer management with QR codes\n"
                         "• IP banning and security\n"
                         "• Real-time status monitoring\n\n"
                         "Created with Python and PyQt6")
    
    def closeEvent(self, event):
        """Handle close event."""
        reply = QMessageBox.question(self, 'Confirm Exit',
                                    'Are you sure you want to exit?',
                                    QMessageBox.StandardButton.Yes |
                                    QMessageBox.StandardButton.No,
                                    QMessageBox.StandardButton.No)
        
        if reply == QMessageBox.StandardButton.Yes:
            # Stop refresh timer
            self.refresh_timer.stop()
            # Save settings
            self.settings.save()
            event.accept()
        else:
            event.ignore()