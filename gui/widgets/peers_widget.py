"""Peers management widget."""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView,
    QMessageBox, QMenu, QFileDialog
)
from PyQt6.QtCore import Qt, pyqtSignal, QPoint
from PyQt6.QtGui import QAction

from core.wireguard import WireGuardManager
from gui.dialogs.peer_dialog import AddPeerDialog
from core.utils import format_bytes

class PeersWidget(QWidget):
    """Widget for managing WireGuard peers."""
    
    refresh_requested = pyqtSignal()
    
    def __init__(self, wg_manager: WireGuardManager, parent=None):
        """Initialize peers widget."""
        super().__init__(parent)
        self.wg_manager = wg_manager
        self.setup_ui()
        
    def setup_ui(self):
        """Setup the UI."""
        layout = QVBoxLayout(self)
        
        # Toolbar
        toolbar_layout = QHBoxLayout()
        layout.addLayout(toolbar_layout)
        
        self.add_btn = QPushButton("Add Peer")
        self.add_btn.clicked.connect(self.add_peer)
        toolbar_layout.addWidget(self.add_btn)
        
        self.generate_keys_btn = QPushButton("Generate Keys")
        self.generate_keys_btn.clicked.connect(self.generate_keys)
        toolbar_layout.addWidget(self.generate_keys_btn)
        
        self.export_btn = QPushButton("Export Config")
        self.export_btn.clicked.connect(self.export_config)
        toolbar_layout.addWidget(self.export_btn)
        
        self.import_btn = QPushButton("Import Config")
        self.import_btn.clicked.connect(self.import_config)
        toolbar_layout.addWidget(self.import_btn)
        
        toolbar_layout.addStretch()
        
        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.clicked.connect(self.refresh)
        toolbar_layout.addWidget(self.refresh_btn)
        
        # Peers table
        self.table = QTableWidget()
        self.table.setColumnCount(8)
        self.table.setHorizontalHeaderLabels([
            "Name", "IP Address", "Public Key", "Type",
            "Latest Handshake", "RX", "TX", "Actions"
        ])
        
        # Set column stretch
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(6, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(7, QHeaderView.ResizeMode.ResizeToContents)
        
        # Enable context menu
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.show_context_menu)
        
        layout.addWidget(self.table)
        
        # Initial refresh
        self.refresh()
    
    def refresh(self):
        """Refresh the peers list."""
        # Get current status
        status = self.wg_manager.get_status()
        peers = self.wg_manager.get_peers()
        
        # Create a map of active peer data
        active_peers = {}
        for peer_status in status.get('peers', []):
            active_peers[peer_status['public_key']] = peer_status
        
        # Update table
        self.table.setRowCount(len(peers))
        
        for row, peer in enumerate(peers):
            # Name
            self.table.setItem(row, 0, QTableWidgetItem(peer.name))
            
            # IP Address
            self.table.setItem(row, 1, QTableWidgetItem(peer.ip_address))
            
            # Public Key (truncated)
            pub_key = peer.public_key
            display_key = f"{pub_key[:10]}...{pub_key[-10:]}" if len(pub_key) > 24 else pub_key
            item = QTableWidgetItem(display_key)
            item.setToolTip(pub_key)  # Full key in tooltip
            self.table.setItem(row, 2, item)
            
            # Type
            peer_type = "Router" if peer.is_router else "Client"
            self.table.setItem(row, 3, QTableWidgetItem(peer_type))
            
            # Get active data if available
            active_data = active_peers.get(peer.public_key, {})
            
            # Latest Handshake
            handshake = active_data.get('latest_handshake', 'Never')
            self.table.setItem(row, 4, QTableWidgetItem(handshake))
            
            # RX/TX
            rx = format_bytes(active_data.get('transfer_rx', 0))
            tx = format_bytes(active_data.get('transfer_tx', 0))
            self.table.setItem(row, 5, QTableWidgetItem(rx))
            self.table.setItem(row, 6, QTableWidgetItem(tx))
            
            # Actions button
            actions_btn = QPushButton("Actions")
            actions_btn.clicked.connect(lambda checked, r=row: self.show_peer_actions(r))
            self.table.setCellWidget(row, 7, actions_btn)
    
    def add_peer(self):
        """Add a new peer."""
        dialog = AddPeerDialog(self.wg_manager, self)
        if dialog.exec():
            self.refresh()
            self.refresh_requested.emit()
    
    def generate_keys(self):
        """Generate new keys."""
        keys = self.wg_manager.generate_keys()
        
        # Show keys in a message box
        QMessageBox.information(self, "Generated Keys",
                              f"<b>Private Key:</b><br>{keys['private']}<br><br>"
                              f"<b>Public Key:</b><br>{keys['public']}<br><br>"
                              f"<b>Preshared Key:</b><br>{keys['preshared']}")
    
    def export_config(self):
        """Export configuration."""
        filename, _ = QFileDialog.getSaveFileName(
            self, "Export Configuration", "", "Config Files (*.conf);;All Files (*)"
        )
        
        if filename:
            try:
                # Copy current config to selected location
                import shutil
                shutil.copy(self.wg_manager.config_file, filename)
                QMessageBox.information(self, "Success", f"Configuration exported to {filename}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to export configuration: {str(e)}")
    
    def import_config(self):
        """Import configuration."""
        filename, _ = QFileDialog.getOpenFileName(
            self, "Import Configuration", "", "Config Files (*.conf);;All Files (*)"
        )
        
        if filename:
            try:
                self.wg_manager.load_config(filename)
                self.refresh()
                self.refresh_requested.emit()
                QMessageBox.information(self, "Success", "Configuration imported successfully")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to import configuration: {str(e)}")
    
    def show_peer_actions(self, row: int):
        """Show actions menu for a peer."""
        menu = QMenu(self)
        
        # Get peer data
        peer_name = self.table.item(row, 0).text()
        peer_key = self.table.item(row, 2).toolTip()  # Full key from tooltip
        
        # View config action
        view_action = QAction("View Configuration", self)
        view_action.triggered.connect(lambda: self.view_peer_config(peer_name))
        menu.addAction(view_action)
        
        # Show QR code action
        qr_action = QAction("Show QR Code", self)
        qr_action.triggered.connect(lambda: self.show_qr_code(peer_name))
        menu.addAction(qr_action)
        
        menu.addSeparator()
        
        # Edit action
        edit_action = QAction("Edit Peer", self)
        edit_action.triggered.connect(lambda: self.edit_peer(peer_name))
        menu.addAction(edit_action)
        
        menu.addSeparator()
        
        # Remove action
        remove_action = QAction("Remove Peer", self)
        remove_action.triggered.connect(lambda: self.remove_peer(peer_key, peer_name))
        menu.addAction(remove_action)
        
        # Show menu at button position
        button = self.table.cellWidget(row, 7)
        menu.exec(button.mapToGlobal(QPoint(0, button.height())))
    
    def show_context_menu(self, position):
        """Show context menu for table."""
        item = self.table.itemAt(position)
        if item is None:
            return
        
        row = item.row()
        self.show_peer_actions(row)
    
    def view_peer_config(self, peer_name: str):
        """View peer configuration."""
        from pathlib import Path
        from core.utils import sanitize_filename
        
        safe_name = sanitize_filename(peer_name)
        config_dir = Path(self.wg_manager.settings.wireguard.config_dir) / "peers"
        config_file = config_dir / f"{safe_name}.conf"
        
        if config_file.exists():
            config_text = config_file.read_text()
            QMessageBox.information(self, f"Configuration for {peer_name}",
                                  f"<pre>{config_text}</pre>")
        else:
            QMessageBox.warning(self, "Not Found",
                               f"Configuration file for {peer_name} not found")
    
    def show_qr_code(self, peer_name: str):
        """Show QR code for peer configuration."""
        from pathlib import Path
        from core.utils import sanitize_filename
        from PyQt6.QtGui import QPixmap
        from PyQt6.QtWidgets import QDialog, QVBoxLayout, QLabel
        
        safe_name = sanitize_filename(peer_name)
        config_dir = Path(self.wg_manager.settings.wireguard.config_dir) / "peers"
        qr_file = config_dir / f"{safe_name}.png"
        
        if qr_file.exists():
            dialog = QDialog(self)
            dialog.setWindowTitle(f"QR Code for {peer_name}")
            dialog.setModal(True)
            
            layout = QVBoxLayout(dialog)
            
            label = QLabel()
            pixmap = QPixmap(str(qr_file))
            label.setPixmap(pixmap)
            layout.addWidget(label)
            
            dialog.exec()
        else:
            QMessageBox.warning(self, "Not Found",
                               f"QR code for {peer_name} not found")
    
    def edit_peer(self, peer_name: str):
        """Edit peer configuration."""
        QMessageBox.information(self, "Edit Peer",
                              f"Edit functionality for {peer_name} will be implemented")
    
    def remove_peer(self, public_key: str, peer_name: str):
        """Remove a peer."""
        reply = QMessageBox.question(self, "Confirm Removal",
                                    f"Are you sure you want to remove peer '{peer_name}'?",
                                    QMessageBox.StandardButton.Yes |
                                    QMessageBox.StandardButton.No)
        
        if reply == QMessageBox.StandardButton.Yes:
            try:
                if self.wg_manager.remove_peer(public_key):
                    self.refresh()
                    self.refresh_requested.emit()
                    QMessageBox.information(self, "Success", f"Peer '{peer_name}' removed successfully")
                else:
                    QMessageBox.warning(self, "Warning", f"Could not remove peer '{peer_name}'")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to remove peer: {str(e)}")