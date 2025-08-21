"""Add/Edit peer dialog."""

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QFormLayout,
    QLineEdit, QSpinBox, QCheckBox, QTextEdit,
    QPushButton, QDialogButtonBox, QMessageBox,
    QLabel, QGroupBox
)
from PyQt6.QtCore import Qt

from core.wireguard import WireGuardManager
from models.peer import Peer

class AddPeerDialog(QDialog):
    """Dialog for adding a new peer."""
    
    def __init__(self, wg_manager: WireGuardManager, parent=None):
        """Initialize dialog."""
        super().__init__(parent)
        self.wg_manager = wg_manager
        self.setWindowTitle("Add New Peer")
        self.setModal(True)
        self.setMinimumWidth(500)
        self.setup_ui()
        
    def setup_ui(self):
        """Setup the UI."""
        layout = QVBoxLayout(self)
        
        # Basic Information
        basic_group = QGroupBox("Basic Information")
        basic_layout = QFormLayout()
        basic_group.setLayout(basic_layout)
        layout.addWidget(basic_group)
        
        # Peer name
        self.name_edit = QLineEdit()
        self.name_edit.setPlaceholderText("e.g., laptop, phone, john-pc")
        basic_layout.addRow("Peer Name:", self.name_edit)
        
        # Peer type
        self.is_router_check = QCheckBox("This is a router (routes traffic for other devices)")
        self.is_router_check.toggled.connect(self.on_router_toggled)
        basic_layout.addRow("Peer Type:", self.is_router_check)
        
        # Keepalive
        self.keepalive_spin = QSpinBox()
        self.keepalive_spin.setRange(0, 3600)
        self.keepalive_spin.setValue(25)
        self.keepalive_spin.setSuffix(" seconds")
        self.keepalive_spin.setSpecialValueText("Disabled")
        basic_layout.addRow("Keepalive:", self.keepalive_spin)
        
        # Router Configuration (hidden by default)
        self.router_group = QGroupBox("Router Configuration")
        router_layout = QFormLayout()
        self.router_group.setLayout(router_layout)
        self.router_group.setVisible(False)
        layout.addWidget(self.router_group)
        
        # Routed networks
        self.networks_edit = QTextEdit()
        self.networks_edit.setPlaceholderText("Enter networks this router will route, one per line\n"
                                              "Example:\n"
                                              "192.168.1.0/24\n"
                                              "192.168.2.0/24")
        self.networks_edit.setMaximumHeight(100)
        router_layout.addRow("Routed Networks:", self.networks_edit)
        
        # Instructions
        instructions = QLabel("The router will need to be configured with the generated "
                            "configuration file. OpenWRT and Linux routers are supported.")
        instructions.setWordWrap(True)
        instructions.setStyleSheet("color: #666; font-style: italic;")
        router_layout.addRow(instructions)
        
        # Button box
        button_box = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok |
            QDialogButtonBox.StandardButton.Cancel
        )
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)
        
        # Set focus
        self.name_edit.setFocus()
    
    def on_router_toggled(self, checked: bool):
        """Handle router checkbox toggle."""
        self.router_group.setVisible(checked)
        self.adjustSize()
    
    def accept(self):
        """Validate and accept the dialog."""
        # Validate name
        name = self.name_edit.text().strip()
        if not name:
            QMessageBox.warning(self, "Invalid Input", "Please enter a peer name.")
            return
        
        # Get routed networks if router
        routed_networks = []
        if self.is_router_check.isChecked():
            networks_text = self.networks_edit.toPlainText().strip()
            if networks_text:
                for line in networks_text.split('\n'):
                    network = line.strip()
                    if network:
                        # Basic validation
                        if '/' not in network:
                            QMessageBox.warning(self, "Invalid Network",
                                              f"Invalid network format: {network}\n"
                                              "Use CIDR notation (e.g., 192.168.1.0/24)")
                            return
                        routed_networks.append(network)
        
        # Create peer
        peer = Peer(
            name=name,
            is_router=self.is_router_check.isChecked(),
            routed_networks=routed_networks,
            persistent_keepalive=self.keepalive_spin.value()
        )
        
        try:
            # Add peer
            result = self.wg_manager.add_peer(peer)
            
            # Show success message with details
            msg = f"Peer '{name}' added successfully!\n\n"
            msg += f"IP Address: {result['ip_address']}\n"
            msg += f"Public Key: {result['public_key']}\n\n"
            
            if result.get('config_file'):
                msg += f"Configuration saved to:\n{result['config_file']}\n\n"
            
            if result.get('qr_file'):
                msg += f"QR code saved to:\n{result['qr_file']}"
            
            QMessageBox.information(self, "Success", msg)
            
            super().accept()
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to add peer: {str(e)}")