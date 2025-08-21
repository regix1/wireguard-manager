"""Port forwarding dialog."""

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QFormLayout, QLineEdit,
    QComboBox, QPushButton, QDialogButtonBox,
    QMessageBox, QLabel, QCheckBox
)
from PyQt6.QtCore import Qt

from core.firewall import FirewallManager
from models.firewall_rule import FirewallRule
from core.utils import validate_ip

class PortForwardDialog(QDialog):
    """Dialog for adding port forwarding rules."""
    
    def __init__(self, fw_manager: FirewallManager, parent=None):
        """Initialize dialog."""
        super().__init__(parent)
        self.fw_manager = fw_manager
        self.setWindowTitle("Add Port Forwarding Rule")
        self.setModal(True)
        self.setMinimumWidth(500)
        self.setup_ui()
        
    def setup_ui(self):
        """Setup the UI."""
        layout = QVBoxLayout(self)
        
        # Form layout
        form_layout = QFormLayout()
        layout.addLayout(form_layout)
        
        # Protocol
        self.protocol_combo = QComboBox()
        self.protocol_combo.addItems(["tcp", "udp", "both"])
        form_layout.addRow("Protocol:", self.protocol_combo)
        
        # External interface
        self.ext_interface_edit = QLineEdit(self.fw_manager.settings.firewall.external_interface)
        form_layout.addRow("External Interface:", self.ext_interface_edit)
        
        # External ports
        self.ports_edit = QLineEdit()
        self.ports_edit.setPlaceholderText("e.g., 80 or 8000:8100 or 80,443,3012")
        form_layout.addRow("External Port(s):", self.ports_edit)
        
        # Destination IP
        self.dest_ip_edit = QLineEdit()
        self.dest_ip_edit.setPlaceholderText("e.g., 192.168.1.100 or 10.0.4.246")
        form_layout.addRow("Destination IP:", self.dest_ip_edit)
        
        # Destination port (optional)
        self.dest_port_edit = QLineEdit()
        self.dest_port_edit.setPlaceholderText("Leave empty to use same as external port")
        form_layout.addRow("Destination Port:", self.dest_port_edit)
        
        # WebRTC/Special handling
        self.webrtc_check = QCheckBox("Add SNAT for WebRTC/n.eko (UDP only)")
        self.webrtc_check.toggled.connect(self.on_webrtc_toggled)
        form_layout.addRow("Special:", self.webrtc_check)
        
        # SNAT source (hidden by default)
        self.snat_label = QLabel("SNAT Source IP:")
        self.snat_edit = QLineEdit("10.10.20.1")
        form_layout.addRow(self.snat_label, self.snat_edit)
        self.snat_label.setVisible(False)
        self.snat_edit.setVisible(False)
        
        # Comment
        self.comment_edit = QLineEdit()
        self.comment_edit.setPlaceholderText("e.g., Web server, Minecraft, Game server")
        form_layout.addRow("Description:", self.comment_edit)
        
        # Info label
        info_label = QLabel("Examples:\n"
                          "• Web server: TCP port 80,443 to 10.0.4.246\n"
                          "• Minecraft: TCP 25565-25580 to 172.16.1.225\n"
                          "• Game server: UDP 27015 to 172.16.1.225")
        info_label.setStyleSheet("color: #666; font-style: italic;")
        layout.addWidget(info_label)
        
        # Button box
        button_box = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok |
            QDialogButtonBox.StandardButton.Cancel
        )
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)
        
        # Set focus
        self.ports_edit.setFocus()
    
    def on_webrtc_toggled(self, checked: bool):
        """Handle WebRTC checkbox toggle."""
        self.snat_label.setVisible(checked)
        self.snat_edit.setVisible(checked)
        
        # WebRTC only works with UDP
        if checked:
            self.protocol_combo.setCurrentText("udp")
    
    def accept(self):
        """Validate and accept the dialog."""
        # Get values
        protocol = self.protocol_combo.currentText()
        interface = self.ext_interface_edit.text().strip()
        ports = self.ports_edit.text().strip()
        dest_ip = self.dest_ip_edit.text().strip()
        dest_port = self.dest_port_edit.text().strip()
        comment = self.comment_edit.text().strip()
        
        # Validate required fields
        if not all([interface, ports, dest_ip]):
            QMessageBox.warning(self, "Invalid Input",
                               "Please fill in all required fields.")
            return
        
        # Validate destination IP
        if not validate_ip(dest_ip):
            QMessageBox.warning(self, "Invalid IP",
                               f"Invalid destination IP address: {dest_ip}")
            return
        
        # Build destination
        destination = dest_ip
        if dest_port:
            # If specific destination port, add it
            destination = f"{dest_ip}:{dest_port}"
        
        # Generate comment if not provided
        if not comment:
            comment = f"Port forward {protocol}/{ports} to {destination}"
        
        try:
            # Handle both TCP and UDP if "both" selected
            if protocol == "both":
                # Add TCP rule
                tcp_rule = FirewallRule(
                    type='port_forward',
                    protocol='tcp',
                    interface=interface,
                    ports=ports,
                    destination=destination,
                    comment=f"{comment} (TCP)"
                )
                self.fw_manager.add_rule(tcp_rule)
                
                # Add UDP rule
                udp_rule = FirewallRule(
                    type='port_forward',
                    protocol='udp',
                    interface=interface,
                    ports=ports,
                    destination=destination,
                    comment=f"{comment} (UDP)"
                )
                self.fw_manager.add_rule(udp_rule)
                
            else:
                # Single protocol rule
                rule = FirewallRule(
                    type='port_forward',
                    protocol=protocol,
                    interface=interface,
                    ports=ports,
                    destination=destination,
                    comment=comment
                )
                self.fw_manager.add_rule(rule)
            
            # Add SNAT if WebRTC is checked
            if self.webrtc_check.isChecked() and protocol in ["udp", "both"]:
                snat_ip = self.snat_edit.text().strip()
                if snat_ip:
                    # Add SNAT rule for WebRTC
                    snat_command = (f"iptables -t nat -A POSTROUTING -o wg0 -p udp "
                                  f"-m multiport --dports {ports} -d {dest_ip} "
                                  f"-j SNAT --to-source {snat_ip}")
                    
                    snat_rule = FirewallRule(
                        type='custom',
                        command=snat_command,
                        comment=f"SNAT for WebRTC/n.eko to {dest_ip}"
                    )
                    self.fw_manager.add_rule(snat_rule)
            
            QMessageBox.information(self, "Success",
                                   "Port forwarding rule(s) added successfully.\n\n"
                                   "Restart the firewall to apply changes.")
            
            super().accept()
            
        except Exception as e:
            QMessageBox.critical(self, "Error",
                                f"Failed to add port forwarding rule: {str(e)}")