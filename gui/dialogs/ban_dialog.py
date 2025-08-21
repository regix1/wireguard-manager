"""Ban/Unban IP dialog."""

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QFormLayout, QLineEdit,
    QTextEdit, QPushButton, QDialogButtonBox,
    QMessageBox, QLabel
)
from PyQt6.QtCore import Qt

from core.firewall import FirewallManager
from core.utils import validate_ip

class BanIPDialog(QDialog):
    """Dialog for banning an IP address."""
    
    def __init__(self, fw_manager: FirewallManager, parent=None):
        """Initialize dialog."""
        super().__init__(parent)
        self.fw_manager = fw_manager
        self.setWindowTitle("Ban IP Address")
        self.setModal(True)
        self.setMinimumWidth(400)
        self.setup_ui()
        
    def setup_ui(self):
        """Setup the UI."""
        layout = QVBoxLayout(self)
        
        # Form layout
        form_layout = QFormLayout()
        layout.addLayout(form_layout)
        
        # IP address input
        self.ip_edit = QLineEdit()
        self.ip_edit.setPlaceholderText("e.g., 192.168.1.100 or 10.0.0.0/24")
        form_layout.addRow("IP Address:", self.ip_edit)
        
        # Reason input
        self.reason_edit = QLineEdit()
        self.reason_edit.setPlaceholderText("e.g., Minecraft bot, DDoS attack")
        form_layout.addRow("Reason:", self.reason_edit)
        
        # Info label
        info_label = QLabel("You can ban a single IP (192.168.1.100) or a subnet (10.0.0.0/24)")
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
        self.ip_edit.setFocus()
    
    def accept(self):
        """Validate and accept the dialog."""
        ip = self.ip_edit.text().strip()
        reason = self.reason_edit.text().strip()
        
        # Validate IP
        if not ip:
            QMessageBox.warning(self, "Invalid Input", "Please enter an IP address.")
            return
        
        # Check if it's a subnet or single IP
        if '/' in ip:
            # Subnet - validate network part
            network_part = ip.split('/')[0]
            if not validate_ip(network_part):
                QMessageBox.warning(self, "Invalid IP", 
                                   f"Invalid IP address format: {network_part}")
                return
        else:
            # Single IP
            if not validate_ip(ip):
                QMessageBox.warning(self, "Invalid IP", 
                                   f"Invalid IP address format: {ip}")
                return
        
        try:
            # Ban the IP
            if self.fw_manager.ban_ip(ip, reason):
                QMessageBox.information(self, "Success", 
                                       f"IP {ip} has been banned successfully.")
                super().accept()
            else:
                QMessageBox.warning(self, "Already Banned", 
                                   f"IP {ip} is already in the ban list.")
                
        except Exception as e:
            QMessageBox.critical(self, "Error", 
                                f"Failed to ban IP: {str(e)}")