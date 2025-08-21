"""Firewall rules editor dialog."""

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QTextEdit,
    QPushButton, QDialogButtonBox, QMessageBox,
    QLabel, QComboBox, QLineEdit, QFormLayout,
    QGroupBox, QRadioButton, QButtonGroup
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont

from core.firewall import FirewallManager
from models.firewall_rule import FirewallRule
from pathlib import Path

class RulesEditorDialog(QDialog):
    """Dialog for editing firewall rules."""
    
    def __init__(self, fw_manager: FirewallManager, parent=None):
        """Initialize dialog."""
        super().__init__(parent)
        self.fw_manager = fw_manager
        self.setWindowTitle("Edit Firewall Rules")
        self.setModal(True)
        self.resize(800, 600)
        self.setup_ui()
        self.load_rules()
        
    def setup_ui(self):
        """Setup the UI."""
        layout = QVBoxLayout(self)
        
        # Info label
        info_label = QLabel("Edit firewall rules below. Each line should be a valid iptables command.")
        info_label.setWordWrap(True)
        layout.addWidget(info_label)
        
        # Text editor
        self.rules_edit = QTextEdit()
        self.rules_edit.setFont(QFont("Courier", 9))
        self.rules_edit.setAcceptRichText(False)
        layout.addWidget(self.rules_edit)
        
        # Button box
        button_box = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save |
            QDialogButtonBox.StandardButton.Cancel
        )
        button_box.button(QDialogButtonBox.StandardButton.Save).clicked.connect(self.save_rules)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)
    
    def load_rules(self):
        """Load current rules."""
        rules_file = Path(self.fw_manager.settings.firewall.rules_file)
        
        if rules_file.exists():
            self.rules_edit.setPlainText(rules_file.read_text())
        else:
            # Load template
            template = """# WireGuard Firewall Rules Configuration
# This file contains ONLY iptables commands - no bash code
# Lines starting with # are comments and will be ignored
#
# Format: One iptables command per line
# Example: iptables -A FORWARD -p tcp --dport 80 -j ACCEPT

# ========== NAT Rules ==========

# ========== Basic Access Rules ==========

# ========== Port Forwarding Rules ==========

# ========== Security Rules ==========
"""
            self.rules_edit.setPlainText(template)
    
    def save_rules(self):
        """Save the rules."""
        rules_text = self.rules_edit.toPlainText()
        
        # Basic validation
        errors = []
        for i, line in enumerate(rules_text.split('\n'), 1):
            line = line.strip()
            if line and not line.startswith('#'):
                if not line.startswith('iptables'):
                    errors.append(f"Line {i}: Must start with 'iptables'")
        
        if errors:
            QMessageBox.warning(self, "Validation Errors",
                               "Found the following errors:\n\n" + "\n".join(errors[:5]))
            return
        
        try:
            # Save rules
            rules_file = Path(self.fw_manager.settings.firewall.rules_file)
            rules_file.parent.mkdir(parents=True, exist_ok=True)
            rules_file.write_text(rules_text)
            
            QMessageBox.information(self, "Success",
                                   "Rules saved successfully.\n\n"
                                   "Restart the firewall to apply changes.")
            self.accept()
            
        except Exception as e:
            QMessageBox.critical(self, "Error",
                                f"Failed to save rules: {str(e)}")


class AddRuleDialog(QDialog):
    """Dialog for adding a new firewall rule."""
    
    def __init__(self, fw_manager: FirewallManager, parent=None):
        """Initialize dialog."""
        super().__init__(parent)
        self.fw_manager = fw_manager
        self.setWindowTitle("Add Firewall Rule")
        self.setModal(True)
        self.setMinimumWidth(600)
        self.setup_ui()
        
    def setup_ui(self):
        """Setup the UI."""
        layout = QVBoxLayout(self)
        
        # Rule type selection
        type_group = QGroupBox("Rule Type")
        type_layout = QVBoxLayout()
        type_group.setLayout(type_layout)
        layout.addWidget(type_group)
        
        self.type_group = QButtonGroup()
        
        self.port_forward_radio = QRadioButton("Port Forwarding")
        self.port_forward_radio.setChecked(True)
        self.port_forward_radio.toggled.connect(self.on_type_changed)
        self.type_group.addButton(self.port_forward_radio, 0)
        type_layout.addWidget(self.port_forward_radio)
        
        self.nat_radio = QRadioButton("NAT/Masquerade")
        self.nat_radio.toggled.connect(self.on_type_changed)
        self.type_group.addButton(self.nat_radio, 1)
        type_layout.addWidget(self.nat_radio)
        
        self.filter_radio = QRadioButton("Filter Rule")
        self.filter_radio.toggled.connect(self.on_type_changed)
        self.type_group.addButton(self.filter_radio, 2)
        type_layout.addWidget(self.filter_radio)
        
        self.custom_radio = QRadioButton("Custom iptables Command")
        self.custom_radio.toggled.connect(self.on_type_changed)
        self.type_group.addButton(self.custom_radio, 3)
        type_layout.addWidget(self.custom_radio)
        
        # Configuration area
        self.config_group = QGroupBox("Configuration")
        self.config_layout = QFormLayout()
        self.config_group.setLayout(self.config_layout)
        layout.addWidget(self.config_group)
        
        # Initialize with port forward config
        self.setup_port_forward_config()
        
        # Comment
        comment_group = QGroupBox("Comment")
        comment_layout = QVBoxLayout()
        comment_group.setLayout(comment_layout)
        layout.addWidget(comment_group)
        
        self.comment_edit = QLineEdit()
        self.comment_edit.setPlaceholderText("Brief description of this rule")
        comment_layout.addWidget(self.comment_edit)
        
        # Button box
        button_box = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok |
            QDialogButtonBox.StandardButton.Cancel
        )
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)
    
    def clear_config_layout(self):
        """Clear the configuration layout."""
        while self.config_layout.count():
            child = self.config_layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()
    
    def setup_port_forward_config(self):
        """Setup port forwarding configuration."""
        self.clear_config_layout()
        
        # Protocol
        self.protocol_combo = QComboBox()
        self.protocol_combo.addItems(["tcp", "udp", "both"])
        self.config_layout.addRow("Protocol:", self.protocol_combo)
        
        # External interface
        self.ext_interface_edit = QLineEdit(self.fw_manager.settings.firewall.external_interface)
        self.config_layout.addRow("External Interface:", self.ext_interface_edit)
        
        # Ports
        self.ports_edit = QLineEdit()
        self.ports_edit.setPlaceholderText("e.g., 80 or 8000:8100 or 80,443")
        self.config_layout.addRow("Port(s):", self.ports_edit)
        
        # Destination
        self.destination_edit = QLineEdit()
        self.destination_edit.setPlaceholderText("e.g., 192.168.1.100 or 10.0.4.246:8080")
        self.config_layout.addRow("Destination:", self.destination_edit)
    
    def setup_nat_config(self):
        """Setup NAT configuration."""
        self.clear_config_layout()
        
        # Source network
        self.source_network_edit = QLineEdit()
        self.source_network_edit.setPlaceholderText("e.g., 10.0.0.0/24")
        self.config_layout.addRow("Source Network:", self.source_network_edit)
        
        # Output interface
        self.out_interface_edit = QLineEdit(self.fw_manager.settings.firewall.external_interface)
        self.config_layout.addRow("Output Interface:", self.out_interface_edit)
        
        # NAT type
        self.nat_type_combo = QComboBox()
        self.nat_type_combo.addItems(["MASQUERADE", "SNAT"])
        self.nat_type_combo.currentTextChanged.connect(self.on_nat_type_changed)
        self.config_layout.addRow("NAT Type:", self.nat_type_combo)
        
        # SNAT IP (hidden by default)
        self.snat_ip_label = QLabel("SNAT IP:")
        self.snat_ip_edit = QLineEdit()
        self.snat_ip_edit.setPlaceholderText("e.g., 203.0.113.1")
        self.config_layout.addRow(self.snat_ip_label, self.snat_ip_edit)
        self.snat_ip_label.setVisible(False)
        self.snat_ip_edit.setVisible(False)
    
    def setup_filter_config(self):
        """Setup filter rule configuration."""
        self.clear_config_layout()
        
        # Chain
        self.chain_combo = QComboBox()
        self.chain_combo.addItems(["INPUT", "FORWARD", "OUTPUT"])
        self.config_layout.addRow("Chain:", self.chain_combo)
        
        # Protocol
        self.filter_protocol_combo = QComboBox()
        self.filter_protocol_combo.addItems(["all", "tcp", "udp", "icmp"])
        self.config_layout.addRow("Protocol:", self.filter_protocol_combo)
        
        # Interface
        self.filter_interface_edit = QLineEdit()
        self.filter_interface_edit.setPlaceholderText("e.g., eth0, wg0 (optional)")
        self.config_layout.addRow("Interface:", self.filter_interface_edit)
        
        # Source
        self.filter_source_edit = QLineEdit()
        self.filter_source_edit.setPlaceholderText("e.g., 192.168.1.0/24 (optional)")
        self.config_layout.addRow("Source:", self.filter_source_edit)
        
        # Destination
        self.filter_dest_edit = QLineEdit()
        self.filter_dest_edit.setPlaceholderText("e.g., 10.0.0.1 (optional)")
        self.config_layout.addRow("Destination:", self.filter_dest_edit)
        
        # Port
        self.filter_port_edit = QLineEdit()
        self.filter_port_edit.setPlaceholderText("e.g., 22 or 80,443 (optional)")
        self.config_layout.addRow("Port(s):", self.filter_port_edit)
        
        # Action
        self.action_combo = QComboBox()
        self.action_combo.addItems(["ACCEPT", "DROP", "REJECT"])
        self.config_layout.addRow("Action:", self.action_combo)
    
    def setup_custom_config(self):
        """Setup custom command configuration."""
        self.clear_config_layout()
        
        # Custom command
        self.custom_edit = QTextEdit()
        self.custom_edit.setPlaceholderText("Enter complete iptables command(s), one per line")
        self.custom_edit.setMaximumHeight(100)
        self.config_layout.addRow("Command(s):", self.custom_edit)
    
    def on_type_changed(self):
        """Handle rule type change."""
        if self.port_forward_radio.isChecked():
            self.setup_port_forward_config()
        elif self.nat_radio.isChecked():
            self.setup_nat_config()
        elif self.filter_radio.isChecked():
            self.setup_filter_config()
        elif self.custom_radio.isChecked():
            self.setup_custom_config()
    
    def on_nat_type_changed(self, nat_type: str):
        """Handle NAT type change."""
        show_snat = nat_type == "SNAT"
        self.snat_ip_label.setVisible(show_snat)
        self.snat_ip_edit.setVisible(show_snat)
    
    def accept(self):
        """Validate and accept the dialog."""
        comment = self.comment_edit.text().strip()
        
        try:
            if self.port_forward_radio.isChecked():
                # Validate port forward
                protocol = self.protocol_combo.currentText()
                interface = self.ext_interface_edit.text().strip()
                ports = self.ports_edit.text().strip()
                destination = self.destination_edit.text().strip()
                
                if not all([interface, ports, destination]):
                    QMessageBox.warning(self, "Invalid Input",
                                       "Please fill in all required fields.")
                    return
                
                rule = FirewallRule(
                    type='port_forward',
                    protocol=protocol,
                    interface=interface,
                    ports=ports,
                    destination=destination,
                    comment=comment or f"Port forward {protocol}/{ports} to {destination}"
                )
                
            elif self.nat_radio.isChecked():
                # Validate NAT
                source = self.source_network_edit.text().strip()
                interface = self.out_interface_edit.text().strip()
                nat_type = self.nat_type_combo.currentText()
                snat_ip = self.snat_ip_edit.text().strip() if nat_type == "SNAT" else ""
                
                if not all([source, interface]):
                    QMessageBox.warning(self, "Invalid Input",
                                       "Please fill in all required fields.")
                    return
                
                if nat_type == "SNAT" and not snat_ip:
                    QMessageBox.warning(self, "Invalid Input",
                                       "Please specify SNAT IP address.")
                    return
                
                rule = FirewallRule(
                    type='nat',
                    source_network=source,
                    interface=interface,
                    nat_type=nat_type,
                    snat_ip=snat_ip,
                    comment=comment or f"NAT for {source}"
                )
                
            elif self.filter_radio.isChecked():
                # Create filter rule
                rule = FirewallRule(
                    type='filter',
                    chain=self.chain_combo.currentText(),
                    protocol=self.filter_protocol_combo.currentText(),
                    interface=self.filter_interface_edit.text().strip(),
                    source_network=self.filter_source_edit.text().strip(),
                    destination=self.filter_dest_edit.text().strip(),
                    ports=self.filter_port_edit.text().strip(),
                    action=self.action_combo.currentText(),
                    comment=comment or "Filter rule"
                )
                
            elif self.custom_radio.isChecked():
                # Custom command
                command = self.custom_edit.toPlainText().strip()
                if not command:
                    QMessageBox.warning(self, "Invalid Input",
                                       "Please enter a custom command.")
                    return
                
                rule = FirewallRule(
                    type='custom',
                    command=command,
                    comment=comment or "Custom rule"
                )
            
            # Add the rule
            self.fw_manager.add_rule(rule)
            
            QMessageBox.information(self, "Success",
                                   "Rule added successfully.\n\n"
                                   "The rule has been added to the configuration file.")
            
            super().accept()
            
        except Exception as e:
            QMessageBox.critical(self, "Error",
                                f"Failed to add rule: {str(e)}")