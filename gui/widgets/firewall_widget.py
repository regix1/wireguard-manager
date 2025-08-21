"""Firewall control widget."""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView,
    QTabWidget, QTextEdit, QMessageBox, QMenu
)
from PyQt6.QtCore import Qt, pyqtSignal, QPoint
from PyQt6.QtGui import QAction, QFont

from core.firewall import FirewallManager
from gui.dialogs.ban_dialog import BanIPDialog
from gui.dialogs.rules_dialog import RulesEditorDialog

class FirewallWidget(QWidget):
    """Widget for managing firewall rules."""
    
    refresh_requested = pyqtSignal()
    
    def __init__(self, fw_manager: FirewallManager, parent=None):
        """Initialize firewall widget."""
        super().__init__(parent)
        self.fw_manager = fw_manager
        self.setup_ui()
        
    def setup_ui(self):
        """Setup the UI."""
        layout = QVBoxLayout(self)
        
        # Create tabs
        self.tabs = QTabWidget()
        layout.addWidget(self.tabs)
        
        # Banned IPs tab
        self.banned_widget = self.create_banned_widget()
        self.tabs.addTab(self.banned_widget, "Banned IPs")
        
        # Firewall Rules tab
        self.rules_widget = self.create_rules_widget()
        self.tabs.addTab(self.rules_widget, "Firewall Rules")
        
        # Port Forwarding tab
        self.port_forward_widget = self.create_port_forward_widget()
        self.tabs.addTab(self.port_forward_widget, "Port Forwarding")
        
        # Initial refresh
        self.refresh()
    
    def create_banned_widget(self):
        """Create banned IPs widget."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Toolbar
        toolbar_layout = QHBoxLayout()
        layout.addLayout(toolbar_layout)
        
        self.ban_btn = QPushButton("Ban IP")
        self.ban_btn.clicked.connect(self.ban_ip)
        toolbar_layout.addWidget(self.ban_btn)
        
        self.unban_btn = QPushButton("Unban Selected")
        self.unban_btn.clicked.connect(self.unban_selected)
        toolbar_layout.addWidget(self.unban_btn)
        
        toolbar_layout.addStretch()
        
        self.refresh_banned_btn = QPushButton("Refresh")
        self.refresh_banned_btn.clicked.connect(self.refresh_banned)
        toolbar_layout.addWidget(self.refresh_banned_btn)
        
        # Banned IPs table
        self.banned_table = QTableWidget()
        self.banned_table.setColumnCount(3)
        self.banned_table.setHorizontalHeaderLabels(["IP Address", "Reason", "Actions"])
        
        header = self.banned_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        
        layout.addWidget(self.banned_table)
        
        return widget
    
    def create_rules_widget(self):
        """Create firewall rules widget."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Toolbar
        toolbar_layout = QHBoxLayout()
        layout.addLayout(toolbar_layout)
        
        self.edit_rules_btn = QPushButton("Edit Rules")
        self.edit_rules_btn.clicked.connect(self.edit_rules)
        toolbar_layout.addWidget(self.edit_rules_btn)
        
        self.add_rule_btn = QPushButton("Add Rule")
        self.add_rule_btn.clicked.connect(self.add_rule)
        toolbar_layout.addWidget(self.add_rule_btn)
        
        self.reload_rules_btn = QPushButton("Reload Rules")
        self.reload_rules_btn.clicked.connect(self.reload_rules)
        toolbar_layout.addWidget(self.reload_rules_btn)
        
        toolbar_layout.addStretch()
        
        # Rules display
        self.rules_text = QTextEdit()
        self.rules_text.setReadOnly(True)
        self.rules_text.setFont(QFont("Courier", 9))
        layout.addWidget(self.rules_text)
        
        return widget
    
    def create_port_forward_widget(self):
        """Create port forwarding widget."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Toolbar
        toolbar_layout = QHBoxLayout()
        layout.addLayout(toolbar_layout)
        
        self.add_forward_btn = QPushButton("Add Port Forward")
        self.add_forward_btn.clicked.connect(self.add_port_forward)
        toolbar_layout.addWidget(self.add_forward_btn)
        
        self.remove_forward_btn = QPushButton("Remove Selected")
        self.remove_forward_btn.clicked.connect(self.remove_port_forward)
        toolbar_layout.addWidget(self.remove_forward_btn)
        
        toolbar_layout.addStretch()
        
        # Port forwarding table
        self.forward_table = QTableWidget()
        self.forward_table.setColumnCount(5)
        self.forward_table.setHorizontalHeaderLabels([
            "Protocol", "External Port(s)", "Destination IP", "Comment", "Actions"
        ])
        
        header = self.forward_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        
        layout.addWidget(self.forward_table)
        
        return widget
    
    def refresh(self):
        """Refresh all firewall information."""
        self.refresh_banned()
        self.refresh_rules()
        self.refresh_port_forwards()
    
    def refresh_banned(self):
        """Refresh banned IPs list."""
        banned_ips = self.fw_manager.get_banned_ips()
        
        self.banned_table.setRowCount(len(banned_ips))
        
        for row, banned_ip in enumerate(banned_ips):
            # IP Address
            self.banned_table.setItem(row, 0, QTableWidgetItem(banned_ip.ip))
            
            # Reason
            self.banned_table.setItem(row, 1, QTableWidgetItem(banned_ip.reason))
            
            # Actions button
            actions_btn = QPushButton("Unban")
            actions_btn.clicked.connect(lambda checked, ip=banned_ip.ip: self.unban_ip(ip))
            self.banned_table.setCellWidget(row, 2, actions_btn)
    
    def refresh_rules(self):
        """Refresh firewall rules display."""
        from pathlib import Path
        
        rules_file = Path(self.fw_manager.settings.firewall.rules_file)
        
        if rules_file.exists():
            rules_text = rules_file.read_text()
            self.rules_text.setPlainText(rules_text)
        else:
            self.rules_text.setPlainText("# No rules file found")
    
    def refresh_port_forwards(self):
        """Refresh port forwarding rules."""
        # Parse rules to find port forwards
        rules = self.fw_manager.get_rules()
        
        forwards = []
        for rule in rules:
            if 'DNAT' in rule.command:
                # Parse port forwarding rule
                parts = rule.command.split()
                protocol = ""
                ports = ""
                destination = ""
                
                for i, part in enumerate(parts):
                    if part == '-p':
                        protocol = parts[i+1] if i+1 < len(parts) else ""
                    elif part == '--dports':
                        ports = parts[i+1] if i+1 < len(parts) else ""
                    elif part == '--dport':
                        ports = parts[i+1] if i+1 < len(parts) else ""
                    elif part == '--to-destination':
                        destination = parts[i+1] if i+1 < len(parts) else ""
                
                if protocol and ports and destination:
                    forwards.append({
                        'protocol': protocol,
                        'ports': ports,
                        'destination': destination,
                        'comment': rule.comment
                    })
        
        self.forward_table.setRowCount(len(forwards))
        
        for row, forward in enumerate(forwards):
            self.forward_table.setItem(row, 0, QTableWidgetItem(forward['protocol']))
            self.forward_table.setItem(row, 1, QTableWidgetItem(forward['ports']))
            self.forward_table.setItem(row, 2, QTableWidgetItem(forward['destination']))
            self.forward_table.setItem(row, 3, QTableWidgetItem(forward['comment']))
            
            # Actions button
            actions_btn = QPushButton("Remove")
            actions_btn.clicked.connect(lambda checked, r=row: self.remove_forward_at_row(r))
            self.forward_table.setCellWidget(row, 4, actions_btn)
    
    def ban_ip(self):
        """Ban an IP address."""
        dialog = BanIPDialog(self.fw_manager, self)
        if dialog.exec():
            self.refresh_banned()
            self.refresh_requested.emit()
    
    def unban_selected(self):
        """Unban selected IP addresses."""
        current_row = self.banned_table.currentRow()
        if current_row >= 0:
            ip = self.banned_table.item(current_row, 0).text()
            self.unban_ip(ip)
    
    def unban_ip(self, ip: str):
        """Unban a specific IP."""
        reply = QMessageBox.question(self, "Confirm Unban",
                                    f"Are you sure you want to unban {ip}?",
                                    QMessageBox.StandardButton.Yes |
                                    QMessageBox.StandardButton.No)
        
        if reply == QMessageBox.StandardButton.Yes:
            try:
                if self.fw_manager.unban_ip(ip):
                    self.refresh_banned()
                    self.refresh_requested.emit()
                    QMessageBox.information(self, "Success", f"IP {ip} unbanned successfully")
                else:
                    QMessageBox.warning(self, "Warning", f"IP {ip} was not found in ban list")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to unban IP: {str(e)}")
    
    def edit_rules(self):
        """Edit firewall rules."""
        dialog = RulesEditorDialog(self.fw_manager, self)
        if dialog.exec():
            self.refresh_rules()
            self.refresh_requested.emit()
    
    def add_rule(self):
        """Add a new firewall rule."""
        from gui.dialogs.rules_dialog import AddRuleDialog
        
        dialog = AddRuleDialog(self.fw_manager, self)
        if dialog.exec():
            self.refresh_rules()
            self.refresh_requested.emit()
    
    def reload_rules(self):
        """Reload firewall rules."""
        reply = QMessageBox.question(self, "Reload Rules",
                                    "This will restart the firewall with the current rules. Continue?",
                                    QMessageBox.StandardButton.Yes |
                                    QMessageBox.StandardButton.No)
        
        if reply == QMessageBox.StandardButton.Yes:
            try:
                self.fw_manager.restart()
                self.refresh()
                self.refresh_requested.emit()
                QMessageBox.information(self, "Success", "Firewall rules reloaded successfully")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to reload rules: {str(e)}")
    
    def add_port_forward(self):
        """Add port forwarding rule."""
        from gui.dialogs.port_forward_dialog import PortForwardDialog
        
        dialog = PortForwardDialog(self.fw_manager, self)
        if dialog.exec():
            self.refresh_port_forwards()
            self.refresh_requested.emit()
    
    def remove_port_forward(self):
        """Remove selected port forward."""
        current_row = self.forward_table.currentRow()
        if current_row >= 0:
            self.remove_forward_at_row(current_row)
    
    def remove_forward_at_row(self, row: int):
        """Remove port forward at specific row."""
        protocol = self.forward_table.item(row, 0).text()
        ports = self.forward_table.item(row, 1).text()
        destination = self.forward_table.item(row, 2).text()
        
        reply = QMessageBox.question(self, "Confirm Removal",
                                    f"Remove port forward {protocol}/{ports} -> {destination}?",
                                    QMessageBox.StandardButton.Yes |
                                    QMessageBox.StandardButton.No)
        
        if reply == QMessageBox.StandardButton.Yes:
            QMessageBox.information(self, "Note",
                                  "Port forward removal will be implemented.\n"
                                  "For now, please edit the rules file directly.")
            # TODO: Implement removal of specific port forward rule