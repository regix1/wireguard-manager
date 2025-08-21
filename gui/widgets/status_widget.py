"""Status display widget."""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QGroupBox, QGridLayout, QProgressBar
)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QPalette, QColor

from core.utils import format_bytes

class StatusWidget(QWidget):
    """Widget for displaying system status."""
    
    def __init__(self, parent=None):
        """Initialize status widget."""
        super().__init__(parent)
        self.setup_ui()
        
    def setup_ui(self):
        """Setup the UI."""
        layout = QVBoxLayout(self)
        
        # Create horizontal layout for two columns
        h_layout = QHBoxLayout()
        layout.addLayout(h_layout)
        
        # WireGuard Status
        wg_group = QGroupBox("WireGuard Status")
        wg_layout = QGridLayout()
        wg_group.setLayout(wg_layout)
        h_layout.addWidget(wg_group)
        
        # WireGuard status indicators
        self.wg_status_label = self._create_status_label("Status:", "Inactive")
        wg_layout.addWidget(self.wg_status_label[0], 0, 0)
        wg_layout.addWidget(self.wg_status_label[1], 0, 1)
        
        self.wg_interface_label = self._create_status_label("Interface:", "wg0")
        wg_layout.addWidget(self.wg_interface_label[0], 1, 0)
        wg_layout.addWidget(self.wg_interface_label[1], 1, 1)
        
        self.wg_port_label = self._create_status_label("Port:", "N/A")
        wg_layout.addWidget(self.wg_port_label[0], 2, 0)
        wg_layout.addWidget(self.wg_port_label[1], 2, 1)
        
        self.wg_peers_label = self._create_status_label("Active Peers:", "0")
        wg_layout.addWidget(self.wg_peers_label[0], 3, 0)
        wg_layout.addWidget(self.wg_peers_label[1], 3, 1)
        
        self.wg_traffic_label = self._create_status_label("Traffic:", "RX: 0 B / TX: 0 B")
        wg_layout.addWidget(self.wg_traffic_label[0], 4, 0)
        wg_layout.addWidget(self.wg_traffic_label[1], 4, 1)
        
        # Firewall Status
        fw_group = QGroupBox("Firewall Status")
        fw_layout = QGridLayout()
        fw_group.setLayout(fw_layout)
        h_layout.addWidget(fw_group)
        
        # Firewall status indicators
        self.fw_status_label = self._create_status_label("Status:", "Inactive")
        fw_layout.addWidget(self.fw_status_label[0], 0, 0)
        fw_layout.addWidget(self.fw_status_label[1], 0, 1)
        
        self.fw_policies_label = self._create_status_label("Policies:", "N/A")
        fw_layout.addWidget(self.fw_policies_label[0], 1, 0)
        fw_layout.addWidget(self.fw_policies_label[1], 1, 1)
        
        self.fw_rules_label = self._create_status_label("Active Rules:", "0")
        fw_layout.addWidget(self.fw_rules_label[0], 2, 0)
        fw_layout.addWidget(self.fw_rules_label[1], 2, 1)
        
        self.fw_banned_label = self._create_status_label("Banned IPs:", "0")
        fw_layout.addWidget(self.fw_banned_label[0], 3, 0)
        fw_layout.addWidget(self.fw_banned_label[1], 3, 1)
        
        self.fw_nat_label = self._create_status_label("NAT Rules:", "0")
        fw_layout.addWidget(self.fw_nat_label[0], 4, 0)
        fw_layout.addWidget(self.fw_nat_label[1], 4, 1)
        
        # System Overview
        system_group = QGroupBox("System Overview")
        system_layout = QGridLayout()
        system_group.setLayout(system_layout)
        layout.addWidget(system_group)
        
        # System indicators
        self.ip_forwarding_label = self._create_status_label("IP Forwarding:", "Unknown")
        system_layout.addWidget(self.ip_forwarding_label[0], 0, 0)
        system_layout.addWidget(self.ip_forwarding_label[1], 0, 1)
        
        self.public_ip_label = self._create_status_label("Public IP:", "Unknown")
        system_layout.addWidget(self.public_ip_label[0], 0, 2)
        system_layout.addWidget(self.public_ip_label[1], 0, 3)
        
        self.cpu_label = self._create_status_label("CPU Usage:", "0%")
        system_layout.addWidget(self.cpu_label[0], 1, 0)
        system_layout.addWidget(self.cpu_label[1], 1, 1)
        
        self.memory_label = self._create_status_label("Memory:", "0%")
        system_layout.addWidget(self.memory_label[0], 1, 2)
        system_layout.addWidget(self.memory_label[1], 1, 3)
        
        # Add stretch
        layout.addStretch()
    
    def _create_status_label(self, label_text: str, value_text: str) -> tuple:
        """Create a status label pair."""
        label = QLabel(label_text)
        label.setStyleSheet("font-weight: bold;")
        value = QLabel(value_text)
        return (label, value)
    
    def update_status(self, wg_status: dict, fw_status: dict):
        """Update status displays."""
        # Update WireGuard status
        if wg_status.get('active'):
            self.wg_status_label[1].setText("Active")
            self.wg_status_label[1].setStyleSheet("color: green; font-weight: bold;")
        else:
            self.wg_status_label[1].setText("Inactive")
            self.wg_status_label[1].setStyleSheet("color: red; font-weight: bold;")
        
        self.wg_interface_label[1].setText(wg_status.get('interface', 'wg0'))
        self.wg_port_label[1].setText(str(wg_status.get('listening_port', 'N/A')))
        self.wg_peers_label[1].setText(str(len(wg_status.get('peers', []))))
        
        # Format traffic
        rx = format_bytes(wg_status.get('total_rx', 0))
        tx = format_bytes(wg_status.get('total_tx', 0))
        self.wg_traffic_label[1].setText(f"RX: {rx} / TX: {tx}")
        
        # Update Firewall status
        if fw_status.get('active'):
            self.fw_status_label[1].setText("Active")
            self.fw_status_label[1].setStyleSheet("color: green; font-weight: bold;")
        else:
            self.fw_status_label[1].setText("Inactive")
            self.fw_status_label[1].setStyleSheet("color: red; font-weight: bold;")
        
        # Format policies
        policies = fw_status.get('policies', {})
        if policies:
            policy_text = f"I:{policies.get('INPUT', '?')} F:{policies.get('FORWARD', '?')} O:{policies.get('OUTPUT', '?')}"
            self.fw_policies_label[1].setText(policy_text)
        
        # Rules count
        rules_count = fw_status.get('rules_count', {})
        total_rules = sum(rules_count.values())
        self.fw_rules_label[1].setText(str(total_rules))
        
        self.fw_banned_label[1].setText(str(fw_status.get('banned_ips_count', 0)))
        self.fw_nat_label[1].setText(str(fw_status.get('nat_rules', 0)))
        
        # Update system info
        self._update_system_info()
    
    def _update_system_info(self):
        """Update system information."""
        import psutil
        from core.utils import get_public_ip
        
        # IP forwarding status
        try:
            with open('/proc/sys/net/ipv4/ip_forward', 'r') as f:
                if f.read().strip() == '1':
                    self.ip_forwarding_label[1].setText("Enabled")
                    self.ip_forwarding_label[1].setStyleSheet("color: green;")
                else:
                    self.ip_forwarding_label[1].setText("Disabled")
                    self.ip_forwarding_label[1].setStyleSheet("color: red;")
        except:
            self.ip_forwarding_label[1].setText("Unknown")
        
        # Public IP (cached)
        if not hasattr(self, '_public_ip'):
            self._public_ip = get_public_ip() or "Unknown"
        self.public_ip_label[1].setText(self._public_ip)
        
        # CPU usage
        cpu_percent = psutil.cpu_percent(interval=0.1)
        self.cpu_label[1].setText(f"{cpu_percent:.1f}%")
        if cpu_percent > 80:
            self.cpu_label[1].setStyleSheet("color: red;")
        elif cpu_percent > 50:
            self.cpu_label[1].setStyleSheet("color: orange;")
        else:
            self.cpu_label[1].setStyleSheet("color: green;")
        
        # Memory usage
        memory = psutil.virtual_memory()
        self.memory_label[1].setText(f"{memory.percent:.1f}%")
        if memory.percent > 80:
            self.memory_label[1].setStyleSheet("color: red;")
        elif memory.percent > 50:
            self.memory_label[1].setStyleSheet("color: orange;")
        else:
            self.memory_label[1].setStyleSheet("color: green;")