# WireGuard Manager TUI

A beautiful terminal-based interface for managing WireGuard VPN and firewall rules on headless Linux servers.

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Linux-orange)

## 🎯 Features

### Beautiful Terminal UI
- 🎨 Rich, colorful interface using the Rich library
- 📊 Real-time status dashboards
- 🔄 Interactive menus and dialogs
- 📱 QR code generation in terminal for mobile clients

### WireGuard Management
- ✨ Easy peer creation and management
- 🔑 Automatic key generation
- 🌐 Support for routers and subnet routing
- 📊 Traffic monitoring and statistics
- 📱 Mobile-friendly QR codes for configuration

### Firewall & Security
- 🔒 Comprehensive iptables management
- 🚫 IP banning with reason tracking
- 🔄 Port forwarding configuration
- 📝 Custom rule editor with validation
- 🛡️ DDoS protection options

### System Features
- 💾 Automatic configuration backups
- 📊 Real-time system monitoring
- 🔧 Service control (start/stop/restart)
- 📝 Comprehensive logging
- 🚀 CLI mode for automation

## 📋 Requirements

- **OS**: Ubuntu/Debian-based Linux
- **Python**: 3.8 or higher
- **Privileges**: Root or sudo access
- **Dependencies**: WireGuard tools, iptables

## 🚀 Installation

### Quick Install

```bash
# Clone the repository
git clone https://github.com/yourusername/wireguard-firewall.git
cd wireguard-firewall

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run the application
sudo python run.py
```

### System Dependencies

```bash
# Install required system packages
sudo apt update
sudo apt install -y wireguard-tools iptables qrencode python3-pip python3-venv

# Enable IP forwarding
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

## 💻 Usage

### Interactive TUI Mode

```bash
# Start the interactive terminal UI
sudo python run.py
```

### CLI Mode for Automation

```bash
# Quick commands without entering TUI
sudo python run.py --cli --status                    # Show status
sudo python run.py --cli --start-wg                  # Start WireGuard
sudo python run.py --cli --stop-wg                   # Stop WireGuard
sudo python run.py --cli --add-peer "laptop"         # Add a peer
sudo python run.py --cli --ban-ip "192.168.1.100"   # Ban an IP
```

### Available CLI Options

```
--start-wg          Start WireGuard service
--stop-wg           Stop WireGuard service
--start-fw          Start firewall
--stop-fw           Stop firewall
--status            Show system status
--add-peer NAME     Add a new peer
--remove-peer KEY   Remove a peer by public key
--ban-ip IP         Ban an IP address
--unban-ip IP       Unban an IP address
--debug             Enable debug logging
--no-check          Skip requirements check
```

## 🎨 TUI Navigation

### Main Menu Structure

```
1. Dashboard           - System overview and statistics
2. Peers Management    - Add, remove, and manage peers
3. Firewall & Security - Manage rules and banned IPs
4. Configuration       - Edit settings
5. Service Control     - Start/stop services
6. Logs & Diagnostics  - View logs and troubleshoot

A. Quick Actions       - Common administrative tasks
R. Refresh Status      - Update all information
Q. Quit               - Exit application
```

### Keyboard Shortcuts

- `↑/↓` - Navigate menus
- `Enter` - Select option
- `Ctrl+C` - Cancel/Back
- `q` - Quit application

## 📁 Project Structure

```
wireguard-firewall/
├── config/             # Configuration management
│   ├── __init__.py
│   └── settings.py     # Settings dataclasses
├── core/               # Core functionality
│   ├── __init__.py
│   ├── wireguard.py    # WireGuard operations
│   ├── firewall.py     # Firewall management
│   └── utils.py        # Utility functions
├── models/             # Data models
│   ├── __init__.py
│   ├── peer.py         # Peer model
│   ├── firewall_rule.py # Firewall rule model
│   └── banned_ip.py    # Banned IP model
├── tui/                # Terminal UI components
│   ├── __init__.py
│   ├── main_app.py     # Main TUI application
│   ├── screens.py      # Screen components
│   ├── dialogs.py      # Interactive dialogs
│   └── cli_mode.py     # CLI mode handler
├── requirements.txt    # Python dependencies
├── run.py             # Main entry point
└── README.md          # This file
```

## 🔧 Configuration Files

### Default Locations

```
/etc/wireguard/               # WireGuard configs
├── wg0.conf                  # Main interface config
├── peers/                    # Peer configurations
├── keys/                     # Key storage
└── firewall-rules.conf       # Firewall rules

~/.wireguard-manager/         # Manager settings
├── settings.json             # Application settings
├── logs/                     # Application logs
└── backups/                  # Configuration backups
```

## 🛠️ Advanced Features

### Router Configuration

The manager supports configuring peers as routers that can route traffic for other networks:

```python
# When adding a peer, mark it as a router
# and specify the networks it will route
Router: Yes
Routed Networks: 
  - 192.168.1.0/24
  - 192.168.2.0/24
```

### Port Forwarding

Easy port forwarding setup with special support for services like WebRTC:

```
Protocol: tcp/udp/both
External Port: 8080
Destination: 192.168.1.100:80
Description: Web server
```

### Custom Firewall Rules

Add custom iptables rules with validation:

```bash
# Custom rule example
iptables -A INPUT -s 10.0.0.0/8 -j DROP
```

## 🔍 Monitoring & Diagnostics

### Dashboard View

- Real-time service status
- Active peer connections
- Traffic statistics
- System resource usage
- IP forwarding status

### Diagnostic Tools

- Connectivity testing
- DNS resolution checks
- Service health monitoring
- Log analysis
- Configuration validation

## 🚨 Troubleshooting

### Common Issues

#### "Must be run as root"
```bash
# Always run with sudo
sudo python run.py
```

#### "WireGuard service not running"
```bash
# Start via TUI or CLI
sudo python run.py --cli --start-wg
```

#### "Firewall rules not applying"
```bash
# Restart firewall after changes
sudo python run.py --cli --start-fw
```

### Log Files

- Application logs: `~/.wireguard-manager/logs/`
- WireGuard logs: `journalctl -u wg-quick@wg0`
- System logs: `/var/log/syslog`

## 🔐 Security Considerations

1. **Always run as root** - Required for network configuration
2. **Backup configurations** - Automatic backups before changes
3. **Test firewall rules** - Validate before applying
4. **Monitor banned IPs** - Review ban list regularly
5. **Keep software updated** - Regular updates for security

## 📝 License

MIT License - See LICENSE file for details

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 🙏 Acknowledgments

- [Rich](https://github.com/Textualize/rich) - Beautiful terminal formatting
- [WireGuard](https://www.wireguard.com/) - Fast, modern VPN protocol
- Community contributors

## 📧 Support

For issues, questions, or suggestions:
- Create an issue on GitHub
- Check existing documentation
- Review closed issues for solutions

---

Made with ❤️ for the self-hosting community