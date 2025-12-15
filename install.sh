#!/bin/bash
# WireGuard Manager Installation Script

set -e

echo "=== WireGuard Manager Installer ==="
echo

# Check root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (sudo ./install.sh)"
    exit 1
fi

# Detect OS
if [ -f /etc/debian_version ]; then
    OS="debian"
elif [ -f /etc/redhat-release ]; then
    OS="redhat"
else
    OS="unknown"
fi

echo "Detected OS: $OS"

# Install system dependencies
echo "Installing system dependencies..."
if [ "$OS" = "debian" ]; then
    apt-get update
    apt-get install -y python3 python3-pip python3-venv wireguard wireguard-tools qrencode
elif [ "$OS" = "redhat" ]; then
    dnf install -y python3 python3-pip wireguard-tools qrencode
fi

# Install Python dependencies
echo "Installing Python dependencies..."
pip3 install pyyaml qrcode requests

# Create symlink
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
chmod +x "$SCRIPT_DIR/wg-manager.py"

if [ -L /usr/local/bin/wg-manager ]; then
    rm /usr/local/bin/wg-manager
fi

ln -s "$SCRIPT_DIR/wg-manager.py" /usr/local/bin/wg-manager

# Create directories
mkdir -p /etc/wireguard/{peers,backups,firewall,keys}
chmod 700 /etc/wireguard
chmod 700 /etc/wireguard/keys

# Enable IP forwarding
echo "Enabling IP forwarding..."
sysctl -w net.ipv4.ip_forward=1
if ! grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf; then
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
fi

echo
echo "=== Installation Complete ==="
echo
echo "Usage:"
echo "  sudo wg-manager peer list"
echo "  sudo wg-manager peer add myphone"
echo "  sudo wg-manager service status"
echo "  sudo wg-manager --help"
echo
