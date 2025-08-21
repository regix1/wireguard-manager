#!/bin/bash

#############################################
# WireGuard Manager TUI - Uninstallation Script
# Version: 2.0.0
# Description: Removes WireGuard Manager from system
#############################################

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Installation paths
INSTALL_DIR="/opt/wireguard-manager"
BIN_PATH="/usr/local/bin/wg-manager"
SYSTEMD_PATH="/etc/systemd/system/wg-manager.service"
CONFIG_DIR="/etc/wireguard"
DATA_DIR="/var/lib/wireguard-manager"
LOG_DIR="/var/log/wireguard-manager"

# Print colored output
print_status() {
    echo -e "${BLUE}[*]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

# Header
clear
echo -e "${RED}"
echo "╔══════════════════════════════════════════════════════════╗"
echo "║        WireGuard Manager TUI Uninstallation             ║"
echo "║                    Version 2.0.0                        ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   print_error "This script must be run as root (use sudo)"
   exit 1
fi

print_warning "This will uninstall WireGuard Manager TUI from your system."
echo
read -p "Are you sure you want to continue? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    print_status "Uninstallation cancelled"
    exit 0
fi

# Stop services if running
print_status "Stopping services..."
if systemctl is-active --quiet wg-manager.service; then
    systemctl stop wg-manager.service
    print_success "Stopped wg-manager service"
fi

if systemctl is-enabled --quiet wg-manager.service 2>/dev/null; then
    systemctl disable wg-manager.service 2>/dev/null
    print_success "Disabled wg-manager service"
fi

# Ask about WireGuard service
echo
print_warning "WireGuard VPN service status:"
if systemctl is-active --quiet wg-quick@wg0; then
    echo "  WireGuard is currently running"
    read -p "  Stop WireGuard VPN service? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        systemctl stop wg-quick@wg0
        systemctl disable wg-quick@wg0 2>/dev/null || true
        print_success "WireGuard VPN stopped"
    else
        print_status "WireGuard VPN left running"
    fi
else
    print_status "WireGuard VPN is not running"
fi

# Remove executable files
print_status "Removing executable files..."
rm -f /usr/local/bin/wg-manager
rm -f /usr/local/bin/wireguard-manager
rm -f /usr/local/bin/wgm
print_success "Executable files removed"

# Remove systemd service
if [[ -f "$SYSTEMD_PATH" ]]; then
    print_status "Removing systemd service..."
    rm -f "$SYSTEMD_PATH"
    systemctl daemon-reload
    print_success "Systemd service removed"
fi

# Remove bash completion
if [[ -f /etc/bash_completion.d/wg-manager ]]; then
    print_status "Removing bash completion..."
    rm -f /etc/bash_completion.d/wg-manager
    print_success "Bash completion removed"
fi

# Remove installation directory
if [[ -d "$INSTALL_DIR" ]]; then
    print_status "Removing installation directory..."
    rm -rf "$INSTALL_DIR"
    print_success "Installation directory removed"
fi

# Ask about configuration files
echo
print_warning "Configuration and data files:"
echo "  • WireGuard configs: $CONFIG_DIR/"
echo "  • Application data:  $DATA_DIR/"
echo "  • Log files:        $LOG_DIR/"
echo
read -p "Remove ALL configuration and data files? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    print_warning "This will remove ALL WireGuard configurations!"
    read -p "Are you ABSOLUTELY sure? Type 'yes' to confirm: " -r
    if [[ $REPLY == "yes" ]]; then
        # Backup configurations first
        BACKUP_DIR="/tmp/wireguard-backup-$(date +%Y%m%d-%H%M%S)"
        print_status "Creating backup at $BACKUP_DIR..."
        mkdir -p "$BACKUP_DIR"
        
        if [[ -d "$CONFIG_DIR" ]]; then
            cp -r "$CONFIG_DIR" "$BACKUP_DIR/" 2>/dev/null || true
        fi
        if [[ -d "$DATA_DIR" ]]; then
            cp -r "$DATA_DIR" "$BACKUP_DIR/" 2>/dev/null || true
        fi
        
        print_success "Backup created at $BACKUP_DIR"
        
        # Remove directories
        rm -rf "$DATA_DIR"
        rm -rf "$LOG_DIR"
        
        # Only remove our files from WireGuard config dir
        rm -f "$CONFIG_DIR/firewall-rules.conf"
        rm -f "$CONFIG_DIR/banned_ips.txt"
        rm -rf "$CONFIG_DIR/peers"
        rm -rf "$CONFIG_DIR/keys"
        rm -rf "$CONFIG_DIR/backups"
        
        print_success "Configuration files removed (backup saved)"
    else
        print_status "Configuration files preserved"
    fi
else
    print_status "Configuration files preserved"
fi

# Ask about keeping WireGuard itself
echo
read -p "Keep WireGuard tools installed? (Y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Nn]$ ]]; then
    print_status "Removing WireGuard tools..."
    apt-get remove -y wireguard wireguard-tools >/dev/null 2>&1
    print_success "WireGuard tools removed"
else
    print_status "WireGuard tools kept installed"
fi

# Clean up Python cache
print_status "Cleaning up Python cache..."
find /usr/local -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find /opt -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
print_success "Python cache cleaned"

# Final message
echo
echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║         Uninstallation Complete!                        ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
echo
print_success "WireGuard Manager TUI has been removed from your system"

if [[ -d "$BACKUP_DIR" ]]; then
    echo
    print_warning "Configuration backup saved at: $BACKUP_DIR"
    echo "  You can restore it manually if needed"
fi

echo
echo "Thank you for using WireGuard Manager TUI!"
echo