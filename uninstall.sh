#!/bin/bash
#############################################
# WireGuard Manager Uninstallation Script
#############################################

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${RED}================================${NC}"
echo -e "${RED}  WireGuard Manager Uninstaller${NC}"
echo -e "${RED}================================${NC}"
echo

# Check for root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root${NC}"
   exit 1
fi

echo -e "${YELLOW}This will uninstall WireGuard Manager.${NC}"
echo "Your WireGuard configurations will NOT be removed."
echo
read -p "Continue? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Uninstall cancelled"
    exit 0
fi

# Remove installation
if [ -d "/opt/wireguard-manager" ]; then
    echo "Removing /opt/wireguard-manager..."
    rm -rf /opt/wireguard-manager
fi

# Remove commands
if [ -f "/usr/local/bin/wg-manager" ]; then
    echo "Removing commands..."
    rm -f /usr/local/bin/wg-manager
    rm -f /usr/local/bin/wireguard-manager
    rm -f /usr/local/bin/wgm
fi

echo
echo -e "${GREEN}✓ WireGuard Manager uninstalled${NC}"
echo
echo "Your WireGuard configurations are still in /etc/wireguard/"
echo
echo "To remove WireGuard itself, run:"
echo "  apt remove wireguard wireguard-tools"