#!/bin/bash

#############################################
# WireGuard Manager TUI - Quick Install
# One-line installation script
#############################################

# This script can be run with:
# curl -sSL https://raw.githubusercontent.com/regix1/wireguard-manager/main/quick-install.sh | sudo bash

set -e

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}Starting WireGuard Manager TUI Quick Installation...${NC}"

# Create temp directory
TEMP_DIR=$(mktemp -d)
cd "$TEMP_DIR"

# Download the repository
echo "Downloading WireGuard Manager..."
git clone https://github.com/regix1/wireguard-manager.git >/dev/null 2>&1 || {
    # Fallback to wget if git fails
    wget -q https://github.com/regix1/wireguard-manager/archive/main.tar.gz
    tar -xzf main.tar.gz
    mv wireguard-manager-main wireguard-manager
}

# Run the installer
cd wireguard-manager
chmod +x install.sh
./install.sh

# Cleanup
cd /
rm -rf "$TEMP_DIR"

echo -e "${GREEN}Installation complete! Run 'sudo wgm' to start.${NC}"