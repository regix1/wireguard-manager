#!/bin/bash
#############################################
# WireGuard Manager Installation Script
# Simple and clean installation
#############################################

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}================================${NC}"
echo -e "${GREEN}  WireGuard Manager Installer${NC}"
echo -e "${GREEN}================================${NC}"
echo

# Check for root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root${NC}"
   exit 1
fi

# Installation directories
INSTALL_DIR="/opt/wireguard-manager"
BIN_PATH="/usr/local/bin/wg-manager"

echo "This will install WireGuard Manager to:"
echo "  • $INSTALL_DIR"
echo "  • $BIN_PATH (command)"
echo
read -p "Continue? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Installation cancelled"
    exit 0
fi

# Backup existing installation if exists
if [ -d "$INSTALL_DIR" ]; then
    echo -e "${YELLOW}Existing installation found. Backing up...${NC}"
    mv "$INSTALL_DIR" "${INSTALL_DIR}.backup.$(date +%Y%m%d-%H%M%S)"
fi

# Create installation directory
echo "Creating installation directory..."
mkdir -p "$INSTALL_DIR"

# Copy files
echo "Copying files..."
cp -r src templates data VERSION requirements.txt run.py "$INSTALL_DIR/"

# Install Python dependencies
echo "Installing Python dependencies..."
pip3 install -r "$INSTALL_DIR/requirements.txt" >/dev/null 2>&1

# Create executable
echo "Creating system command..."
cat > "$BIN_PATH" << 'EOF'
#!/bin/bash
cd /opt/wireguard-manager
python3 run.py "$@"
EOF

chmod +x "$BIN_PATH"

# Create alternative commands
ln -sf "$BIN_PATH" /usr/local/bin/wireguard-manager 2>/dev/null || true
ln -sf "$BIN_PATH" /usr/local/bin/wgm 2>/dev/null || true

echo
echo -e "${GREEN}✓ Installation complete!${NC}"
echo
echo "You can now run the manager using any of these commands:"
echo "  • wg-manager"
echo "  • wgm"
echo "  • wireguard-manager"
echo
echo "Run 'sudo wg-manager' to start"