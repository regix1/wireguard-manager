#!/bin/bash

#############################################
# WireGuard Manager TUI - Installation Script
# Version: 2.0.0
# Description: Installs WireGuard Manager system-wide
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
echo -e "${CYAN}"
echo "╔══════════════════════════════════════════════════════════╗"
echo "║          WireGuard Manager TUI Installation             ║"
echo "║                    Version 2.0.0                        ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   print_error "This script must be run as root (use sudo)"
   exit 1
fi

print_success "Running as root"

# Detect OS
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    OS=$ID
    VERSION=$VERSION_ID
else
    print_error "Cannot detect operating system"
    exit 1
fi

print_status "Detected OS: $OS $VERSION"

# Check if it's Debian/Ubuntu based
if [[ "$OS" != "ubuntu" && "$OS" != "debian" && "$OS" != "raspbian" ]]; then
    print_warning "This script is designed for Debian/Ubuntu systems"
    read -p "Continue anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Update package lists
print_status "Updating package lists..."
apt-get update >/dev/null 2>&1

# Install system dependencies
print_status "Installing system dependencies..."

PACKAGES="python3 python3-pip python3-venv python3-dev git curl wget"
PACKAGES="$PACKAGES wireguard wireguard-tools iptables"
PACKAGES="$PACKAGES qrencode net-tools iproute2"

for package in $PACKAGES; do
    if dpkg -l | grep -q "^ii  $package "; then
        print_success "$package already installed"
    else
        print_status "Installing $package..."
        apt-get install -y $package >/dev/null 2>&1
        print_success "$package installed"
    fi
done

# Enable IP forwarding
print_status "Configuring IP forwarding..."
if ! grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf; then
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    sysctl -p >/dev/null 2>&1
    print_success "IP forwarding enabled"
else
    print_success "IP forwarding already enabled"
fi

# Create installation directory
print_status "Creating installation directory..."
if [[ -d "$INSTALL_DIR" ]]; then
    print_warning "Installation directory exists. Backing up..."
    mv "$INSTALL_DIR" "${INSTALL_DIR}.backup.$(date +%Y%m%d_%H%M%S)"
fi
mkdir -p "$INSTALL_DIR"
print_success "Created $INSTALL_DIR"

# Clone or copy the application
print_status "Installing WireGuard Manager..."

# Check if we're running from the git repo
if [[ -f "run.py" && -d "tui" && -d "core" ]]; then
    print_status "Installing from current directory..."
    cp -r . "$INSTALL_DIR/"
elif [[ -d ".git" ]]; then
    print_status "Installing from git repository..."
    cp -r . "$INSTALL_DIR/"
else
    print_status "Downloading from GitHub..."
    git clone https://github.com/regix1/wireguard-manager.git "$INSTALL_DIR" >/dev/null 2>&1
fi

cd "$INSTALL_DIR"

# Create Python virtual environment
print_status "Creating Python virtual environment..."
python3 -m venv venv
print_success "Virtual environment created"

# Activate venv and install Python dependencies
print_status "Installing Python dependencies..."
source venv/bin/activate
pip install --upgrade pip >/dev/null 2>&1
pip install -r requirements.txt >/dev/null 2>&1
deactivate
print_success "Python dependencies installed"

# Create data directories
print_status "Creating data directories..."
mkdir -p "$CONFIG_DIR/peers"
mkdir -p "$CONFIG_DIR/keys"
mkdir -p "$DATA_DIR/backups"
mkdir -p "$LOG_DIR"
print_success "Data directories created"

# Set permissions
print_status "Setting permissions..."
chmod -R 750 "$INSTALL_DIR"
chmod -R 750 "$DATA_DIR"
chmod -R 750 "$LOG_DIR"
chmod 700 "$CONFIG_DIR/keys"
print_success "Permissions configured"

# Create the main executable script
print_status "Creating system executable..."
cat > "$BIN_PATH" << 'EOF'
#!/bin/bash
# WireGuard Manager TUI Launcher

# Activate virtual environment and run the application
cd /opt/wireguard-manager
source venv/bin/activate
python run.py "$@"
deactivate
EOF

chmod +x "$BIN_PATH"
print_success "System executable created at $BIN_PATH"

# Create command aliases
print_status "Creating command aliases..."

# Create wg-manager command (full name)
ln -sf "$BIN_PATH" /usr/local/bin/wireguard-manager 2>/dev/null || true

# Create short alias
cat > /usr/local/bin/wgm << 'EOF'
#!/bin/bash
# WireGuard Manager TUI - Short alias
exec wg-manager "$@"
EOF
chmod +x /usr/local/bin/wgm

print_success "Command aliases created (wg-manager, wireguard-manager, wgm)"

# Create systemd service (optional - for auto-start features)
print_status "Creating systemd service..."
cat > "$SYSTEMD_PATH" << EOF
[Unit]
Description=WireGuard Manager TUI Service
After=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/wg-manager --cli --start-wg --start-fw
ExecStop=/usr/local/bin/wg-manager --cli --stop-wg --stop-fw
WorkingDirectory=/opt/wireguard-manager
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
print_success "Systemd service created (wg-manager.service)"

# Create bash completion
print_status "Installing bash completion..."
cat > /etc/bash_completion.d/wg-manager << 'EOF'
_wg_manager_completion() {
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    
    # Main options
    opts="--help --debug --cli --status --start-wg --stop-wg --start-fw --stop-fw"
    opts="$opts --add-peer --remove-peer --ban-ip --unban-ip --config-dir --no-check"
    
    # Handle options that need arguments
    case "${prev}" in
        --add-peer|--remove-peer|--ban-ip|--unban-ip|--config-dir)
            return 0
            ;;
        *)
            COMPREPLY=( $(compgen -W "${opts}" -- ${cur}) )
            return 0
            ;;
    esac
}

complete -F _wg_manager_completion wg-manager
complete -F _wg_manager_completion wireguard-manager
complete -F _wg_manager_completion wgm
EOF

print_success "Bash completion installed"

# Create uninstall script
print_status "Creating uninstall script..."
cat > "$INSTALL_DIR/uninstall.sh" << 'EOF'
#!/bin/bash
# WireGuard Manager TUI - Uninstaller

echo "Uninstalling WireGuard Manager TUI..."

# Stop services
systemctl stop wg-manager.service 2>/dev/null || true
systemctl disable wg-manager.service 2>/dev/null || true

# Remove files
rm -f /usr/local/bin/wg-manager
rm -f /usr/local/bin/wireguard-manager
rm -f /usr/local/bin/wgm
rm -f /etc/systemd/system/wg-manager.service
rm -f /etc/bash_completion.d/wg-manager
rm -rf /opt/wireguard-manager

# Optional: Remove data directories (ask user)
read -p "Remove configuration and data directories? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    rm -rf /var/lib/wireguard-manager
    rm -rf /var/log/wireguard-manager
    echo "Data directories removed"
fi

echo "Uninstallation complete!"
EOF

chmod +x "$INSTALL_DIR/uninstall.sh"
print_success "Uninstall script created"

# Initialize configuration if needed
if [[ ! -f "$CONFIG_DIR/wg0.conf" ]]; then
    print_status "Initializing WireGuard configuration..."
    cd "$INSTALL_DIR"
    source venv/bin/activate
    python -c "
from config.settings import Settings
from core.wireguard import WireGuardManager
from core.utils import get_public_ip

settings = Settings()
wg = WireGuardManager(settings)

# Generate initial server config
public_ip = get_public_ip() or 'YOUR_PUBLIC_IP'
config = wg.generate_server_config(
    port=51820,
    subnet='10.10.20.0/24',
    dns='1.1.1.1,1.0.0.1',
    public_ip=public_ip
)

# Save config
with open('$CONFIG_DIR/wg0.conf', 'w') as f:
    f.write(config)

print('Initial configuration created')
" 2>/dev/null || print_warning "Could not auto-generate initial config"
    deactivate
fi

# Final setup
echo
echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║         Installation Complete! 🎉                        ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
echo
print_success "WireGuard Manager TUI has been installed successfully!"
echo
echo -e "${CYAN}Available Commands:${NC}"
echo "  • wg-manager     - Full command"
echo "  • wgm            - Short alias"
echo "  • wireguard-manager - Alternative name"
echo
echo -e "${CYAN}Quick Start:${NC}"
echo "  sudo wgm                    # Start TUI interface"
echo "  sudo wgm --status           # Show status"
echo "  sudo wgm --help             # Show all options"
echo
echo -e "${CYAN}Service Management:${NC}"
echo "  sudo systemctl start wg-manager    # Start services"
echo "  sudo systemctl enable wg-manager   # Enable on boot"
echo "  sudo systemctl status wg-manager   # Check status"
echo
echo -e "${CYAN}Configuration Files:${NC}"
echo "  • WireGuard configs: $CONFIG_DIR/"
echo "  • Application data:  $DATA_DIR/"
echo "  • Logs:             $LOG_DIR/"
echo
echo -e "${CYAN}Uninstall:${NC}"
echo "  sudo $INSTALL_DIR/uninstall.sh"
echo
print_warning "Remember to configure your public IP address if needed!"
echo

# Ask if user wants to start the service now
read -p "Would you like to start WireGuard Manager now? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    wg-manager
fi