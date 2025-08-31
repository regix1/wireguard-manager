#!/bin/bash
# WireGuard Manager - Complete Auto-Installation Script
# This script automatically installs all dependencies and sets up the environment

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[i]${NC} $1"
}

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check if a package is installed
package_installed() {
    dpkg -l | grep -q "^ii  $1"
}

echo -e "${GREEN}======================================${NC}"
echo -e "${GREEN}  WireGuard Manager Auto-Installer    ${NC}"
echo -e "${GREEN}======================================${NC}"
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   print_error "This script must be run as root"
   echo "Please run: sudo ./auto_install.sh"
   exit 1
fi

print_status "Running as root"

# Detect OS
if [ -f /etc/debian_version ]; then
    OS="debian"
    print_info "Detected Debian/Ubuntu system"
elif [ -f /etc/redhat-release ]; then
    OS="redhat"
    print_info "Detected RedHat/CentOS system"
else
    print_error "Unsupported operating system"
    exit 1
fi

# Update package lists
print_info "Updating package lists..."
if [ "$OS" = "debian" ]; then
    apt-get update -qq
else
    yum check-update -q || true
fi

# Function to install packages on Debian/Ubuntu
install_debian_packages() {
    local packages=("$@")
    local to_install=()
    
    for pkg in "${packages[@]}"; do
        if ! package_installed "$pkg"; then
            to_install+=("$pkg")
        fi
    done
    
    if [ ${#to_install[@]} -gt 0 ]; then
        print_info "Installing: ${to_install[*]}"
        apt-get install -y -qq "${to_install[@]}"
    fi
}

# Function to install packages on RedHat/CentOS
install_redhat_packages() {
    local packages=("$@")
    print_info "Installing: ${packages[*]}"
    yum install -y -q "${packages[@]}"
}

# Install system dependencies
print_info "Checking and installing system dependencies..."

if [ "$OS" = "debian" ]; then
    # Required packages for Debian/Ubuntu
    REQUIRED_PACKAGES=(
        "python3"
        "python3-pip"
        "python3-venv"
        "python3-full"
        "wireguard"
        "wireguard-tools"
        "iptables"
        "qrencode"
        "curl"
        "git"
        "dos2unix"
    )
    
    install_debian_packages "${REQUIRED_PACKAGES[@]}"
    
else
    # Required packages for RedHat/CentOS
    print_info "Installing EPEL repository..."
    yum install -y epel-release elrepo-release
    
    REQUIRED_PACKAGES=(
        "python3"
        "python3-pip"
        "kmod-wireguard"
        "wireguard-tools"
        "iptables"
        "qrencode"
        "curl"
        "git"
        "dos2unix"
    )
    
    install_redhat_packages "${REQUIRED_PACKAGES[@]}"
fi

print_status "System dependencies installed"

# Check Python version
PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
print_info "Python version: $PYTHON_VERSION"

# Fix line endings for all Python files
print_info "Fixing line endings..."
if command_exists dos2unix; then
    find . -name "*.py" -exec dos2unix -q {} \; 2>/dev/null || true
    [ -f setup.py ] && dos2unix -q setup.py 2>/dev/null || true
fi

# Create necessary directories
print_info "Creating directory structure..."
mkdir -p src
mkdir -p data/templates
mkdir -p /etc/wireguard/backups
mkdir -p /etc/wireguard/peers
mkdir -p /etc/wireguard/configs
mkdir -p /etc/wireguard/keys

# Create VERSION file if it doesn't exist
if [ ! -f VERSION ]; then
    echo "2.0.0" > VERSION
    print_status "Created VERSION file"
fi

# Create defaults.json if it doesn't exist
if [ ! -f data/defaults.json ]; then
    cat > data/defaults.json << 'EOF'
{
  "server_port": 51820,
  "server_subnet": "10.0.0.0/24",
  "server_address": "10.0.0.1/24",
  "dns_servers": "1.1.1.1, 1.0.0.1",
  "keepalive": 25,
  "mtu": 1420,
  "external_interface": "eth0",
  "save_config": false,
  "allowed_ips": "0.0.0.0/0, ::/0",
  "public_ip": "auto",
  "backup_count": 10,
  "log_level": 1
}
EOF
    print_status "Created defaults.json"
fi

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    print_info "Creating Python virtual environment..."
    python3 -m venv venv
    print_status "Virtual environment created"
else
    print_info "Virtual environment already exists"
fi

# Activate virtual environment and install Python packages
print_info "Installing Python dependencies..."
source venv/bin/activate

# Upgrade pip first
pip install --upgrade pip -q

# Install requirements
if [ -f requirements.txt ]; then
    pip install -q -r requirements.txt
    print_status "Python dependencies installed"
else
    print_warning "requirements.txt not found, creating default..."
    cat > requirements.txt << 'EOF'
rich>=13.7.0
jinja2>=3.1.2
pyyaml>=6.0
psutil>=5.9.0
requests>=2.31.0
qrcode[pil]>=7.4.2
EOF
    pip install -q -r requirements.txt
    print_status "Python dependencies installed"
fi

# Enable IP forwarding
print_info "Configuring IP forwarding..."
if ! grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf; then
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf
fi
sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1
sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1
print_status "IP forwarding enabled"

# Check WireGuard kernel module
print_info "Checking WireGuard kernel module..."
if lsmod | grep -q wireguard; then
    print_status "WireGuard kernel module loaded"
else
    print_warning "WireGuard kernel module not loaded, attempting to load..."
    modprobe wireguard 2>/dev/null || print_warning "Could not load WireGuard kernel module (may not be needed)"
fi

# Create launcher script
cat > wg-manager << 'EOF'
#!/bin/bash
# WireGuard Manager launcher

# Get the directory of this script
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   echo "Please run: sudo ./wg-manager"
   exit 1
fi

# Change to script directory and activate venv
cd "$DIR"
source venv/bin/activate

# Add src directory to Python path and run
export PYTHONPATH="${DIR}/src:${PYTHONPATH}"
python -m src "$@"
EOF

chmod +x wg-manager
print_status "Created launcher script"

# Test import
print_info "Testing Python module import..."

# Add src to Python path for testing
export PYTHONPATH="${PWD}/src:${PYTHONPATH}"

if python -c "import src; print('Version:', src.__version__)" 2>/dev/null; then
    print_status "Module imports successfully"
else
    print_warning "Module import check - verifying files..."
    
    REQUIRED_FILES=(
        "src/__init__.py"
        "src/__main__.py"
        "src/cli.py"
        "src/constants.py"
        "src/utils.py"
        "src/config_manager.py"
        "src/peer_manager.py"
        "src/service_manager.py"
        "src/firewall_manager.py"
        "src/backup.py"
        "src/installer.py"
        "src/troubleshooter.py"
        "src/menu_system.py"
    )
    
    missing_files=0
    for file in "${REQUIRED_FILES[@]}"; do
        if [ ! -f "$file" ]; then
            print_error "Missing: $file"
            missing_files=$((missing_files + 1))
        else
            print_status "Found: $file"
        fi
    done
    
    if [ $missing_files -eq 0 ]; then
        print_status "All required files present"
    fi
fi

# Deactivate virtual environment
deactivate

# Final summary
echo ""
echo -e "${GREEN}======================================${NC}"
echo -e "${GREEN}    Installation Complete!            ${NC}"
echo -e "${GREEN}======================================${NC}"
echo ""
echo "To run WireGuard Manager:"
echo -e "  ${YELLOW}sudo ./wg-manager${NC}"
echo ""
echo "Or with the virtual environment:"
echo -e "  ${YELLOW}sudo bash -c 'source venv/bin/activate && PYTHONPATH=src python -m src'${NC}"
echo ""
print_info "Note: The application requires root privileges to manage WireGuard"
echo ""

# Check if we can actually run it
if command_exists wg; then
    print_status "WireGuard tools are installed and ready"
else
    print_warning "WireGuard tools not found - the application may not work properly"
fi

# Offer to run the application
echo ""
read -p "Would you like to run WireGuard Manager now? (y/n) " -n 1 -r
echo ""
if [[ $REPLY =~ ^[Yy]$ ]]; then
    source venv/bin/activate
    export PYTHONPATH="${PWD}/src:${PYTHONPATH}"
    python -m src
fi