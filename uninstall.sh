#!/bin/bash

# WireGuard Manager Uninstaller
# This script removes all traces of wireguard-manager installations

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Function to print colored output
print_color() {
    local color=$1
    shift
    echo -e "${color}$*${NC}"
}

# Function to print section headers
print_header() {
    echo
    print_color "$BLUE" "═══════════════════════════════════════════════════════════════"
    print_color "$BLUE" "  $1"
    print_color "$BLUE" "═══════════════════════════════════════════════════════════════"
}

# Function to ask for confirmation - DEFAULTS TO YES
confirm() {
    local prompt="$1"
    local response
    read -p "$(echo -e ${YELLOW}${prompt} [Y/n]: ${NC})" response
    if [[ "$response" =~ ^[nN][oO]?$ ]]; then
        return 1
    else
        return 0
    fi
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   print_color "$RED" "This script must be run as root"
   exit 1
fi

print_header "WireGuard Manager Uninstaller"

print_color "$YELLOW" "This will remove WireGuard Manager but preserve your WireGuard configurations."
print_color "$YELLOW" "Press Ctrl+C to cancel, or Enter to continue..."
read

# Track what was found and removed
FOUND_ITEMS=0
REMOVED_ITEMS=0

# 1. Stop any running instances
print_header "Stopping WireGuard Manager"

# Kill any running Python processes related to wireguard_manager
if pgrep -f "wireguard_manager" > /dev/null 2>&1; then
    pkill -f "wireguard_manager" 2>/dev/null || true
    print_color "$GREEN" "✓ Stopped wireguard_manager processes"
fi

if pgrep -f "wg-manager" > /dev/null 2>&1; then
    pkill -f "wg-manager" 2>/dev/null || true
    print_color "$GREEN" "✓ Stopped wg-manager processes"
fi

# 2. Remove pip/pip3 installations
print_header "Removing pip installations"

for pip_cmd in pip pip3; do
    if command -v $pip_cmd &> /dev/null; then
        # Check if wireguard-manager is installed
        if $pip_cmd list 2>/dev/null | grep -qi "wireguard-manager"; then
            print_color "$YELLOW" "Found wireguard-manager installed via $pip_cmd"
            ((FOUND_ITEMS++))
            $pip_cmd uninstall -y wireguard-manager 2>/dev/null || true
            print_color "$GREEN" "✓ Removed wireguard-manager pip package"
            ((REMOVED_ITEMS++))
        fi
        
        # Check for wg-manager (old name)
        if $pip_cmd list 2>/dev/null | grep -qi "wg-manager"; then
            print_color "$YELLOW" "Found old wg-manager installed via $pip_cmd"
            ((FOUND_ITEMS++))
            $pip_cmd uninstall -y wg-manager 2>/dev/null || true
            print_color "$GREEN" "✓ Removed old wg-manager pip package"
            ((REMOVED_ITEMS++))
        fi
    fi
done

# 3. Remove command-line tools
print_header "Removing command-line tools"

CMD_LOCATIONS=(
    "/usr/local/bin/wg-manager"
    "/usr/bin/wg-manager"
    "/usr/local/bin/wireguard-manager"
    "/usr/bin/wireguard-manager"
    "/opt/wireguard-manager/wg-manager"
    "$HOME/.local/bin/wg-manager"
    "$HOME/.local/bin/wireguard-manager"
)

for cmd_path in "${CMD_LOCATIONS[@]}"; do
    if [[ -f "$cmd_path" ]] || [[ -L "$cmd_path" ]]; then
        print_color "$YELLOW" "Found command at: $cmd_path"
        ((FOUND_ITEMS++))
        if confirm "Remove $cmd_path?"; then
            rm -f "$cmd_path"
            print_color "$GREEN" "✓ Removed $cmd_path"
            ((REMOVED_ITEMS++))
        fi
    fi
done

# 4. Remove installation directories
print_header "Removing installation directories"

# Main installation directories
INSTALL_DIRS=(
    "/opt/wireguard-manager"
    "/etc/wireguard/wireguard-manager"
    "/var/lib/wireguard-manager"
    "/usr/local/wireguard-manager"
)

for dir in "${INSTALL_DIRS[@]}"; do
    if [[ -d "$dir" ]]; then
        print_color "$YELLOW" "Found installation directory: $dir"
        ((FOUND_ITEMS++))
        
        # Special handling for /etc/wireguard/wireguard-manager
        if [[ "$dir" == "/etc/wireguard/wireguard-manager" ]]; then
            print_color "$YELLOW" "This is the current installation directory"
            if confirm "Remove $dir? (This will delete the installation)"; then
                # Save the script path before deletion
                SCRIPT_PATH="$0"
                TEMP_SCRIPT="/tmp/uninstall_wg_manager_$$.sh"
                cp "$SCRIPT_PATH" "$TEMP_SCRIPT"
                chmod +x "$TEMP_SCRIPT"
                
                print_color "$YELLOW" "Directory will be removed after script completes"
                REMOVE_CURRENT_DIR=1
            fi
        else
            if confirm "Remove directory $dir?"; then
                rm -rf "$dir"
                print_color "$GREEN" "✓ Removed $dir"
                ((REMOVED_ITEMS++))
            fi
        fi
    fi
done

# Python package directories
print_header "Removing Python packages"

for python_version in python3.{6..12}; do
    PYTHON_DIRS=(
        "/usr/local/lib/$python_version/dist-packages/wireguard_manager"
        "/usr/local/lib/$python_version/site-packages/wireguard_manager"
        "/usr/lib/$python_version/dist-packages/wireguard_manager"
        "/usr/lib/$python_version/site-packages/wireguard_manager"
        "$HOME/.local/lib/$python_version/site-packages/wireguard_manager"
        "/usr/local/lib/$python_version/dist-packages/src"
        "/usr/local/lib/$python_version/site-packages/src"
    )
    
    for dir in "${PYTHON_DIRS[@]}"; do
        if [[ -d "$dir" ]]; then
            print_color "$YELLOW" "Found Python package: $dir"
            ((FOUND_ITEMS++))
            rm -rf "$dir"
            print_color "$GREEN" "✓ Removed $dir"
            ((REMOVED_ITEMS++))
        fi
    done
done

# 5. Remove systemd services
print_header "Removing systemd services"

SERVICES=(
    "wg-manager"
    "wireguard-manager"
    "wg-manager-api"
    "wireguard-manager-api"
)

for service in "${SERVICES[@]}"; do
    service_file="/etc/systemd/system/${service}.service"
    if [[ -f "$service_file" ]]; then
        print_color "$YELLOW" "Found systemd service: $service"
        ((FOUND_ITEMS++))
        systemctl stop "$service" 2>/dev/null || true
        systemctl disable "$service" 2>/dev/null || true
        rm -f "$service_file"
        print_color "$GREEN" "✓ Removed $service service"
        ((REMOVED_ITEMS++))
    fi
done

if [[ $REMOVED_ITEMS -gt 0 ]]; then
    systemctl daemon-reload
fi

# 6. Remove configuration files
print_header "Removing configuration files"

CONFIG_FILES=(
    "/etc/wireguard-manager.conf"
    "/etc/wireguard-manager.yaml"
    "/etc/wireguard-manager/config.yaml"
    "/etc/wireguard/manager.conf"
    "/etc/wireguard/config.yaml"
    "$HOME/.config/wireguard-manager/config.yaml"
    "$HOME/.wireguard-manager.conf"
)

for config_file in "${CONFIG_FILES[@]}"; do
    if [[ -f "$config_file" ]]; then
        print_color "$YELLOW" "Found configuration file: $config_file"
        ((FOUND_ITEMS++))
        rm -f "$config_file"
        print_color "$GREEN" "✓ Removed $config_file"
        ((REMOVED_ITEMS++))
    fi
done

# 7. Remove egg-info directories
print_header "Removing egg-info directories"

find /usr/local/lib /usr/lib $HOME/.local/lib /opt 2>/dev/null -type d \( -name "*wireguard*manager*.egg-info" -o -name "*wg*manager*.egg-info" \) -print0 | while IFS= read -r -d '' egg_dir; do
    print_color "$YELLOW" "Found egg-info directory: $egg_dir"
    ((FOUND_ITEMS++))
    rm -rf "$egg_dir"
    print_color "$GREEN" "✓ Removed $egg_dir"
    ((REMOVED_ITEMS++))
done

# 8. Clean up PATH modifications
print_header "Cleaning shell configuration files"

SHELL_CONFIGS=(
    "$HOME/.bashrc"
    "$HOME/.bash_profile"
    "$HOME/.profile"
    "$HOME/.zshrc"
    "/etc/profile"
    "/etc/bash.bashrc"
)

for config in "${SHELL_CONFIGS[@]}"; do
    if [[ -f "$config" ]] && grep -q "wireguard-manager\|wg-manager" "$config"; then
        print_color "$YELLOW" "Found references in $config"
        cp "$config" "${config}.backup.$(date +%Y%m%d-%H%M%S)"
        sed -i '/wireguard-manager/d; /wg-manager/d' "$config"
        print_color "$GREEN" "✓ Cleaned $config (backup created)"
    fi
done

# 9. Optional: Clean up WireGuard Manager data
print_header "WireGuard Manager Data Cleanup (Optional)"

print_color "$YELLOW" "Remove WireGuard Manager data directories?"
print_color "$RED" "Note: This will NOT affect your WireGuard configurations (wg*.conf files)"

if confirm "Remove WireGuard Manager data directories?"; then
    # Backup directory
    if [[ -d "/etc/wireguard/backups" ]]; then
        rm -rf /etc/wireguard/backups
        print_color "$GREEN" "✓ Removed backup directory"
        ((REMOVED_ITEMS++))
    fi
    
    # Peers directory metadata
    if [[ -d "/etc/wireguard/peers" ]]; then
        # Only remove JSON metadata files, not conf files
        find /etc/wireguard/peers -name "*.json" -delete 2>/dev/null
        print_color "$GREEN" "✓ Removed peer metadata files"
    fi
    
    # Config directory
    if [[ -d "/etc/wireguard/configs" ]]; then
        rm -rf /etc/wireguard/configs
        print_color "$GREEN" "✓ Removed configs directory"
        ((REMOVED_ITEMS++))
    fi
    
    # Manager-specific files
    MANAGER_FILES=(
        "/etc/wireguard/config.yaml"
        "/etc/wireguard/defaults.json"
    )
    
    for file in "${MANAGER_FILES[@]}"; do
        if [[ -f "$file" ]]; then
            rm -f "$file"
            print_color "$GREEN" "✓ Removed $file"
            ((REMOVED_ITEMS++))
        fi
    done
fi

# Summary
print_header "Uninstall Summary"

if [[ $FOUND_ITEMS -eq 0 ]]; then
    print_color "$GREEN" "No WireGuard Manager installations found."
else
    print_color "$BLUE" "Found $FOUND_ITEMS items"
    print_color "$GREEN" "Removed $REMOVED_ITEMS items"
    
    if [[ $REMOVED_ITEMS -lt $FOUND_ITEMS ]]; then
        print_color "$YELLOW" "Some items were not removed (user chose to keep them)."
    fi
fi

# Refresh command database
print_color "$BLUE" "Refreshing command database..."
hash -r 2>/dev/null || true

# Check if commands still exist
if which wg-manager &>/dev/null; then
    print_color "$YELLOW" "Warning: wg-manager command still found in PATH"
else
    print_color "$GREEN" "✓ wg-manager command removed from PATH"
fi

if which wireguard-manager &>/dev/null; then
    print_color "$YELLOW" "Warning: wireguard-manager command still found in PATH"
else
    print_color "$GREEN" "✓ wireguard-manager command removed from PATH"
fi

print_header "Uninstall Complete"
print_color "$GREEN" "WireGuard Manager has been uninstalled."
print_color "$YELLOW" "Your WireGuard configurations (wg*.conf) have been preserved."
print_color "$YELLOW" "Your WireGuard installation remains intact."

# Handle current directory removal if requested
if [[ "${REMOVE_CURRENT_DIR}" == "1" ]]; then
    print_color "$YELLOW" "Removing current installation directory..."
    cd /tmp
    rm -rf /etc/wireguard/wireguard-manager
    print_color "$GREEN" "✓ Removed /etc/wireguard/wireguard-manager"
    
    # Clean up temp script
    rm -f "$TEMP_SCRIPT"
fi

exit 0