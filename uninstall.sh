#!/bin/bash

# WireGuard Manager Uninstaller
# This script removes all traces of wireguard-manager installations

set -e

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

# Function to ask for confirmation
confirm() {
    local prompt="$1"
    local response
    read -p "$(echo -e ${YELLOW}${prompt} [y/N]: ${NC})" response
    case "$response" in
        [yY][eE][sS]|[yY]) 
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   print_color "$RED" "This script must be run as root"
   exit 1
fi

print_header "WireGuard Manager Uninstaller"

# Track what was found and removed
FOUND_ITEMS=0
REMOVED_ITEMS=0

# 1. Check for pip/pip3 installations
print_header "Checking for pip installations"

for pip_cmd in pip pip3; do
    if command -v $pip_cmd &> /dev/null; then
        # Check if wireguard-manager is installed
        if $pip_cmd list 2>/dev/null | grep -q "wireguard-manager"; then
            print_color "$YELLOW" "Found wireguard-manager installed via $pip_cmd"
            ((FOUND_ITEMS++))
            if confirm "Remove wireguard-manager pip package?"; then
                $pip_cmd uninstall -y wireguard-manager 2>/dev/null || true
                print_color "$GREEN" "✓ Removed wireguard-manager pip package"
                ((REMOVED_ITEMS++))
            fi
        fi
        
        # Check for wg-manager (old name)
        if $pip_cmd list 2>/dev/null | grep -q "wg-manager"; then
            print_color "$YELLOW" "Found old wg-manager installed via $pip_cmd"
            ((FOUND_ITEMS++))
            if confirm "Remove old wg-manager pip package?"; then
                $pip_cmd uninstall -y wg-manager 2>/dev/null || true
                print_color "$GREEN" "✓ Removed old wg-manager pip package"
                ((REMOVED_ITEMS++))
            fi
        fi
    fi
done

# 2. Check for command-line tools in common locations
print_header "Checking for installed command-line tools"

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

# 3. Check for installation directories
print_header "Checking for installation directories"

INSTALL_DIRS=(
    "/opt/wireguard-manager"
    "/usr/local/lib/python*/dist-packages/wireguard_manager"
    "/usr/local/lib/python*/site-packages/wireguard_manager"
    "/usr/lib/python*/dist-packages/wireguard_manager"
    "/usr/lib/python*/site-packages/wireguard_manager"
    "$HOME/.local/lib/python*/site-packages/wireguard_manager"
    "/etc/wireguard/wireguard-manager"
    "/var/lib/wireguard-manager"
)

for dir_pattern in "${INSTALL_DIRS[@]}"; do
    for dir in $dir_pattern; do
        if [[ -d "$dir" ]]; then
            print_color "$YELLOW" "Found installation directory: $dir"
            ((FOUND_ITEMS++))
            if confirm "Remove directory $dir?"; then
                rm -rf "$dir"
                print_color "$GREEN" "✓ Removed $dir"
                ((REMOVED_ITEMS++))
            fi
        fi
    done
done

# 4. Check for systemd services
print_header "Checking for systemd services"

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
        if confirm "Remove $service service?"; then
            systemctl stop "$service" 2>/dev/null || true
            systemctl disable "$service" 2>/dev/null || true
            rm -f "$service_file"
            systemctl daemon-reload
            print_color "$GREEN" "✓ Removed $service service"
            ((REMOVED_ITEMS++))
        fi
    fi
done

# 5. Check for configuration files
print_header "Checking for configuration files"

CONFIG_FILES=(
    "/etc/wireguard-manager.conf"
    "/etc/wireguard-manager.yaml"
    "/etc/wireguard-manager/config.yaml"
    "/etc/wireguard/manager.conf"
    "$HOME/.config/wireguard-manager/config.yaml"
    "$HOME/.wireguard-manager.conf"
)

for config_file in "${CONFIG_FILES[@]}"; do
    if [[ -f "$config_file" ]]; then
        print_color "$YELLOW" "Found configuration file: $config_file"
        ((FOUND_ITEMS++))
        if confirm "Remove $config_file?"; then
            rm -f "$config_file"
            print_color "$GREEN" "✓ Removed $config_file"
            ((REMOVED_ITEMS++))
        fi
    fi
done

# 6. Check for Python virtual environments
print_header "Checking for Python virtual environments"

VENV_DIRS=(
    "/etc/wireguard/wireguard-manager/venv"
    "/opt/wireguard-manager/venv"
    "./venv"
)

for venv_dir in "${VENV_DIRS[@]}"; do
    if [[ -d "$venv_dir" ]]; then
        print_color "$YELLOW" "Found virtual environment: $venv_dir"
        ((FOUND_ITEMS++))
        if confirm "Remove virtual environment $venv_dir?"; then
            rm -rf "$venv_dir"
            print_color "$GREEN" "✓ Removed $venv_dir"
            ((REMOVED_ITEMS++))
        fi
    fi
done

# 7. Check for egg-info directories (from setup.py installations)
print_header "Checking for egg-info directories"

find /usr/local/lib /usr/lib $HOME/.local/lib 2>/dev/null -type d -name "*wireguard*manager*.egg-info" | while read -r egg_dir; do
    print_color "$YELLOW" "Found egg-info directory: $egg_dir"
    ((FOUND_ITEMS++))
    if confirm "Remove $egg_dir?"; then
        rm -rf "$egg_dir"
        print_color "$GREEN" "✓ Removed $egg_dir"
        ((REMOVED_ITEMS++))
    fi
done

# 8. Check for any remaining wg-manager related files
print_header "Searching for remaining files"

print_color "$YELLOW" "Searching for any remaining wireguard-manager files..."

SEARCH_PATHS=(
    "/usr/local"
    "/usr/lib"
    "/opt"
    "/etc"
    "$HOME/.local"
    "$HOME/.config"
)

for search_path in "${SEARCH_PATHS[@]}"; do
    if [[ -d "$search_path" ]]; then
        find "$search_path" 2>/dev/null -type f -name "*wireguard-manager*" -o -name "*wg-manager*" | grep -v ".conf$" | while read -r file; do
            # Skip WireGuard configuration files
            if [[ ! "$file" =~ wg[0-9]+\.conf ]]; then
                print_color "$YELLOW" "Found: $file"
                ((FOUND_ITEMS++))
                if confirm "Remove $file?"; then
                    rm -f "$file"
                    print_color "$GREEN" "✓ Removed $file"
                    ((REMOVED_ITEMS++))
                fi
            fi
        done
    fi
done

# 9. Clean up PATH modifications
print_header "Checking shell configuration files"

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
        if confirm "Remove wireguard-manager references from $config?"; then
            cp "$config" "${config}.backup"
            sed -i '/wireguard-manager/d; /wg-manager/d' "$config"
            print_color "$GREEN" "✓ Cleaned $config (backup saved as ${config}.backup)"
        fi
    fi
done

# 10. Optional: Clean up WireGuard data (with strong warning)
print_header "WireGuard Data Cleanup (Optional)"

print_color "$RED" "⚠ WARNING: The following options will affect your WireGuard configuration!"
print_color "$RED" "Only proceed if you want to remove WireGuard-related data."

if confirm "Do you want to see WireGuard data cleanup options?"; then
    # Backup directory
    if [[ -d "/etc/wireguard/backups" ]]; then
        if confirm "Remove WireGuard backup directory (/etc/wireguard/backups)?"; then
            rm -rf /etc/wireguard/backups
            print_color "$GREEN" "✓ Removed backup directory"
        fi
    fi
    
    # Manager-specific files (not core WireGuard configs)
    MANAGER_FILES=(
        "/etc/wireguard/firewall-rules.conf"
        "/etc/wireguard/banned_ips.txt"
        "/etc/wireguard/params"
    )
    
    for file in "${MANAGER_FILES[@]}"; do
        if [[ -f "$file" ]]; then
            if confirm "Remove manager file $file?"; then
                rm -f "$file"
                print_color "$GREEN" "✓ Removed $file"
            fi
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
        print_color "$YELLOW" "Some items were not removed. Run the script again if needed."
    fi
fi

# Refresh command database
print_color "$BLUE" "Refreshing command database..."
hash -r 2>/dev/null || true
which wg-manager &>/dev/null && print_color "$YELLOW" "Warning: wg-manager command still found in PATH" || print_color "$GREEN" "✓ wg-manager command removed from PATH"

print_header "Uninstall Complete"
print_color "$GREEN" "WireGuard Manager uninstallation finished."
print_color "$YELLOW" "Note: Core WireGuard installation and configurations were preserved."

# Fix for the menu issue - check if Python environment is correct
print_header "Troubleshooting Menu Issue"

print_color "$BLUE" "The menu issue might be due to:"
print_color "$YELLOW" "1. Missing Python dependencies"
print_color "$YELLOW" "2. Incorrect Python path"
print_color "$YELLOW" "3. Module import errors"

if [[ -d "/etc/wireguard/wireguard-manager" ]]; then
    print_color "$BLUE" "\nTo fix the menu issue in your current installation:"
    echo -e "${GREEN}cd /etc/wireguard/wireguard-manager${NC}"
    echo -e "${GREEN}source venv/bin/activate${NC}"
    echo -e "${GREEN}python -m wireguard_manager.cli${NC}"
    echo
    print_color "$YELLOW" "Or reinstall with:"
    echo -e "${GREEN}cd /etc/wireguard/wireguard-manager${NC}"
    echo -e "${GREEN}./auto_install.sh${NC}"
fi

# Note about firewall-rules.conf
print_color "$BLUE" "\nNote about firewall-rules.conf:"
print_color "$YELLOW" "The firewall-rules.conf file is being detected as a WireGuard interface"
print_color "$YELLOW" "because the script looks for .conf files. This should be fixed in the"
print_color "$YELLOW" "WireGuard detection logic to only look for wg*.conf files."

exit 0