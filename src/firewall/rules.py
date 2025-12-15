"""Firewall rules file management."""

from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict

from ..config import WIREGUARD_DIR, FIREWALL_DIR
from ..utils import run

RULES_FILE = FIREWALL_DIR / "rules.conf"
SERVICE_FILE = Path("/etc/systemd/system/wireguard-firewall.service")
APPLY_SCRIPT = FIREWALL_DIR / "apply-rules.sh"
REMOVE_SCRIPT = FIREWALL_DIR / "remove-rules.sh"


def setup_firewall_service(
    external_interface: str = "eth0",
    subnets: List[str] = None,
) -> bool:
    """
    Setup the firewall systemd service.

    Creates apply-rules.sh, remove-rules.sh, and systemd service.

    Args:
        external_interface: External network interface
        subnets: List of WireGuard subnets to NAT

    Returns:
        True if successful
    """
    if subnets is None:
        subnets = ["10.10.20.0/24"]

    FIREWALL_DIR.mkdir(parents=True, exist_ok=True)

    # Create apply script
    apply_content = f"""#!/bin/bash
# WireGuard Firewall Rules - Apply Script
# Generated: {datetime.now()}

set -e

echo "Applying WireGuard firewall rules..."

# Enable IP forwarding
sysctl -w net.ipv4.ip_forward=1

# Create BANNED_IPS chain if it doesn't exist
iptables -L BANNED_IPS &>/dev/null || {{
    iptables -N BANNED_IPS
    iptables -I INPUT 1 -j BANNED_IPS
    iptables -I FORWARD 1 -j BANNED_IPS
}}

# Load banned IPs
BANNED_FILE="{FIREWALL_DIR}/banned_ips.txt"
if [ -f "$BANNED_FILE" ]; then
    echo "Loading banned IPs..."
    while IFS= read -r line; do
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ -z "${{line// }}" ]] && continue
        ip=$(echo "$line" | cut -d'|' -f1 | cut -d'#' -f1 | tr -d ' ')
        if [ ! -z "$ip" ]; then
            iptables -A BANNED_IPS -s "$ip" -j DROP 2>/dev/null || true
        fi
    done < "$BANNED_FILE"
fi

# Apply rules from config file
RULES_FILE="{RULES_FILE}"
if [ -f "$RULES_FILE" ]; then
    echo "Applying rules from $RULES_FILE"
    while IFS= read -r line; do
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ -z "${{line// }}" ]] && continue
        eval "$line" 2>/dev/null || echo "Failed: $line"
    done < "$RULES_FILE"
fi

echo "Firewall rules applied successfully"
"""

    APPLY_SCRIPT.write_text(apply_content)
    APPLY_SCRIPT.chmod(0o755)

    # Create remove script
    remove_content = f"""#!/bin/bash
# WireGuard Firewall Rules - Remove Script
# Generated: {datetime.now()}

echo "Removing WireGuard firewall rules..."

# Remove BANNED_IPS chain
iptables -D INPUT -j BANNED_IPS 2>/dev/null || true
iptables -D FORWARD -j BANNED_IPS 2>/dev/null || true
iptables -F BANNED_IPS 2>/dev/null || true
iptables -X BANNED_IPS 2>/dev/null || true

echo "Firewall rules removed"
"""

    REMOVE_SCRIPT.write_text(remove_content)
    REMOVE_SCRIPT.chmod(0o755)

    # Create systemd service
    service_content = f"""[Unit]
Description=WireGuard Firewall Rules
After=network-pre.target
Before=network.target wg-quick@wg0.service
Wants=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart={APPLY_SCRIPT}
ExecStop={REMOVE_SCRIPT}
ExecReload={APPLY_SCRIPT}

[Install]
WantedBy=multi-user.target
"""

    SERVICE_FILE.write_text(service_content)

    # Create default rules file if not exists
    if not RULES_FILE.exists():
        default_rules = f"""# WireGuard Firewall Rules
# Generated: {datetime.now()}
# One iptables command per line
# Lines starting with # are ignored

# ========== NAT Rules ==========
"""
        for subnet in subnets:
            default_rules += f"iptables -t nat -A POSTROUTING -o {external_interface} -s {subnet} -j MASQUERADE\n"

        default_rules += f"""
# ========== Forward Rules ==========
iptables -A FORWARD -i {external_interface} -o wg0 -j ACCEPT
iptables -A FORWARD -i wg0 -j ACCEPT
"""
        RULES_FILE.write_text(default_rules)

    # Reload systemd
    run(["systemctl", "daemon-reload"], check=False)

    print(f"Created firewall service")
    print(f"  Service: {SERVICE_FILE}")
    print(f"  Apply script: {APPLY_SCRIPT}")
    print(f"  Rules file: {RULES_FILE}")

    return True


def enable_firewall_service() -> bool:
    """Enable and start the firewall service."""
    if not SERVICE_FILE.exists():
        print("Firewall service not configured. Run setup first.")
        return False

    run(["systemctl", "enable", "wireguard-firewall"], check=False)
    result = run(["systemctl", "start", "wireguard-firewall"], check=False)

    if result.returncode == 0:
        print("Firewall service enabled and started")
        return True
    else:
        print("Failed to start firewall service")
        return False


def restart_firewall_service() -> bool:
    """Restart the firewall service."""
    result = run(["systemctl", "restart", "wireguard-firewall"], check=False)
    if result.returncode == 0:
        print("Firewall service restarted")
        return True
    else:
        print("Failed to restart firewall service")
        return False


def firewall_service_status() -> Dict:
    """Get firewall service status."""
    result = run(["systemctl", "is-active", "wireguard-firewall"], check=False)
    active = result.returncode == 0

    result = run(["systemctl", "is-enabled", "wireguard-firewall"], check=False)
    enabled = result.returncode == 0

    return {
        "active": active,
        "enabled": enabled,
        "service_exists": SERVICE_FILE.exists(),
        "rules_file_exists": RULES_FILE.exists(),
    }


def load_rules() -> List[str]:
    """
    Load firewall rules from config file.

    Returns:
        List of iptables commands
    """
    if not RULES_FILE.exists():
        return []

    rules = []
    for line in RULES_FILE.read_text().split('\n'):
        line = line.strip()
        # Skip comments and empty lines
        if line and not line.startswith('#'):
            rules.append(line)

    return rules


def save_rules(rules: List[str], comment: Optional[str] = None) -> None:
    """
    Save firewall rules to config file.

    Args:
        rules: List of iptables commands
        comment: Optional header comment
    """
    FIREWALL_DIR.mkdir(parents=True, exist_ok=True)

    content = """# WireGuard Firewall Rules
# One iptables command per line
# Lines starting with # are ignored

"""

    if comment:
        content += f"# {comment}\n\n"

    content += '\n'.join(rules)
    RULES_FILE.write_text(content)
    print(f"Rules saved to {RULES_FILE}")


def apply_rules() -> bool:
    """
    Apply firewall rules from config file.

    Returns:
        True if all rules applied successfully
    """
    rules = load_rules()

    if not rules:
        print("No rules to apply")
        return True

    success = True
    applied = 0
    failed = 0

    for rule in rules:
        # Split the rule into command parts
        parts = rule.split()

        if not parts or parts[0] != 'iptables':
            continue

        try:
            run(parts)
            applied += 1
        except Exception as e:
            print(f"Failed: {rule}")
            print(f"  Error: {e}")
            failed += 1
            success = False

    print(f"Applied {applied} rules ({failed} failed)")
    return success


def clear_rules() -> None:
    """Clear all iptables rules (reset to default)."""
    # Flush all chains in filter table
    run(["iptables", "-F"], check=False)
    run(["iptables", "-X"], check=False)

    # Flush NAT table
    run(["iptables", "-t", "nat", "-F"], check=False)
    run(["iptables", "-t", "nat", "-X"], check=False)

    # Reset policies to ACCEPT
    run(["iptables", "-P", "INPUT", "ACCEPT"], check=False)
    run(["iptables", "-P", "FORWARD", "ACCEPT"], check=False)
    run(["iptables", "-P", "OUTPUT", "ACCEPT"], check=False)

    print("All iptables rules cleared")


def add_rule_to_file(rule: str) -> None:
    """Add a rule to the rules file."""
    rules = load_rules()
    if rule not in rules:
        rules.append(rule)
        save_rules(rules)


def remove_rule_from_file(rule: str) -> bool:
    """Remove a rule from the rules file."""
    rules = load_rules()
    if rule in rules:
        rules.remove(rule)
        save_rules(rules)
        return True
    return False


def export_current_rules() -> str:
    """Export current iptables rules to string."""
    result = run(["iptables-save"], check=False)
    return result.stdout if result.returncode == 0 else ""


def import_rules(rules_text: str) -> bool:
    """Import iptables rules from string."""
    try:
        run(["iptables-restore"], input_text=rules_text)
        return True
    except Exception as e:
        print(f"Failed to import rules: {e}")
        return False


def create_apply_script() -> Path:
    """Create a shell script to apply firewall rules."""
    script_path = FIREWALL_DIR / "apply-rules.sh"

    rules = load_rules()

    script = """#!/bin/bash
# Auto-generated firewall rules script
# Apply with: sudo ./apply-rules.sh

set -e

echo "Applying firewall rules..."

"""

    for rule in rules:
        script += f"{rule}\n"

    script += """
echo "Firewall rules applied successfully"
"""

    script_path.write_text(script)
    script_path.chmod(0o755)

    print(f"Created apply script: {script_path}")
    return script_path


def create_remove_script() -> Path:
    """Create a shell script to remove firewall rules."""
    script_path = FIREWALL_DIR / "remove-rules.sh"

    rules = load_rules()

    script = """#!/bin/bash
# Auto-generated firewall rules removal script

set -e

echo "Removing firewall rules..."

"""

    for rule in rules:
        # Convert -A to -D for deletion
        remove_rule = rule.replace(" -A ", " -D ").replace(" -I ", " -D ")
        script += f"{remove_rule} 2>/dev/null || true\n"

    script += """
echo "Firewall rules removed"
"""

    script_path.write_text(script)
    script_path.chmod(0o755)

    print(f"Created remove script: {script_path}")
    return script_path
