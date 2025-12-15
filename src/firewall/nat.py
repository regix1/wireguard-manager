"""NAT/Masquerade rule management."""

from typing import List, Dict, Optional
from ..utils import run


def add_nat(
    source: str,
    interface: str = "eth0",
    masquerade: bool = True,
    comment: Optional[str] = None,
) -> bool:
    """
    Add NAT/Masquerade rule for a source subnet.

    Args:
        source: Source subnet (e.g., "10.10.20.0/24")
        interface: Outbound interface (e.g., "eth0", "eno1")
        masquerade: Use MASQUERADE (True) or ACCEPT (False)
        comment: Optional comment for the rule

    Returns:
        True if successful
    """
    target = "MASQUERADE" if masquerade else "ACCEPT"

    cmd = [
        "iptables", "-t", "nat", "-A", "POSTROUTING",
        "-o", interface, "-s", source, "-j", target
    ]

    if comment:
        cmd.extend(["-m", "comment", "--comment", comment])

    try:
        run(cmd)
        action = "MASQUERADE" if masquerade else "ACCEPT"
        print(f"Added NAT rule: {source} -> {interface} ({action})")
        return True
    except Exception as e:
        print(f"Failed to add NAT rule: {e}")
        return False


def remove_nat(source: str, interface: str = "eth0", masquerade: bool = True) -> bool:
    """
    Remove NAT/Masquerade rule.

    Args:
        source: Source subnet
        interface: Outbound interface
        masquerade: Match MASQUERADE (True) or ACCEPT (False)

    Returns:
        True if successful
    """
    target = "MASQUERADE" if masquerade else "ACCEPT"

    cmd = [
        "iptables", "-t", "nat", "-D", "POSTROUTING",
        "-o", interface, "-s", source, "-j", target
    ]

    try:
        run(cmd)
        print(f"Removed NAT rule: {source} -> {interface}")
        return True
    except Exception as e:
        print(f"Failed to remove NAT rule: {e}")
        return False


def list_nat() -> List[Dict]:
    """
    List all NAT POSTROUTING rules.

    Returns:
        List of rule dicts
    """
    rules = []

    try:
        result = run(["iptables", "-t", "nat", "-L", "POSTROUTING", "-n", "-v", "--line-numbers"])
        lines = result.stdout.strip().split('\n')

        for line in lines[2:]:  # Skip headers
            parts = line.split()
            if len(parts) >= 8:
                rules.append({
                    'num': parts[0],
                    'pkts': parts[1],
                    'bytes': parts[2],
                    'target': parts[3],
                    'prot': parts[4],
                    'opt': parts[5],
                    'in': parts[6],
                    'out': parts[7],
                    'source': parts[8] if len(parts) > 8 else '*',
                    'dest': parts[9] if len(parts) > 9 else '*',
                    'extra': ' '.join(parts[10:]) if len(parts) > 10 else '',
                })

    except Exception as e:
        print(f"Failed to list NAT rules: {e}")

    return rules


def print_nat() -> None:
    """Print formatted NAT rules."""
    rules = list_nat()

    if not rules:
        print("No NAT rules configured")
        return

    print(f"\n{'#':<4} {'Source':<20} {'Out':<12} {'Target':<15} {'Packets':<12}")
    print("-" * 70)

    for rule in rules:
        print(f"{rule['num']:<4} {rule['source']:<20} {rule['out']:<12} "
              f"{rule['target']:<15} {rule['pkts']:<12}")

    print()
