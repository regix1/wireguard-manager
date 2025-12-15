"""FORWARD chain rule management."""

from typing import List, Dict, Optional
from ..utils import run


def add_forward(
    in_interface: Optional[str] = None,
    out_interface: Optional[str] = None,
    source: Optional[str] = None,
    dest: Optional[str] = None,
    protocol: Optional[str] = None,
    dport: Optional[str] = None,
    action: str = "ACCEPT",
    comment: Optional[str] = None,
) -> bool:
    """
    Add FORWARD chain rule.

    Args:
        in_interface: Input interface (e.g., "wg0")
        out_interface: Output interface (e.g., "eth0")
        source: Source address/subnet
        dest: Destination address/subnet
        protocol: Protocol (tcp, udp, icmp)
        dport: Destination port(s) (single, range "1000:2000", or multiport "80,443")
        action: ACCEPT, DROP, REJECT
        comment: Optional comment

    Returns:
        True if successful
    """
    cmd = ["iptables", "-A", "FORWARD"]

    if in_interface:
        cmd.extend(["-i", in_interface])
    if out_interface:
        cmd.extend(["-o", out_interface])
    if source:
        cmd.extend(["-s", source])
    if dest:
        cmd.extend(["-d", dest])
    if protocol:
        cmd.extend(["-p", protocol])
    if dport:
        if ',' in dport:
            cmd.extend(["-m", "multiport", "--dports", dport])
        else:
            cmd.extend(["--dport", dport])

    cmd.extend(["-j", action])

    if comment:
        cmd.extend(["-m", "comment", "--comment", comment])

    try:
        run(cmd)
        desc = f"{in_interface or '*'} -> {out_interface or '*'}"
        if dest:
            desc += f" ({dest})"
        print(f"Added FORWARD rule: {desc} -> {action}")
        return True
    except Exception as e:
        print(f"Failed to add FORWARD rule: {e}")
        return False


def remove_forward(rule_num: int) -> bool:
    """
    Remove FORWARD rule by number.

    Args:
        rule_num: Rule number from list_forward()

    Returns:
        True if successful
    """
    try:
        run(["iptables", "-D", "FORWARD", str(rule_num)])
        print(f"Removed FORWARD rule #{rule_num}")
        return True
    except Exception as e:
        print(f"Failed to remove FORWARD rule: {e}")
        return False


def add_interface_forward(
    wg_interface: str = "wg0",
    ext_interface: str = "eth0",
) -> bool:
    """
    Add standard forwarding rules for WireGuard interface.

    This sets up bidirectional forwarding between WireGuard and external interface.

    Args:
        wg_interface: WireGuard interface name
        ext_interface: External interface name

    Returns:
        True if successful
    """
    success = True

    # External -> WireGuard
    success &= add_forward(
        in_interface=ext_interface,
        out_interface=wg_interface,
        comment=f"Allow {ext_interface} to {wg_interface}"
    )

    # WireGuard -> External (all traffic from WG)
    success &= add_forward(
        in_interface=wg_interface,
        comment=f"Allow all from {wg_interface}"
    )

    return success


def list_forward() -> List[Dict]:
    """
    List all FORWARD chain rules.

    Returns:
        List of rule dicts
    """
    rules = []

    try:
        result = run(["iptables", "-L", "FORWARD", "-n", "-v", "--line-numbers"])
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
        print(f"Failed to list FORWARD rules: {e}")

    return rules


def print_forward() -> None:
    """Print formatted FORWARD rules."""
    rules = list_forward()

    if not rules:
        print("No FORWARD rules configured")
        return

    print(f"\n{'#':<4} {'In':<10} {'Out':<10} {'Source':<18} {'Dest':<18} {'Target':<10}")
    print("-" * 80)

    for rule in rules:
        print(f"{rule['num']:<4} {rule['in']:<10} {rule['out']:<10} "
              f"{rule['source']:<18} {rule['dest']:<18} {rule['target']:<10}")

    print()
