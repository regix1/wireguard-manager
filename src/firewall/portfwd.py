"""Port forwarding (DNAT) management."""

from typing import List, Dict, Optional
from ..utils import run


def add_port_forward(
    external_port: str,
    internal_ip: str,
    internal_port: Optional[str] = None,
    protocol: str = "tcp",
    interface: str = "eth0",
    comment: Optional[str] = None,
) -> bool:
    """
    Add port forwarding rule (DNAT).

    Args:
        external_port: External port(s) - single, range "1000:2000", or multiport "80,443"
        internal_ip: Internal destination IP
        internal_port: Internal port (defaults to external_port)
        protocol: tcp or udp
        interface: External interface
        comment: Optional comment

    Returns:
        True if successful
    """
    if internal_port is None:
        internal_port = external_port

    # Build DNAT rule
    dnat_cmd = [
        "iptables", "-t", "nat", "-A", "PREROUTING",
        "-i", interface, "-p", protocol
    ]

    # Handle multiport
    if ',' in external_port:
        dnat_cmd.extend(["-m", "multiport", "--dports", external_port])
        dest = internal_ip  # Can't remap multiport
    else:
        dnat_cmd.extend(["--dport", external_port])
        if ':' in internal_port:
            dest = internal_ip
        else:
            dest = f"{internal_ip}:{internal_port}"

    dnat_cmd.extend(["-j", "DNAT", "--to-destination", dest])

    if comment:
        dnat_cmd.extend(["-m", "comment", "--comment", comment])

    # Build FORWARD rule to allow the traffic
    fwd_cmd = [
        "iptables", "-A", "FORWARD",
        "-p", protocol, "-d", internal_ip
    ]

    if ',' in internal_port if internal_port else external_port:
        ports = internal_port if internal_port else external_port
        fwd_cmd.extend(["-m", "multiport", "--dports", ports])
    else:
        port = internal_port if internal_port else external_port
        fwd_cmd.extend(["--dport", port])

    fwd_cmd.extend(["-j", "ACCEPT"])

    try:
        run(dnat_cmd)
        run(fwd_cmd)
        print(f"Added port forward: {interface}:{external_port}/{protocol} -> {internal_ip}:{internal_port}")
        return True
    except Exception as e:
        print(f"Failed to add port forward: {e}")
        return False


def add_port_forward_snat(
    external_port: str,
    internal_ip: str,
    snat_ip: str,
    internal_port: Optional[str] = None,
    protocol: str = "udp",
    interface: str = "eth0",
    wg_interface: str = "wg0",
) -> bool:
    """
    Add port forwarding with SNAT (for services that need return traffic).

    This is useful for services like WebRTC where the internal service
    needs to see traffic coming from the WireGuard server IP.

    Args:
        external_port: External port(s)
        internal_ip: Internal destination IP
        snat_ip: SNAT source IP (usually WireGuard server IP)
        internal_port: Internal port (defaults to external_port)
        protocol: tcp or udp
        interface: External interface
        wg_interface: WireGuard interface

    Returns:
        True if successful
    """
    if internal_port is None:
        internal_port = external_port

    # Add standard DNAT
    success = add_port_forward(
        external_port, internal_ip, internal_port, protocol, interface
    )

    if not success:
        return False

    # Add SNAT for return traffic
    snat_cmd = [
        "iptables", "-t", "nat", "-A", "POSTROUTING",
        "-o", wg_interface, "-p", protocol,
        "-d", internal_ip
    ]

    if ',' in internal_port:
        snat_cmd.extend(["-m", "multiport", "--dports", internal_port])
    else:
        snat_cmd.extend(["--dport", internal_port])

    snat_cmd.extend(["-j", "SNAT", "--to-source", snat_ip])

    try:
        run(snat_cmd)
        print(f"Added SNAT: {internal_ip}:{internal_port} <- {snat_ip}")
        return True
    except Exception as e:
        print(f"Failed to add SNAT rule: {e}")
        return False


def remove_port_forward(
    external_port: str,
    internal_ip: str,
    protocol: str = "tcp",
    interface: str = "eth0",
) -> bool:
    """
    Remove port forwarding rule.

    Args:
        external_port: External port
        internal_ip: Internal destination IP
        protocol: tcp or udp
        interface: External interface

    Returns:
        True if successful
    """
    # Remove DNAT rule
    dnat_cmd = [
        "iptables", "-t", "nat", "-D", "PREROUTING",
        "-i", interface, "-p", protocol,
        "--dport", external_port,
        "-j", "DNAT", "--to-destination", internal_ip
    ]

    # Remove FORWARD rule
    fwd_cmd = [
        "iptables", "-D", "FORWARD",
        "-p", protocol, "-d", internal_ip,
        "--dport", external_port,
        "-j", "ACCEPT"
    ]

    try:
        run(dnat_cmd, check=False)
        run(fwd_cmd, check=False)
        print(f"Removed port forward: {interface}:{external_port}/{protocol} -> {internal_ip}")
        return True
    except Exception as e:
        print(f"Failed to remove port forward: {e}")
        return False


def list_port_forwards() -> List[Dict]:
    """
    List all port forwarding (PREROUTING/DNAT) rules.

    Returns:
        List of rule dicts
    """
    rules = []

    try:
        result = run(["iptables", "-t", "nat", "-L", "PREROUTING", "-n", "-v", "--line-numbers"])
        lines = result.stdout.strip().split('\n')

        for line in lines[2:]:  # Skip headers
            if 'DNAT' in line or 'dpt:' in line:
                parts = line.split()
                if len(parts) >= 8:
                    rule = {
                        'num': parts[0],
                        'pkts': parts[1],
                        'bytes': parts[2],
                        'target': parts[3],
                        'prot': parts[4],
                        'in': parts[6],
                        'source': parts[8] if len(parts) > 8 else '*',
                        'dest': parts[9] if len(parts) > 9 else '*',
                        'extra': ' '.join(parts[10:]) if len(parts) > 10 else '',
                    }

                    # Parse destination from extra
                    extra = rule['extra']
                    if 'to:' in extra:
                        rule['forward_to'] = extra.split('to:')[1].split()[0]
                    if 'dpt:' in extra:
                        rule['dport'] = extra.split('dpt:')[1].split()[0]
                    elif 'dpts:' in extra:
                        rule['dport'] = extra.split('dpts:')[1].split()[0]

                    rules.append(rule)

    except Exception as e:
        print(f"Failed to list port forwards: {e}")

    return rules


def print_port_forwards() -> None:
    """Print formatted port forwarding rules."""
    rules = list_port_forwards()

    if not rules:
        print("No port forwarding rules configured")
        return

    print(f"\n{'#':<4} {'Proto':<8} {'Ext Port':<15} {'Forward To':<25} {'Packets':<12}")
    print("-" * 75)

    for rule in rules:
        dport = rule.get('dport', '*')
        fwd = rule.get('forward_to', '*')
        print(f"{rule['num']:<4} {rule['prot']:<8} {dport:<15} {fwd:<25} {rule['pkts']:<12}")

    print()
