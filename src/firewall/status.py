"""Firewall status and display functions."""

from ..utils import run


def show_status() -> None:
    """Show overall firewall status."""
    print("\n=== Firewall Status ===\n")

    # Check if iptables is available
    result = run(["which", "iptables"], check=False)
    if result.returncode != 0:
        print("iptables not installed")
        return

    # Show filter table summary
    print("Filter Table (INPUT/FORWARD/OUTPUT):")
    print("-" * 50)

    for chain in ["INPUT", "FORWARD", "OUTPUT"]:
        result = run(["iptables", "-L", chain, "-n", "--line-numbers"], check=False)
        if result.returncode == 0:
            lines = result.stdout.strip().split('\n')
            rule_count = len(lines) - 2 if len(lines) > 2 else 0
            policy = "ACCEPT"
            if lines and "policy" in lines[0]:
                policy = lines[0].split("policy")[1].split(")")[0].strip()
            print(f"  {chain}: {rule_count} rules (policy: {policy})")

    print()

    # Show NAT table summary
    print("NAT Table (PREROUTING/POSTROUTING):")
    print("-" * 50)

    for chain in ["PREROUTING", "POSTROUTING"]:
        result = run(["iptables", "-t", "nat", "-L", chain, "-n", "--line-numbers"], check=False)
        if result.returncode == 0:
            lines = result.stdout.strip().split('\n')
            rule_count = len(lines) - 2 if len(lines) > 2 else 0
            print(f"  {chain}: {rule_count} rules")

    print()

    # Show BANNED_IPS chain if exists
    result = run(["iptables", "-L", "BANNED_IPS", "-n", "--line-numbers"], check=False)
    if result.returncode == 0:
        lines = result.stdout.strip().split('\n')
        ban_count = len(lines) - 2 if len(lines) > 2 else 0
        print(f"Banned IPs: {ban_count}")

    print()


def show_rules(table: str = "filter", chain: str = None, verbose: bool = False) -> None:
    """
    Show firewall rules.

    Args:
        table: Table name (filter, nat, mangle)
        chain: Specific chain to show (or all if None)
        verbose: Show verbose output with packet counts
    """
    cmd = ["iptables"]

    if table != "filter":
        cmd.extend(["-t", table])

    cmd.append("-L")

    if chain:
        cmd.append(chain)

    cmd.extend(["-n", "--line-numbers"])

    if verbose:
        cmd.append("-v")

    result = run(cmd, check=False)
    if result.returncode == 0:
        print(result.stdout)
    else:
        print(f"Failed to show rules: {result.stderr}")


def show_nat() -> None:
    """Show all NAT rules."""
    print("\n=== NAT Rules ===\n")
    show_rules("nat", verbose=True)


def show_forward() -> None:
    """Show all FORWARD rules."""
    print("\n=== FORWARD Rules ===\n")
    show_rules("filter", "FORWARD", verbose=True)


def check_ip_forwarding() -> bool:
    """Check if IP forwarding is enabled."""
    result = run(["sysctl", "net.ipv4.ip_forward"], check=False)
    if result.returncode == 0:
        return "= 1" in result.stdout
    return False


def show_diagnostics() -> None:
    """Show firewall diagnostics."""
    print("\n=== Firewall Diagnostics ===\n")

    # IP forwarding
    fwd_enabled = check_ip_forwarding()
    status = "enabled" if fwd_enabled else "DISABLED"
    print(f"IP Forwarding: {status}")

    # iptables version
    result = run(["iptables", "--version"], check=False)
    if result.returncode == 0:
        print(f"iptables: {result.stdout.strip()}")

    # Count rules per chain
    print("\nRule counts:")
    tables = [
        ("filter", ["INPUT", "FORWARD", "OUTPUT"]),
        ("nat", ["PREROUTING", "POSTROUTING", "OUTPUT"]),
    ]

    for table, chains in tables:
        for chain in chains:
            cmd = ["iptables"]
            if table != "filter":
                cmd.extend(["-t", table])
            cmd.extend(["-L", chain, "-n"])

            result = run(cmd, check=False)
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                count = len(lines) - 2 if len(lines) > 2 else 0
                print(f"  {table}/{chain}: {count}")

    print()
