"""System diagnostics for WireGuard."""

from pathlib import Path
from typing import List, Dict

from ..config import WIREGUARD_DIR, get_interface_path
from ..utils import run, run_silent
from .install import is_installed, check_kernel_module


def run_diagnostics() -> Dict[str, bool]:
    """
    Run comprehensive system diagnostics.

    Returns:
        Dict of check name -> passed
    """
    results = {}

    print("\n=== WireGuard Diagnostics ===\n")

    # WireGuard installation
    wg_installed = is_installed()
    results['wireguard_installed'] = wg_installed
    status = "OK" if wg_installed else "FAIL"
    print(f"[{status}] WireGuard installed")

    # Kernel module
    module_loaded = check_kernel_module()
    results['kernel_module'] = module_loaded
    status = "OK" if module_loaded else "WARN"
    print(f"[{status}] Kernel module loaded")

    # IP forwarding
    fwd_result = run(["sysctl", "net.ipv4.ip_forward"], check=False)
    ip_forward = "= 1" in fwd_result.stdout
    results['ip_forwarding'] = ip_forward
    status = "OK" if ip_forward else "FAIL"
    print(f"[{status}] IP forwarding enabled")

    # Configuration directory
    config_exists = WIREGUARD_DIR.exists()
    results['config_dir'] = config_exists
    status = "OK" if config_exists else "FAIL"
    print(f"[{status}] Config directory exists ({WIREGUARD_DIR})")

    # Interface config files
    interfaces = list(WIREGUARD_DIR.glob("wg*.conf")) if config_exists else []
    results['interfaces_configured'] = len(interfaces) > 0
    status = "OK" if interfaces else "WARN"
    print(f"[{status}] Interface configs found ({len(interfaces)})")

    # iptables
    ipt_success, _ = run_silent(["which", "iptables"])
    results['iptables'] = ipt_success
    status = "OK" if ipt_success else "FAIL"
    print(f"[{status}] iptables available")

    # systemd
    systemd_success, _ = run_silent(["which", "systemctl"])
    results['systemd'] = systemd_success
    status = "OK" if systemd_success else "WARN"
    print(f"[{status}] systemd available")

    # qrencode
    qr_success, _ = run_silent(["which", "qrencode"])
    results['qrencode'] = qr_success
    status = "OK" if qr_success else "WARN"
    print(f"[{status}] qrencode available")

    print()

    # Summary
    passed = sum(1 for v in results.values() if v)
    total = len(results)
    print(f"Passed: {passed}/{total}")

    return results


def test_connectivity(peer_ip: str = None) -> bool:
    """
    Test VPN connectivity.

    Args:
        peer_ip: Specific peer IP to test (or None to test all)

    Returns:
        True if connectivity OK
    """
    from ..peers.list import list_peers
    from ..service.status import is_active

    # Check if interface is active
    if not is_active():
        print("WireGuard interface is not active")
        return False

    # Get peers to test
    if peer_ip:
        peers = [{"ip": peer_ip, "name": "specified"}]
    else:
        peers = list_peers(show_live=False)

    if not peers:
        print("No peers to test")
        return False

    print("\n=== Connectivity Test ===\n")

    all_ok = True
    for peer in peers:
        ip = peer.get('ip')
        name = peer.get('name', 'unknown')

        if not ip:
            continue

        result = run(["ping", "-c", "1", "-W", "2", ip], check=False)
        if result.returncode == 0:
            print(f"[OK] {name} ({ip})")
        else:
            print(f"[FAIL] {name} ({ip})")
            all_ok = False

    print()
    return all_ok


def check_config_syntax(interface: str = "wg0") -> bool:
    """
    Validate WireGuard configuration syntax.

    Args:
        interface: Interface to check

    Returns:
        True if valid
    """
    config_path = get_interface_path(interface)
    if not config_path.exists():
        print(f"Configuration not found: {config_path}")
        return False

    # Basic validation - check for required sections
    content = config_path.read_text()

    issues = []

    if '[Interface]' not in content:
        issues.append("Missing [Interface] section")

    if 'PrivateKey' not in content:
        issues.append("Missing PrivateKey")

    if 'Address' not in content:
        issues.append("Missing Address")

    if issues:
        print(f"Configuration issues for {interface}:")
        for issue in issues:
            print(f"  - {issue}")
        return False

    print(f"Configuration syntax OK for {interface}")
    return True


def view_logs(lines: int = 50) -> None:
    """
    View WireGuard related system logs.

    Args:
        lines: Number of lines to show
    """
    result = run(
        ["journalctl", "-u", "wg-quick@*", "-n", str(lines), "--no-pager"],
        check=False
    )
    if result.returncode == 0:
        print(result.stdout)
    else:
        # Fallback to dmesg
        result = run(["dmesg", "-T"], check=False)
        if result.returncode == 0:
            # Filter for wireguard
            for line in result.stdout.split('\n')[-lines:]:
                if 'wireguard' in line.lower() or 'wg' in line.lower():
                    print(line)
