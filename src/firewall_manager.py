"""Firewall and NAT management for WireGuard."""

from pathlib import Path
from typing import List, Dict, Optional
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, IntPrompt

from .utils import run_command, prompt_yes_no
from .config_manager import ConfigManager

console = Console()

class FirewallManager:
    """Manage firewall rules and NAT."""
    
    def __init__(self):
        """Initialize firewall manager."""
        self.config_manager = ConfigManager()
        self.banned_ips_file = Path("/etc/wireguard/banned_ips.txt")
    
    def show_status(self) -> None:
        """Show comprehensive firewall status."""
        console.print(Panel.fit(
            "[bold cyan]Firewall Status[/bold cyan]",
            border_style="cyan"
        ))
        
        # Show IP forwarding status
        console.print("[cyan]IP Forwarding:[/cyan]")
        with open("/proc/sys/net/ipv4/ip_forward", "r") as f:
            ip_forward = f.read().strip()
        
        if ip_forward == "1":
            console.print("  [green]✓ Enabled[/green]")
        else:
            console.print("  [red]✗ Disabled[/red]")
        
        # Show NAT rules
        console.print("\n[cyan]NAT Rules (POSTROUTING):[/cyan]")
        result = run_command(
            ["iptables", "-t", "nat", "-L", "POSTROUTING", "-n", "-v", "--line-numbers"],
            check=False
        )
        
        if result.returncode == 0:
            lines = result.stdout.split('\n')
            nat_rules = [line for line in lines if 'MASQUERADE' in line or 'SNAT' in line or 'DNAT' in line]
            
            if nat_rules:
                for rule in nat_rules:
                    console.print(f"  {rule.strip()}")
            else:
                console.print("  [yellow]No NAT rules found[/yellow]")
        
        # Show port forwarding rules (PREROUTING)
        console.print("\n[cyan]Port Forwarding Rules (PREROUTING):[/cyan]")
        result = run_command(
            ["iptables", "-t", "nat", "-L", "PREROUTING", "-n", "-v", "--line-numbers"],
            check=False
        )
        
        if result.returncode == 0:
            lines = result.stdout.split('\n')
            forward_rules = [line for line in lines if 'DNAT' in line]
            
            if forward_rules:
                for rule in forward_rules:
                    console.print(f"  {rule.strip()}")
            else:
                console.print("  [yellow]No port forwarding rules found[/yellow]")
        
        # Show forward rules
        console.print("\n[cyan]Forward Rules:[/cyan]")
        result = run_command(
            ["iptables", "-L", "FORWARD", "-n", "-v", "--line-numbers"],
            check=False
        )
        
        if result.returncode == 0:
            lines = result.stdout.split('\n')
            # Show first 10 relevant forward rules
            forward_rules = [line for line in lines if any(x in line for x in ['ACCEPT', 'DROP', 'REJECT']) and line.strip()][:10]
            
            if forward_rules:
                for rule in forward_rules:
                    console.print(f"  {rule.strip()}")
            else:
                console.print("  [yellow]No forward rules found[/yellow]")
        
        # Show banned IPs
        console.print("\n[cyan]Banned IPs:[/cyan]")
        banned_count = self._get_banned_ip_count()
        if banned_count > 0:
            console.print(f"  [yellow]{banned_count} IP(s) currently banned[/yellow]")
        else:
            console.print("  [green]No banned IPs[/green]")
    
    def manage_nat_rules(self) -> None:
        """Manage NAT/Masquerade rules."""
        console.print(Panel.fit(
            "[bold cyan]NAT Rule Management[/bold cyan]",
            border_style="cyan"
        ))
        
        options = [
            "View NAT rules",
            "Add masquerade rule",
            "Add SNAT rule",
            "Remove NAT rule",
            "Back"
        ]
        
        for i, option in enumerate(options, 1):
            console.print(f"  {i}. {option}")
        
        choice = IntPrompt.ask("Select option", choices=["1", "2", "3", "4", "5"])
        
        if choice == 1:
            self._view_nat_rules()
        elif choice == 2:
            self._add_masquerade_rule()
        elif choice == 3:
            self._add_snat_rule()
        elif choice == 4:
            self._remove_nat_rule()
    
    def manage_port_forwarding(self) -> None:
        """Manage port forwarding rules."""
        console.print(Panel.fit(
            "[bold cyan]Port Forwarding[/bold cyan]",
            border_style="cyan"
        ))
        
        options = [
            "View current port forwards",
            "Add port forward",
            "Remove port forward",
            "Add range forward",
            "Back"
        ]
        
        for i, option in enumerate(options, 1):
            console.print(f"  {i}. {option}")
        
        choice = IntPrompt.ask("Select option", choices=["1", "2", "3", "4", "5"])
        
        if choice == 1:
            self._view_port_forwards()
        elif choice == 2:
            self._add_port_forward()
        elif choice == 3:
            self._remove_port_forward()
        elif choice == 4:
            self._add_range_forward()
    
    def manage_forward_rules(self) -> None:
        """Manage FORWARD chain rules."""
        console.print(Panel.fit(
            "[bold cyan]Forward Rules Management[/bold cyan]",
            border_style="cyan"
        ))
        
        options = [
            "View forward rules",
            "Add accept rule",
            "Add drop rule",
            "Remove forward rule",
            "Back"
        ]
        
        for i, option in enumerate(options, 1):
            console.print(f"  {i}. {option}")
        
        choice = IntPrompt.ask("Select option", choices=["1", "2", "3", "4", "5"])
        
        if choice == 1:
            self._view_forward_rules()
        elif choice == 2:
            self._add_forward_accept()
        elif choice == 3:
            self._add_forward_drop()
        elif choice == 4:
            self._remove_forward_rule()
    
    def manage_banned_ips(self) -> None:
        """Manage banned IP addresses."""
        console.print(Panel.fit(
            "[bold cyan]Banned IP Management[/bold cyan]",
            border_style="cyan"
        ))
        
        options = [
            "View banned IPs",
            "Ban an IP",
            "Unban an IP",
            "Ban IP range",
            "Clear all bans",
            "Import ban list",
            "Export ban list",
            "Back"
        ]
        
        for i, option in enumerate(options, 1):
            console.print(f"  {i}. {option}")
        
        choice = IntPrompt.ask("Select option", choices=["1", "2", "3", "4", "5", "6", "7", "8"])
        
        if choice == 1:
            self._view_banned_ips()
        elif choice == 2:
            self._ban_ip()
        elif choice == 3:
            self._unban_ip()
        elif choice == 4:
            self._ban_ip_range()
        elif choice == 5:
            self._clear_all_bans()
        elif choice == 6:
            self._import_ban_list()
        elif choice == 7:
            self._export_ban_list()
    
    def apply_nat_rules(self) -> None:
        """Apply standard NAT rules for WireGuard."""
        console.print(Panel.fit(
            "[bold cyan]Apply Standard NAT Rules[/bold cyan]",
            border_style="cyan"
        ))
        
        config = self.config_manager.load_config()
        external_interface = config.get('external_interface', 'eth0')
        subnet = config.get('server_subnet', '10.0.0.0/24')
        
        console.print(f"[cyan]External Interface:[/cyan] {external_interface}")
        console.print(f"[cyan]VPN Subnet:[/cyan] {subnet}")
        
        if not prompt_yes_no("\nApply NAT rules?", default=True):
            return
        
        # Enable IP forwarding
        console.print("\n[cyan]Enabling IP forwarding...[/cyan]")
        run_command(["sysctl", "-w", "net.ipv4.ip_forward=1"], check=False)
        
        # Make it permanent
        with open("/etc/sysctl.conf", "r") as f:
            content = f.read()
        
        if "net.ipv4.ip_forward=1" not in content:
            with open("/etc/sysctl.conf", "a") as f:
                f.write("\nnet.ipv4.ip_forward=1\n")
        
        # Add NAT rule
        console.print("[cyan]Adding NAT rule...[/cyan]")
        run_command([
            "iptables", "-t", "nat", "-A", "POSTROUTING",
            "-s", subnet, "-o", external_interface, "-j", "MASQUERADE"
        ], check=False)
        
        # Add forward rules
        console.print("[cyan]Adding forward rules...[/cyan]")
        run_command([
            "iptables", "-A", "FORWARD", "-i", "wg0", "-j", "ACCEPT"
        ], check=False)
        
        run_command([
            "iptables", "-A", "FORWARD", "-o", "wg0", "-j", "ACCEPT"
        ], check=False)
        
        console.print("\n[green]✓[/green] NAT rules applied")
        
        if prompt_yes_no("Save rules permanently (iptables-save)?", default=True):
            self._save_iptables_rules()
    
    def _view_nat_rules(self) -> None:
        """View detailed NAT rules."""
        console.print("\n[cyan]NAT Table - POSTROUTING Chain:[/cyan]")
        result = run_command(
            ["iptables", "-t", "nat", "-L", "POSTROUTING", "-n", "-v", "--line-numbers"],
            check=False
        )
        if result.returncode == 0:
            console.print(result.stdout)
    
    def _add_masquerade_rule(self) -> None:
        """Add a masquerade rule."""
        console.print("\n[cyan]Add Masquerade Rule[/cyan]")
        
        source = Prompt.ask("Source subnet (e.g., 10.0.0.0/24)")
        interface = Prompt.ask("Output interface (e.g., eth0)")
        
        cmd = [
            "iptables", "-t", "nat", "-A", "POSTROUTING",
            "-s", source, "-o", interface, "-j", "MASQUERADE"
        ]
        
        console.print(f"\n[yellow]Command:[/yellow] {' '.join(cmd)}")
        
        if prompt_yes_no("Execute this command?", default=True):
            result = run_command(cmd, check=False)
            if result.returncode == 0:
                console.print("[green]✓[/green] Masquerade rule added")
            else:
                console.print(f"[red]Failed: {result.stderr}[/red]")
    
    def _add_snat_rule(self) -> None:
        """Add an SNAT rule."""
        console.print("\n[cyan]Add SNAT Rule[/cyan]")
        
        source = Prompt.ask("Source subnet (e.g., 10.0.0.0/24)")
        interface = Prompt.ask("Output interface (e.g., eth0)")
        to_source = Prompt.ask("SNAT to IP address")
        
        cmd = [
            "iptables", "-t", "nat", "-A", "POSTROUTING",
            "-s", source, "-o", interface, "-j", "SNAT",
            "--to-source", to_source
        ]
        
        console.print(f"\n[yellow]Command:[/yellow] {' '.join(cmd)}")
        
        if prompt_yes_no("Execute this command?", default=True):
            result = run_command(cmd, check=False)
            if result.returncode == 0:
                console.print("[green]✓[/green] SNAT rule added")
            else:
                console.print(f"[red]Failed: {result.stderr}[/red]")
    
    def _remove_nat_rule(self) -> None:
        """Remove a NAT rule by line number."""
        self._view_nat_rules()
        
        line_num = IntPrompt.ask("\nEnter rule number to remove (0 to cancel)")
        if line_num == 0:
            return
        
        cmd = ["iptables", "-t", "nat", "-D", "POSTROUTING", str(line_num)]
        
        if prompt_yes_no(f"Remove rule #{line_num}?", default=False):
            result = run_command(cmd, check=False)
            if result.returncode == 0:
                console.print("[green]✓[/green] Rule removed")
            else:
                console.print(f"[red]Failed: {result.stderr}[/red]")
    
    def _view_port_forwards(self) -> None:
        """View current port forwarding rules."""
        console.print("\n[cyan]Port Forwarding Rules (PREROUTING):[/cyan]")
        result = run_command(
            ["iptables", "-t", "nat", "-L", "PREROUTING", "-n", "-v", "--line-numbers"],
            check=False
        )
        if result.returncode == 0:
            console.print(result.stdout)
    
    def _add_port_forward(self) -> None:
        """Add a port forwarding rule."""
        console.print("\n[cyan]Add Port Forward[/cyan]")
        
        external_port = IntPrompt.ask("External port")
        internal_ip = Prompt.ask("Internal IP (VPN client)")
        internal_port = IntPrompt.ask("Internal port", default=external_port)
        protocol = Prompt.ask("Protocol", choices=["tcp", "udp", "both"], default="tcp")
        
        config = self.config_manager.load_config()
        external_interface = config.get('external_interface', 'eth0')
        
        if protocol == "both":
            protocols = ["tcp", "udp"]
        else:
            protocols = [protocol]
        
        for proto in protocols:
            # PREROUTING rule
            cmd1 = [
                "iptables", "-t", "nat", "-A", "PREROUTING",
                "-i", external_interface, "-p", proto,
                "--dport", str(external_port),
                "-j", "DNAT", "--to-destination", f"{internal_ip}:{internal_port}"
            ]
            
            # FORWARD rule
            cmd2 = [
                "iptables", "-A", "FORWARD",
                "-p", proto, "-d", internal_ip,
                "--dport", str(internal_port),
                "-j", "ACCEPT"
            ]
            
            console.print(f"\n[yellow]Commands:[/yellow]")
            console.print(f"  {' '.join(cmd1)}")
            console.print(f"  {' '.join(cmd2)}")
            
            if prompt_yes_no(f"Add port forward for {proto}?", default=True):
                result1 = run_command(cmd1, check=False)
                result2 = run_command(cmd2, check=False)
                
                if result1.returncode == 0 and result2.returncode == 0:
                    console.print(f"[green]✓[/green] Port forward added: {external_port} -> {internal_ip}:{internal_port} ({proto})")
                else:
                    console.print("[red]Failed to add port forward[/red]")
    
    def _add_range_forward(self) -> None:
        """Add port range forwarding."""
        console.print("\n[cyan]Add Port Range Forward[/cyan]")
        
        start_port = IntPrompt.ask("Start port")
        end_port = IntPrompt.ask("End port")
        internal_ip = Prompt.ask("Internal IP (VPN client)")
        protocol = Prompt.ask("Protocol", choices=["tcp", "udp", "both"], default="tcp")
        
        config = self.config_manager.load_config()
        external_interface = config.get('external_interface', 'eth0')
        
        if protocol == "both":
            protocols = ["tcp", "udp"]
        else:
            protocols = [protocol]
        
        for proto in protocols:
            # PREROUTING rule for range
            cmd1 = [
                "iptables", "-t", "nat", "-A", "PREROUTING",
                "-i", external_interface, "-p", proto,
                "--dport", f"{start_port}:{end_port}",
                "-j", "DNAT", "--to-destination", internal_ip
            ]
            
            # FORWARD rule for range
            cmd2 = [
                "iptables", "-A", "FORWARD",
                "-p", proto, "-d", internal_ip,
                "--dport", f"{start_port}:{end_port}",
                "-j", "ACCEPT"
            ]
            
            if prompt_yes_no(f"Add range forward {start_port}-{end_port} for {proto}?", default=True):
                run_command(cmd1, check=False)
                run_command(cmd2, check=False)
                console.print(f"[green]✓[/green] Range forward added: {start_port}-{end_port} -> {internal_ip} ({proto})")
    
    def _remove_port_forward(self) -> None:
        """Remove port forwarding rule."""
        self._view_port_forwards()
        
        line_num = IntPrompt.ask("\nEnter PREROUTING rule number to remove (0 to cancel)")
        if line_num == 0:
            return
        
        cmd = ["iptables", "-t", "nat", "-D", "PREROUTING", str(line_num)]
        
        if prompt_yes_no(f"Remove port forward rule #{line_num}?", default=False):
            result = run_command(cmd, check=False)
            if result.returncode == 0:
                console.print("[green]✓[/green] Port forward removed")
                console.print("[yellow]Note: Remember to also remove corresponding FORWARD rule[/yellow]")
            else:
                console.print(f"[red]Failed: {result.stderr}[/red]")
    
    def _view_forward_rules(self) -> None:
        """View FORWARD chain rules."""
        console.print("\n[cyan]FORWARD Chain Rules:[/cyan]")
        result = run_command(
            ["iptables", "-L", "FORWARD", "-n", "-v", "--line-numbers"],
            check=False
        )
        if result.returncode == 0:
            console.print(result.stdout)
    
    def _add_forward_accept(self) -> None:
        """Add ACCEPT rule to FORWARD chain."""
        console.print("\n[cyan]Add Forward Accept Rule[/cyan]")
        
        source = Prompt.ask("Source IP/subnet (leave empty for any)", default="")
        dest = Prompt.ask("Destination IP/subnet (leave empty for any)", default="")
        interface_in = Prompt.ask("Input interface (leave empty for any)", default="")
        interface_out = Prompt.ask("Output interface (leave empty for any)", default="")
        
        cmd = ["iptables", "-A", "FORWARD"]
        
        if source:
            cmd.extend(["-s", source])
        if dest:
            cmd.extend(["-d", dest])
        if interface_in:
            cmd.extend(["-i", interface_in])
        if interface_out:
            cmd.extend(["-o", interface_out])
        
        cmd.extend(["-j", "ACCEPT"])
        
        console.print(f"\n[yellow]Command:[/yellow] {' '.join(cmd)}")
        
        if prompt_yes_no("Execute this command?", default=True):
            result = run_command(cmd, check=False)
            if result.returncode == 0:
                console.print("[green]✓[/green] Forward accept rule added")
            else:
                console.print(f"[red]Failed: {result.stderr}[/red]")
    
    def _add_forward_drop(self) -> None:
        """Add DROP rule to FORWARD chain."""
        console.print("\n[cyan]Add Forward Drop Rule[/cyan]")
        
        source = Prompt.ask("Source IP/subnet to block", default="")
        dest = Prompt.ask("Destination IP/subnet (leave empty for any)", default="")
        
        cmd = ["iptables", "-A", "FORWARD"]
        
        if source:
            cmd.extend(["-s", source])
        if dest:
            cmd.extend(["-d", dest])
        
        cmd.extend(["-j", "DROP"])
        
        console.print(f"\n[yellow]Command:[/yellow] {' '.join(cmd)}")
        
        if prompt_yes_no("Execute this command?", default=True):
            result = run_command(cmd, check=False)
            if result.returncode == 0:
                console.print("[green]✓[/green] Forward drop rule added")
            else:
                console.print(f"[red]Failed: {result.stderr}[/red]")
    
    def _remove_forward_rule(self) -> None:
        """Remove FORWARD chain rule."""
        self._view_forward_rules()
        
        line_num = IntPrompt.ask("\nEnter rule number to remove (0 to cancel)")
        if line_num == 0:
            return
        
        cmd = ["iptables", "-D", "FORWARD", str(line_num)]
        
        if prompt_yes_no(f"Remove forward rule #{line_num}?", default=False):
            result = run_command(cmd, check=False)
            if result.returncode == 0:
                console.print("[green]✓[/green] Rule removed")
            else:
                console.print(f"[red]Failed: {result.stderr}[/red]")
    
    def _view_banned_ips(self) -> None:
        """View banned IP addresses."""
        console.print("\n[cyan]Banned IP Addresses:[/cyan]")
        
        # Check BANNED_IPS chain
        result = run_command(
            ["iptables", "-L", "BANNED_IPS", "-n", "-v", "--line-numbers"],
            check=False
        )
        
        if result.returncode == 0:
            lines = result.stdout.split('\n')
            ban_rules = [line for line in lines if 'DROP' in line]
            
            if ban_rules:
                table = Table(show_header=True, header_style="bold magenta")
                table.add_column("#", width=3)
                table.add_column("IP Address")
                table.add_column("Comment")
                table.add_column("Packets", justify="right")
                table.add_column("Bytes", justify="right")
                
                for rule in ban_rules:
                    parts = rule.split()
                    if len(parts) >= 7:
                        num = parts[0]
                        packets = parts[1]
                        bytes_val = parts[2]
                        ip = ""
                        comment = ""
                        
                        # Find IP
                        for i, part in enumerate(parts):
                            if part in [parts[7], parts[8]] and '.' in part:
                                ip = part
                                break
                        
                        # Find comment
                        if "/*" in rule and "*/" in rule:
                            comment = rule[rule.find("/*")+2:rule.find("*/")].strip()
                        
                        table.add_row(num, ip, comment, packets, bytes_val)
                
                console.print(table)
            else:
                console.print("[yellow]No banned IPs found[/yellow]")
        else:
            console.print("[yellow]BANNED_IPS chain not found[/yellow]")
            if prompt_yes_no("Create BANNED_IPS chain?", default=True):
                self._create_banned_ips_chain()
    
    def _ban_ip(self) -> None:
        """Ban an IP address."""
        console.print("\n[cyan]Ban IP Address[/cyan]")
        
        ip = Prompt.ask("IP address to ban")
        comment = Prompt.ask("Comment/reason (optional)", default="")
        
        # Ensure BANNED_IPS chain exists
        self._ensure_banned_ips_chain()
        
        # Add to BANNED_IPS chain
        cmd = ["iptables", "-A", "BANNED_IPS", "-s", ip]
        
        if comment:
            cmd.extend(["-m", "comment", "--comment", comment])
        
        cmd.extend(["-j", "DROP"])
        
        result = run_command(cmd, check=False)
        if result.returncode == 0:
            console.print(f"[green]✓[/green] IP {ip} banned")
            
            # Save to file
            self._save_banned_ip_to_file(ip, comment)
        else:
            console.print(f"[red]Failed to ban IP: {result.stderr}[/red]")
    
    def _unban_ip(self) -> None:
        """Unban an IP address."""
        self._view_banned_ips()
        
        console.print("\n[cyan]Unban IP Address[/cyan]")
        choice = Prompt.ask("Enter IP to unban or rule # to remove")
        
        if choice.isdigit():
            # Remove by rule number
            cmd = ["iptables", "-D", "BANNED_IPS", choice]
        else:
            # Remove by IP
            cmd = ["iptables", "-D", "BANNED_IPS", "-s", choice, "-j", "DROP"]
        
        result = run_command(cmd, check=False)
        if result.returncode == 0:
            console.print(f"[green]✓[/green] IP unbanned")
            
            # Remove from file
            if not choice.isdigit():
                self._remove_banned_ip_from_file(choice)
        else:
            console.print(f"[red]Failed to unban: {result.stderr}[/red]")
    
    def _ban_ip_range(self) -> None:
        """Ban an IP range."""
        console.print("\n[cyan]Ban IP Range[/cyan]")
        
        ip_range = Prompt.ask("IP range to ban (e.g., 192.168.1.0/24)")
        comment = Prompt.ask("Comment/reason (optional)", default="")
        
        self._ensure_banned_ips_chain()
        
        cmd = ["iptables", "-A", "BANNED_IPS", "-s", ip_range]
        
        if comment:
            cmd.extend(["-m", "comment", "--comment", comment])
        
        cmd.extend(["-j", "DROP"])
        
        result = run_command(cmd, check=False)
        if result.returncode == 0:
            console.print(f"[green]✓[/green] IP range {ip_range} banned")
            self._save_banned_ip_to_file(ip_range, comment)
        else:
            console.print(f"[red]Failed: {result.stderr}[/red]")
    
    def _clear_all_bans(self) -> None:
        """Clear all banned IPs."""
        if not prompt_yes_no("Remove ALL banned IPs?", default=False):
            return
        
        # Flush BANNED_IPS chain
        run_command(["iptables", "-F", "BANNED_IPS"], check=False)
        
        # Clear file
        self.banned_ips_file.write_text("")
        
        console.print("[green]✓[/green] All IP bans cleared")
    
    def _import_ban_list(self) -> None:
        """Import IP ban list from file."""
        console.print("\n[cyan]Import Ban List[/cyan]")
        
        file_path = Prompt.ask("Path to ban list file", default="/tmp/ban_list.txt")
        file_path = Path(file_path)
        
        if not file_path.exists():
            console.print(f"[red]File not found: {file_path}[/red]")
            return
        
        self._ensure_banned_ips_chain()
        
        imported = 0
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    parts = line.split('#', 1)
                    ip = parts[0].strip()
                    comment = parts[1].strip() if len(parts) > 1 else ""
                    
                    cmd = ["iptables", "-A", "BANNED_IPS", "-s", ip]
                    if comment:
                        cmd.extend(["-m", "comment", "--comment", comment])
                    cmd.extend(["-j", "DROP"])
                    
                    result = run_command(cmd, check=False)
                    if result.returncode == 0:
                        imported += 1
                        self._save_banned_ip_to_file(ip, comment)
        
        console.print(f"[green]✓[/green] Imported {imported} IP ban(s)")
    
    def _export_ban_list(self) -> None:
        """Export IP ban list to file."""
        console.print("\n[cyan]Export Ban List[/cyan]")
        
        file_path = Prompt.ask("Export to file", default="/tmp/ban_list_export.txt")
        
        result = run_command(
            ["iptables", "-L", "BANNED_IPS", "-n"],
            check=False
        )
        
        if result.returncode == 0:
            with open(file_path, 'w') as f:
                f.write(f"# WireGuard Banned IPs - Exported {datetime.now()}\n")
                f.write("# Format: IP_ADDRESS # comment\n\n")
                
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'DROP' in line:
                        parts = line.split()
                        for part in parts:
                            if '.' in part and '/' in part or '.' in part:
                                f.write(f"{part}")
                                if "/*" in line and "*/" in line:
                                    comment = line[line.find("/*")+2:line.find("*/")].strip()
                                    f.write(f" # {comment}")
                                f.write("\n")
                                break
            
            console.print(f"[green]✓[/green] Ban list exported to {file_path}")
        else:
            console.print("[red]Failed to export ban list[/red]")
    
    def _ensure_banned_ips_chain(self) -> None:
        """Ensure BANNED_IPS chain exists."""
        # Check if chain exists
        result = run_command(["iptables", "-L", "BANNED_IPS"], check=False)
        
        if result.returncode != 0:
            # Create chain
            run_command(["iptables", "-N", "BANNED_IPS"], check=False)
            
            # Add jump rules
            run_command(["iptables", "-I", "INPUT", "1", "-j", "BANNED_IPS"], check=False)
            run_command(["iptables", "-I", "FORWARD", "1", "-j", "BANNED_IPS"], check=False)
            
            console.print("[green]✓[/green] Created BANNED_IPS chain")
    
    def _create_banned_ips_chain(self) -> None:
        """Create BANNED_IPS chain."""
        self._ensure_banned_ips_chain()
    
    def _save_banned_ip_to_file(self, ip: str, comment: str = "") -> None:
        """Save banned IP to file."""
        with open(self.banned_ips_file, 'a') as f:
            f.write(f"{ip} # {comment} # {datetime.now()}\n")
    
    def _remove_banned_ip_from_file(self, ip: str) -> None:
        """Remove banned IP from file."""
        if self.banned_ips_file.exists():
            lines = self.banned_ips_file.read_text().split('\n')
            new_lines = [line for line in lines if not line.startswith(ip)]
            self.banned_ips_file.write_text('\n'.join(new_lines))
    
    def _get_banned_ip_count(self) -> int:
        """Get count of banned IPs."""
        result = run_command(["iptables", "-L", "BANNED_IPS", "-n"], check=False)
        if result.returncode == 0:
            return result.stdout.count('DROP')
        return 0
    
    def _save_iptables_rules(self) -> None:
        """Save iptables rules permanently."""
        console.print("\n[cyan]Saving iptables rules...[/cyan]")
        
        # For Debian/Ubuntu
        if Path("/etc/iptables").exists():
            run_command(["iptables-save"], check=False, capture_output=False)
            console.print("[green]✓[/green] Rules saved (iptables-save)")
        
        # For systems with iptables-persistent
        if Path("/etc/iptables/rules.v4").exists():
            result = run_command(["iptables-save"], check=False)
            if result.returncode == 0:
                Path("/etc/iptables/rules.v4").write_text(result.stdout)
                console.print("[green]✓[/green] Rules saved to /etc/iptables/rules.v4")
        
        # For RedHat/CentOS
        elif Path("/etc/sysconfig/iptables").exists():
            result = run_command(["iptables-save"], check=False)
            if result.returncode == 0:
                Path("/etc/sysconfig/iptables").write_text(result.stdout)
                console.print("[green]✓[/green] Rules saved to /etc/sysconfig/iptables")