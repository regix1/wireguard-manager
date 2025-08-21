"""Firewall rule data model."""

from dataclasses import dataclass
from typing import Optional

@dataclass
class FirewallRule:
    """Firewall rule configuration."""
    
    type: str  # 'port_forward', 'nat', 'filter', 'custom'
    comment: str = ""
    command: str = ""
    
    # Port forwarding specific
    protocol: str = "tcp"  # tcp, udp, both
    ports: str = ""  # e.g., "80,443" or "8000:8100"
    destination: str = ""
    interface: str = "eno1"
    
    # NAT specific
    source_network: str = ""
    nat_type: str = "MASQUERADE"  # MASQUERADE, SNAT
    snat_ip: str = ""
    
    # Filter specific
    chain: str = "INPUT"  # INPUT, FORWARD, OUTPUT
    action: str = "ACCEPT"  # ACCEPT, DROP, REJECT
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            'type': self.type,
            'comment': self.comment,
            'command': self.command,
            'protocol': self.protocol,
            'ports': self.ports,
            'destination': self.destination,
            'interface': self.interface,
            'source_network': self.source_network,
            'nat_type': self.nat_type,
            'snat_ip': self.snat_ip,
            'chain': self.chain,
            'action': self.action
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> 'FirewallRule':
        """Create from dictionary."""
        return cls(**data)
    
    def to_iptables(self) -> str:
        """Convert to iptables command."""
        if self.type == 'custom':
            return self.command
        
        elif self.type == 'port_forward':
            cmds = []
            # PREROUTING rule
            cmd = f"iptables -t nat -A PREROUTING -i {self.interface} -p {self.protocol}"
            if ',' in self.ports or ':' in self.ports:
                cmd += f" -m multiport --dports {self.ports}"
            else:
                cmd += f" --dport {self.ports}"
            cmd += f" -j DNAT --to-destination {self.destination}"
            cmds.append(cmd)
            
            # FORWARD rule
            cmd = f"iptables -A FORWARD -p {self.protocol} -d {self.destination}"
            if ',' in self.ports or ':' in self.ports:
                cmd += f" -m multiport --dports {self.ports}"
            else:
                cmd += f" --dport {self.ports}"
            cmd += " -j ACCEPT"
            cmds.append(cmd)
            
            return '\n'.join(cmds)
        
        elif self.type == 'nat':
            cmd = f"iptables -t nat -A POSTROUTING"
            if self.source_network:
                cmd += f" -s {self.source_network}"
            cmd += f" -o {self.interface}"
            
            if self.nat_type == 'SNAT' and self.snat_ip:
                cmd += f" -j SNAT --to-source {self.snat_ip}"
            else:
                cmd += " -j MASQUERADE"
            
            return cmd
        
        elif self.type == 'filter':
            cmd = f"iptables -A {self.chain}"
            if self.interface:
                if self.chain == 'INPUT':
                    cmd += f" -i {self.interface}"
                elif self.chain == 'OUTPUT':
                    cmd += f" -o {self.interface}"
            
            if self.protocol and self.protocol != 'all':
                cmd += f" -p {self.protocol}"
            
            if self.ports:
                if ',' in self.ports or ':' in self.ports:
                    cmd += f" -m multiport --dports {self.ports}"
                else:
                    cmd += f" --dport {self.ports}"
            
            if self.source_network:
                cmd += f" -s {self.source_network}"
            
            if self.destination:
                cmd += f" -d {self.destination}"
            
            cmd += f" -j {self.action}"
            
            return cmd
        
        return ""