"""Peer data model."""

from dataclasses import dataclass, field
from typing import List, Optional
from datetime import datetime

@dataclass
class Peer:
    """WireGuard peer configuration."""
    
    name: str
    public_key: str = ""
    private_key: str = ""
    ip_address: str = ""
    endpoint: str = ""
    allowed_ips: List[str] = field(default_factory=list)
    persistent_keepalive: int = 25
    is_router: bool = False
    routed_networks: List[str] = field(default_factory=list)
    latest_handshake: Optional[datetime] = None
    transfer_rx: int = 0
    transfer_tx: int = 0
    created_at: datetime = field(default_factory=datetime.now)
    
    @property
    def keepalive(self) -> int:
        """Alias for persistent_keepalive."""
        return self.persistent_keepalive
    
    @keepalive.setter
    def keepalive(self, value: int):
        """Set persistent_keepalive."""
        self.persistent_keepalive = value
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            'name': self.name,
            'public_key': self.public_key,
            'ip_address': self.ip_address,
            'endpoint': self.endpoint,
            'allowed_ips': self.allowed_ips,
            'persistent_keepalive': self.persistent_keepalive,
            'is_router': self.is_router,
            'routed_networks': self.routed_networks,
            'latest_handshake': self.latest_handshake.isoformat() if self.latest_handshake else None,
            'transfer_rx': self.transfer_rx,
            'transfer_tx': self.transfer_tx,
            'created_at': self.created_at.isoformat()
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> 'Peer':
        """Create from dictionary."""
        peer = cls(
            name=data.get('name', 'Unknown'),
            public_key=data.get('public_key', ''),
            ip_address=data.get('ip_address', ''),
            endpoint=data.get('endpoint', ''),
            allowed_ips=data.get('allowed_ips', []),
            persistent_keepalive=data.get('persistent_keepalive', 25),
            is_router=data.get('is_router', False),
            routed_networks=data.get('routed_networks', []),
            transfer_rx=data.get('transfer_rx', 0),
            transfer_tx=data.get('transfer_tx', 0)
        )
        
        if data.get('latest_handshake'):
            peer.latest_handshake = datetime.fromisoformat(data['latest_handshake'])
        
        if data.get('created_at'):
            peer.created_at = datetime.fromisoformat(data['created_at'])
        
        return peer