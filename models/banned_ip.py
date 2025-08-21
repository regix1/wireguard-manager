"""Banned IP data model."""

from dataclasses import dataclass
from datetime import datetime

@dataclass
class BannedIP:
    """Banned IP configuration."""
    
    ip: str
    reason: str = ""
    banned_at: datetime = None
    
    def __post_init__(self):
        """Initialize banned_at if not provided."""
        if self.banned_at is None:
            self.banned_at = datetime.now()
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            'ip': self.ip,
            'reason': self.reason,
            'banned_at': self.banned_at.isoformat() if self.banned_at else None
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> 'BannedIP':
        """Create from dictionary."""
        banned_ip = cls(
            ip=data.get('ip', ''),
            reason=data.get('reason', '')
        )
        
        if data.get('banned_at'):
            banned_ip.banned_at = datetime.fromisoformat(data['banned_at'])
        
        return banned_ip
    
    def to_file_format(self) -> str:
        """Convert to file format (ip|reason)."""
        if self.reason:
            return f"{self.ip}|{self.reason}"
        return self.ip
    
    @classmethod
    def from_file_format(cls, line: str) -> 'BannedIP':
        """Create from file format."""
        if '|' in line:
            ip, reason = line.split('|', 1)
            return cls(ip=ip.strip(), reason=reason.strip())
        return cls(ip=line.strip())