#!/usr/bin/env python3
"""
Configuration Scanner
Scans for WireGuard configurations in common locations
"""

import glob
from pathlib import Path
from typing import List, Optional

class ConfigScanner:
    """Scan system for WireGuard configurations"""
    
    # Default paths to scan
    SCAN_PATHS = [
        "/etc/wireguard",
        "/opt/wireguard",
        "/root/wireguard",
        "/root",  # Check root directory
        "/home/*/wireguard",
        str(Path.home() / "wireguard"),
        str(Path.home())  # Check home directory
    ]
    
    def __init__(self):
        self.detected_paths = []
        self.primary_config_dir = None
        self.scan()
    
    def scan(self):
        """Scan for WireGuard configurations"""
        self.detected_paths = []
        
        for path_pattern in self.SCAN_PATHS:
            # Handle wildcards
            if "*" in path_pattern:
                for expanded_path in glob.glob(path_pattern):
                    self._check_path(Path(expanded_path))
            else:
                self._check_path(Path(path_pattern))
        
        # Set primary config directory
        if self.detected_paths:
            self.primary_config_dir = Path(self.detected_paths[0])
        else:
            self.primary_config_dir = Path("/etc/wireguard")
    
    def _check_path(self, path: Path):
        """Check if path contains WireGuard configs"""
        if not path.exists() or not path.is_dir():
            return
        
        # Look for .conf files
        conf_files = list(path.glob("*.conf"))
        
        # Also check for wg*.conf pattern in root directories
        if path.name in ["root", "home"]:
            conf_files.extend(list(path.glob("wg*.conf")))
        
        if conf_files:
            self.detected_paths.append(str(path))
    
    def get_config_dir(self) -> Path:
        """Get primary configuration directory"""
        if not self.primary_config_dir:
            self.primary_config_dir = Path("/etc/wireguard")
        return self.primary_config_dir
    
    def get_interfaces(self) -> List[str]:
        """Get list of configured interfaces"""
        interfaces = []
        config_dir = self.get_config_dir()
        
        if config_dir.exists():
            for conf_file in config_dir.glob("*.conf"):
                interfaces.append(conf_file.stem)
        
        return interfaces
    
    def get_config_file(self, interface: str) -> Optional[Path]:
        """Get config file path for an interface"""
        config_dir = self.get_config_dir()
        config_file = config_dir / f"{interface}.conf"
        
        if config_file.exists():
            return config_file
        
        # Check other detected paths
        for path in self.detected_paths:
            alt_file = Path(path) / f"{interface}.conf"
            if alt_file.exists():
                return alt_file
        
        return None