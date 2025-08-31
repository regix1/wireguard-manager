#!/usr/bin/env python3
"""
WireGuard Manager - Main Entry Point
"""

import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'src'))

from main import WireGuardManager

def main():
    """Main entry point"""
    # Check for root
    if os.geteuid() != 0:
        print("This script must be run as root (use sudo)")
        sys.exit(1)
    
    # Run the manager
    manager = WireGuardManager()
    manager.run()

if __name__ == "__main__":
    main()