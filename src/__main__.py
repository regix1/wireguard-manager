#!/usr/bin/env python3
"""Entry point for the wireguard-manager application."""

import sys
from .cli import main

if __name__ == "__main__":
    sys.exit(main())