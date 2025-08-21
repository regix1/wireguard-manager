#!/usr/bin/env python3
"""
Setup script for WireGuard Manager TUI.
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read version
VERSION = "2.0.0"

# Read README for long description
readme_file = Path(__file__).parent / "README.md"
long_description = readme_file.read_text() if readme_file.exists() else ""

setup(
    name="wireguard-manager-tui",
    version=VERSION,
    author="WireGuard Manager Team",
    description="A beautiful terminal UI for managing WireGuard VPN and firewall rules",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/regix1/wireguard-manager",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: System Administrators",
        "Topic :: System :: Networking",
        "Topic :: System :: Systems Administration",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: POSIX :: Linux",
    ],
    python_requires=">=3.8",
    install_requires=[
        "rich>=13.7.0",
        "textual>=0.47.0",
        "pyyaml>=6.0",
        "qrcode[pil]>=7.4.2",
        "netifaces>=0.11.0",
        "psutil>=5.9.0",
        "cryptography>=41.0.0",
        "requests>=2.31.0",
        "python-iptables>=1.0.0",
        "pyroute2>=0.7.0",
        "colorama>=0.4.6",
        "python-dateutil>=2.8.2",
        "click>=8.1.0",
        "tabulate>=0.9.0",
    ],
    extras_require={
        "dev": [
            "black>=23.0.0",
            "pylint>=2.17.0",
            "pytest>=7.4.0",
            "flake8>=6.0.0",
        ]
    },
    entry_points={
        "console_scripts": [
            "wg-manager=run:main",
            "wireguard-manager=run:main",
            "wgm=run:main",
        ],
    },
    include_package_data=True,
    package_data={
        "config": ["*.yaml", "*.json"],
        "tui": ["*.py"],
    },
    zip_safe=False,
    scripts=["install.sh", "uninstall.sh"],
)