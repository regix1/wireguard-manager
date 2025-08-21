#!/usr/bin/env python3
"""
Setup script for WireGuard Manager.
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README for long description
readme_file = Path(__file__).parent / "README.md"
long_description = readme_file.read_text() if readme_file.exists() else ""

setup(
    name="wireguard-manager",
    version="2.0.0",
    author="WireGuard Manager Team",
    description="A comprehensive GUI tool for managing WireGuard VPN and firewall rules",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/wireguard-manager",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "Topic :: System :: Networking",
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
        "PyQt6>=6.4.0",
        "pyyaml>=6.0",
        "qrcode[pil]>=7.4.2",
        "netifaces>=0.11.0",
        "psutil>=5.9.0",
        "cryptography>=41.0.0",
        "python-iptables>=1.0.0",
        "pyroute2>=0.7.0",
        "colorama>=0.4.6",
        "python-dateutil>=2.8.2",
    ],
    extras_require={
        "dev": [
            "black>=23.0.0",
            "pylint>=2.17.0",
            "pytest>=7.4.0",
        ]
    },
    entry_points={
        "console_scripts": [
            "wireguard-manager=run:main",
        ],
    },
    include_package_data=True,
    package_data={
        "config": ["*.yaml"],
    },
    zip_safe=False,
)