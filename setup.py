#!/usr/bin/env python3
"""Setup script for WireGuard Manager."""

from setuptools import setup, find_packages
from pathlib import Path

# Get the directory containing this file
here = Path(__file__).parent

# Read version
version_file = here / "VERSION"
with open(version_file, "r", encoding="utf-8") as f:
    version = f.read().strip()

# Read requirements
requirements_file = here / "requirements.txt"
with open(requirements_file, "r", encoding="utf-8") as f:
    requirements = [line.strip() for line in f if line.strip()
                    and not line.startswith("#")]
    
readme_file = here / "README.md"
try:
    with open(readme_file, "r", encoding="utf-8") as f:
        long_description = f.read()
except FileNotFoundError:
    long_description = "A modern WireGuard VPN management tool"

setup(
    name="wireguard-manager",
    version=version,
    author="Regix",
    description="A modern WireGuard VPN management tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=find_packages(),
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "wg-manager=wireguard_manager.cli:main",
        ],
    },
    include_package_data=True,
    package_data={
        "wireguard_manager": ["../data/**/*"],
    },
    python_requires=">=3.8",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
)