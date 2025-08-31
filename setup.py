#!/usr/bin/env python3
"""Setup script for WireGuard Manager."""

from setuptools import setup, find_packages
from pathlib import Path

# Read the VERSION file
version_file = Path(__file__).parent / "VERSION"
if version_file.exists():
    version = version_file.read_text().strip()
else:
    version = "2.0.0"

# Read the README file
readme_file = Path(__file__).parent / "README.md"
if readme_file.exists():
    long_description = readme_file.read_text()
else:
    long_description = "WireGuard Manager - A modern VPN management tool"

setup(
    name="wireguard-manager",
    version=version,
    author="Regix",
    author_email="",
    description="A comprehensive WireGuard VPN management tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/regix1/wireguard-manager",
    packages=["src"],
    package_dir={"src": "src"},
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Environment :: Console",
        "Intended Audience :: System Administrators",
        "Topic :: System :: Networking",
    ],
    python_requires=">=3.6",
    install_requires=[
        "rich>=13.7.0",
        "jinja2>=3.1.2",
        "pyyaml>=6.0",
        "psutil>=5.9.0",
        "requests>=2.31.0",
        "qrcode[pil]>=7.4.2",
    ],
    entry_points={
        "console_scripts": [
            "wg-manager=src.cli:main",
            "wireguard-manager=src.cli:main",
        ],
    },
    include_package_data=True,
    package_data={
        "src": ["../data/templates/*.j2", "../data/*.json"],
    },
)