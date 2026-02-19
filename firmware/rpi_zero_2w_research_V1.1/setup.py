#!/usr/bin/env python3
"""
SPARK Mesh Router - Setup Script

For development installation:
    pip install -e .

For production, use install.sh instead.
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read version from package
version = "0.1.0"

# Read README
readme_path = Path(__file__).parent / "README.md"
long_description = readme_path.read_text() if readme_path.exists() else ""

setup(
    name="spark-mesh",
    version=version,
    description="Decentralized privacy-first mesh router firmware",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="SPARK Project",
    url="https://github.com/spark-mesh/spark",
    license="Open Source",
    
    packages=find_packages(),
    python_requires=">=3.9",
    
    install_requires=[
        "cryptography>=3.4",
    ],
    
    extras_require={
        "dev": [
            "pytest>=7.0",
            "pytest-cov>=3.0",
            "black>=22.0",
            "mypy>=0.9",
        ],
        "toml": [
            "toml>=0.10",
        ],
        "hardware": [
            "spidev>=3.5",
        ],
    },
    
    entry_points={
        "console_scripts": [
            "sparkd=sparkd.main:main",
            "meshctl=meshctl.main:main",
        ],
    },
    
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Communications",
        "Topic :: Internet",
        "Topic :: Security :: Cryptography",
        "Topic :: System :: Networking",
    ],
    
    keywords="mesh networking lora privacy encryption decentralized",
)
