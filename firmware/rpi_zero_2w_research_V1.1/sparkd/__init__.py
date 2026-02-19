"""
SPARK Daemon - Secure Private Autonomous Routing Kernel

A decentralized, privacy-first mesh networking daemon implementing
region-based 3-layer onion routing.

This package contains:
- crypto/    : Cryptographic primitives and onion routing
- radio/     : Radio abstraction layer
- mesh/      : Mesh networking and peer discovery
- onion/     : Onion routing protocol implementation
- packet/    : Packet formats and storage
- rpc/       : IPC interface for meshctl

Copyright (c) 2026 SPARK Project
License: Open Source (see LICENSE)
"""

__version__ = "0.1.0"
__author__ = "SPARK Project"

# Core constants
PROTOCOL_VERSION = 1
NODE_ID_LENGTH = 16  # bytes
MESSAGE_ID_LENGTH = 16  # bytes
MAX_PACKET_SIZE = 255  # bytes (LoRa limit)
ONION_LAYERS = 3
