"""
SPARK Packet Module

Handles wire format definitions, packet construction/parsing,
deduplication, and persistent storage for delay-tolerant delivery.
"""

from .format import (
    PacketType,
    PacketHeader,
    Packet,
    parse_packet,
    build_packet,
    MAX_PACKET_SIZE,
)

from .dedup import (
    DeduplicationCache,
)

from .store import (
    MessageStore,
    StoredMessage,
    MessageStatus,
)

__all__ = [
    # Format
    'PacketType',
    'PacketHeader',
    'Packet',
    'parse_packet',
    'build_packet',
    'MAX_PACKET_SIZE',
    # Dedup
    'DeduplicationCache',
    # Store
    'MessageStore',
    'StoredMessage',
    'MessageStatus',
]
