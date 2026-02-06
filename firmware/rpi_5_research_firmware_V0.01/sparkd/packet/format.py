"""
SPARK Packet Wire Format

Defines the structure of packets transmitted over the radio.

Packet Structure:
    Header (fixed size) + Payload (variable)

Header Format (10 bytes):
    version     (1 byte)  - Protocol version
    type        (1 byte)  - Packet type
    flags       (1 byte)  - Packet flags
    hop_count   (1 byte)  - Number of hops traversed
    ttl         (1 byte)  - Time-to-live (max remaining hops)
    payload_len (2 bytes) - Payload length (big-endian)
    checksum    (2 bytes) - CRC-16 of header fields
    reserved    (1 byte)  - Reserved for future use

Design Principles:
- Fixed header size for efficient radio parsing
- CRC for integrity checking (in addition to radio CRC)
- Minimal header to maximize payload space
- Extensible via flags and reserved fields
"""

import struct
from dataclasses import dataclass
from enum import IntEnum
from typing import Optional

from ..crypto.primitives import blake2b_hash


# Maximum packet size (LoRa constraint)
MAX_PACKET_SIZE = 255

# Header size in bytes
HEADER_SIZE = 10

# Maximum payload size
MAX_PAYLOAD_SIZE = MAX_PACKET_SIZE - HEADER_SIZE

# Current protocol version
PROTOCOL_VERSION = 1


class PacketType(IntEnum):
    """Packet type identifiers."""
    # Data packets
    ONION = 0x01          # Onion-routed message
    DIRECT = 0x02         # Direct (non-onion) message
    BROADCAST = 0x03      # Broadcast to region
    
    # Control packets
    BEACON = 0x10         # Peer discovery beacon
    PEER_REQUEST = 0x11   # Request peer information
    PEER_RESPONSE = 0x12  # Peer information response
    
    # Acknowledgments
    ACK = 0x20            # Delivery acknowledgment
    NACK = 0x21           # Negative acknowledgment
    
    # Mesh maintenance
    LINK_PROBE = 0x30     # Link quality probe
    LINK_REPORT = 0x31    # Link quality report
    REGION_ANNOUNCE = 0x32 # Region membership announcement
    
    # Debug/Test
    ECHO_REQUEST = 0xE0   # Echo request (ping)
    ECHO_REPLY = 0xE1     # Echo reply (pong)


class PacketFlags(IntEnum):
    """Packet flag bits."""
    NONE = 0x00
    URGENT = 0x01         # High priority
    RELIABLE = 0x02       # Request acknowledgment
    FRAGMENT = 0x04       # Part of fragmented message
    LAST_FRAGMENT = 0x08  # Last fragment
    ENCRYPTED = 0x10      # Payload is encrypted
    COMPRESSED = 0x20     # Payload is compressed


def _crc16(data: bytes) -> int:
    """
    Compute CRC-16-CCITT checksum.
    
    Uses polynomial 0x1021 (CRC-16-CCITT).
    """
    crc = 0xFFFF
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = (crc << 1) ^ 0x1021
            else:
                crc <<= 1
            crc &= 0xFFFF
    return crc


@dataclass
class PacketHeader:
    """
    Packet header structure.
    
    Fixed 10-byte header preceding all packets.
    """
    version: int          # Protocol version (1 byte)
    packet_type: PacketType  # Packet type (1 byte)
    flags: int            # Packet flags (1 byte)
    hop_count: int        # Hops traversed (1 byte)
    ttl: int              # Time-to-live (1 byte)
    payload_len: int      # Payload length (2 bytes)
    checksum: int         # CRC-16 (2 bytes)
    reserved: int         # Reserved (1 byte)
    
    def to_bytes(self) -> bytes:
        """Serialize header to bytes."""
        # Pack header without checksum first
        header_data = struct.pack(
            ">BBBBBHB",
            self.version,
            self.packet_type,
            self.flags,
            self.hop_count,
            self.ttl,
            self.payload_len,
            self.reserved,
        )
        
        # Compute checksum
        checksum = _crc16(header_data)
        
        # Insert checksum (bytes 7-8)
        return header_data[:7] + struct.pack(">H", checksum) + header_data[7:]
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'PacketHeader':
        """Parse header from bytes."""
        if len(data) < HEADER_SIZE:
            raise ValueError(f"Header too short: {len(data)} < {HEADER_SIZE}")
        
        # Unpack fields
        (version, packet_type, flags, hop_count, ttl,
         payload_len, checksum, reserved) = struct.unpack(
            ">BBBBBHHB",
            data[:HEADER_SIZE]
        )
        
        # Verify checksum
        header_for_crc = data[:7] + data[9:10]  # Exclude checksum bytes
        expected_crc = _crc16(header_for_crc)
        if checksum != expected_crc:
            raise ValueError(f"Header checksum mismatch: {checksum:#06x} != {expected_crc:#06x}")
        
        return cls(
            version=version,
            packet_type=PacketType(packet_type),
            flags=flags,
            hop_count=hop_count,
            ttl=ttl,
            payload_len=payload_len,
            checksum=checksum,
            reserved=reserved,
        )
    
    def validate(self) -> None:
        """Validate header fields."""
        if self.version != PROTOCOL_VERSION:
            raise ValueError(f"Unsupported protocol version: {self.version}")
        
        if self.payload_len > MAX_PAYLOAD_SIZE:
            raise ValueError(f"Payload too large: {self.payload_len} > {MAX_PAYLOAD_SIZE}")
        
        if self.ttl == 0:
            raise ValueError("TTL expired")


@dataclass
class Packet:
    """
    Complete packet with header and payload.
    """
    header: PacketHeader
    payload: bytes
    
    # Reception metadata (optional)
    rssi: Optional[int] = None
    snr: Optional[float] = None
    received_at: Optional[float] = None
    
    @property
    def packet_type(self) -> PacketType:
        """Packet type shortcut."""
        return self.header.packet_type
    
    @property
    def total_size(self) -> int:
        """Total packet size in bytes."""
        return HEADER_SIZE + len(self.payload)
    
    @property
    def is_urgent(self) -> bool:
        """Check urgent flag."""
        return bool(self.header.flags & PacketFlags.URGENT)
    
    @property
    def is_reliable(self) -> bool:
        """Check reliable flag."""
        return bool(self.header.flags & PacketFlags.RELIABLE)
    
    @property
    def is_encrypted(self) -> bool:
        """Check encrypted flag."""
        return bool(self.header.flags & PacketFlags.ENCRYPTED)
    
    def to_bytes(self) -> bytes:
        """Serialize packet to bytes."""
        return self.header.to_bytes() + self.payload
    
    @classmethod
    def from_bytes(
        cls,
        data: bytes,
        rssi: Optional[int] = None,
        snr: Optional[float] = None,
        received_at: Optional[float] = None,
    ) -> 'Packet':
        """Parse packet from bytes."""
        if len(data) < HEADER_SIZE:
            raise ValueError(f"Packet too short: {len(data)} < {HEADER_SIZE}")
        
        header = PacketHeader.from_bytes(data[:HEADER_SIZE])
        
        expected_size = HEADER_SIZE + header.payload_len
        if len(data) < expected_size:
            raise ValueError(f"Packet truncated: {len(data)} < {expected_size}")
        
        payload = data[HEADER_SIZE:expected_size]
        
        return cls(
            header=header,
            payload=payload,
            rssi=rssi,
            snr=snr,
            received_at=received_at,
        )
    
    def increment_hop(self) -> 'Packet':
        """
        Create copy with incremented hop count and decremented TTL.
        
        Returns:
            Packet: New packet for forwarding
            
        Raises:
            ValueError: If TTL would become 0
        """
        if self.header.ttl <= 1:
            raise ValueError("Cannot forward: TTL expired")
        
        new_header = PacketHeader(
            version=self.header.version,
            packet_type=self.header.packet_type,
            flags=self.header.flags,
            hop_count=self.header.hop_count + 1,
            ttl=self.header.ttl - 1,
            payload_len=self.header.payload_len,
            checksum=0,  # Will be recalculated
            reserved=self.header.reserved,
        )
        
        return Packet(header=new_header, payload=self.payload)


def build_packet(
    packet_type: PacketType,
    payload: bytes,
    flags: int = PacketFlags.NONE,
    ttl: int = 64,
) -> Packet:
    """
    Build a new packet.
    
    Args:
        packet_type: Type of packet
        payload: Packet payload
        flags: Packet flags
        ttl: Time-to-live
        
    Returns:
        Packet: Constructed packet
        
    Raises:
        ValueError: If payload too large
    """
    if len(payload) > MAX_PAYLOAD_SIZE:
        raise ValueError(f"Payload too large: {len(payload)} > {MAX_PAYLOAD_SIZE}")
    
    header = PacketHeader(
        version=PROTOCOL_VERSION,
        packet_type=packet_type,
        flags=flags,
        hop_count=0,
        ttl=ttl,
        payload_len=len(payload),
        checksum=0,  # Will be calculated in to_bytes()
        reserved=0,
    )
    
    return Packet(header=header, payload=payload)


def parse_packet(
    data: bytes,
    rssi: Optional[int] = None,
    snr: Optional[float] = None,
    received_at: Optional[float] = None,
) -> Packet:
    """
    Parse a packet from wire format.
    
    Args:
        data: Raw packet bytes
        rssi: Optional RSSI from radio
        snr: Optional SNR from radio
        received_at: Optional reception timestamp
        
    Returns:
        Packet: Parsed packet
        
    Raises:
        ValueError: If packet is invalid
    """
    return Packet.from_bytes(data, rssi, snr, received_at)


# Beacon payload format
@dataclass
class BeaconPayload:
    """
    Beacon packet payload for peer discovery.
    
    Sent periodically to announce presence.
    """
    node_id: bytes        # 16 bytes
    public_key: bytes     # 32 bytes (X25519)
    region_id: bytes      # 16 bytes
    capabilities: int     # 1 byte (bitmask)
    radio_type: int       # 1 byte
    sequence: int         # 2 bytes (rolling counter)
    
    CAPABILITIES_GATEWAY = 0x01
    CAPABILITIES_RELAY = 0x02
    CAPABILITIES_STORAGE = 0x04
    
    def to_bytes(self) -> bytes:
        """Serialize beacon payload."""
        return struct.pack(
            ">16s32s16sBBH",
            self.node_id,
            self.public_key,
            self.region_id,
            self.capabilities,
            self.radio_type,
            self.sequence,
        )
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'BeaconPayload':
        """Parse beacon payload."""
        if len(data) < 68:
            raise ValueError(f"Beacon payload too short: {len(data)}")
        
        node_id, public_key, region_id, capabilities, radio_type, sequence = struct.unpack(
            ">16s32s16sBBH",
            data[:68]
        )
        
        return cls(
            node_id=node_id,
            public_key=public_key,
            region_id=region_id,
            capabilities=capabilities,
            radio_type=radio_type,
            sequence=sequence,
        )


# ACK payload format
@dataclass
class AckPayload:
    """
    Acknowledgment packet payload.
    """
    message_id: bytes     # 16 bytes
    status: int           # 1 byte (0=success, 1+=error code)
    hop_count: int        # 1 byte (hops from destination)
    
    STATUS_SUCCESS = 0
    STATUS_UNKNOWN_DEST = 1
    STATUS_EXPIRED = 2
    STATUS_REJECTED = 3
    
    def to_bytes(self) -> bytes:
        """Serialize ACK payload."""
        return struct.pack(">16sBB", self.message_id, self.status, self.hop_count)
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'AckPayload':
        """Parse ACK payload."""
        if len(data) < 18:
            raise ValueError(f"ACK payload too short: {len(data)}")
        
        message_id, status, hop_count = struct.unpack(">16sBB", data[:18])
        return cls(message_id=message_id, status=status, hop_count=hop_count)
