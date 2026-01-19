"""
SPARK Network Data Structures
Defines the packet structures and network addressing
"""

import struct
from dataclasses import dataclass
from typing import Optional, List

@dataclass
class NodeAddress:
    """Network address: submesh_id (16-bit) + node_id (16-bit)"""
    submesh_id: int
    node_id: int
    
    def __eq__(self, other) -> bool:
        if not isinstance(other, NodeAddress):
            return False
        return self.submesh_id == other.submesh_id and self.node_id == other.node_id
    
    def __ne__(self, other) -> bool:
        return not self.__eq__(other)
    
    def __hash__(self) -> int:
        return hash((self.submesh_id, self.node_id))
    
    def is_broadcast(self) -> bool:
        """Check if this is a broadcast address (0xFFFF:0xFFFF)"""
        return self.submesh_id == 0xFFFF and self.node_id == 0xFFFF
    
    def to_bytes(self) -> bytes:
        """Serialize to 4 bytes: [submesh_hi, submesh_lo, node_hi, node_lo]"""
        return struct.pack('>HH', self.submesh_id, self.node_id)
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'NodeAddress':
        """Deserialize from 4 bytes"""
        if len(data) < 4:
            raise ValueError("Need at least 4 bytes for NodeAddress")
        submesh_id, node_id = struct.unpack('>HH', data[:4])
        return cls(submesh_id, node_id)
    
    def __repr__(self) -> str:
        return f"NodeAddress(submesh={self.submesh_id}, node={self.node_id})"


@dataclass
class RoutingHeader:
    """
    Routing header structure - 20 bytes total
    All fields are packed in network byte order (big-endian)
    """
    source: NodeAddress
    destination: NodeAddress
    next_hop: NodeAddress
    previous_submesh: NodeAddress
    hop_count: int
    layers_remaining: int
    submesh_crossings: int
    message_id: int
    
    # Header size: 4 (source) + 4 (dest) + 4 (next_hop) + 4 (prev_submesh) + 
    #              1 (hop_count) + 1 (layers) + 1 (crossings) + 4 (msg_id) - 1 (overlap) = 20 bytes
    HEADER_SIZE = 20
    
    def to_bytes(self) -> bytes:
        """Serialize routing header to bytes"""
        # Pack all fields in network byte order
        return (
            self.source.to_bytes() +
            self.destination.to_bytes() +
            self.next_hop.to_bytes() +
            self.previous_submesh.to_bytes() +
            struct.pack('>BBBI', 
                       self.hop_count & 0xFF,
                       self.layers_remaining & 0xFF,
                       self.submesh_crossings & 0xFF,
                       self.message_id & 0xFFFFFFFF)
        )
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'RoutingHeader':
        """Deserialize routing header from bytes"""
        if len(data) < cls.HEADER_SIZE:
            raise ValueError(f"Need at least {cls.HEADER_SIZE} bytes for RoutingHeader, got {len(data)}")
        
        source = NodeAddress.from_bytes(data[0:4])
        destination = NodeAddress.from_bytes(data[4:8])
        next_hop = NodeAddress.from_bytes(data[8:12])
        previous_submesh = NodeAddress.from_bytes(data[12:16])
        hop_count, layers_remaining, submesh_crossings, message_id = struct.unpack('>BBBI', data[16:20])
        
        return cls(
            source=source,
            destination=destination,
            next_hop=next_hop,
            previous_submesh=previous_submesh,
            hop_count=hop_count,
            layers_remaining=layers_remaining,
            submesh_crossings=submesh_crossings,
            message_id=message_id
        )
    
    def __repr__(self) -> str:
        return (f"RoutingHeader(src={self.source}, dst={self.destination}, "
                f"hop={self.hop_count}, layers={self.layers_remaining}, "
                f"msg_id={self.message_id})")


@dataclass
class MeshMessage:
    """Complete mesh message with encryption layers"""
    header: RoutingHeader
    payload: bytes
    encrypted_layers: List[bytes]
    layer_sizes: List[int]
    nonces: List[bytes]  # Each nonce: 16 bytes for CTR, 12 bytes for GCM (outermost)
    auth_tag: bytes  # 16 bytes GCM authentication tag for outermost layer
    
    def __init__(self):
        self.header: Optional[RoutingHeader] = None
        self.payload = b''
        self.encrypted_layers = []
        self.layer_sizes = []
        self.nonces = []
        self.auth_tag = b''


@dataclass
class RoutingEntry:
    """Entry in the probabilistic routing table"""
    destination: NodeAddress
    next_hop: NodeAddress
    submesh_id: int
    probability: float
    hop_distance: int
    last_seen: float  # Unix timestamp
    
    def __repr__(self) -> str:
        return (f"RoutingEntry(dst={self.destination}, via={self.next_hop}, "
                f"prob={self.probability:.2f}, hops={self.hop_distance})")
