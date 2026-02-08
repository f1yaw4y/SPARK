"""
SPARK Onion Routing Cryptography

Implements the 3-layer region-based onion routing protocol.

Onion Structure:
    Layer 1 (outermost): Local region → Transit region
    Layer 2 (middle):    Transit region → Destination region
    Layer 3 (innermost): Final delivery to recipient

Each layer contains:
    - Ephemeral X25519 public key (32 bytes)
    - Encrypted routing info + inner envelope
    - Poly1305 authentication tag (16 bytes)

SECURITY NOTES:
- Each layer uses independent ephemeral keys
- Routing info is encrypted; intermediaries learn only next hop
- Perfect forward secrecy via ephemeral keys
"""

import struct
from typing import Optional, List, Tuple
from dataclasses import dataclass
from enum import IntEnum

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

from .primitives import (
    blake2b_hash,
    X25519_KEY_SIZE,
    POLY1305_TAG_SIZE,
)
from .keys import (
    IdentityKey,
    EphemeralKey,
    public_key_from_bytes,
)
from .envelope import (
    seal_envelope,
    open_envelope,
    EnvelopeError,
)


class OnionError(Exception):
    """Exception raised for onion routing errors."""
    pass


class LayerType(IntEnum):
    """Onion layer type identifier."""
    ROUTING = 1      # Intermediate layer with routing info
    DELIVERY = 2     # Final layer with payload


class DeliveryScope(IntEnum):
    """Delivery scope for final layer."""
    DIRECT = 1       # Deliver to specific node
    REGION = 2       # Deliver to any node in region (broadcast)
    ANYCAST = 3      # Deliver to nearest matching node


# Wire format constants
ROUTING_HEADER_SIZE = (
    1 +   # layer_type
    16 +  # next_region_id
    1 +   # scope
    1 +   # ttl
    1 +   # flags
    2     # inner_length
)  # = 22 bytes

DELIVERY_HEADER_SIZE = (
    1 +   # layer_type
    16 +  # dest_node_id
    16 +  # message_id
    8 +   # timestamp
    1 +   # payload_type
    2     # payload_length
)  # = 44 bytes


@dataclass
class RoutingInfo:
    """
    Routing information for intermediate onion layers.
    
    This is decrypted by gateway nodes to determine
    where to forward the packet.
    """
    next_region_id: bytes   # 16 bytes: target region
    scope: DeliveryScope    # How to deliver in next region
    ttl: int               # Time-to-live (hop limit)
    flags: int             # Reserved flags
    inner_envelope: bytes   # Encrypted inner layer
    
    def to_bytes(self) -> bytes:
        """Serialize routing info to bytes."""
        header = struct.pack(
            ">B16sBBBH",
            LayerType.ROUTING,
            self.next_region_id,
            self.scope,
            self.ttl,
            self.flags,
            len(self.inner_envelope),
        )
        return header + self.inner_envelope
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'RoutingInfo':
        """Deserialize routing info from bytes."""
        if len(data) < ROUTING_HEADER_SIZE:
            raise OnionError(f"Routing info too short: {len(data)} bytes")
        
        layer_type, next_region, scope, ttl, flags, inner_len = struct.unpack(
            ">B16sBBBH",
            data[:ROUTING_HEADER_SIZE]
        )
        
        if layer_type != LayerType.ROUTING:
            raise OnionError(f"Invalid layer type: {layer_type} (expected ROUTING)")
        
        inner_start = ROUTING_HEADER_SIZE
        inner_end = inner_start + inner_len
        
        if len(data) < inner_end:
            raise OnionError(f"Truncated inner envelope: expected {inner_len} bytes")
        
        return cls(
            next_region_id=next_region,
            scope=DeliveryScope(scope),
            ttl=ttl,
            flags=flags,
            inner_envelope=data[inner_start:inner_end],
        )


@dataclass
class DeliveryInfo:
    """
    Delivery information for final onion layer.
    
    This is decrypted by the recipient to obtain
    the actual message payload.
    """
    dest_node_id: bytes     # 16 bytes: recipient node ID
    message_id: bytes       # 16 bytes: unique message identifier
    timestamp: int          # Unix timestamp (8 bytes)
    payload_type: int       # Payload type identifier
    payload: bytes          # Actual message content
    
    def to_bytes(self) -> bytes:
        """Serialize delivery info to bytes."""
        header = struct.pack(
            ">B16s16sQBH",
            LayerType.DELIVERY,
            self.dest_node_id,
            self.message_id,
            self.timestamp,
            self.payload_type,
            len(self.payload),
        )
        return header + self.payload
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'DeliveryInfo':
        """Deserialize delivery info from bytes."""
        if len(data) < DELIVERY_HEADER_SIZE:
            raise OnionError(f"Delivery info too short: {len(data)} bytes")
        
        (layer_type, dest_node, msg_id, timestamp,
         payload_type, payload_len) = struct.unpack(
            ">B16s16sQBH",
            data[:DELIVERY_HEADER_SIZE]
        )
        
        if layer_type != LayerType.DELIVERY:
            raise OnionError(f"Invalid layer type: {layer_type} (expected DELIVERY)")
        
        payload_start = DELIVERY_HEADER_SIZE
        payload_end = payload_start + payload_len
        
        if len(data) < payload_end:
            raise OnionError(f"Truncated payload: expected {payload_len} bytes")
        
        return cls(
            dest_node_id=dest_node,
            message_id=msg_id,
            timestamp=timestamp,
            payload_type=payload_type,
            payload=data[payload_start:payload_end],
        )


@dataclass
class OnionLayer:
    """
    Single layer of an onion packet.
    
    Contains:
    - gateway_pubkey: X25519 public key of the gateway for this layer
    - envelope: Encrypted routing/delivery info
    """
    gateway_pubkey: bytes   # 32 bytes: gateway's X25519 public key
    envelope: bytes         # Encrypted layer contents
    
    def to_bytes(self) -> bytes:
        """Serialize layer to bytes."""
        return self.envelope  # Envelope already includes ephemeral pubkey
    
    @classmethod
    def from_bytes(cls, data: bytes, gateway_pubkey: bytes) -> 'OnionLayer':
        """Parse layer from bytes."""
        return cls(gateway_pubkey=gateway_pubkey, envelope=data)


@dataclass
class OnionPacket:
    """
    Complete 3-layer onion packet.
    
    The outermost envelope is what gets transmitted.
    Each layer is peeled by a gateway to reveal the next.
    """
    outer_envelope: bytes   # Complete wire-format packet
    
    @property
    def size(self) -> int:
        """Total packet size in bytes."""
        return len(self.outer_envelope)
    
    def to_bytes(self) -> bytes:
        """Get wire format."""
        return self.outer_envelope


def build_onion(
    # Destination
    dest_node_id: bytes,
    message_id: bytes,
    timestamp: int,
    payload_type: int,
    payload: bytes,
    # Layer 3 gateway (destination region entry)
    layer3_gateway_pubkey: bytes,
    layer3_region_id: bytes,
    # Layer 2 gateway (transit region entry)  
    layer2_gateway_pubkey: bytes,
    layer2_region_id: bytes,
    # Layer 1 gateway (local region exit)
    layer1_gateway_pubkey: bytes,
    # TTL
    ttl: int = 64,
) -> OnionPacket:
    """
    Construct a 3-layer onion packet.
    
    Construction order (inside-out):
    1. Create Layer 3 (delivery info for recipient)
    2. Wrap with Layer 2 (routing to destination region)
    3. Wrap with Layer 1 (routing to transit region)
    
    Args:
        dest_node_id: Recipient's node ID (16 bytes)
        message_id: Unique message identifier (16 bytes)
        timestamp: Unix timestamp
        payload_type: Type of payload (application-defined)
        payload: Message content
        layer3_gateway_pubkey: Gateway public key for destination region
        layer3_region_id: Destination region identifier
        layer2_gateway_pubkey: Gateway public key for transit region
        layer2_region_id: Transit region identifier
        layer1_gateway_pubkey: Gateway public key for local region exit
        ttl: Time-to-live counter
        
    Returns:
        OnionPacket: Complete onion packet ready for transmission
        
    Raises:
        OnionError: If construction fails
    """
    # Validate inputs
    if len(dest_node_id) != 16:
        raise OnionError(f"Invalid dest_node_id length: {len(dest_node_id)}")
    if len(message_id) != 16:
        raise OnionError(f"Invalid message_id length: {len(message_id)}")
    if len(layer3_gateway_pubkey) != X25519_KEY_SIZE:
        raise OnionError(f"Invalid layer3 gateway pubkey length")
    if len(layer2_gateway_pubkey) != X25519_KEY_SIZE:
        raise OnionError(f"Invalid layer2 gateway pubkey length")
    if len(layer1_gateway_pubkey) != X25519_KEY_SIZE:
        raise OnionError(f"Invalid layer1 gateway pubkey length")
    
    # ===== LAYER 3: Delivery to recipient =====
    # This is the innermost layer, encrypted for the final recipient
    delivery_info = DeliveryInfo(
        dest_node_id=dest_node_id,
        message_id=message_id,
        timestamp=timestamp,
        payload_type=payload_type,
        payload=payload,
    )
    
    layer3_plaintext = delivery_info.to_bytes()
    layer3_recipient_pub = public_key_from_bytes(layer3_gateway_pubkey)
    layer3_envelope = seal_envelope(
        plaintext=layer3_plaintext,
        recipient_public=layer3_recipient_pub,
        associated_data=b"spark-onion-layer3",
    )
    
    # ===== LAYER 2: Routing to destination region =====
    # Encrypted for the transit region gateway
    routing_info_2 = RoutingInfo(
        next_region_id=layer3_region_id,
        scope=DeliveryScope.DIRECT,
        ttl=ttl,
        flags=0,
        inner_envelope=layer3_envelope,
    )
    
    layer2_plaintext = routing_info_2.to_bytes()
    layer2_recipient_pub = public_key_from_bytes(layer2_gateway_pubkey)
    layer2_envelope = seal_envelope(
        plaintext=layer2_plaintext,
        recipient_public=layer2_recipient_pub,
        associated_data=b"spark-onion-layer2",
    )
    
    # ===== LAYER 1: Routing to transit region =====
    # Encrypted for the local region gateway
    routing_info_1 = RoutingInfo(
        next_region_id=layer2_region_id,
        scope=DeliveryScope.DIRECT,
        ttl=ttl,
        flags=0,
        inner_envelope=layer2_envelope,
    )
    
    layer1_plaintext = routing_info_1.to_bytes()
    layer1_recipient_pub = public_key_from_bytes(layer1_gateway_pubkey)
    layer1_envelope = seal_envelope(
        plaintext=layer1_plaintext,
        recipient_public=layer1_recipient_pub,
        associated_data=b"spark-onion-layer1",
    )
    
    return OnionPacket(outer_envelope=layer1_envelope)


def peel_layer(
    envelope: bytes,
    gateway_identity: IdentityKey,
    layer_number: int,
) -> Tuple[Optional[RoutingInfo], Optional[DeliveryInfo]]:
    """
    Peel one layer from an onion packet.
    
    Used by gateway nodes to process onion packets:
    - Decrypt the outer layer using gateway's private key
    - Extract routing info (next region) or delivery info (final destination)
    - Return inner envelope for forwarding or payload for delivery
    
    Args:
        envelope: Encrypted onion layer
        gateway_identity: Gateway's identity key for decryption
        layer_number: Which layer this is (1, 2, or 3) for associated data
        
    Returns:
        Tuple of (RoutingInfo, None) for intermediate layers
        Tuple of (None, DeliveryInfo) for final layer
        
    Raises:
        OnionError: If decryption or parsing fails
    """
    if layer_number not in (1, 2, 3):
        raise OnionError(f"Invalid layer number: {layer_number}")
    
    associated_data = f"spark-onion-layer{layer_number}".encode()
    
    try:
        plaintext = open_envelope(
            envelope=envelope,
            recipient_identity=gateway_identity,
            associated_data=associated_data,
        )
    except EnvelopeError as e:
        raise OnionError(f"Failed to decrypt layer {layer_number}: {e}")
    
    if len(plaintext) < 1:
        raise OnionError("Empty layer contents")
    
    # Check layer type
    layer_type = plaintext[0]
    
    if layer_type == LayerType.ROUTING:
        routing_info = RoutingInfo.from_bytes(plaintext)
        return (routing_info, None)
    
    elif layer_type == LayerType.DELIVERY:
        delivery_info = DeliveryInfo.from_bytes(plaintext)
        return (None, delivery_info)
    
    else:
        raise OnionError(f"Unknown layer type: {layer_type}")


def build_onion_2layer(
    # Destination
    dest_node_id: bytes,
    message_id: bytes,
    timestamp: int,
    payload_type: int,
    payload: bytes,
    # Layer 2 gateway (destination region entry)
    layer2_gateway_pubkey: bytes,
    layer2_region_id: bytes,
    # Layer 1 gateway (local region exit)
    layer1_gateway_pubkey: bytes,
    # TTL
    ttl: int = 64,
) -> OnionPacket:
    """
    Construct a 2-layer onion packet.
    
    Provides one relay hop of anonymity (local → destination).
    Used when payload is too large for 3 layers.
    
    Construction:
    1. Layer 2 (inner): DeliveryInfo encrypted for layer2 gateway
    2. Layer 1 (outer): RoutingInfo encrypted for layer1 gateway
    """
    # Validate
    if len(dest_node_id) != 16:
        raise OnionError(f"Invalid dest_node_id length: {len(dest_node_id)}")
    if len(message_id) != 16:
        raise OnionError(f"Invalid message_id length: {len(message_id)}")
    if len(layer2_gateway_pubkey) != X25519_KEY_SIZE:
        raise OnionError("Invalid layer2 gateway pubkey length")
    if len(layer1_gateway_pubkey) != X25519_KEY_SIZE:
        raise OnionError("Invalid layer1 gateway pubkey length")
    
    # ===== LAYER 2: Delivery to recipient =====
    delivery_info = DeliveryInfo(
        dest_node_id=dest_node_id,
        message_id=message_id,
        timestamp=timestamp,
        payload_type=payload_type,
        payload=payload,
    )
    
    layer2_plaintext = delivery_info.to_bytes()
    layer2_recipient_pub = public_key_from_bytes(layer2_gateway_pubkey)
    layer2_envelope = seal_envelope(
        plaintext=layer2_plaintext,
        recipient_public=layer2_recipient_pub,
        associated_data=b"spark-onion-layer2",
    )
    
    # ===== LAYER 1: Routing to destination region =====
    routing_info = RoutingInfo(
        next_region_id=layer2_region_id,
        scope=DeliveryScope.DIRECT,
        ttl=ttl,
        flags=0,
        inner_envelope=layer2_envelope,
    )
    
    layer1_plaintext = routing_info.to_bytes()
    layer1_recipient_pub = public_key_from_bytes(layer1_gateway_pubkey)
    layer1_envelope = seal_envelope(
        plaintext=layer1_plaintext,
        recipient_public=layer1_recipient_pub,
        associated_data=b"spark-onion-layer1",
    )
    
    return OnionPacket(outer_envelope=layer1_envelope)


def build_onion_1layer(
    # Destination
    dest_node_id: bytes,
    message_id: bytes,
    timestamp: int,
    payload_type: int,
    payload: bytes,
    # Destination gateway
    dest_gateway_pubkey: bytes,
    # TTL
    ttl: int = 64,
) -> OnionPacket:
    """
    Construct a 1-layer onion packet.
    
    No relay hops -- encrypted directly to destination gateway.
    Provides confidentiality but minimal anonymity.
    Used when payload is too large for 2 or 3 layers.
    
    Construction:
    1. DeliveryInfo encrypted for destination gateway (as layer 3)
    """
    # Validate
    if len(dest_node_id) != 16:
        raise OnionError(f"Invalid dest_node_id length: {len(dest_node_id)}")
    if len(message_id) != 16:
        raise OnionError(f"Invalid message_id length: {len(message_id)}")
    if len(dest_gateway_pubkey) != X25519_KEY_SIZE:
        raise OnionError("Invalid destination gateway pubkey length")
    
    # Single layer: delivery info encrypted as layer 3
    delivery_info = DeliveryInfo(
        dest_node_id=dest_node_id,
        message_id=message_id,
        timestamp=timestamp,
        payload_type=payload_type,
        payload=payload,
    )
    
    layer_plaintext = delivery_info.to_bytes()
    recipient_pub = public_key_from_bytes(dest_gateway_pubkey)
    layer_envelope = seal_envelope(
        plaintext=layer_plaintext,
        recipient_public=recipient_pub,
        associated_data=b"spark-onion-layer3",
    )
    
    return OnionPacket(outer_envelope=layer_envelope)


# Envelope overhead: ephemeral X25519 pubkey + Poly1305 tag
ENVELOPE_OVERHEAD = X25519_KEY_SIZE + POLY1305_TAG_SIZE  # 48 bytes


def estimate_onion_size(payload_size: int) -> int:
    """
    Estimate total onion packet size for given payload size.
    
    Useful for checking against radio MTU limits.
    
    Args:
        payload_size: Size of message payload in bytes
        
    Returns:
        int: Estimated total packet size
    """
    # Layer 3: delivery header + payload + envelope overhead
    layer3_content = DELIVERY_HEADER_SIZE + payload_size
    layer3_envelope = ENVELOPE_OVERHEAD + layer3_content
    
    # Layer 2: routing header + layer 3 envelope + envelope overhead
    layer2_content = ROUTING_HEADER_SIZE + layer3_envelope
    layer2_envelope = ENVELOPE_OVERHEAD + layer2_content
    
    # Layer 1: routing header + layer 2 envelope + envelope overhead
    layer1_content = ROUTING_HEADER_SIZE + layer2_envelope
    layer1_envelope = ENVELOPE_OVERHEAD + layer1_content
    
    return layer1_envelope


def max_onion_payload(num_layers: int, max_packet_payload: int = 245) -> int:
    """
    Calculate maximum message payload for a given number of onion layers.
    
    Args:
        num_layers: Number of onion layers (1, 2, or 3)
        max_packet_payload: Max SPARK packet payload (default 245 = 255 - 10)
        
    Returns:
        Maximum payload bytes that fit in the packet
    """
    if num_layers == 3:
        overhead = (
            3 * ENVELOPE_OVERHEAD +     # 3 x 48 = 144
            2 * ROUTING_HEADER_SIZE +   # 2 x 22 = 44
            DELIVERY_HEADER_SIZE        # 44
        )  # = 232
    elif num_layers == 2:
        overhead = (
            2 * ENVELOPE_OVERHEAD +     # 2 x 48 = 96
            1 * ROUTING_HEADER_SIZE +   # 1 x 22 = 22
            DELIVERY_HEADER_SIZE        # 44
        )  # = 162
    elif num_layers == 1:
        overhead = (
            1 * ENVELOPE_OVERHEAD +     # 1 x 48 = 48
            DELIVERY_HEADER_SIZE        # 44
        )  # = 92
    else:
        raise OnionError(f"Invalid layer count: {num_layers}")
    
    return max(0, max_packet_payload - overhead)


# Maximum payload size for LoRa (255 byte packets, 10 byte SPARK header)
MAX_SPARK_PAYLOAD = 245

MAX_PAYLOAD_3LAYER = max_onion_payload(3)   # 13 bytes
MAX_PAYLOAD_2LAYER = max_onion_payload(2)   # 83 bytes
MAX_PAYLOAD_1LAYER = max_onion_payload(1)   # 153 bytes
