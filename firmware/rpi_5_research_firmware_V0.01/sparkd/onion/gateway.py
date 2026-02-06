"""
SPARK Gateway Processing

Handles onion layer peeling at region boundaries.

Gateway nodes:
1. Receive onion packets at region boundaries
2. Decrypt their layer to reveal routing info
3. Forward the inner envelope to the next region
"""

import time
from typing import Optional, Tuple
from dataclasses import dataclass
from enum import IntEnum

from ..crypto.onion import (
    peel_layer,
    RoutingInfo,
    DeliveryInfo,
    OnionError,
)
from ..crypto.keys import IdentityKey
from ..mesh.region import RegionManager


class ProcessingResult(IntEnum):
    """Result of gateway processing."""
    FORWARD = 1          # Forward to next region
    DELIVER_LOCAL = 2    # Deliver locally (we are recipient)
    DELIVER_REGION = 3   # Deliver within our region
    DROP_EXPIRED = 4     # Drop: TTL expired
    DROP_DECRYPT = 5     # Drop: Decryption failed
    DROP_INVALID = 6     # Drop: Invalid format


@dataclass
class ProcessedPacket:
    """
    Result of processing an onion layer.
    """
    # Processing result
    result: ProcessingResult
    
    # For FORWARD: routing info and inner envelope
    next_region_id: Optional[bytes] = None
    inner_envelope: Optional[bytes] = None
    ttl: int = 0
    
    # For DELIVER_*: delivery info
    dest_node_id: Optional[bytes] = None
    message_id: Optional[bytes] = None
    payload: Optional[bytes] = None
    payload_type: int = 0
    timestamp: int = 0
    
    # Error info
    error_message: Optional[str] = None


class GatewayProcessor:
    """
    Processes onion packets at gateway nodes.
    
    Called when:
    1. We receive a packet destined for another region
    2. We are the entry point for our region
    
    Usage:
        processor = GatewayProcessor(identity, region_manager)
        
        # Process incoming onion packet
        result = processor.process(envelope, layer_number)
        
        if result.result == ProcessingResult.FORWARD:
            forward_to_region(result.next_region_id, result.inner_envelope)
        elif result.result == ProcessingResult.DELIVER_LOCAL:
            deliver_message(result.payload)
    """
    
    def __init__(
        self,
        identity: IdentityKey,
        region_manager: RegionManager,
    ):
        """
        Initialize gateway processor.
        
        Args:
            identity: Our node identity (for decryption)
            region_manager: Region manager
        """
        self._identity = identity
        self._region_manager = region_manager
    
    def process(
        self,
        envelope: bytes,
        layer_number: int,
    ) -> ProcessedPacket:
        """
        Process an onion layer.
        
        Args:
            envelope: Encrypted onion envelope
            layer_number: Which layer this is (1, 2, or 3)
            
        Returns:
            ProcessedPacket with result and relevant data
        """
        # Try to peel the layer
        try:
            routing_info, delivery_info = peel_layer(
                envelope=envelope,
                gateway_identity=self._identity,
                layer_number=layer_number,
            )
        except OnionError as e:
            return ProcessedPacket(
                result=ProcessingResult.DROP_DECRYPT,
                error_message=str(e),
            )
        except Exception as e:
            return ProcessedPacket(
                result=ProcessingResult.DROP_INVALID,
                error_message=str(e),
            )
        
        # Handle routing layer (intermediate)
        if routing_info is not None:
            # Check TTL
            if routing_info.ttl <= 0:
                return ProcessedPacket(
                    result=ProcessingResult.DROP_EXPIRED,
                    error_message="TTL expired",
                )
            
            # Determine if we should forward or deliver within region
            local_region = self._region_manager.get_local_region()
            
            if local_region and routing_info.next_region_id == local_region.region_id:
                # Next region is our region - this shouldn't happen
                # at a gateway (indicates routing error)
                pass
            
            return ProcessedPacket(
                result=ProcessingResult.FORWARD,
                next_region_id=routing_info.next_region_id,
                inner_envelope=routing_info.inner_envelope,
                ttl=routing_info.ttl - 1,
            )
        
        # Handle delivery layer (final)
        if delivery_info is not None:
            # Check if we are the recipient
            if delivery_info.dest_node_id == self._identity.node_id:
                return ProcessedPacket(
                    result=ProcessingResult.DELIVER_LOCAL,
                    dest_node_id=delivery_info.dest_node_id,
                    message_id=delivery_info.message_id,
                    payload=delivery_info.payload,
                    payload_type=delivery_info.payload_type,
                    timestamp=delivery_info.timestamp,
                )
            
            # Need to deliver to someone else in our region
            return ProcessedPacket(
                result=ProcessingResult.DELIVER_REGION,
                dest_node_id=delivery_info.dest_node_id,
                message_id=delivery_info.message_id,
                payload=delivery_info.payload,
                payload_type=delivery_info.payload_type,
                timestamp=delivery_info.timestamp,
            )
        
        # Should not reach here
        return ProcessedPacket(
            result=ProcessingResult.DROP_INVALID,
            error_message="No routing or delivery info",
        )
    
    def can_process_layer(self, layer_number: int) -> bool:
        """
        Check if we can process a specific layer.
        
        We can only process layers if we are a gateway.
        
        Args:
            layer_number: Layer number (1, 2, or 3)
            
        Returns:
            True if we can process this layer
        """
        from ..mesh.region import RegionRole
        
        role = self._region_manager.get_local_role()
        
        # Gateways can process any layer
        if role == RegionRole.GATEWAY:
            return True
        
        # Relays can process layer 3 (final delivery in region)
        if role == RegionRole.RELAY and layer_number == 3:
            return True
        
        # Leaf nodes can only receive (layer 3, if we're recipient)
        if role == RegionRole.LEAF and layer_number == 3:
            return True
        
        return False


class LayerDetector:
    """
    Detects which onion layer a packet is at.
    
    This is done by attempting to decrypt with our key
    and checking the layer type.
    """
    
    def __init__(self, identity: IdentityKey):
        """Initialize detector with our identity."""
        self._identity = identity
    
    def detect_layer(self, envelope: bytes) -> Optional[int]:
        """
        Try to detect which layer this envelope is for us.
        
        Tries each layer number and returns the one that decrypts.
        
        Args:
            envelope: Onion envelope
            
        Returns:
            Layer number (1, 2, or 3) if we can decrypt, None otherwise
        """
        for layer in (1, 2, 3):
            try:
                peel_layer(envelope, self._identity, layer)
                return layer
            except OnionError:
                continue
            except Exception:
                continue
        
        return None
