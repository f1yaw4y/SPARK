"""
SPARK Onion Layer Construction

Builds 3-layer onion packets for region-based routing.

The sender:
1. Selects three regions (local, transit, destination)
2. Selects gateway nodes for each layer boundary
3. Constructs nested encrypted envelopes (inside-out)
4. Injects packet into local mesh
"""

import time
from typing import Optional, Tuple, List
from dataclasses import dataclass

from ..crypto.onion import (
    build_onion,
    OnionPacket,
    DeliveryScope,
)
from ..crypto.primitives import generate_message_id
from ..crypto.keys import IdentityKey
from ..mesh.peer import Peer, PeerManager
from ..mesh.region import Region, RegionManager


class OnionBuildError(Exception):
    """Exception raised when onion construction fails."""
    pass


@dataclass
class OnionPath:
    """
    Selected path for onion routing.
    
    Contains the three regions and gateway nodes.
    """
    # Regions
    local_region: Region
    transit_region: Region
    dest_region: Region
    
    # Gateways (X25519 public keys)
    layer1_gateway_pubkey: bytes  # Local → Transit
    layer2_gateway_pubkey: bytes  # Transit → Destination
    layer3_gateway_pubkey: bytes  # Destination entry
    
    # Gateway peer info (for debugging/logging)
    layer1_gateway_id: bytes
    layer2_gateway_id: bytes
    layer3_gateway_id: bytes


class OnionBuilder:
    """
    Builds onion packets for sending messages.
    
    Usage:
        builder = OnionBuilder(identity, peer_manager, region_manager)
        
        # Send a message
        packet, msg_id = builder.build_message(
            recipient_id=dest_node_id,
            payload=b"Hello!",
        )
        
        # Inject into mesh
        router.forward(packet)
    """
    
    def __init__(
        self,
        identity: IdentityKey,
        peer_manager: PeerManager,
        region_manager: RegionManager,
    ):
        """
        Initialize onion builder.
        
        Args:
            identity: Our node identity
            peer_manager: Peer manager for gateway selection
            region_manager: Region manager for region selection
        """
        self._identity = identity
        self._peer_manager = peer_manager
        self._region_manager = region_manager
    
    def _select_path(
        self,
        dest_region_id: bytes,
    ) -> OnionPath:
        """
        Select the three-region path for onion routing.
        
        Args:
            dest_region_id: Destination region ID
            
        Returns:
            OnionPath with selected regions and gateways
            
        Raises:
            OnionBuildError: If path cannot be constructed
        """
        # Get local region
        local_region = self._region_manager.get_local_region()
        if not local_region:
            raise OnionBuildError("No local region - network not initialized")
        
        # Get destination region
        dest_region = self._region_manager.get_region(dest_region_id)
        if not dest_region:
            raise OnionBuildError(f"Unknown destination region: {dest_region_id.hex()}")
        
        # Select transit region
        transit_region = self._region_manager.select_transit_region(
            dest_region_id,
            exclude={local_region.region_id},
        )
        
        # If no transit region available, use destination as transit
        # (reduced anonymity but still functional)
        if not transit_region:
            transit_region = dest_region
        
        # Select gateway for Layer 1 (local → transit)
        layer1_gateway = self._select_gateway_for_region(transit_region.region_id)
        if not layer1_gateway:
            raise OnionBuildError("No gateway available for Layer 1")
        
        # Select gateway for Layer 2 (transit → destination)
        layer2_gateway = self._select_gateway_for_region(dest_region_id)
        if not layer2_gateway:
            # Fall back to Layer 1 gateway
            layer2_gateway = layer1_gateway
        
        # Select gateway for Layer 3 (destination entry)
        layer3_gateway = self._select_gateway_for_region(dest_region_id)
        if not layer3_gateway:
            layer3_gateway = layer2_gateway
        
        return OnionPath(
            local_region=local_region,
            transit_region=transit_region,
            dest_region=dest_region,
            layer1_gateway_pubkey=layer1_gateway.public_key,
            layer2_gateway_pubkey=layer2_gateway.public_key,
            layer3_gateway_pubkey=layer3_gateway.public_key,
            layer1_gateway_id=layer1_gateway.node_id,
            layer2_gateway_id=layer2_gateway.node_id,
            layer3_gateway_id=layer3_gateway.node_id,
        )
    
    def _select_gateway_for_region(self, region_id: bytes) -> Optional[Peer]:
        """Select a gateway node for reaching a region."""
        # First try to get specific gateway for region
        gateway = self._region_manager.get_gateway_for_region(region_id)
        if gateway:
            return gateway
        
        # Fall back to any gateway peer
        gateways = self._peer_manager.get_gateway_peers()
        if gateways:
            # Select best by link quality
            return max(gateways, key=lambda p: p.link_quality.quality_score)
        
        # Fall back to any reachable peer
        peers = self._peer_manager.get_reachable_peers()
        if peers:
            return max(peers, key=lambda p: p.link_quality.quality_score)
        
        return None
    
    def _get_recipient_region(self, recipient_id: bytes) -> bytes:
        """
        Determine which region a recipient is in.
        
        Args:
            recipient_id: Recipient's node ID
            
        Returns:
            Region ID
        """
        # Check if recipient is a known peer
        peer = self._peer_manager.get_peer(recipient_id)
        if peer and peer.region_id:
            return peer.region_id
        
        # Unknown recipient - use a hash-based region assignment
        # This allows routing to unknown nodes through the mesh
        from ..crypto.primitives import blake2b_hash
        return blake2b_hash(recipient_id, digest_size=16, person=b"spark-region")
    
    def build_message(
        self,
        recipient_id: bytes,
        payload: bytes,
        payload_type: int = 0,
        ttl: int = 64,
    ) -> Tuple[OnionPacket, bytes]:
        """
        Build an onion-routed message.
        
        Args:
            recipient_id: Recipient's node ID
            payload: Message payload (will be encrypted)
            payload_type: Application-defined payload type
            ttl: Time-to-live for routing
            
        Returns:
            Tuple of (OnionPacket, message_id)
            
        Raises:
            OnionBuildError: If message cannot be built
        """
        # Generate message ID
        timestamp = int(time.time())
        message_id = generate_message_id(
            self._identity.node_id,
            recipient_id,
            timestamp,
        )
        
        # Determine recipient's region
        dest_region_id = self._get_recipient_region(recipient_id)
        
        # Select path
        path = self._select_path(dest_region_id)
        
        # Build onion packet
        packet = build_onion(
            dest_node_id=recipient_id,
            message_id=message_id,
            timestamp=timestamp,
            payload_type=payload_type,
            payload=payload,
            layer3_gateway_pubkey=path.layer3_gateway_pubkey,
            layer3_region_id=path.dest_region.region_id,
            layer2_gateway_pubkey=path.layer2_gateway_pubkey,
            layer2_region_id=path.transit_region.region_id,
            layer1_gateway_pubkey=path.layer1_gateway_pubkey,
            ttl=ttl,
        )
        
        return packet, message_id
    
    def build_message_direct(
        self,
        recipient_id: bytes,
        recipient_pubkey: bytes,
        dest_region_id: bytes,
        payload: bytes,
        payload_type: int = 0,
        ttl: int = 64,
    ) -> Tuple[OnionPacket, bytes]:
        """
        Build an onion message with explicit recipient info.
        
        Used when recipient info is known (e.g., from contact list).
        
        Args:
            recipient_id: Recipient's node ID
            recipient_pubkey: Recipient's X25519 public key
            dest_region_id: Recipient's region ID
            payload: Message payload
            payload_type: Application-defined payload type
            ttl: Time-to-live
            
        Returns:
            Tuple of (OnionPacket, message_id)
        """
        timestamp = int(time.time())
        message_id = generate_message_id(
            self._identity.node_id,
            recipient_id,
            timestamp,
        )
        
        # Select path
        path = self._select_path(dest_region_id)
        
        # Build onion packet
        packet = build_onion(
            dest_node_id=recipient_id,
            message_id=message_id,
            timestamp=timestamp,
            payload_type=payload_type,
            payload=payload,
            layer3_gateway_pubkey=path.layer3_gateway_pubkey,
            layer3_region_id=path.dest_region.region_id,
            layer2_gateway_pubkey=path.layer2_gateway_pubkey,
            layer2_region_id=path.transit_region.region_id,
            layer1_gateway_pubkey=path.layer1_gateway_pubkey,
            ttl=ttl,
        )
        
        return packet, message_id
    
    def estimate_message_size(self, payload_size: int) -> int:
        """
        Estimate total onion packet size for a payload.
        
        Args:
            payload_size: Size of payload in bytes
            
        Returns:
            Estimated total packet size
        """
        from ..crypto.onion import estimate_onion_size
        return estimate_onion_size(payload_size)
