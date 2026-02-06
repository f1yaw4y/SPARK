"""
SPARK Region Management

Handles region grouping for onion routing.

Regions are groups of sub-meshes that form logical layers
for onion routing:
- Layer 1 (Local): Our sub-mesh and nearby connected sub-meshes
- Layer 2 (Transit): Intermediate sub-meshes for mixing
- Layer 3 (Destination): Recipient's local region

Key Design Points:
- Regions are NOT globally agreed upon
- Each node has its own view of regional boundaries
- Region assignment is heuristic and probabilistic
- Gateway nodes sit at region boundaries
"""

import time
import threading
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import IntEnum

from ..crypto.primitives import blake2b_hash
from .peer import Peer, PeerManager
from .submesh import SubMesh, SubMeshManager


# Minimum sub-meshes to form a region
MIN_REGION_SIZE = 1

# Maximum hops to consider "local" region
LOCAL_REGION_HOPS = 2

# Region recalculation interval (seconds)
REGION_RECALC_INTERVAL = 120


class RegionRole(IntEnum):
    """Node's role within region topology."""
    LEAF = 1       # Local-only (no gateway capability)
    RELAY = 2      # Can forward within region
    GATEWAY = 3    # Can forward between regions


@dataclass
class Region:
    """
    Represents a logical region for onion routing.
    """
    # Identifier
    region_id: bytes  # 16 bytes
    
    # Member sub-meshes
    submesh_ids: Set[bytes] = field(default_factory=set)
    
    # Gateway nodes (can route to other regions)
    gateway_ids: Set[bytes] = field(default_factory=set)
    
    # Connected regions (regions we can reach via gateways)
    connected_regions: Set[bytes] = field(default_factory=set)
    
    # Metadata
    is_local: bool = False  # Are we in this region?
    hop_distance: int = 0   # Hops from our region (0 = local)
    
    # Timestamps
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    
    @property
    def id_hex(self) -> str:
        """Region ID as hex string."""
        return self.region_id.hex()
    
    @property
    def size(self) -> int:
        """Number of sub-meshes in region."""
        return len(self.submesh_ids)


class RegionManager:
    """
    Manages region detection and role assignment.
    
    The region manager:
    1. Groups sub-meshes into regions based on connectivity
    2. Detects gateway nodes at region boundaries
    3. Assigns roles (LEAF, RELAY, GATEWAY) to local node
    4. Tracks reachable regions for onion routing
    
    Usage:
        manager = RegionManager(peer_manager, submesh_manager, my_node_id)
        
        # Recalculate regions
        manager.recalculate()
        
        # Get our role
        role = manager.get_local_role()
        
        # Get local region
        region = manager.get_local_region()
        
        # Select transit region for onion routing
        transit = manager.select_transit_region(dest_region_id)
    """
    
    def __init__(
        self,
        peer_manager: PeerManager,
        submesh_manager: SubMeshManager,
        local_node_id: bytes,
    ):
        """
        Initialize region manager.
        
        Args:
            peer_manager: Peer manager
            submesh_manager: Sub-mesh manager
            local_node_id: Our node ID
        """
        self._peer_manager = peer_manager
        self._submesh_manager = submesh_manager
        self._local_node_id = local_node_id
        
        self._regions: Dict[bytes, Region] = {}
        self._local_region_id: Optional[bytes] = None
        self._local_role = RegionRole.LEAF
        
        self._lock = threading.RLock()
        self._last_recalc = 0.0
    
    def _compute_region_id(self, submesh_ids: Set[bytes]) -> bytes:
        """
        Compute region ID from member sub-mesh IDs.
        
        Args:
            submesh_ids: Set of sub-mesh IDs in region
            
        Returns:
            16-byte region ID
        """
        sorted_ids = sorted(submesh_ids)
        data = b"".join(sorted_ids)
        return blake2b_hash(data, digest_size=16, person=b"spark-region")
    
    def _detect_gateways(self) -> Set[bytes]:
        """
        Detect nodes that can act as gateways.
        
        A gateway is a node that:
        - Has connections to multiple sub-meshes
        - Or has connections to nodes in different regions
        
        Returns:
            Set of gateway node IDs
        """
        gateways = set()
        
        # Get peers advertising gateway capability
        for peer in self._peer_manager.get_gateway_peers():
            gateways.add(peer.node_id)
        
        # Check if we should be a gateway
        # (For now, any node with relay capability can be a gateway)
        local_submesh = self._submesh_manager.get_local_submesh()
        if local_submesh and local_submesh.size >= 2:
            # We have multiple peers, could be a gateway
            pass
        
        return gateways
    
    def _group_into_regions(self) -> Dict[bytes, Region]:
        """
        Group sub-meshes into regions.
        
        For the initial implementation, we use a simple approach:
        - Our sub-mesh forms the local region
        - Each remote sub-mesh we know about forms its own region
        
        A more sophisticated implementation would:
        - Group nearby sub-meshes
        - Consider connectivity patterns
        - Use gateway distribution
        
        Returns:
            Dict mapping region_id to Region
        """
        regions: Dict[bytes, Region] = {}
        
        # Get local sub-mesh
        local_submesh = self._submesh_manager.get_local_submesh()
        
        if local_submesh:
            # Local region contains our sub-mesh
            region_id = self._compute_region_id({local_submesh.submesh_id})
            regions[region_id] = Region(
                region_id=region_id,
                submesh_ids={local_submesh.submesh_id},
                is_local=True,
                hop_distance=0,
            )
        
        # Add regions for peers claiming different region IDs
        seen_regions: Set[bytes] = set()
        if local_submesh:
            seen_regions.add(local_submesh.submesh_id)
        
        for peer in self._peer_manager.get_reachable_peers():
            if peer.region_id and peer.region_id not in seen_regions:
                seen_regions.add(peer.region_id)
                
                # Create region for this peer's claimed region
                regions[peer.region_id] = Region(
                    region_id=peer.region_id,
                    submesh_ids={peer.region_id},  # Use region_id as placeholder
                    is_local=False,
                    hop_distance=1,  # Assume 1 hop for now
                )
        
        return regions
    
    def _determine_local_role(self) -> RegionRole:
        """
        Determine our role in the network.
        
        Returns:
            Our assigned role
        """
        # Check if we have gateway-worthy connectivity
        peers = self._peer_manager.get_reachable_peers()
        
        if len(peers) == 0:
            return RegionRole.LEAF
        
        # Check if we connect to multiple regions
        region_ids = set()
        for peer in peers:
            if peer.region_id:
                region_ids.add(peer.region_id)
        
        if len(region_ids) > 1:
            return RegionRole.GATEWAY
        
        # Check if we can relay
        if len(peers) >= 2:
            return RegionRole.RELAY
        
        return RegionRole.LEAF
    
    def recalculate(self, force: bool = False) -> None:
        """
        Recalculate region membership and role.
        
        Args:
            force: Force recalculation even if interval not elapsed
        """
        now = time.time()
        
        if not force and now - self._last_recalc < REGION_RECALC_INTERVAL:
            return
        
        with self._lock:
            # Ensure sub-meshes are up to date
            self._submesh_manager.recalculate(force=force)
            
            # Detect gateways
            gateways = self._detect_gateways()
            
            # Group into regions
            self._regions = self._group_into_regions()
            
            # Find local region
            for region_id, region in self._regions.items():
                if region.is_local:
                    self._local_region_id = region_id
                    region.gateway_ids = gateways
                    break
            
            # Determine our role
            self._local_role = self._determine_local_role()
            
            # Update connected regions
            self._update_region_connectivity()
            
            self._last_recalc = now
    
    def _update_region_connectivity(self) -> None:
        """Update which regions can reach which other regions."""
        local_region = self.get_local_region()
        if not local_region:
            return
        
        # Local region can reach all regions we know about
        for region_id in self._regions:
            if region_id != self._local_region_id:
                local_region.connected_regions.add(region_id)
    
    def get_local_region(self) -> Optional[Region]:
        """Get our local region."""
        with self._lock:
            if self._local_region_id:
                return self._regions.get(self._local_region_id)
            return None
    
    def get_local_region_id(self) -> Optional[bytes]:
        """Get our local region ID."""
        with self._lock:
            return self._local_region_id
    
    def get_local_role(self) -> RegionRole:
        """Get our role in the network."""
        with self._lock:
            return self._local_role
    
    def get_region(self, region_id: bytes) -> Optional[Region]:
        """Get a specific region by ID."""
        with self._lock:
            return self._regions.get(region_id)
    
    def get_all_regions(self) -> List[Region]:
        """Get all known regions."""
        with self._lock:
            return list(self._regions.values())
    
    def get_reachable_regions(self) -> List[Region]:
        """Get regions we can reach (for onion routing)."""
        with self._lock:
            local = self.get_local_region()
            if not local:
                return []
            
            return [
                r for r in self._regions.values()
                if r.region_id in local.connected_regions
            ]
    
    def select_transit_region(
        self,
        dest_region_id: bytes,
        exclude: Optional[Set[bytes]] = None,
    ) -> Optional[Region]:
        """
        Select a transit region for onion routing.
        
        The transit region provides the mixing layer between
        sender and destination.
        
        Args:
            dest_region_id: Destination region ID
            exclude: Region IDs to exclude
            
        Returns:
            Selected transit region, or None if none available
        """
        with self._lock:
            candidates = []
            exclude = exclude or set()
            
            # Add local region to exclude
            if self._local_region_id:
                exclude.add(self._local_region_id)
            exclude.add(dest_region_id)
            
            for region in self._regions.values():
                if region.region_id in exclude:
                    continue
                
                # Prefer regions with gateways
                # Prefer regions with more sub-meshes (better mixing)
                candidates.append(region)
            
            if not candidates:
                # No transit region available - might need to route directly
                return None
            
            # Sort by preference (size descending)
            candidates.sort(key=lambda r: len(r.gateway_ids), reverse=True)
            
            return candidates[0]
    
    def get_gateway_for_region(self, region_id: bytes) -> Optional[Peer]:
        """
        Get a gateway node for reaching a region.
        
        Args:
            region_id: Target region ID
            
        Returns:
            Gateway peer, or None if not reachable
        """
        with self._lock:
            # First, check if we know peers in that region
            peers = self._peer_manager.get_peers_in_region(region_id)
            if peers:
                # Return best peer by link quality
                return max(peers, key=lambda p: p.link_quality.quality_score)
            
            # Check gateway peers that might know the region
            gateways = self._peer_manager.get_gateway_peers()
            if gateways:
                return max(gateways, key=lambda p: p.link_quality.quality_score)
            
            return None
    
    def get_stats(self) -> dict:
        """Get region manager statistics."""
        with self._lock:
            local = self.get_local_region()
            
            return {
                "region_count": len(self._regions),
                "local_region_id": self._local_region_id.hex() if self._local_region_id else None,
                "local_role": self._local_role.name,
                "local_submesh_count": len(local.submesh_ids) if local else 0,
                "local_gateway_count": len(local.gateway_ids) if local else 0,
                "reachable_regions": len(self.get_reachable_regions()),
                "last_recalc": self._last_recalc,
            }
