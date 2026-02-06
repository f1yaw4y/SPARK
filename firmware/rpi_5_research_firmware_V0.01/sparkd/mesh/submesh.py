"""
SPARK Sub-Mesh Management

Handles sub-mesh formation and membership tracking.

Sub-meshes are local clusters of mutually reachable nodes.
They are:
- Ephemeral and dynamic
- Based on connectivity density
- May split or merge

The sub-mesh ID is derived from member node IDs, providing
a semi-stable identifier that changes when membership changes
significantly.
"""

import time
import threading
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field

from ..crypto.primitives import blake2b_hash
from .peer import Peer, PeerManager


# Minimum peers to form a sub-mesh
MIN_SUBMESH_SIZE = 2

# Connectivity density threshold for sub-mesh membership
DENSITY_THRESHOLD = 0.5

# Sub-mesh ID recalculation interval (seconds)
SUBMESH_RECALC_INTERVAL = 60


@dataclass
class SubMesh:
    """
    Represents a local sub-mesh of mutually connected nodes.
    """
    # Identifier (derived from members)
    submesh_id: bytes  # 16 bytes
    
    # Member node IDs
    members: Set[bytes] = field(default_factory=set)
    
    # Our node's membership status
    is_member: bool = False
    
    # Creation/update times
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    
    # Statistics
    density: float = 0.0  # Connectivity density (0-1)
    
    @property
    def size(self) -> int:
        """Number of members in sub-mesh."""
        return len(self.members)
    
    @property
    def id_hex(self) -> str:
        """Sub-mesh ID as hex string."""
        return self.submesh_id.hex()


class SubMeshManager:
    """
    Manages sub-mesh detection and membership.
    
    Sub-meshes are detected by analyzing the connectivity graph
    of known peers. Nodes that can all reach each other directly
    form a sub-mesh.
    
    Usage:
        manager = SubMeshManager(peer_manager, my_node_id)
        
        # Recalculate sub-meshes
        manager.recalculate()
        
        # Get our sub-mesh
        submesh = manager.get_local_submesh()
        
        # Get all known sub-meshes
        for sm in manager.get_all_submeshes():
            print(sm.id_hex, sm.size)
    """
    
    def __init__(
        self,
        peer_manager: PeerManager,
        local_node_id: bytes,
    ):
        """
        Initialize sub-mesh manager.
        
        Args:
            peer_manager: Peer manager for connectivity info
            local_node_id: Our node's ID
        """
        self._peer_manager = peer_manager
        self._local_node_id = local_node_id
        self._submeshes: Dict[bytes, SubMesh] = {}
        self._local_submesh_id: Optional[bytes] = None
        self._lock = threading.RLock()
        
        self._last_recalc = 0.0
    
    def _compute_submesh_id(self, members: Set[bytes]) -> bytes:
        """
        Compute sub-mesh ID from member node IDs.
        
        ID is deterministic for the same set of members,
        regardless of order.
        
        Args:
            members: Set of member node IDs
            
        Returns:
            16-byte sub-mesh ID
        """
        # Sort members for deterministic ordering
        sorted_members = sorted(members)
        
        # Concatenate and hash
        data = b"".join(sorted_members)
        return blake2b_hash(data, digest_size=16, person=b"spark-submesh")
    
    def _detect_clusters(self, peers: List[Peer]) -> List[Set[bytes]]:
        """
        Detect clusters of mutually connected peers.
        
        Uses a simple algorithm based on shared neighbors.
        
        Args:
            peers: List of reachable peers
            
        Returns:
            List of clusters (sets of node IDs)
        """
        if not peers:
            return []
        
        # Build adjacency information
        # For now, assume all peers we can reach are in our cluster
        # In a more sophisticated implementation, we would use
        # peer reports of their own neighbors
        
        # Start with all peers in one cluster
        cluster = {self._local_node_id}
        for peer in peers:
            cluster.add(peer.node_id)
        
        return [cluster]
    
    def _calculate_density(self, members: Set[bytes], peers: List[Peer]) -> float:
        """
        Calculate connectivity density for a set of members.
        
        Density = actual_edges / possible_edges
        
        Args:
            members: Set of member node IDs
            peers: List of peer objects
            
        Returns:
            Density value (0-1)
        """
        n = len(members)
        if n < 2:
            return 1.0
        
        possible_edges = n * (n - 1) / 2
        
        # For now, assume full connectivity among reachable peers
        # In reality, we would track which peers can reach each other
        actual_edges = possible_edges
        
        return actual_edges / possible_edges
    
    def recalculate(self, force: bool = False) -> None:
        """
        Recalculate sub-mesh membership.
        
        Args:
            force: Force recalculation even if interval not elapsed
        """
        now = time.time()
        
        if not force and now - self._last_recalc < SUBMESH_RECALC_INTERVAL:
            return
        
        with self._lock:
            # Get reachable peers
            peers = self._peer_manager.get_reachable_peers()
            
            # Detect clusters
            clusters = self._detect_clusters(peers)
            
            # Build sub-meshes
            new_submeshes: Dict[bytes, SubMesh] = {}
            local_submesh_id = None
            
            for members in clusters:
                if len(members) < MIN_SUBMESH_SIZE:
                    continue
                
                submesh_id = self._compute_submesh_id(members)
                is_local = self._local_node_id in members
                
                # Calculate density
                cluster_peers = [p for p in peers if p.node_id in members]
                density = self._calculate_density(members, cluster_peers)
                
                submesh = SubMesh(
                    submesh_id=submesh_id,
                    members=members,
                    is_member=is_local,
                    density=density,
                )
                
                new_submeshes[submesh_id] = submesh
                
                if is_local:
                    local_submesh_id = submesh_id
            
            self._submeshes = new_submeshes
            self._local_submesh_id = local_submesh_id
            self._last_recalc = now
    
    def get_local_submesh(self) -> Optional[SubMesh]:
        """Get the sub-mesh we belong to."""
        with self._lock:
            if self._local_submesh_id:
                return self._submeshes.get(self._local_submesh_id)
            return None
    
    def get_local_submesh_id(self) -> Optional[bytes]:
        """Get our sub-mesh ID."""
        with self._lock:
            return self._local_submesh_id
    
    def get_submesh(self, submesh_id: bytes) -> Optional[SubMesh]:
        """Get a specific sub-mesh by ID."""
        with self._lock:
            return self._submeshes.get(submesh_id)
    
    def get_all_submeshes(self) -> List[SubMesh]:
        """Get all known sub-meshes."""
        with self._lock:
            return list(self._submeshes.values())
    
    def get_peers_in_submesh(self, submesh_id: bytes) -> List[Peer]:
        """Get peers that belong to a specific sub-mesh."""
        with self._lock:
            submesh = self._submeshes.get(submesh_id)
            if not submesh:
                return []
            
            peers = []
            for node_id in submesh.members:
                if node_id == self._local_node_id:
                    continue
                peer = self._peer_manager.get_peer(node_id)
                if peer:
                    peers.append(peer)
            
            return peers
    
    def is_peer_in_local_submesh(self, node_id: bytes) -> bool:
        """Check if a peer is in our sub-mesh."""
        with self._lock:
            submesh = self.get_local_submesh()
            if not submesh:
                return False
            return node_id in submesh.members
    
    def get_stats(self) -> dict:
        """Get sub-mesh manager statistics."""
        with self._lock:
            local = self.get_local_submesh()
            
            return {
                "submesh_count": len(self._submeshes),
                "local_submesh_id": self._local_submesh_id.hex() if self._local_submesh_id else None,
                "local_submesh_size": local.size if local else 0,
                "local_submesh_density": local.density if local else 0,
                "last_recalc": self._last_recalc,
            }
