"""
SPARK Intra-Region Routing

Handles packet forwarding within a region using opportunistic routing.

Design:
- Maintains routing table of next-hop preferences
- Uses link quality for route selection
- Supports multi-path routing for reliability
- Implements flooding for unknown destinations
"""

import time
import threading
from typing import Dict, List, Optional, Tuple, Callable
from dataclasses import dataclass, field
from enum import IntEnum

from .peer import Peer, PeerManager, LinkQuality
from .region import Region, RegionManager


# Route expiry time (seconds)
ROUTE_EXPIRY = 300

# Maximum routes per destination
MAX_ROUTES_PER_DEST = 3


class RoutingDecision(IntEnum):
    """Routing decision for a packet."""
    FORWARD = 1      # Forward to next hop
    DELIVER = 2      # Deliver locally
    DROP = 3         # Drop packet
    FLOOD = 4        # Flood to all neighbors


@dataclass
class RouteEntry:
    """
    Entry in the routing table.
    """
    # Destination
    dest_node_id: bytes       # 16 bytes
    dest_region_id: bytes     # 16 bytes
    
    # Next hop
    next_hop_id: bytes        # 16 bytes
    
    # Metrics
    hop_count: int = 1
    quality_score: float = 0.0
    
    # Timestamps
    created_at: float = field(default_factory=time.time)
    last_used: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    
    @property
    def is_expired(self) -> bool:
        """Check if route has expired."""
        return time.time() - self.updated_at > ROUTE_EXPIRY
    
    @property
    def age(self) -> float:
        """Route age in seconds."""
        return time.time() - self.created_at


class Router:
    """
    Intra-region packet router.
    
    Handles routing decisions for packets within a region.
    Uses a combination of:
    - Explicit routes (learned from traffic)
    - Link quality (from peer manager)
    - Flooding (for unknown destinations)
    
    Usage:
        router = Router(peer_manager, region_manager, my_node_id)
        
        # Make routing decision
        decision, next_hops = router.route_packet(dest_node_id, dest_region_id)
        
        if decision == RoutingDecision.FORWARD:
            for next_hop in next_hops:
                forward_to(next_hop, packet)
        elif decision == RoutingDecision.DELIVER:
            deliver_locally(packet)
        elif decision == RoutingDecision.FLOOD:
            for peer in router.get_flood_targets():
                forward_to(peer, packet)
    """
    
    def __init__(
        self,
        peer_manager: PeerManager,
        region_manager: RegionManager,
        local_node_id: bytes,
    ):
        """
        Initialize router.
        
        Args:
            peer_manager: Peer manager for link info
            region_manager: Region manager for region info
            local_node_id: Our node ID
        """
        self._peer_manager = peer_manager
        self._region_manager = region_manager
        self._local_node_id = local_node_id
        
        # Routing table: dest_node_id -> list of RouteEntry
        self._routes: Dict[bytes, List[RouteEntry]] = {}
        
        self._lock = threading.RLock()
    
    def route_packet(
        self,
        dest_node_id: bytes,
        dest_region_id: Optional[bytes] = None,
        exclude_nodes: Optional[List[bytes]] = None,
    ) -> Tuple[RoutingDecision, List[Peer]]:
        """
        Make routing decision for a packet.
        
        Args:
            dest_node_id: Destination node ID
            dest_region_id: Destination region ID (optional)
            exclude_nodes: Nodes to exclude from routing
            
        Returns:
            Tuple of (decision, list of next-hop peers)
        """
        exclude = set(exclude_nodes or [])
        
        # Check if destination is us
        if dest_node_id == self._local_node_id:
            return (RoutingDecision.DELIVER, [])
        
        # Check if destination is a direct peer
        peer = self._peer_manager.get_peer(dest_node_id)
        if peer and peer.is_reachable and peer.node_id not in exclude:
            return (RoutingDecision.FORWARD, [peer])
        
        # Check routing table
        with self._lock:
            if dest_node_id in self._routes:
                routes = self._routes[dest_node_id]
                # Filter out expired routes and excluded nodes
                valid_routes = [
                    r for r in routes
                    if not r.is_expired and r.next_hop_id not in exclude
                ]
                
                if valid_routes:
                    # Get peers for valid routes
                    next_hops = []
                    for route in sorted(valid_routes, key=lambda r: -r.quality_score):
                        peer = self._peer_manager.get_peer(route.next_hop_id)
                        if peer and peer.is_reachable:
                            next_hops.append(peer)
                            route.last_used = time.time()
                    
                    if next_hops:
                        return (RoutingDecision.FORWARD, next_hops[:MAX_ROUTES_PER_DEST])
        
        # Check if destination is in a known region
        if dest_region_id:
            gateway = self._region_manager.get_gateway_for_region(dest_region_id)
            if gateway and gateway.node_id not in exclude:
                return (RoutingDecision.FORWARD, [gateway])
        
        # No route found - flood to all reachable peers
        flood_targets = self._get_flood_targets(exclude)
        if flood_targets:
            return (RoutingDecision.FLOOD, flood_targets)
        
        # No way to forward
        return (RoutingDecision.DROP, [])
    
    def _get_flood_targets(self, exclude: set) -> List[Peer]:
        """Get peers to flood packet to."""
        peers = self._peer_manager.get_reachable_peers()
        return [p for p in peers if p.node_id not in exclude]
    
    def add_route(
        self,
        dest_node_id: bytes,
        dest_region_id: bytes,
        next_hop_id: bytes,
        hop_count: int = 1,
    ) -> None:
        """
        Add or update a route.
        
        Args:
            dest_node_id: Destination node ID
            dest_region_id: Destination region ID
            next_hop_id: Next hop node ID
            hop_count: Number of hops to destination
        """
        # Get link quality for next hop
        peer = self._peer_manager.get_peer(next_hop_id)
        quality = peer.link_quality.quality_score if peer else 0.0
        
        with self._lock:
            if dest_node_id not in self._routes:
                self._routes[dest_node_id] = []
            
            routes = self._routes[dest_node_id]
            
            # Check if route via this next hop exists
            for route in routes:
                if route.next_hop_id == next_hop_id:
                    # Update existing route
                    route.hop_count = hop_count
                    route.quality_score = quality
                    route.updated_at = time.time()
                    return
            
            # Add new route
            route = RouteEntry(
                dest_node_id=dest_node_id,
                dest_region_id=dest_region_id,
                next_hop_id=next_hop_id,
                hop_count=hop_count,
                quality_score=quality,
            )
            routes.append(route)
            
            # Prune excess routes
            if len(routes) > MAX_ROUTES_PER_DEST:
                # Keep best routes
                routes.sort(key=lambda r: -r.quality_score)
                self._routes[dest_node_id] = routes[:MAX_ROUTES_PER_DEST]
    
    def remove_route(self, dest_node_id: bytes, next_hop_id: bytes) -> bool:
        """
        Remove a specific route.
        
        Args:
            dest_node_id: Destination node ID
            next_hop_id: Next hop to remove
            
        Returns:
            True if route was removed
        """
        with self._lock:
            if dest_node_id not in self._routes:
                return False
            
            routes = self._routes[dest_node_id]
            original_len = len(routes)
            
            self._routes[dest_node_id] = [
                r for r in routes if r.next_hop_id != next_hop_id
            ]
            
            # Clean up empty entries
            if not self._routes[dest_node_id]:
                del self._routes[dest_node_id]
            
            return len(self._routes.get(dest_node_id, [])) < original_len
    
    def invalidate_routes_via(self, node_id: bytes) -> int:
        """
        Invalidate all routes using a node as next hop.
        
        Called when a node becomes unreachable.
        
        Args:
            node_id: Node to invalidate routes through
            
        Returns:
            Number of routes invalidated
        """
        count = 0
        
        with self._lock:
            for dest_id in list(self._routes.keys()):
                routes = self._routes[dest_id]
                original_len = len(routes)
                
                self._routes[dest_id] = [
                    r for r in routes if r.next_hop_id != node_id
                ]
                
                count += original_len - len(self._routes[dest_id])
                
                if not self._routes[dest_id]:
                    del self._routes[dest_id]
        
        return count
    
    def cleanup_expired(self) -> int:
        """
        Remove expired routes.
        
        Returns:
            Number of routes removed
        """
        count = 0
        
        with self._lock:
            for dest_id in list(self._routes.keys()):
                routes = self._routes[dest_id]
                original_len = len(routes)
                
                self._routes[dest_id] = [r for r in routes if not r.is_expired]
                
                count += original_len - len(self._routes[dest_id])
                
                if not self._routes[dest_id]:
                    del self._routes[dest_id]
        
        return count
    
    def get_routes(self, dest_node_id: bytes) -> List[RouteEntry]:
        """Get all routes to a destination."""
        with self._lock:
            routes = self._routes.get(dest_node_id, [])
            return [r for r in routes if not r.is_expired]
    
    def get_all_routes(self) -> Dict[bytes, List[RouteEntry]]:
        """Get all routes."""
        with self._lock:
            return {
                dest: [r for r in routes if not r.is_expired]
                for dest, routes in self._routes.items()
            }
    
    def get_route_count(self) -> int:
        """Get total number of active routes."""
        with self._lock:
            return sum(
                len([r for r in routes if not r.is_expired])
                for routes in self._routes.values()
            )
    
    def learn_from_packet(
        self,
        source_node_id: bytes,
        source_region_id: bytes,
        received_from: bytes,
        hop_count: int,
    ) -> None:
        """
        Learn routing information from a received packet.
        
        Called when we receive a packet to learn about the source.
        
        Args:
            source_node_id: Original sender's node ID
            source_region_id: Original sender's region ID
            received_from: Node we received packet from
            hop_count: Number of hops packet has traveled
        """
        if source_node_id == self._local_node_id:
            return  # Don't add route to ourselves
        
        self.add_route(
            dest_node_id=source_node_id,
            dest_region_id=source_region_id,
            next_hop_id=received_from,
            hop_count=hop_count,
        )
    
    def get_stats(self) -> dict:
        """Get router statistics."""
        with self._lock:
            total_routes = 0
            total_destinations = len(self._routes)
            
            for routes in self._routes.values():
                total_routes += len([r for r in routes if not r.is_expired])
            
            return {
                "total_destinations": total_destinations,
                "total_routes": total_routes,
                "avg_routes_per_dest": (
                    total_routes / total_destinations if total_destinations > 0 else 0
                ),
            }
