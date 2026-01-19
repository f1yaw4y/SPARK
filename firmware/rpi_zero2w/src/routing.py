"""
SPARK Routing Module
Manages probabilistic routing table and pathfinding
"""

import time
from typing import Optional, List
from network import NodeAddress, RoutingEntry
import config


class RoutingTable:
    """Probabilistic routing table manager"""
    
    def __init__(self, my_address: NodeAddress):
        """
        Initialize routing table
        
        Args:
            my_address: This node's address
        """
        self.my_address = my_address
        self.entries: list[RoutingEntry] = []
        self.max_size = config.MAX_ROUTING_TABLE
        self._initialize_self_entry()
    
    def _initialize_self_entry(self):
        """Initialize routing table with self-entry"""
        self_entry = RoutingEntry(
            destination=self.my_address,
            next_hop=self.my_address,
            submesh_id=self.my_address.submesh_id,
            probability=1.0,
            hop_distance=0,
            last_seen=time.time()
        )
        self.entries.append(self_entry)
    
    def is_in_same_submesh(self, addr1: NodeAddress, addr2: NodeAddress) -> bool:
        """Check if two addresses are in the same sub-mesh"""
        return addr1.submesh_id == addr2.submesh_id
    
    def calculate_submesh_distance(self, submesh1: int, submesh2: int) -> int:
        """Calculate 'distance' between sub-meshes (absolute difference)"""
        return abs(submesh1 - submesh2)
    
    def validate_routing_update(self, from_addr: NodeAddress, claimed_hops: int) -> bool:
        """
        Validate a routing update before accepting it
        
        Args:
            from_addr: Address of node sending the update
            claimed_hops: Hop count claimed by the update
        
        Returns:
            True if update is valid, False otherwise
        """
        # Sanity check
        if claimed_hops > config.MAX_HOP_COUNT:
            return False
        
        # Check if we already have a route to this node
        existing = self.find_entry(from_addr)
        if existing:
            # Only accept if new hop count is reasonable (within 3 hops of existing)
            if claimed_hops > existing.hop_distance + 3:
                return False  # Suspiciously high hop count
        
        return True
    
    def find_entry(self, destination: NodeAddress) -> Optional[RoutingEntry]:
        """Find routing entry for a destination"""
        for entry in self.entries:
            if entry.destination == destination:
                return entry
        return None
    
    def find_next_hop(self, destination: NodeAddress) -> NodeAddress:
        """
        Find the best next hop for a destination using probabilistic routing
        
        Args:
            destination: Target destination address
        
        Returns:
            Next hop address (or broadcast address if no route found)
        """
        best_hop = NodeAddress(0, 0)
        best_score = 0.0
        
        # Check if destination is in same sub-mesh
        if self.is_in_same_submesh(self.my_address, destination):
            # Direct routing within sub-mesh
            for entry in self.entries:
                if self.is_in_same_submesh(entry.destination, destination):
                    if entry.probability > best_score:
                        best_score = entry.probability
                        best_hop = entry.next_hop
        else:
            # Cross-submesh routing: prefer nodes closer to destination sub-mesh
            dest_submesh = destination.submesh_id
            my_submesh = self.my_address.submesh_id
            
            for entry in self.entries:
                hop_submesh = entry.submesh_id
                my_to_hop = self.calculate_submesh_distance(my_submesh, hop_submesh)
                hop_to_dest = self.calculate_submesh_distance(hop_submesh, dest_submesh)
                my_to_dest = self.calculate_submesh_distance(my_submesh, dest_submesh)
                
                # Score based on progress toward destination and probability
                if my_to_dest > 0:
                    progress = (my_to_dest - hop_to_dest) / my_to_dest
                else:
                    progress = 0.0
                
                score = entry.probability * (0.5 + 0.5 * progress)
                
                if score > best_score and hop_to_dest < my_to_dest:
                    best_score = score
                    best_hop = entry.next_hop
        
        # If no route found, use broadcast or default route
        if best_hop.submesh_id == 0 and best_hop.node_id == 0:
            # Only broadcast if we have no route and destination is not local
            if not self.is_in_same_submesh(self.my_address, destination):
                best_hop = NodeAddress(0xFFFF, 0xFFFF)  # Broadcast address
            # Otherwise, destination in same sub-mesh but no route - will drop
        
        return best_hop
    
    def update_routing_table(self, from_addr: NodeAddress, via: NodeAddress, hops: int):
        """
        Update or add routing entry
        
        Args:
            from_addr: Address we learned about
            via: Next hop to reach from_addr
            hops: Hop distance to from_addr
        """
        # Validate routing update
        if not self.validate_routing_update(from_addr, hops):
            return
        
        # Find existing entry
        existing = self.find_entry(from_addr)
        now = time.time()
        
        if existing:
            # Update existing entry
            if hops < existing.hop_distance or (now - existing.last_seen) > 60:
                existing.next_hop = via
                existing.hop_distance = hops
                # Calculate probability with bounds
                new_prob = max(config.MIN_PROBABILITY, 
                             min(config.MAX_PROBABILITY, 1.0 - (hops * 0.01)))
                existing.probability = new_prob
            else:
                # Slightly increase probability for known good routes
                existing.probability = min(config.MAX_PROBABILITY, 
                                         existing.probability + 0.05)
            existing.last_seen = now
            existing.submesh_id = from_addr.submesh_id
        elif len(self.entries) < self.max_size:
            # Add new entry
            new_prob = max(config.MIN_PROBABILITY, 
                         min(config.MAX_PROBABILITY, 1.0 - (hops * 0.01)))
            new_entry = RoutingEntry(
                destination=from_addr,
                next_hop=via,
                submesh_id=from_addr.submesh_id,
                probability=new_prob,
                hop_distance=hops,
                last_seen=now
            )
            self.entries.append(new_entry)
    
    def decay(self):
        """Decay probabilities and remove stale entries"""
        now = time.time()
        entries_to_remove = []
        
        for i, entry in enumerate(self.entries):
            # Skip self-entry
            if entry.destination == self.my_address:
                continue
            
            # Decay probability
            entry.probability *= config.ROUTING_DECAY_RATE
            
            # Enforce bounds
            if entry.probability < config.MIN_PROBABILITY:
                entry.probability = config.MIN_PROBABILITY
            if entry.probability > config.MAX_PROBABILITY:
                entry.probability = config.MAX_PROBABILITY
            
            # Remove very stale entries
            if (now - entry.last_seen) > config.ROUTING_STALE_TIMEOUT_SECONDS:
                entries_to_remove.append(i)
        
        # Remove stale entries (in reverse order to maintain indices)
        for i in reversed(entries_to_remove):
            self.entries.pop(i)
    
    def get_all_entries(self) -> List[RoutingEntry]:
        """Get all routing entries"""
        return self.entries.copy()
