"""
SPARK Replay Protection Module
Prevents replay attacks by tracking seen messages
"""

import time
from collections import deque
from network import NodeAddress
import config


class ReplayCache:
    """Manages replay protection cache"""
    
    def __init__(self):
        """Initialize replay cache"""
        self.cache = {}  # (source, message_id) -> timestamp
        self.max_size = config.REPLAY_CACHE_SIZE
        self.ttl = config.REPLAY_TTL_SECONDS
    
    def is_replay(self, source: NodeAddress, message_id: int) -> bool:
        """
        Check if a message is a replay
        
        Args:
            source: Source node address
            message_id: Message ID
        
        Returns:
            True if this is a replay, False otherwise
        """
        key = (source.submesh_id, source.node_id, message_id)
        now = time.time()
        
        if key in self.cache:
            timestamp = self.cache[key]
            # Check if still within TTL
            if now - timestamp < self.ttl:
                return True  # Replay detected
            else:
                # Expired, remove it
                del self.cache[key]
        
        return False  # Not a replay
    
    def record_message(self, source: NodeAddress, message_id: int):
        """
        Record a message to prevent replays
        
        Args:
            source: Source node address
            message_id: Message ID
        """
        key = (source.submesh_id, source.node_id, message_id)
        now = time.time()
        
        # If cache is full, remove oldest entry
        if len(self.cache) >= self.max_size and key not in self.cache:
            # Find oldest entry
            oldest_key = min(self.cache.items(), key=lambda x: x[1])[0]
            del self.cache[oldest_key]
        
        # Record this message
        self.cache[key] = now
    
    def cleanup(self):
        """Remove expired entries from cache"""
        now = time.time()
        expired_keys = [
            key for key, timestamp in self.cache.items()
            if now - timestamp >= self.ttl
        ]
        for key in expired_keys:
            del self.cache[key]
    
    def __len__(self) -> int:
        return len(self.cache)
