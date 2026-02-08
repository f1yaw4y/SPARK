"""
SPARK Packet Deduplication

Prevents processing of duplicate packets in the mesh network.

Features:
- Time-bounded cache (configurable TTL)
- Memory-efficient storage
- Thread-safe operations
- Automatic cleanup

Design:
- Uses packet hash as key
- Stores timestamp of first seen
- Evicts entries older than TTL
"""

import time
import threading
from typing import Dict, Optional, Set
from dataclasses import dataclass

from ..crypto.primitives import blake2b_hash


# Default cache TTL in seconds
DEFAULT_CACHE_TTL = 300  # 5 minutes

# Default maximum cache size
DEFAULT_MAX_ENTRIES = 10000

# Cleanup interval in seconds
CLEANUP_INTERVAL = 60


@dataclass
class CacheEntry:
    """Entry in the deduplication cache."""
    packet_hash: bytes
    first_seen: float
    last_seen: float
    count: int  # Number of times seen


class DeduplicationCache:
    """
    Time-bounded deduplication cache for packets.
    
    Usage:
        cache = DeduplicationCache(ttl_seconds=300)
        
        # Check and add packet
        packet_data = b"..."
        if cache.check_and_add(packet_data):
            # Duplicate - already seen
            pass
        else:
            # New packet - process it
            process(packet_data)
    """
    
    def __init__(
        self,
        ttl_seconds: int = DEFAULT_CACHE_TTL,
        max_entries: int = DEFAULT_MAX_ENTRIES,
    ):
        """
        Initialize deduplication cache.
        
        Args:
            ttl_seconds: Time-to-live for cache entries
            max_entries: Maximum number of entries before forced eviction
        """
        self._ttl = ttl_seconds
        self._max_entries = max_entries
        
        # Cache storage: hash -> CacheEntry
        self._cache: Dict[bytes, CacheEntry] = {}
        
        # Lock for thread safety
        self._lock = threading.RLock()
        
        # Statistics
        self._hits = 0
        self._misses = 0
        self._evictions = 0
        
        # Background cleanup
        self._cleanup_thread: Optional[threading.Thread] = None
        self._running = False
    
    def start(self) -> None:
        """Start background cleanup thread."""
        if self._running:
            return
        
        self._running = True
        self._cleanup_thread = threading.Thread(
            target=self._cleanup_loop,
            daemon=True,
            name="dedup-cleanup",
        )
        self._cleanup_thread.start()
    
    def stop(self) -> None:
        """Stop background cleanup thread."""
        self._running = False
        if self._cleanup_thread:
            self._cleanup_thread.join(timeout=5.0)
            self._cleanup_thread = None
    
    def _cleanup_loop(self) -> None:
        """Background cleanup loop."""
        while self._running:
            time.sleep(CLEANUP_INTERVAL)
            if self._running:
                self.cleanup()
    
    def _compute_hash(self, data: bytes) -> bytes:
        """
        Compute hash for packet data.
        
        Uses BLAKE2b with 16-byte output for efficiency.
        """
        return blake2b_hash(data, digest_size=16)
    
    def check(self, data: bytes) -> bool:
        """
        Check if packet has been seen (without adding).
        
        Args:
            data: Packet data
            
        Returns:
            True if packet is a duplicate
        """
        packet_hash = self._compute_hash(data)
        
        with self._lock:
            if packet_hash not in self._cache:
                return False
            
            entry = self._cache[packet_hash]
            
            # Check if entry has expired
            if time.time() - entry.first_seen > self._ttl:
                del self._cache[packet_hash]
                return False
            
            return True
    
    def check_and_add(self, data: bytes) -> bool:
        """
        Check if packet is duplicate and add if not.
        
        This is the primary interface for deduplication.
        
        Args:
            data: Packet data
            
        Returns:
            True if packet is a duplicate (already seen)
            False if packet is new (added to cache)
        """
        packet_hash = self._compute_hash(data)
        now = time.time()
        
        with self._lock:
            if packet_hash in self._cache:
                entry = self._cache[packet_hash]
                
                # Check if entry has expired
                if now - entry.first_seen > self._ttl:
                    # Expired - treat as new
                    self._cache[packet_hash] = CacheEntry(
                        packet_hash=packet_hash,
                        first_seen=now,
                        last_seen=now,
                        count=1,
                    )
                    self._misses += 1
                    return False
                
                # Not expired - it's a duplicate
                entry.last_seen = now
                entry.count += 1
                self._hits += 1
                return True
            
            # New packet - add to cache
            self._cache[packet_hash] = CacheEntry(
                packet_hash=packet_hash,
                first_seen=now,
                last_seen=now,
                count=1,
            )
            self._misses += 1
            
            # Check if we need to evict
            if len(self._cache) > self._max_entries:
                self._evict_oldest()
            
            return False
    
    def add(self, data: bytes) -> None:
        """
        Add packet to cache (without checking).
        
        Useful when you've already processed a packet
        and want to prevent reprocessing.
        
        Args:
            data: Packet data
        """
        packet_hash = self._compute_hash(data)
        now = time.time()
        
        with self._lock:
            if packet_hash not in self._cache:
                self._cache[packet_hash] = CacheEntry(
                    packet_hash=packet_hash,
                    first_seen=now,
                    last_seen=now,
                    count=1,
                )
    
    def remove(self, data: bytes) -> bool:
        """
        Remove packet from cache.
        
        Args:
            data: Packet data
            
        Returns:
            True if packet was in cache
        """
        packet_hash = self._compute_hash(data)
        
        with self._lock:
            if packet_hash in self._cache:
                del self._cache[packet_hash]
                return True
            return False
    
    def cleanup(self) -> int:
        """
        Remove expired entries from cache.
        
        Returns:
            Number of entries removed
        """
        now = time.time()
        expired = []
        
        with self._lock:
            for packet_hash, entry in self._cache.items():
                if now - entry.first_seen > self._ttl:
                    expired.append(packet_hash)
            
            for packet_hash in expired:
                del self._cache[packet_hash]
                self._evictions += 1
        
        return len(expired)
    
    def _evict_oldest(self) -> None:
        """Evict oldest entries when cache is full."""
        # Find oldest entries
        entries = sorted(
            self._cache.items(),
            key=lambda x: x[1].first_seen,
        )
        
        # Remove oldest 10%
        to_remove = max(1, len(entries) // 10)
        for packet_hash, _ in entries[:to_remove]:
            del self._cache[packet_hash]
            self._evictions += 1
    
    def clear(self) -> None:
        """Clear all entries from cache."""
        with self._lock:
            self._cache.clear()
    
    def get_stats(self) -> dict:
        """
        Get cache statistics.
        
        Returns:
            dict: Statistics including size, hits, misses, evictions
        """
        with self._lock:
            return {
                "size": len(self._cache),
                "max_entries": self._max_entries,
                "ttl_seconds": self._ttl,
                "hits": self._hits,
                "misses": self._misses,
                "evictions": self._evictions,
                "hit_rate": self._hits / (self._hits + self._misses) if (self._hits + self._misses) > 0 else 0,
            }
    
    def __len__(self) -> int:
        """Get number of entries in cache."""
        with self._lock:
            return len(self._cache)
    
    def __contains__(self, data: bytes) -> bool:
        """Check if packet is in cache."""
        return self.check(data)
