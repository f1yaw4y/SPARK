"""
SPARK XOR Distance Routing Table (k-buckets)

Kademlia-inspired routing for address-based forwarding in the SPARK mesh.

Node IDs (128-bit, from BLAKE2b of public key) serve as addresses in a
hash space.  XOR distance defines "closeness" - greedy XOR routing
converges in O(log N) hops to any destination.

Key Properties:
- No global knowledge: each node knows a limited subset of peers
- Deterministic forwarding: each hop moves closer in XOR space
- Privacy: address space has no correlation with physical location
- Dynamic: entries expire and refresh through beacons and gossip

Design:
- 128 k-buckets, one per bit position of the 128-bit node ID
- Bucket *i* holds peers whose XOR distance from us has bit *i* as
  the most significant set bit
- Each bucket holds up to K entries (default K = 8)
- Entries carry the peer's public key so onion layers can be encrypted
  to gateways discovered through gossip alone
"""

import time
import threading
from typing import Optional, List, Set, Tuple
from dataclasses import dataclass, field

from ..crypto.primitives import blake2b_hash, constant_time_compare


# ---------------------------------------------------------------------------
# XOR distance primitives
# ---------------------------------------------------------------------------

def xor_distance(a: bytes, b: bytes) -> int:
    """XOR distance between two 16-byte node IDs."""
    return int.from_bytes(a, "big") ^ int.from_bytes(b, "big")


def distance_bit(a: bytes, b: bytes) -> int:
    """
    Index of the most significant differing bit (0-127).

    Returns -1 when *a* equals *b*.
    This determines which k-bucket a peer belongs to.
    """
    d = xor_distance(a, b)
    if d == 0:
        return -1
    return d.bit_length() - 1


def node_region(node_id: bytes) -> int:
    """
    Region number (0-255) derived from the first byte of a node ID.

    Nodes sharing the same first byte are in the same "address zone".
    This is purely deterministic from the address - no negotiation
    required between nodes.
    """
    return node_id[0]


def same_region(a: bytes, b: bytes) -> bool:
    """True when two node IDs share the same first-byte region."""
    return a[0] == b[0]


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

K = 40              # Max entries per k-bucket
ENTRY_TTL = 600     # Routing entry lifetime in seconds (10 min)
MAX_GOSSIP = 6      # Max gossip entries carried per beacon


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

def _verify_node_id(node_id: bytes, ed25519_key: bytes) -> bool:
    """Verify that node_id was derived from the Ed25519 public key."""
    expected = blake2b_hash(ed25519_key, digest_size=16, person=b"spark-nodeid")
    return constant_time_compare(node_id, expected)


@dataclass
class RoutingEntry:
    """An entry in the XOR routing table."""

    node_id: bytes            # 16 bytes - peer address
    public_key: bytes         # 32 bytes - X25519 public key
    ed25519_key: Optional[bytes] = None  # 32 bytes - Ed25519 key (if known)
    next_hop: Optional[bytes] = None   # node_id of direct neighbor to relay through
    is_direct: bool = True    # True if this is a direct radio neighbor
    verified: bool = False    # True if node_id was verified against ed25519_key
    last_seen: float = field(default_factory=time.time)

    # ------------------------------------------------------------------
    @property
    def is_alive(self) -> bool:
        return time.time() - self.last_seen < ENTRY_TTL

    def touch(self) -> None:
        self.last_seen = time.time()


class KBucket:
    """
    A single bucket holding up to *K* peers at a specific XOR distance
    range.  Peers are ordered by last-seen time (most recent at the
    end).
    """

    def __init__(self, k: int = K):
        self._k = k
        self.entries: List[RoutingEntry] = []

    # ------------------------------------------------------------------
    def add(self, entry: RoutingEntry) -> bool:
        """Add or update an entry.  Returns True if successful.
        
        Sybil resistance:
        - Verified entries are always preferred over unverified ones.
        - When the bucket is full, an unverified entry will be evicted
          to make room for a verified newcomer.
        - Unverified entries cannot evict verified ones.
        """
        # Update existing
        for i, existing in enumerate(self.entries):
            if existing.node_id == entry.node_id:
                # Upgrade: keep verified status if already set
                if existing.verified and not entry.verified:
                    entry.verified = True
                    entry.ed25519_key = entry.ed25519_key or existing.ed25519_key
                self.entries.pop(i)
                self.entries.append(entry)
                return True

        # Evict expired
        self.entries = [e for e in self.entries if e.is_alive]

        if len(self.entries) < self._k:
            self.entries.append(entry)
            return True

        # Bucket full -- try to evict an unverified entry for a verified one
        if entry.verified:
            for i, existing in enumerate(self.entries):
                if not existing.verified:
                    self.entries.pop(i)
                    self.entries.append(entry)
                    return True

        return False   # bucket full, no eviction possible

    def remove(self, node_id: bytes) -> None:
        self.entries = [e for e in self.entries if e.node_id != node_id]

    def get(self, node_id: bytes) -> Optional[RoutingEntry]:
        for e in self.entries:
            if e.node_id == node_id:
                return e
        return None

    @property
    def size(self) -> int:
        return len(self.entries)


# ---------------------------------------------------------------------------
# Routing Table
# ---------------------------------------------------------------------------

class RoutingTable:
    """
    128-bit XOR routing table backed by k-buckets.

    Provides:
    - ``add_peer`` / ``remove_peer`` for table maintenance
    - ``find_closest`` for nearest-neighbour lookups
    - ``find_next_hop`` for greedy XOR forwarding (one step)
    - ``route_to`` for relay selection (returns a direct neighbour)
    - ``get_gossip_entries`` for beacon gossip
    """

    def __init__(self, local_id: bytes, k: int = K):
        self.local_id = local_id
        self._k = k
        self._buckets = [KBucket(k) for _ in range(128)]
        self._lock = threading.RLock()

    # ------ mutators -----------------------------------------------------

    def add_peer(
        self,
        node_id: bytes,
        public_key: bytes,
        next_hop: Optional[bytes] = None,
        is_direct: bool = True,
        ed25519_key: Optional[bytes] = None,
    ) -> bool:
        """Add (or refresh) a peer in the routing table.
        
        When *ed25519_key* is provided, verifies that *node_id* was
        genuinely derived from it.  Rejects the entry on mismatch,
        preventing routing table poisoning via forged gossip.
        """
        if node_id == self.local_id:
            return False

        # Verify node_id binding when ed25519_key is available
        verified = False
        if ed25519_key is not None:
            if not _verify_node_id(node_id, ed25519_key):
                return False  # reject: forged identity
            verified = True

        bucket_idx = distance_bit(self.local_id, node_id)
        if bucket_idx < 0:
            return False
        entry = RoutingEntry(
            node_id=node_id,
            public_key=public_key,
            ed25519_key=ed25519_key,
            next_hop=None if is_direct else next_hop,
            is_direct=is_direct,
            verified=verified,
        )
        with self._lock:
            return self._buckets[bucket_idx].add(entry)

    def remove_peer(self, node_id: bytes) -> None:
        bucket_idx = distance_bit(self.local_id, node_id)
        if bucket_idx >= 0:
            with self._lock:
                self._buckets[bucket_idx].remove(node_id)

    # ------ queries ------------------------------------------------------

    def get_peer(self, node_id: bytes) -> Optional[RoutingEntry]:
        bucket_idx = distance_bit(self.local_id, node_id)
        if bucket_idx < 0:
            return None
        with self._lock:
            return self._buckets[bucket_idx].get(node_id)

    def find_closest(self, target: bytes, count: int = K) -> List[RoutingEntry]:
        """Return up to *count* alive entries closest to *target*."""
        all_entries: List[RoutingEntry] = []
        with self._lock:
            for bucket in self._buckets:
                all_entries.extend(e for e in bucket.entries if e.is_alive)
        all_entries.sort(key=lambda e: xor_distance(e.node_id, target))
        return all_entries[:count]

    def find_next_hop(self, target: bytes) -> Optional[RoutingEntry]:
        """
        Greedy XOR step: return the entry closest to *target* that is
        strictly closer than we are, or ``None`` if we are already the
        closest known node (== destination sub-mesh).
        """
        my_dist = xor_distance(self.local_id, target)
        closest = self.find_closest(target, count=1)
        if closest and xor_distance(closest[0].node_id, target) < my_dist:
            return closest[0]
        return None

    def route_to(
        self,
        target: bytes,
        exclude: Optional[Set[bytes]] = None,
    ) -> Optional[Tuple[bytes, RoutingEntry]]:
        """
        Determine which *direct neighbour* to transmit to in order to
        reach *target* via greedy XOR routing.

        Returns ``(neighbour_node_id, best_entry)`` or ``None`` when no
        eligible direct neighbour is closer than we are.

        Args:
            target: destination node_id
            exclude: set of node_ids to skip (e.g. recently visited)

        Strategy:
        1. If target is a direct neighbour → send to them.
        2. If target is known via gossip and next_hop is not excluded
           → use the gossip chain.
        3. Otherwise pick the direct neighbour closest to *target*
           (excluding recently visited nodes to break loops).
        """
        _excl = exclude or set()

        # Fast-path: target is a direct neighbour
        known = self.get_peer(target)
        if known and known.is_direct and target not in _excl:
            return (target, known)

        # Gossip fast-path (with loop prevention)
        if known and known.next_hop and known.next_hop not in _excl:
            return (known.next_hop, known)

        # Greedy XOR: pick the direct neighbour closest to target
        my_dist = xor_distance(self.local_id, target)
        best: Optional[RoutingEntry] = None
        best_dist = my_dist

        with self._lock:
            for bucket in self._buckets:
                for entry in bucket.entries:
                    if not entry.is_alive or not entry.is_direct:
                        continue
                    if entry.node_id in _excl:
                        continue
                    d = xor_distance(entry.node_id, target)
                    if d < best_dist:
                        best_dist = d
                        best = entry

        if best is not None:
            return (best.node_id, best)
        return None

    # ------ gossip helpers -----------------------------------------------

    def get_gossip_entries(
        self,
        exclude: Optional[Set[bytes]] = None,
        rng=None,
    ) -> List[RoutingEntry]:
        """
        Pick a diverse sample of *verified* entries for beacon gossip.

        Selects one verified entry from each non-empty bucket (giving
        broad address-space coverage), shuffles, and returns up to
        ``MAX_GOSSIP`` entries.  Only verified entries are gossiped to
        prevent propagation of forged identities.
        """
        import random as _rng_mod
        _rng = rng or _rng_mod

        exclude = exclude or set()
        exclude.add(self.local_id)

        candidates: List[RoutingEntry] = []
        with self._lock:
            for bucket in self._buckets:
                alive = [
                    e for e in bucket.entries
                    if e.is_alive and e.verified and e.node_id not in exclude
                ]
                if alive:
                    candidates.append(alive[-1])  # most recently seen

        _rng.shuffle(candidates)
        return candidates[:MAX_GOSSIP]

    # ------ statistics ---------------------------------------------------

    def get_all_entries(self) -> List[RoutingEntry]:
        """Return every alive entry in the table."""
        result: List[RoutingEntry] = []
        with self._lock:
            for bucket in self._buckets:
                result.extend(e for e in bucket.entries if e.is_alive)
        return result

    def total_peers(self) -> int:
        with self._lock:
            return sum(b.size for b in self._buckets)

    def regions_known(self) -> Set[int]:
        """Distinct first-byte regions present in the table."""
        regions: Set[int] = set()
        with self._lock:
            for bucket in self._buckets:
                for e in bucket.entries:
                    if e.is_alive:
                        regions.add(e.node_id[0])
        return regions
