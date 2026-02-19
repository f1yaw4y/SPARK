"""
SPARK Peer Management

Handles peer discovery, tracking, and link quality estimation.

Features:
- Automatic peer discovery via beacons
- Link quality tracking (RSSI, SNR, packet loss)
- Peer state management
- Persistent peer cache

Design:
- Peers are discovered passively (beacons) and actively (probes)
- Link quality is estimated from recent packet statistics
- Stale peers are automatically removed
"""

import time
import threading
import sqlite3
from pathlib import Path
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field
from enum import IntEnum
from contextlib import contextmanager

from ..crypto.primitives import blake2b_hash


# Peer timeout (seconds without contact)
PEER_TIMEOUT = 300  # 5 minutes

# Peer expiry (seconds without contact before removal)
PEER_EXPIRY = 3600  # 1 hour

# Link quality window (seconds)
LINK_QUALITY_WINDOW = 60

# Default peer database path
DEFAULT_PEER_DB = Path("/var/lib/spark/peers.db")


class PeerState(IntEnum):
    """Peer connection state."""
    UNKNOWN = 0      # Never seen
    DISCOVERED = 1   # Seen beacon, not verified
    ACTIVE = 2       # Recently communicated
    STALE = 3        # No recent contact
    UNREACHABLE = 4  # Failed to reach


@dataclass
class LinkQuality:
    """
    Link quality metrics for a peer.
    
    Estimated from recent packet statistics.
    """
    # Signal metrics (most recent)
    rssi: int = -100          # Received Signal Strength (dBm)
    snr: float = 0.0          # Signal-to-Noise Ratio (dB)
    
    # Packet statistics (rolling window)
    packets_received: int = 0
    packets_sent: int = 0
    packets_lost: int = 0
    
    # Latency (milliseconds)
    avg_latency_ms: float = 0.0
    min_latency_ms: float = 0.0
    max_latency_ms: float = 0.0
    
    # Timestamps
    last_rx: float = 0.0
    last_tx: float = 0.0
    
    @property
    def packet_loss_rate(self) -> float:
        """Calculate packet loss rate (0.0-1.0)."""
        total = self.packets_sent
        if total == 0:
            return 0.0
        return self.packets_lost / total
    
    @property
    def quality_score(self) -> float:
        """
        Calculate overall link quality score (0.0-1.0).
        
        Higher is better.
        """
        # RSSI component (normalize -100 to -30 dBm)
        rssi_score = max(0, min(1, (self.rssi + 100) / 70))
        
        # SNR component (normalize -10 to 20 dB)
        snr_score = max(0, min(1, (self.snr + 10) / 30))
        
        # Packet loss component
        loss_score = 1.0 - self.packet_loss_rate
        
        # Weighted average
        return 0.3 * rssi_score + 0.3 * snr_score + 0.4 * loss_score


@dataclass
class Peer:
    """
    Represents a discovered peer node.
    """
    # Identity
    node_id: bytes                # 16 bytes
    public_key: bytes             # 32 bytes (X25519)
    
    # State
    state: PeerState = PeerState.UNKNOWN
    
    # Region membership
    region_id: Optional[bytes] = None  # Peer's claimed region
    
    # Capabilities
    capabilities: int = 0
    is_gateway: bool = False
    is_relay: bool = False
    
    # Link quality
    link_quality: LinkQuality = field(default_factory=LinkQuality)
    
    # Timestamps
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    last_beacon: float = 0.0
    
    # Beacon sequence (for detecting missed beacons)
    last_beacon_seq: int = 0
    
    @property
    def is_active(self) -> bool:
        """Check if peer is currently active."""
        return self.state == PeerState.ACTIVE
    
    @property
    def is_reachable(self) -> bool:
        """Check if peer is likely reachable."""
        return self.state in (PeerState.DISCOVERED, PeerState.ACTIVE)
    
    @property
    def age(self) -> float:
        """Time since first seen (seconds)."""
        return time.time() - self.first_seen
    
    @property
    def idle_time(self) -> float:
        """Time since last contact (seconds)."""
        return time.time() - self.last_seen
    
    def update_link_quality(
        self,
        rssi: Optional[int] = None,
        snr: Optional[float] = None,
        is_rx: bool = True,
    ) -> None:
        """Update link quality metrics from a packet."""
        now = time.time()
        
        if rssi is not None:
            self.link_quality.rssi = rssi
        if snr is not None:
            self.link_quality.snr = snr
        
        if is_rx:
            self.link_quality.packets_received += 1
            self.link_quality.last_rx = now
        else:
            self.link_quality.packets_sent += 1
            self.link_quality.last_tx = now
        
        self.last_seen = now
    
    def node_id_hex(self) -> str:
        """Get node ID as hex string."""
        return self.node_id.hex()


class PeerManager:
    """
    Manages discovered peers and their state.
    
    Usage:
        manager = PeerManager()
        
        # Add peer from beacon
        manager.add_or_update_peer(node_id, public_key, region_id)
        
        # Get active peers
        for peer in manager.get_active_peers():
            print(peer.node_id_hex())
        
        # Get best peer for forwarding
        peer = manager.get_best_peer_for_region(region_id)
    """
    
    def __init__(self, db_path: Optional[Path] = None):
        """
        Initialize peer manager.
        
        Args:
            db_path: Path to peer database
        """
        self._db_path = db_path or DEFAULT_PEER_DB
        self._peers: Dict[bytes, Peer] = {}
        self._lock = threading.RLock()
        
        # Ensure directory exists
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Initialize database
        self._init_db()
        
        # Load cached peers
        self._load_peers()
    
    def _init_db(self) -> None:
        """Initialize peer database schema."""
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS peers (
                    node_id BLOB PRIMARY KEY,
                    public_key BLOB NOT NULL,
                    region_id BLOB,
                    capabilities INTEGER DEFAULT 0,
                    first_seen REAL NOT NULL,
                    last_seen REAL NOT NULL,
                    rssi INTEGER DEFAULT -100,
                    snr REAL DEFAULT 0
                )
            """)
            conn.commit()
    
    @contextmanager
    def _get_connection(self):
        """Get database connection."""
        conn = sqlite3.connect(str(self._db_path), timeout=10.0)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()
    
    def _load_peers(self) -> None:
        """Load peers from database."""
        with self._get_connection() as conn:
            rows = conn.execute("SELECT * FROM peers").fetchall()
            
            for row in rows:
                peer = Peer(
                    node_id=row["node_id"],
                    public_key=row["public_key"],
                    region_id=row["region_id"],
                    capabilities=row["capabilities"],
                    first_seen=row["first_seen"],
                    last_seen=row["last_seen"],
                    state=PeerState.STALE,  # Mark as stale until we hear from them
                )
                peer.link_quality.rssi = row["rssi"]
                peer.link_quality.snr = row["snr"]
                
                self._peers[peer.node_id] = peer
    
    def _save_peer(self, peer: Peer) -> None:
        """Save peer to database."""
        with self._get_connection() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO peers
                (node_id, public_key, region_id, capabilities, first_seen, last_seen, rssi, snr)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                peer.node_id,
                peer.public_key,
                peer.region_id,
                peer.capabilities,
                peer.first_seen,
                peer.last_seen,
                peer.link_quality.rssi,
                peer.link_quality.snr,
            ))
            conn.commit()
    
    def add_or_update_peer(
        self,
        node_id: bytes,
        public_key: bytes,
        region_id: Optional[bytes] = None,
        capabilities: int = 0,
        rssi: Optional[int] = None,
        snr: Optional[float] = None,
        beacon_seq: Optional[int] = None,
    ) -> Peer:
        """
        Add a new peer or update existing one.
        
        Called when receiving a beacon or other packet from a peer.
        
        Args:
            node_id: Peer's node ID
            public_key: Peer's X25519 public key
            region_id: Peer's claimed region ID
            capabilities: Peer's capability flags
            rssi: Signal strength from packet
            snr: Signal-to-noise ratio from packet
            beacon_seq: Beacon sequence number
            
        Returns:
            Peer: The added or updated peer
        """
        with self._lock:
            if node_id in self._peers:
                peer = self._peers[node_id]
                peer.state = PeerState.ACTIVE
                peer.region_id = region_id
                peer.capabilities = capabilities
                
                if beacon_seq is not None:
                    # Check for missed beacons
                    if peer.last_beacon_seq > 0:
                        expected = (peer.last_beacon_seq + 1) & 0xFFFF
                        if beacon_seq != expected:
                            missed = (beacon_seq - expected) & 0xFFFF
                            peer.link_quality.packets_lost += missed
                    peer.last_beacon_seq = beacon_seq
                    peer.last_beacon = time.time()
            else:
                peer = Peer(
                    node_id=node_id,
                    public_key=public_key,
                    region_id=region_id,
                    capabilities=capabilities,
                    state=PeerState.DISCOVERED,
                )
                if beacon_seq is not None:
                    peer.last_beacon_seq = beacon_seq
                    peer.last_beacon = time.time()
                self._peers[node_id] = peer
            
            # Update link quality
            peer.update_link_quality(rssi=rssi, snr=snr, is_rx=True)
            
            # Parse capabilities
            from ..packet.format import BeaconPayload
            peer.is_gateway = bool(capabilities & BeaconPayload.CAPABILITIES_GATEWAY)
            peer.is_relay = bool(capabilities & BeaconPayload.CAPABILITIES_RELAY)
            
            # Save to database
            self._save_peer(peer)
            
            return peer
    
    def get_peer(self, node_id: bytes) -> Optional[Peer]:
        """Get peer by node ID."""
        with self._lock:
            return self._peers.get(node_id)
    
    def get_all_peers(self) -> List[Peer]:
        """Get all known peers."""
        with self._lock:
            return list(self._peers.values())
    
    def get_active_peers(self) -> List[Peer]:
        """Get peers that are currently active."""
        with self._lock:
            return [p for p in self._peers.values() if p.is_active]
    
    def get_reachable_peers(self) -> List[Peer]:
        """Get peers that are likely reachable."""
        with self._lock:
            return [p for p in self._peers.values() if p.is_reachable]
    
    def get_gateway_peers(self) -> List[Peer]:
        """Get peers that advertise gateway capability."""
        with self._lock:
            return [p for p in self._peers.values() 
                    if p.is_gateway and p.is_reachable]
    
    def get_peers_in_region(self, region_id: bytes) -> List[Peer]:
        """Get peers that belong to a specific region."""
        with self._lock:
            return [p for p in self._peers.values()
                    if p.region_id == region_id and p.is_reachable]
    
    def get_best_peer_for_region(self, region_id: bytes) -> Optional[Peer]:
        """
        Get the best peer for reaching a region.
        
        Prefers gateways with good link quality.
        
        Args:
            region_id: Target region ID
            
        Returns:
            Best peer, or None if no suitable peer found
        """
        candidates = self.get_peers_in_region(region_id)
        if not candidates:
            return None
        
        # Sort by: gateway preference, then link quality
        def score(peer: Peer) -> tuple:
            return (
                1 if peer.is_gateway else 0,
                peer.link_quality.quality_score,
            )
        
        candidates.sort(key=score, reverse=True)
        return candidates[0]
    
    def update_peer_states(self) -> None:
        """
        Update peer states based on timeout.
        
        Should be called periodically.
        """
        now = time.time()
        
        with self._lock:
            expired = []
            
            for node_id, peer in self._peers.items():
                idle = peer.idle_time
                
                if idle > PEER_EXPIRY:
                    # Remove expired peer
                    expired.append(node_id)
                elif idle > PEER_TIMEOUT:
                    # Mark as stale
                    peer.state = PeerState.STALE
            
            # Remove expired peers
            for node_id in expired:
                del self._peers[node_id]
            
            # Remove from database
            if expired:
                with self._get_connection() as conn:
                    placeholders = ",".join("?" * len(expired))
                    conn.execute(
                        f"DELETE FROM peers WHERE node_id IN ({placeholders})",
                        expired
                    )
                    conn.commit()
    
    def mark_unreachable(self, node_id: bytes) -> None:
        """Mark a peer as unreachable."""
        with self._lock:
            if node_id in self._peers:
                self._peers[node_id].state = PeerState.UNREACHABLE
    
    def mark_packet_sent(self, node_id: bytes) -> None:
        """Record that we sent a packet to a peer."""
        with self._lock:
            if node_id in self._peers:
                peer = self._peers[node_id]
                peer.link_quality.packets_sent += 1
                peer.link_quality.last_tx = time.time()
    
    def mark_packet_lost(self, node_id: bytes) -> None:
        """Record a lost packet to a peer."""
        with self._lock:
            if node_id in self._peers:
                peer = self._peers[node_id]
                peer.link_quality.packets_lost += 1
    
    def get_stats(self) -> dict:
        """Get peer manager statistics."""
        with self._lock:
            states = {}
            for state in PeerState:
                states[state.name.lower()] = sum(
                    1 for p in self._peers.values() if p.state == state
                )
            
            return {
                "total_peers": len(self._peers),
                "by_state": states,
                "gateways": sum(1 for p in self._peers.values() if p.is_gateway),
                "relays": sum(1 for p in self._peers.values() if p.is_relay),
            }
    
    def __len__(self) -> int:
        """Get number of known peers."""
        return len(self._peers)
