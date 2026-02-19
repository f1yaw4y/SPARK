#!/usr/bin/env python3
"""
SPARK Large-Scale Network Simulation (with per-link encryption)

Simulates hundreds to thousands of virtual SPARK nodes to validate
address-based XOR routing with onion encryption AND per-link encrypted
channels at scale, under real-world network conditions.

Security model (per-link encryption):
  - Beacons are identity-free: only an ephemeral DH key (no node_id)
  - Link sessions established via anonymous DH key exchange
  - Identity (node_id, public key, gossip) exchanged only over encrypted links
  - All data frames encrypted per-link (ChaCha20-Poly1305)
  - Each neighbour pair has a unique key; no network-wide secret
  - Passive observers see only random bytes (no metadata leakage)

Routing reliability (multi-path + receipt ACK):
  - Receipt ACK per hop: relay ACKs immediately on receipt, allowing
    same-neighbour retry for packet loss recovery (lightweight).
  - Multi-path sending: each attempt sends 2 copies through different
    gateways, providing independent routing paths.
  - End-to-end retry: sender retransmits with fresh gateways on failure.
  - Full visited tracking prevents loops; multi-path handles dead-ends.
  - Combined: up to 12 independent paths per message for ~100% delivery.

Realism features:
  - Packet loss:          radio interference / collisions (default 5%)
  - Variable radio range: terrain/antenna variation (default ±20%)
  - Node death:           permanent hardware failure (default 2%)
  - Temporary dropout:    brief power/software glitch (default 3%)
  - Per-link encryption:  28-byte overhead per frame, handshake latency

Architecture:
  - Node IDs (128-bit, from BLAKE2b of public key) serve as addresses
  - XOR distance defines closeness; greedy forwarding converges in O(log N)
  - Gossip entries shared only over encrypted links (not broadcast)
  - 3-layer onion encryption protects sender/recipient privacy
  - No node has global knowledge; each knows only ~200 peers via gossip

Usage:
    python3 tests/sim_network.py --nodes 500 --messages 100
    python3 tests/sim_network.py --nodes 5000 --messages 200 --seed 42
    python3 tests/sim_network.py --nodes 1000 --packet-loss 0.10 --verbose
"""

import gc
import os
import sys
import math
import time
import zlib
import random
import argparse
import numpy as np
from typing import Optional, List, Dict, Tuple, Set, Any
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Project imports
# ---------------------------------------------------------------------------
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from sparkd.crypto.keys import generate_identity, IdentityKey
from sparkd.crypto.primitives import generate_message_id
from sparkd.crypto.onion import (
    build_onion,
    build_onion_1layer,
    peel_layer,
    OnionError,
)
from sparkd.crypto.envelope import (
    seal_envelope_for_pubkey_bytes,
    open_envelope,
    EnvelopeError,
)
from sparkd.packet.format import DirectMessagePayload
from sparkd.crypto.link import LINK_OVERHEAD
from sparkd.mesh.kbucket import (
    RoutingTable,
    RoutingEntry,
    xor_distance,
    node_region,
    MAX_GOSSIP,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
PAYLOAD_COMPRESSED = 0x01

# Frame types carried by SimMedium
FRAME_BEACON   = 0    # legacy (unused with link encryption)
FRAME_ONION    = 1    # onion envelope being XOR-routed to a gateway
FRAME_DIRECT   = 2    # direct encrypted message to a neighbour
FRAME_DELIVERY = 3    # last-mile delivery (decrypted, inner-mesh)
FRAME_ACK      = 4    # end-to-end delivery receipt (meshctl)
FRAME_HOP_ACK  = 5    # hop-by-hop: "my next hop confirmed receipt"
FRAME_HOP_NACK = 6    # hop-by-hop: "I can't forward, try someone else"
FRAME_HANDSHAKE = 7   # anonymous DH key exchange (identity-free)
FRAME_LINK_IDENTITY = 8  # signed identity over established link
FRAME_CHALLENGE = 9      # trust: random nonce challenge
FRAME_CHALLENGE_RESP = 10 # trust: signed nonce response

MAX_PROPAGATION_TICKS = 8000   # PER ATTEMPT (auto-scaled for network diameter)
MAX_E2E_RETRIES = 12           # sender retransmits with different gateways
HOP_ACK_TIMEOUT = 8            # receipt ACK: fast packet loss recovery
MAX_SAME_RETRIES_DEFAULT = 2   # same-neighbour retries before switching

# Congestion / TX queue
MAX_TX_PER_TICK = 2            # LoRa: ~1-2 packets/sec per node
MAX_QUEUE_SIZE = 200           # generous FIFO queue per node

# RF realism
# In a tick-based simulation, all events within a tick appear simultaneous.
# In reality, LoRa transmissions are staggered in time within that window.
# A 255-byte SF7/125kHz packet takes ~0.4s of airtime.  We model:
#   - half-duplex: P(deaf while TX-ing) = TX_OVERLAP_PROB
#   - collisions: P(two TXes overlap) per interferer = COLLISION_DUTY
# Both are lower than 1.0 because the tick bundles non-simultaneous events.
BUSY_TICKS = 0                 # extra ticks a node stays deaf after its TX tick
TX_OVERLAP_PROB = 0.35         # P(node is deaf when it TX-ed this tick)
                               # ~0.4s airtime / ~1.1s effective tick window
COLLISION_DUTY = 0.08          # P(two random TXes in same tick actually overlap)
                               # kept low: tick bundles staggered real-time events

# Trust system constants (simulation-scale -- real daemon uses hours)
TRUST_INITIAL     = 50
TRUST_NORMAL      = 40         # >= this: normal routing
TRUST_DEPRIORITIZE = 20        # >= this: deprioritized
TRUST_MIN         = 0
TRUST_MAX         = 100

# Malicious node behaviours
MALICIOUS_DROP_RATE = 0.40     # selective dropper: silently discard 40% of forwards
MALICIOUS_CORRUPT  = False     # (future: modify payloads)

# Trust score adjustments (tuned for simulation tick-scale)
T_CHALLENGE_PASS   =  5
T_CHALLENGE_FAIL   = -20
T_FORWARD_OK       =  3
T_FORWARD_FAIL     = -8        # E2E failure is strong evidence of dropping
T_BEACON_OK        =  1
T_SUSPECT_RELAY    = -15       # repeated multi-path failure is very suspicious
SUSPECT_THRESHOLD  =  2        # flag faster (2 independent path failures)


# ===================================================================
# SimFrame -- a "radio transmission" in the virtual medium
# ===================================================================

@dataclass
class SimFrame:
    """One radio transmission in the simulation."""
    frame_id: int              # unique ID for dedup
    frame_type: int
    sender_id: bytes           # who transmitted THIS hop
    dest_id: bytes             # ultimate XOR routing destination
    next_hop: bytes            # specific neighbour to relay (b"" = broadcast)
    payload: object            # frame-type-specific data
    ttl: int = 64
    hop_count: int = 0
    visited: tuple = ()        # node_ids already visited (loop prevention)
    # Hop-by-hop ACK tracking
    ack_to: bytes = b""        # who to ACK/NACK on outcome
    ack_tracking: int = 0      # upstream's tracking ID
    randomness: float = 0.0    # routing randomness (increases with E2E retries)


# ===================================================================
# PendingForward -- message held at a relay awaiting downstream ACK
# ===================================================================

MAX_SAME_RETRIES = 3       # retransmit to same neighbour before switching

@dataclass
class PendingForward:
    """A message copy held at a relay while the downstream hop is tried."""
    tracking_id: int           # our tracking ID for this attempt
    frame: SimFrame            # stored frame (for retry with different next-hop)
    forwarded_to: bytes        # current downstream neighbour
    upstream_node: bytes       # who to ACK/NACK (b"" = we are the sender)
    upstream_tracking: int     # their tracking ID
    tried: Set[bytes]          # neighbours already attempted
    timeout: int               # ticks remaining before retry
    last_fid: int = 0          # frame_id of last transmit (for same-neighbour retry)
    same_retries: int = 0      # retransmissions to same neighbour so far


# ===================================================================
# SimMedium -- topology-aware virtual radio channel
# ===================================================================

@dataclass
class _PendingTX:
    source_id: bytes
    source_pos: Tuple[float, float]
    frame: SimFrame


class SimMedium:
    """
    2-D range-limited radio medium with realistic packet loss.

    Nodes register with a position and individual effective range.
    When one transmits, all nodes within radio range receive the frame
    in the next tick -- subject to random packet loss.
    """

    def __init__(self, base_radio_range: float, packet_loss: float = 0.0,
                 rng: Optional[random.Random] = None):
        self.base_radio_range = base_radio_range
        self.packet_loss = packet_loss
        self._rng = rng or random.Random()
        self.nodes: Dict[bytes, "SimNode"] = {}
        self.pending: List[_PendingTX] = []
        self._neighbours: Dict[bytes, List[bytes]] = {}

    def register(self, node: "SimNode") -> None:
        self.nodes[node.node_id] = node

    def build_neighbour_graph(self) -> None:
        """Build the static neighbour graph using per-node effective ranges.

        Uses numpy chunked vectorized distance computation for speed.
        Processes in row-chunks to limit peak memory (~60MB per chunk).
        """
        ids = list(self.nodes.keys())
        n = len(ids)
        self._neighbours = {nid: set() for nid in ids}

        # Build numpy arrays of positions and ranges
        positions = np.empty((n, 2), dtype=np.float64)
        ranges_arr = np.empty(n, dtype=np.float64)
        for i, nid in enumerate(ids):
            node = self.nodes[nid]
            positions[i, 0] = node.position[0]
            positions[i, 1] = node.position[1]
            ranges_arr[i] = node.effective_range

        # Use squared distances to avoid sqrt
        ranges_sq = ranges_arr ** 2

        # Process in chunks to limit memory: chunk rows vs ALL columns
        CHUNK = min(500, n)
        for start in range(0, n, CHUNK):
            end = min(start + CHUNK, n)
            chunk_size = end - start

            # Pairwise squared distances: chunk rows vs ALL nodes
            # Shape: (chunk_size, n)
            dx = positions[start:end, 0:1] - positions[:, 0].reshape(1, -1)
            dy = positions[start:end, 1:2] - positions[:, 1].reshape(1, -1)
            dist_sq = dx * dx + dy * dy

            # Link range = min of each pair's range, squared
            chunk_ranges_sq = np.minimum(
                ranges_sq[start:end].reshape(-1, 1),
                ranges_sq.reshape(1, -1),
            )

            # Mask: within range AND upper triangle only (j > i)
            mask = dist_sq <= chunk_ranges_sq
            # Zero out lower triangle + diagonal (only keep j > i pairs)
            for bi in range(chunk_size):
                i = start + bi
                mask[bi, :i + 1] = False

            # Extract all (row_in_chunk, col) pairs
            rows, cols = np.nonzero(mask)
            # Convert to Python ints and populate sets
            rows_py = (rows + start).tolist()
            cols_py = cols.tolist()
            for i_idx, j_idx in zip(rows_py, cols_py):
                self._neighbours[ids[i_idx]].add(ids[j_idx])
                self._neighbours[ids[j_idx]].add(ids[i_idx])

    def remove_node(self, node_id: bytes) -> None:
        """Remove a dead node from the neighbour graph."""
        if node_id in self._neighbours:
            for nb_id in self._neighbours[node_id]:
                self._neighbours.get(nb_id, set()).discard(node_id)
            del self._neighbours[node_id]

    def neighbour_count(self, nid: bytes) -> int:
        return len(self._neighbours.get(nid, []))

    def avg_neighbours(self) -> float:
        if not self._neighbours:
            return 0.0
        return sum(len(v) for v in self._neighbours.values()) / len(self._neighbours)

    def transmit(self, source: "SimNode", frame: SimFrame) -> None:
        self.pending.append(_PendingTX(source.node_id, source.position, frame))

    def is_neighbour(self, a: bytes, b: bytes) -> bool:
        """Check if two nodes are within radio range (O(1) set lookup)."""
        return b in self._neighbours.get(a, set())

    def deliver_pending(self) -> int:
        batch = self.pending
        self.pending = []
        deliveries = 0
        for tx in batch:
            for nid in self._neighbours.get(tx.source_id, []):
                node = self.nodes.get(nid)
                if node is None or node.is_dead or node.is_offline:
                    continue
                if self.packet_loss > 0 and self._rng.random() < self.packet_loss:
                    continue
                node.rx_queue.append(tx.frame)
                deliveries += 1
        return deliveries


def _distance(a: Tuple[float, float], b: Tuple[float, float]) -> float:
    return math.hypot(a[0] - b[0], a[1] - b[1])


# ===================================================================
# SimNode -- a virtual SPARK node (no threads)
# ===================================================================

class SimNode:
    """
    Lightweight virtual SPARK node driven by tick calls.

    Uses the real SPARK crypto (build_onion / peel_layer / envelopes)
    but replaces PeerManager / RegionManager with a single RoutingTable
    backed by k-buckets + gossip.
    """

    def __init__(
        self,
        index: int,
        position: Tuple[float, float],
        medium: SimMedium,
        rng: random.Random,
        effective_range: float = 1500.0,
    ):
        self.index = index
        self.position = position
        self._medium = medium
        self._rng = rng
        self.effective_range = effective_range

        # Identity (real Ed25519 / X25519)
        self.identity: IdentityKey = generate_identity()
        self.node_id: bytes = self.identity.node_id
        self.node_id_short: str = self.node_id.hex()[:8]

        # XOR routing table
        self.routing_table = RoutingTable(self.node_id)

        # Inbox  (message_id, payload_bytes)
        self.inbox: List[Tuple[bytes, bytes]] = []

        # Full direct-neighbour list (populated after medium builds graph).
        # Keys = neighbour node_id, values = public_key bytes.
        # NOT limited by k-bucket capacity -- essential for path diversity.
        self.direct_peers: Dict[bytes, bytes] = {}

        # Per-link encryption: set of neighbour node_ids with established
        # link sessions (DH handshake completed + identity exchanged).
        # Only neighbours in this set can forward/receive data frames.
        self.link_sessions: Set[bytes] = set()

        # RX queue (filled by medium, drained by tick_receive)
        self.rx_queue: List[SimFrame] = []

        # Node state
        self.is_dead: bool = False
        self.is_offline: bool = False

        # Hop-by-hop ACK: messages held while awaiting downstream ACK
        self._pending_forwards: Dict[int, PendingForward] = {}
        self._tracking_seq = 0

        # Dedup
        self._seen: Set[int] = set()

        # TX queue (congestion management)
        self.tx_queue: List[SimFrame] = []
        self.tx_this_tick: int = 0
        self._rate_limited: bool = False  # enabled during messaging phase
        self._ack_timeout: int = HOP_ACK_TIMEOUT  # can be increased for congestion

        # RF realism: half-duplex + airtime
        self.busy_until: int = 0      # tick number until which this node is deaf

        # Trust system
        self._trust: Dict[bytes, int] = {}           # node_id -> score
        self._forward_sent: Dict[bytes, int] = {}    # node_id -> msgs sent via
        self._forward_acked: Dict[bytes, int] = {}   # node_id -> msgs ACKed via
        self._suspect_count: Dict[bytes, int] = {}   # multi-path failure counter

        # Authenticated E2E ACK tracking
        self._pending_e2e: Dict[bytes, bytes] = {}  # msg_id -> receipt_token
        self._e2e_confirmed: Set[bytes] = set()      # msg_ids with verified ACK

        # Malicious node state (set externally by simulation)
        self.is_malicious: bool = False

        # Counters
        self._frame_seq = 0
        self._beacon_seq = 0
        self.tx_count = 0
        self.rx_count = 0

    # ---------- helpers --------------------------------------------------

    def _next_fid(self) -> int:
        self._frame_seq += 1
        return hash((id(self), self._frame_seq))

    def _next_tracking(self) -> int:
        self._tracking_seq += 1
        return hash((id(self), "trk", self._tracking_seq))

    def _transmit(self, frame: SimFrame) -> None:
        if self.is_dead or self.is_offline:
            return

        if not self._rate_limited:
            # Discovery phase or rate limiting disabled -- transmit immediately
            self._medium.transmit(self, frame)
            self.tx_count += 1
            return

        # ACK/NACK bypass the queue (tiny packets, critical for reliability)
        if frame.frame_type in (FRAME_HOP_ACK, FRAME_HOP_NACK):
            self._medium.transmit(self, frame)
            self.tx_count += 1
            return

        # Rate-limited: transmit if under budget, else queue (FIFO)
        if self.tx_this_tick < MAX_TX_PER_TICK:
            self.tx_this_tick += 1
            self._medium.transmit(self, frame)
            self.tx_count += 1
        elif len(self.tx_queue) < MAX_QUEUE_SIZE:
            self.tx_queue.append(frame)
        # else: extreme congestion, frame dropped (should be very rare)

    def tick_drain_queue(self) -> bool:
        """
        Drain queued TX frames up to the per-tick rate limit.
        Called at the start of each propagation tick.
        Returns True if queue still has frames.
        """
        self.tx_this_tick = 0
        while self.tx_queue and self.tx_this_tick < MAX_TX_PER_TICK:
            frame = self.tx_queue.pop(0)
            self.tx_this_tick += 1
            self._medium.transmit(self, frame)
            self.tx_count += 1
        return len(self.tx_queue) > 0

    def kill(self) -> None:
        """Permanently kill this node (hardware failure)."""
        self.is_dead = True
        self.rx_queue.clear()
        self.tx_queue.clear()
        self._pending_forwards.clear()
        self.link_sessions.clear()
        self._medium.remove_node(self.node_id)

    def remove_dead_peer(self, dead_id: bytes) -> None:
        """Remove a dead node from this node's knowledge."""
        self.direct_peers.pop(dead_id, None)
        self.link_sessions.discard(dead_id)
        self.routing_table.remove_peer(dead_id)
        self._trust.pop(dead_id, None)
        self._forward_sent.pop(dead_id, None)
        self._forward_acked.pop(dead_id, None)
        self._suspect_count.pop(dead_id, None)

    # ---------- trust helpers ------------------------------------------------

    def _get_trust(self, node_id: bytes) -> int:
        return self._trust.get(node_id, TRUST_INITIAL)

    def _adjust_trust(self, node_id: bytes, delta: int) -> None:
        score = self._trust.get(node_id, TRUST_INITIAL)
        self._trust[node_id] = max(TRUST_MIN, min(TRUST_MAX, score + delta))

    def _trust_weight(self, node_id: bytes) -> float:
        """Routing weight based on trust score.
        
        Aggressive weighting so low-trust nodes are strongly avoided:
          >= TRUST_NORMAL:       1.0  (fully trusted)
          DEPRIORITIZE..NORMAL:  0.2 - 1.0  (linearly scaled)
          < DEPRIORITIZE:        0.01 - 0.2  (nearly excluded)
        """
        s = self._get_trust(node_id)
        if s >= TRUST_NORMAL:
            return 1.0
        elif s >= TRUST_DEPRIORITIZE:
            return 0.2 + 0.8 * (s - TRUST_DEPRIORITIZE) / (TRUST_NORMAL - TRUST_DEPRIORITIZE)
        else:
            return max(0.01, s / TRUST_DEPRIORITIZE * 0.2)

    def _record_forward_ok(self, via_node: bytes) -> None:
        self._forward_sent[via_node] = self._forward_sent.get(via_node, 0) + 1
        self._forward_acked[via_node] = self._forward_acked.get(via_node, 0) + 1
        self._adjust_trust(via_node, T_FORWARD_OK)
        # Reduce suspect counter on success
        if via_node in self._suspect_count and self._suspect_count[via_node] > 0:
            self._suspect_count[via_node] -= 1

    def _record_forward_fail(self, via_node: bytes) -> None:
        self._forward_sent[via_node] = self._forward_sent.get(via_node, 0) + 1
        self._adjust_trust(via_node, T_FORWARD_FAIL)

    def _record_suspect(self, node_id: bytes) -> None:
        """Multi-path: this node was the common failure point."""
        cnt = self._suspect_count.get(node_id, 0) + 1
        self._suspect_count[node_id] = cnt
        if cnt >= SUSPECT_THRESHOLD:
            self._adjust_trust(node_id, T_SUSPECT_RELAY)

    # ---------- tick: challenge-response -----------------------------------

    def tick_challenges(self) -> None:
        """Send challenge nonces to a subset of link partners."""
        if self.is_dead or self.is_offline:
            return
        # Challenge a random subset of linked peers each cycle
        linked = list(self.link_sessions)
        if not linked:
            return
        target = self._rng.choice(linked)
        nonce = self._rng.getrandbits(64)
        self._transmit(SimFrame(
            frame_id=self._next_fid(),
            frame_type=FRAME_CHALLENGE,
            sender_id=self.node_id,
            dest_id=target,
            next_hop=target,
            payload=nonce,
            ttl=1,
        ))

    def _on_challenge(self, frame: SimFrame) -> None:
        """Respond to a challenge with our node_id (simulates Ed25519 sign)."""
        if self.is_malicious:
            # Malicious nodes still respond to challenges to maintain cover
            pass
        nonce = frame.payload
        self._transmit(SimFrame(
            frame_id=self._next_fid(),
            frame_type=FRAME_CHALLENGE_RESP,
            sender_id=self.node_id,
            dest_id=frame.sender_id,
            next_hop=frame.sender_id,
            payload=(nonce, self.node_id),
            ttl=1,
        ))

    def _on_challenge_resp(self, frame: SimFrame) -> None:
        """Verify a challenge response."""
        nonce, claimed_id = frame.payload
        if claimed_id == frame.sender_id:
            self._adjust_trust(frame.sender_id, T_CHALLENGE_PASS)
        else:
            self._adjust_trust(frame.sender_id, T_CHALLENGE_FAIL)

    # ---------- tick: beacon (identity-free handshake) --------------------

    def tick_handshake(self) -> None:
        """Broadcast an anonymous handshake beacon (no identity)."""
        if self.is_dead or self.is_offline:
            return
        frame = SimFrame(
            frame_id=self._next_fid(),
            frame_type=FRAME_HANDSHAKE,
            sender_id=self.node_id,
            dest_id=b"",
            next_hop=b"",  # broadcast
            payload=None,  # identity-free: no data
            ttl=1,
        )
        self._transmit(frame)

    def tick_link_identity(self) -> None:
        """Send signed identity + gossip to all established link partners.
        
        This replaces the old cleartext beacon gossip.  Identity and
        routing info are only shared over encrypted links.
        """
        if self.is_dead or self.is_offline:
            return
        gossip = self.routing_table.get_gossip_entries(rng=self._rng)
        identity_data = {
            "nid": self.node_id,
            "pk": self.identity.x25519_public_bytes,
            "gossip": [(e.node_id, e.public_key) for e in gossip],
        }
        for peer_id in self.link_sessions:
            frame = SimFrame(
                frame_id=self._next_fid(),
                frame_type=FRAME_LINK_IDENTITY,
                sender_id=self.node_id,
                dest_id=peer_id,
                next_hop=peer_id,  # unicast to specific link partner
                payload=identity_data,
                ttl=1,
            )
            self._transmit(frame)

    # Legacy beacon (backward compat, unused with link encryption)
    def tick_beacon(self) -> None:
        self.tick_handshake()

    # ---------- tick: receive --------------------------------------------

    def tick_receive(self) -> None:
        if self.is_dead or self.is_offline:
            self.rx_queue.clear()
            return
        batch = self.rx_queue
        self.rx_queue = []
        for frame in batch:
            if frame.frame_id in self._seen:
                # Re-ACK for retransmitted frames (handles lost ACKs)
                if (frame.ack_to and frame.ack_tracking
                        and frame.next_hop == self.node_id):
                    self._send_ack(frame.ack_to, frame.ack_tracking)
                continue
            self._seen.add(frame.frame_id)

            if frame.next_hop and frame.next_hop != self.node_id:
                continue

            self.rx_count += 1

            if frame.frame_type == FRAME_HANDSHAKE:
                self._on_handshake(frame)
            elif frame.frame_type == FRAME_LINK_IDENTITY:
                self._on_link_identity(frame)
            elif frame.frame_type == FRAME_BEACON:
                self._on_beacon(frame)
            elif frame.frame_type == FRAME_ONION:
                self._on_onion(frame)
            elif frame.frame_type == FRAME_DIRECT:
                self._on_direct(frame)
            elif frame.frame_type == FRAME_DELIVERY:
                self._on_delivery(frame)
            elif frame.frame_type == FRAME_ACK:
                self._on_e2e_ack(frame)
            elif frame.frame_type == FRAME_HOP_ACK:
                self._on_hop_ack(frame)
            elif frame.frame_type == FRAME_HOP_NACK:
                self._on_hop_nack(frame)
            elif frame.frame_type == FRAME_CHALLENGE:
                self._on_challenge(frame)
            elif frame.frame_type == FRAME_CHALLENGE_RESP:
                self._on_challenge_resp(frame)

    # ---------- tick: pending forward timeouts ----------------------------

    def tick_pending(self) -> None:
        """Check for ACK timeouts on pending forwards and retry."""
        if self.is_dead or self.is_offline:
            return
        expired = []
        for tid, pf in self._pending_forwards.items():
            pf.timeout -= 1
            if pf.timeout <= 0:
                expired.append(tid)
        for tid in expired:
            pf = self._pending_forwards.get(tid)
            if pf:
                self._retry_forward(pf)

    # ---------- handshake handler (identity-free link establishment) ------

    def _on_handshake(self, frame: SimFrame) -> None:
        """Handle anonymous handshake beacon -- establish link session.
        
        In the real protocol, this would involve DH key exchange.
        In the simulation, we model the result: both sides add each
        other to link_sessions after exchanging handshakes.
        """
        peer_id = frame.sender_id
        if peer_id == self.node_id:
            return
        # Mutual link establishment (DH complete)
        self.link_sessions.add(peer_id)

    def _on_link_identity(self, frame: SimFrame) -> None:
        """Handle signed identity received over an established link.
        
        This is the encrypted-channel equivalent of the old cleartext
        beacon.  Only processes data from established link partners.
        """
        peer_id = frame.sender_id
        if peer_id not in self.link_sessions:
            return  # reject: no link session established
        
        data = frame.payload
        sender_id = data["nid"]
        public_key = data["pk"]
        self.routing_table.add_peer(sender_id, public_key, is_direct=True)
        self._adjust_trust(sender_id, T_BEACON_OK)
        for nid, pk in data.get("gossip", []):
            if nid != self.node_id:
                self.routing_table.add_peer(
                    nid, pk, next_hop=sender_id, is_direct=False,
                )

    # ---------- legacy beacon handler (backward compat) ------------------

    def _on_beacon(self, frame: SimFrame) -> None:
        data = frame.payload
        sender_id = data["nid"]
        public_key = data["pk"]
        self.routing_table.add_peer(sender_id, public_key, is_direct=True)
        for nid, pk in data.get("gossip", []):
            if nid != self.node_id:
                self.routing_table.add_peer(
                    nid, pk, next_hop=sender_id, is_direct=False,
                )

    # ---------- onion handler --------------------------------------------

    def _on_onion(self, frame: SimFrame) -> None:
        envelope: bytes = frame.payload

        # MALICIOUS BEHAVIOR: selective dropping
        # A compromised node silently drops a fraction of forwarded
        # messages while still ACKing upstream (to maintain trust).
        if self.is_malicious and frame.dest_id != self.node_id:
            if self._rng.random() < MALICIOUS_DROP_RATE:
                # ACK upstream to hide the drop (appear cooperative)
                self._send_ack(frame.ack_to, frame.ack_tracking)
                return  # silently discard

        if frame.dest_id == self.node_id:
            # We are the target gateway -- peel the onion layer
            result = self._try_peel(envelope)
            if result is None:
                self._send_nack(frame.ack_to, frame.ack_tracking)
                return

            # Gateway received the outer frame -- ACK the relay that
            # delivered it (this onion leg is complete).
            self._send_ack(frame.ack_to, frame.ack_tracking)

            action = result[0]

            if action == "FORWARD":
                next_gw_id = result[1]
                inner_env  = result[2]
                # Start a new independent forwarding chain for the
                # inner onion payload (ack_to="" = we are the origin)
                self._xor_forward(SimFrame(
                    frame_id=self._next_fid(),
                    frame_type=FRAME_ONION,
                    sender_id=self.node_id,
                    dest_id=next_gw_id,
                    next_hop=b"",
                    payload=inner_env,
                    ttl=500,
                ))

            elif action == "DELIVER_LOCAL":
                msg_id        = result[1]
                payload       = result[2]
                pay_type      = result[3]
                receipt_token = result[4]
                # Payload has sender_node_id prepended (16 bytes)
                sender_node_id = payload[:16]
                payload = payload[16:]
                if pay_type & PAYLOAD_COMPRESSED:
                    try:
                        payload = zlib.decompress(payload)
                    except zlib.error:
                        pass
                self.inbox.append((msg_id, payload))
                # Send authenticated E2E ACK back to original sender
                self._xor_forward(SimFrame(
                    frame_id=self._next_fid(),
                    frame_type=FRAME_ACK,
                    sender_id=self.node_id,
                    dest_id=sender_node_id,
                    next_hop=b"",
                    payload=(msg_id, receipt_token),
                    ttl=500,
                ))

            elif action == "DELIVER_REGION":
                dest_nid      = result[1]
                msg_id        = result[2]
                payload       = result[3]
                pay_type      = result[4]
                receipt_token = result[5]
                # payload = sender_node_id(16) + msg_data(maybe compressed)
                # Extract sender_id, decompress msg_data, re-prepend for
                # the delivery frame so final recipient can send E2E ACK
                sender_nid_region = payload[:16]
                msg_body = payload[16:]
                if pay_type & PAYLOAD_COMPRESSED:
                    try:
                        msg_body = zlib.decompress(msg_body)
                    except zlib.error:
                        pass
                # Re-prepend sender_node_id for the final recipient
                full_payload = sender_nid_region + msg_body
                # Pass receipt_token in delivery frame payload for
                # the final recipient to send the E2E ACK
                self._xor_forward(SimFrame(
                    frame_id=self._next_fid(),
                    frame_type=FRAME_DELIVERY,
                    sender_id=self.node_id,
                    dest_id=dest_nid,
                    next_hop=b"",
                    payload=(msg_id, full_payload, receipt_token),
                    ttl=500,
                ))
        else:
            # Relay: ACK upstream immediately (receipt confirmed),
            # then forward independently toward dest_id
            self._send_ack(frame.ack_to, frame.ack_tracking)
            self._xor_forward(frame)

    def _try_peel(self, envelope: bytes):
        """Attempt to decrypt an onion layer (tries layers 1-3)."""
        for layer in (1, 2, 3):
            try:
                routing_info, delivery_info = peel_layer(
                    envelope, self.identity, layer,
                )
            except (OnionError, Exception):
                continue

            if routing_info is not None:
                return (
                    "FORWARD",
                    routing_info.next_region_id,
                    routing_info.inner_envelope,
                    routing_info.ttl,
                )
            if delivery_info is not None:
                if delivery_info.dest_node_id == self.node_id:
                    return (
                        "DELIVER_LOCAL",
                        delivery_info.message_id,
                        delivery_info.payload,
                        delivery_info.payload_type,
                        delivery_info.receipt_token,
                    )
                else:
                    return (
                        "DELIVER_REGION",
                        delivery_info.dest_node_id,
                        delivery_info.message_id,
                        delivery_info.payload,
                        delivery_info.payload_type,
                        delivery_info.receipt_token,
                    )
        return None

    # ---------- direct message handler -----------------------------------

    def _on_direct(self, frame: SimFrame) -> None:
        envelope: bytes = frame.payload
        try:
            plaintext = open_envelope(
                envelope, self.identity, b"spark-direct-v1",
            )
            msg = DirectMessagePayload.from_bytes(plaintext)
        except Exception:
            return
        payload = msg.payload
        if msg.payload_type & PAYLOAD_COMPRESSED:
            try:
                payload = zlib.decompress(payload)
            except zlib.error:
                pass
        self.inbox.append((msg.message_id, payload))

    # ---------- last-mile delivery handler --------------------------------

    def _on_delivery(self, frame: SimFrame) -> None:
        # MALICIOUS: selective dropping of delivery frames
        if self.is_malicious and frame.dest_id != self.node_id:
            if self._rng.random() < MALICIOUS_DROP_RATE:
                self._send_ack(frame.ack_to, frame.ack_tracking)
                return
        if frame.dest_id == self.node_id:
            # Unpack: payload may include receipt_token (new) or not (legacy)
            pld = frame.payload
            if len(pld) == 3:
                msg_id, payload, receipt_token = pld
            else:
                msg_id, payload = pld
                receipt_token = None
            # Payload has sender_node_id prepended (16 bytes)
            sender_node_id = payload[:16]
            real_payload = payload[16:]
            self.inbox.append((msg_id, real_payload))
            self._send_ack(frame.ack_to, frame.ack_tracking)
            # Send authenticated E2E ACK back to original sender
            if receipt_token is not None:
                self._xor_forward(SimFrame(
                    frame_id=self._next_fid(),
                    frame_type=FRAME_ACK,
                    sender_id=self.node_id,
                    dest_id=sender_node_id,
                    next_hop=b"",
                    payload=(msg_id, receipt_token),
                    ttl=500,
                ))
        else:
            self._send_ack(frame.ack_to, frame.ack_tracking)
            self._xor_forward(frame)

    # ---------- E2E ACK handler -------------------------------------------

    def _on_e2e_ack(self, frame: SimFrame) -> None:
        """Handle an authenticated E2E delivery ACK routed back to sender."""
        # Malicious nodes drop E2E ACKs too (same behaviour as data)
        if self.is_malicious and frame.dest_id != self.node_id:
            if self._rng.random() < MALICIOUS_DROP_RATE:
                self._send_ack(frame.ack_to, frame.ack_tracking)
                return
        if frame.dest_id == self.node_id:
            # We are the original sender -- verify the receipt token
            msg_id, receipt_token = frame.payload
            expected = self._pending_e2e.pop(msg_id, None)
            if expected is not None and receipt_token == expected:
                self._e2e_confirmed.add(msg_id)
            self._send_ack(frame.ack_to, frame.ack_tracking)
        else:
            # Relay the E2E ACK toward the sender
            self._send_ack(frame.ack_to, frame.ack_tracking)
            self._xor_forward(frame)

    # ---------- hop-by-hop ACK/NACK handlers ------------------------------

    def _on_hop_ack(self, frame: SimFrame) -> None:
        """Downstream confirmed receipt -- discard held copy.
        
        NOTE: hop ACKs do NOT update trust.  A malicious node can ACK
        a hop and then silently drop the payload.  Trust is only updated
        based on E2E delivery success/failure, tracked by the sender.
        """
        tracking_id = frame.payload
        self._pending_forwards.pop(tracking_id, None)

    def _on_hop_nack(self, frame: SimFrame) -> None:
        """Downstream couldn't forward -- try next neighbour."""
        tracking_id = frame.payload
        pf = self._pending_forwards.get(tracking_id)
        if pf is None:
            return
        self._retry_forward(pf, is_nack=True)

    # ---------- ACK/NACK senders -----------------------------------------

    def _send_ack(self, to_node: bytes, tracking_id: int) -> None:
        """Send a small ACK packet back to the upstream relay."""
        if not to_node:
            return  # we are the message origin, nobody to ACK
        self._transmit(SimFrame(
            frame_id=self._next_fid(),
            frame_type=FRAME_HOP_ACK,
            sender_id=self.node_id,
            dest_id=to_node,
            next_hop=to_node,
            payload=tracking_id,
            ttl=1,
        ))

    def _send_nack(self, to_node: bytes, tracking_id: int) -> None:
        """Send a small NACK packet back to the upstream relay."""
        if not to_node:
            return
        self._transmit(SimFrame(
            frame_id=self._next_fid(),
            frame_type=FRAME_HOP_NACK,
            sender_id=self.node_id,
            dest_id=to_node,
            next_hop=to_node,
            payload=tracking_id,
            ttl=1,
        ))

    # ---------- XOR forwarding with hop ACK ------------------------------

    def _find_next_hop(
        self, dest_id: bytes, exclude: Set[bytes],
        randomness: float = 0.0,
    ) -> Optional[bytes]:
        """
        Find the best next hop toward *dest_id*, excluding nodes in
        *exclude* (visited + already tried).

        SECURITY: Only neighbours with established link sessions are
        considered.  This ensures all data travels over encrypted links.

        TRUST: Routing weights are multiplied by trust weight so that
        low-trust neighbours are deprioritized but not excluded.

        Args:
            randomness: 0.0 = pure greedy, 1.0 = uniform random among
                        candidates.  Increased on retries to break out
                        of deterministic routing patterns.
        """
        # Build exclusion set: visited + tried + unlinked neighbours
        full_exclude = set(exclude)
        for nb_id in self.direct_peers:
            if nb_id not in self.link_sessions:
                full_exclude.add(nb_id)

        # 1. Strict XOR improvement (trust check: skip avoided nodes
        #    unless they're the only option)
        if randomness < 0.3:
            route = self.routing_table.route_to(dest_id, exclude=full_exclude)
            if route is not None:
                nid = route[0]
                trust = self._get_trust(nid)
                if trust >= TRUST_DEPRIORITIZE:
                    return nid

        # 2. Trust-weighted random exploratory step
        candidates: List[Tuple[bytes, int]] = []
        for nb_id in self.direct_peers:
            if nb_id in full_exclude:
                continue
            d = xor_distance(nb_id, dest_id)
            candidates.append((nb_id, d))

        if not candidates:
            # Last resort: check route_to even if we skipped it above
            route = self.routing_table.route_to(dest_id, exclude=full_exclude)
            if route is not None:
                return route[0]
            return None
        if len(candidates) == 1:
            return candidates[0][0]

        # Sort by distance, assign weights with trust and randomness
        candidates.sort(key=lambda x: x[1])

        # Base weight: exponential decay by XOR rank
        # Randomness flattens the distribution so further neighbours
        # have a realistic chance of being selected
        base_decay = max(0.3, 1.0 - randomness)  # 1.0 → greedy, 0.3 → nearly flat
        weights = []
        for i, (nid, _d) in enumerate(candidates):
            xor_weight = base_decay ** i  # flatter as randomness increases
            trust_w = self._trust_weight(nid)
            weights.append(xor_weight * trust_w)

        total_w = sum(weights)
        if total_w <= 0:
            return candidates[0][0]
        r = self._rng.random() * total_w
        cumulative = 0.0
        for (nid, _d), w in zip(candidates, weights):
            cumulative += w
            if r <= cumulative:
                return nid
        return candidates[0][0]  # fallback

    def _xor_forward(self, frame: SimFrame) -> None:
        """
        Forward a frame toward frame.dest_id using hop-by-hop ACK.

        Flow:
        1. Pick best next hop, send the payload forward.
        2. Hold a copy in _pending_forwards while awaiting receipt ACK.
        3. On ACK from next hop: discard the held copy (handoff complete).
        4. On NACK from next hop (it couldn't forward onward):
           pick the next best neighbour and retry.
        5. On timeout (next hop didn't ACK -- died or packet lost):
           retry with a different neighbour.
        6. If ALL neighbours are exhausted: NACK upstream so the
           *previous* relay can try a different path to us.

        Only small ACK/NACK packets ever travel backward -- the
        payload is always held locally and only moves forward.
        """
        if frame.ttl <= 0:
            return

        visited_set = set(frame.visited)
        visited_set.add(self.node_id)
        new_visited = frame.visited + (self.node_id,)

        tried: Set[bytes] = set()
        exclude = visited_set | tried

        next_hop = self._find_next_hop(frame.dest_id, exclude,
                                        randomness=frame.randomness)
        if next_hop is None:
            # No reachable neighbour at all -- NACK upstream
            self._send_nack(frame.ack_to, frame.ack_tracking)
            return

        tried.add(next_hop)
        tracking_id = self._next_tracking()
        fid = self._next_fid()

        out = SimFrame(
            frame_id=fid,
            frame_type=frame.frame_type,
            sender_id=self.node_id,
            dest_id=frame.dest_id,
            next_hop=next_hop,
            payload=frame.payload,
            ttl=frame.ttl - 1,
            hop_count=frame.hop_count + 1,
            visited=new_visited,
            ack_to=self.node_id,
            ack_tracking=tracking_id,
            randomness=frame.randomness,
        )
        self._transmit(out)

        # Hold a copy for retry on NACK / timeout
        stored_frame = SimFrame(
            frame_id=0,
            frame_type=frame.frame_type,
            sender_id=self.node_id,
            dest_id=frame.dest_id,
            next_hop=b"",
            payload=frame.payload,
            ttl=frame.ttl - 1,
            hop_count=frame.hop_count,
            visited=new_visited,
            randomness=frame.randomness,
        )

        # Timeout accounts for queue drain time: if the frame was queued
        # (rate limited), the downstream can't ACK until it's actually
        # transmitted.  queue_depth / TX_RATE + base timeout.
        effective_timeout = self._ack_timeout + len(self.tx_queue) * 2
        self._pending_forwards[tracking_id] = PendingForward(
            tracking_id=tracking_id,
            frame=stored_frame,
            forwarded_to=next_hop,
            upstream_node=frame.ack_to,
            upstream_tracking=frame.ack_tracking,
            tried=tried,
            timeout=effective_timeout,
            last_fid=fid,
            same_retries=0,
        )

    def _retry_forward(self, pf: PendingForward, is_nack: bool = False) -> None:
        """
        Retry forwarding.  Called on NACK or ACK timeout.

        On timeout (likely packet loss): retransmit to the SAME
        neighbour using the SAME frame_id -- the neighbour will
        re-ACK via duplicate detection, avoiding path duplication.

        On NACK (neighbour explicitly can't forward): switch to
        the next untried neighbour.
        """
        # --- Retransmit to SAME neighbour (packet loss recovery) ---
        if not is_nack and pf.same_retries < MAX_SAME_RETRIES:
            pf.same_retries += 1
            # Resend the SAME frame_id so the neighbour re-ACKs
            out = SimFrame(
                frame_id=pf.last_fid,
                frame_type=pf.frame.frame_type,
                sender_id=self.node_id,
                dest_id=pf.frame.dest_id,
                next_hop=pf.forwarded_to,
                payload=pf.frame.payload,
                ttl=pf.frame.ttl,
                hop_count=pf.frame.hop_count + 1,
                visited=pf.frame.visited,
                ack_to=self.node_id,
                ack_tracking=pf.tracking_id,
            )
            self._transmit(out)
            pf.timeout = self._ack_timeout + len(self.tx_queue) * 2
            return

        # --- Switch to a DIFFERENT neighbour ---
        visited_set = set(pf.frame.visited)
        exclude = visited_set | pf.tried

        next_hop = self._find_next_hop(pf.frame.dest_id, exclude,
                                        randomness=pf.frame.randomness)
        if next_hop is None:
            # All neighbours exhausted -- record failure for the last tried
            self._record_forward_fail(pf.forwarded_to)
            self._pending_forwards.pop(pf.tracking_id, None)
            return

        pf.tried.add(next_hop)
        new_tracking = self._next_tracking()
        fid = self._next_fid()

        out = SimFrame(
            frame_id=fid,
            frame_type=pf.frame.frame_type,
            sender_id=self.node_id,
            dest_id=pf.frame.dest_id,
            next_hop=next_hop,
            payload=pf.frame.payload,
            ttl=pf.frame.ttl,
            hop_count=pf.frame.hop_count + 1,
            visited=pf.frame.visited,
            ack_to=self.node_id,
            ack_tracking=new_tracking,
            randomness=pf.frame.randomness,
        )
        self._transmit(out)

        # Replace the old pending entry with the new tracking ID
        self._pending_forwards.pop(pf.tracking_id, None)
        pf.tracking_id = new_tracking
        pf.forwarded_to = next_hop
        pf.timeout = self._ack_timeout + len(self.tx_queue) * 2
        pf.last_fid = fid
        pf.same_retries = 0
        self._pending_forwards[new_tracking] = pf

    # ---------- message sending ------------------------------------------

    def send_message(
        self, recipient_id: bytes, payload: bytes,
        exclude_gateways: Optional[Set[bytes]] = None,
        randomness: float = 0.0,
    ) -> Dict:
        peer = self.routing_table.get_peer(recipient_id)
        if peer and peer.is_direct:
            return self._send_direct(recipient_id, peer.public_key, payload)
        return self._send_onion(recipient_id, payload, exclude_gateways,
                                randomness=randomness)

    def send_probe(
        self, via_neighbor: bytes, target_id: bytes, target_pubkey: bytes,
    ) -> Optional[bytes]:
        """Send a probe (indistinguishable from real onion traffic) through
        a specific neighbor to a known 2-hop target.

        The probe is a real 1-layer onion message encrypted for the target.
        It's sent as a FRAME_ONION frame with next_hop forced to via_neighbor,
        so the specific neighbor MUST forward it.

        Returns the message_id (for E2E ACK matching) or None on error.
        """
        payload = b"probe"
        ts = int(time.time())
        mid = generate_message_id(self.node_id, target_id, ts)

        # Prepend sender node_id for E2E ACK return routing
        msg_data = self.node_id + payload

        try:
            onion, receipt_token = build_onion_1layer(
                dest_node_id=target_id,
                message_id=mid,
                timestamp=ts,
                payload_type=0,
                payload=msg_data,
                dest_gateway_pubkey=target_pubkey,
                ttl=255,
            )
        except Exception:
            return None

        self._pending_e2e[mid] = receipt_token

        # Force first hop to the specific neighbor being tested
        self._transmit(SimFrame(
            frame_id=self._next_fid(),
            frame_type=FRAME_ONION,
            sender_id=self.node_id,
            dest_id=target_id,
            next_hop=via_neighbor,
            payload=onion.to_bytes(),
            ttl=500,
        ))
        return mid

    def _send_direct(
        self, recipient_id: bytes, pubkey: bytes, payload: bytes,
    ) -> Dict:
        compressed = zlib.compress(payload, 9)
        if len(compressed) < len(payload):
            msg_data, ptype = compressed, PAYLOAD_COMPRESSED
        else:
            msg_data, ptype = payload, 0

        ts = int(time.time())
        mid = generate_message_id(self.node_id, recipient_id, ts)
        dm = DirectMessagePayload(
            message_id=mid, timestamp=ts, payload_type=ptype, payload=msg_data,
        )
        try:
            envelope = seal_envelope_for_pubkey_bytes(
                dm.to_bytes(), pubkey, b"spark-direct-v1",
            )
        except Exception as e:
            return {"error": str(e), "mode": "direct", "onion_layers": 0}

        self._transmit(SimFrame(
            frame_id=self._next_fid(),
            frame_type=FRAME_DIRECT,
            sender_id=self.node_id,
            dest_id=recipient_id,
            next_hop=recipient_id,
            payload=envelope,
            ttl=1,
        ))
        return {"message_id": mid.hex(), "mode": "direct", "onion_layers": 0}

    def _send_onion(
        self, recipient_id: bytes, payload: bytes,
        exclude_gateways: Optional[Set[bytes]] = None,
        randomness: float = 0.0,
    ) -> Dict:
        compressed = zlib.compress(payload, 9)
        if len(compressed) < len(payload):
            msg_data, ptype = compressed, PAYLOAD_COMPRESSED
        else:
            msg_data, ptype = payload, 0

        # Prepend sender node_id so recipient can route E2E ACK back
        msg_data_with_sender = self.node_id + msg_data

        ts = int(time.time())
        mid = generate_message_id(self.node_id, recipient_id, ts)

        gws = self._select_gateways(recipient_id, exclude=exclude_gateways)
        if gws is None:
            # Adaptive: try 2-layer or 1-layer if 3 isn't possible
            gws = self._select_gateways_adaptive(recipient_id, exclude=exclude_gateways)
            if gws is None:
                return {"error": "cannot find gateways", "mode": "onion",
                        "onion_layers": 0}

        num_layers = len(gws)
        try:
            if num_layers == 3:
                g1, g2, g3 = gws
                onion, receipt_token = build_onion(
                    dest_node_id=recipient_id,
                    message_id=mid,
                    timestamp=ts,
                    payload_type=ptype,
                    payload=msg_data_with_sender,
                    layer3_gateway_pubkey=g3.public_key,
                    layer3_region_id=g3.node_id,
                    layer2_gateway_pubkey=g2.public_key,
                    layer2_region_id=g2.node_id,
                    layer1_gateway_pubkey=g1.public_key,
                    ttl=255,
                )
                first_dest = g1.node_id
                gw_ids = (g1.node_id, g2.node_id, g3.node_id)
            elif num_layers == 2:
                g1, g2 = gws
                onion, receipt_token = build_onion(
                    dest_node_id=recipient_id,
                    message_id=mid,
                    timestamp=ts,
                    payload_type=ptype,
                    payload=msg_data_with_sender,
                    layer3_gateway_pubkey=g2.public_key,
                    layer3_region_id=g2.node_id,
                    layer2_gateway_pubkey=g1.public_key,
                    layer2_region_id=g1.node_id,
                    layer1_gateway_pubkey=g1.public_key,
                    ttl=255,
                )
                first_dest = g1.node_id
                gw_ids = (g1.node_id, g2.node_id)
            else:  # 1 layer
                g1 = gws[0]
                onion, receipt_token = build_onion(
                    dest_node_id=recipient_id,
                    message_id=mid,
                    timestamp=ts,
                    payload_type=ptype,
                    payload=msg_data_with_sender,
                    layer3_gateway_pubkey=g1.public_key,
                    layer3_region_id=g1.node_id,
                    layer2_gateway_pubkey=g1.public_key,
                    layer2_region_id=g1.node_id,
                    layer1_gateway_pubkey=g1.public_key,
                    ttl=255,
                )
                first_dest = g1.node_id
                gw_ids = (g1.node_id,)
        except Exception as e:
            return {"error": str(e), "mode": "onion", "onion_layers": 0}

        # Store receipt token for E2E ACK verification
        self._pending_e2e[mid] = receipt_token

        # Inject -- sender is origin (ack_to="" -- nobody upstream)
        # Track the first hop chosen by _xor_forward
        pending_before = set(self._pending_forwards.keys())
        self._xor_forward(SimFrame(
            frame_id=self._next_fid(),
            frame_type=FRAME_ONION,
            sender_id=self.node_id,
            dest_id=first_dest,
            next_hop=b"",
            payload=onion.to_bytes(),
            ttl=500,
            randomness=randomness,
        ))
        pending_after = set(self._pending_forwards.keys())
        new_tracking = pending_after - pending_before
        first_hops = set()
        for tk in new_tracking:
            pf = self._pending_forwards.get(tk)
            if pf:
                first_hops.add(pf.forwarded_to)

        return {
            "message_id": mid.hex(),
            "mode": "onion",
            "onion_layers": num_layers,
            "gateway_ids": gw_ids,
            "gateways": tuple(g.hex()[:8] for g in gw_ids),
            "first_hops": first_hops,
        }

    def _select_gateways(
        self, recipient_id: bytes, exclude: Optional[Set[bytes]] = None,
    ):
        """
        Select 3 gateways for onion routing, excluding any node IDs in
        *exclude* (used for end-to-end retries with different paths).
        """
        all_entries = self.routing_table.get_all_entries()
        if exclude:
            all_entries = [e for e in all_entries if e.node_id not in exclude]
        if len(all_entries) < 3:
            return None

        my_region = node_region(self.node_id)

        all_entries.sort(key=lambda e: xor_distance(e.node_id, recipient_id))
        g3 = all_entries[0]

        g1 = None
        avoid1 = {my_region, node_region(g3.node_id)}
        for e in all_entries:
            if (e.is_direct
                    and e.node_id != g3.node_id
                    and node_region(e.node_id) not in avoid1):
                g1 = e
                break
        if g1 is None:
            for e in all_entries:
                if e.is_direct and e.node_id != g3.node_id:
                    g1 = e
                    break
        if g1 is None:
            for e in all_entries:
                if e.node_id != g3.node_id:
                    g1 = e
                    break
        if g1 is None:
            return None

        avoid2 = {node_region(g1.node_id), node_region(g3.node_id)}
        g2 = None
        for e in all_entries:
            if (e.node_id not in (g1.node_id, g3.node_id)
                    and node_region(e.node_id) not in avoid2):
                g2 = e
                break
        if g2 is None:
            for e in all_entries:
                if e.node_id not in (g1.node_id, g3.node_id):
                    g2 = e
                    break
        if g2 is None:
            return None

        return g1, g2, g3

    def _select_gateways_adaptive(
        self, recipient_id: bytes, exclude: Optional[Set[bytes]] = None,
    ):
        """
        Adaptive gateway selection: try 3, fall back to 2, then 1.
        Returns a list of 1-3 routing entries, or None.
        """
        all_entries = self.routing_table.get_all_entries()
        if exclude:
            all_entries = [e for e in all_entries if e.node_id not in exclude]
        if not all_entries:
            return None

        all_entries.sort(key=lambda e: xor_distance(e.node_id, recipient_id))

        # Best exit gateway (closest to destination)
        g3 = all_entries[0]

        if len(all_entries) < 2:
            return [g3]

        # Try to find g1 (entry gateway, preferably direct)
        g1 = None
        for e in all_entries:
            if e.is_direct and e.node_id != g3.node_id:
                g1 = e
                break
        if g1 is None:
            for e in all_entries:
                if e.node_id != g3.node_id:
                    g1 = e
                    break
        if g1 is None:
            return [g3]

        if len(all_entries) < 3:
            return [g1, g3]

        # Try to find g2 (middle relay)
        g2 = None
        for e in all_entries:
            if e.node_id not in (g1.node_id, g3.node_id):
                g2 = e
                break
        if g2 is None:
            return [g1, g3]

        return [g1, g2, g3]


# ===================================================================
# NetworkSimulation
# ===================================================================

@dataclass
class MessageResult:
    sender_short: str
    recipient_short: str
    delivered: bool
    mode: str
    onion_layers: int
    hops: int
    error: str = ""


class NetworkSimulation:
    """Orchestrates setup, discovery, messaging, and reporting."""

    def __init__(
        self,
        num_nodes: int,
        area_size: float,
        radio_range: float,
        beacon_cycles: int,
        num_messages: int,
        seed: Optional[int],
        verbose: bool,
        packet_loss: float = 0.0,
        range_variance: float = 0.0,
        node_death_rate: float = 0.0,
        dropout_rate: float = 0.0,
        bottleneck: int = 0,
        malicious_rate: float = 0.0,
    ):
        self.num_nodes = num_nodes
        self.area_size = area_size
        self.radio_range = radio_range
        self.beacon_cycles = beacon_cycles
        self.num_messages = num_messages
        self.verbose = verbose
        self.rng = random.Random(seed)

        self.packet_loss = packet_loss
        self.range_variance = range_variance
        self.node_death_rate = node_death_rate
        self.dropout_rate = dropout_rate
        self.bottleneck = bottleneck  # number of bridge nodes (0 = normal)
        self.malicious_rate = malicious_rate

        self.medium = SimMedium(radio_range, packet_loss, self.rng)
        self.nodes: List[SimNode] = []
        self.live_nodes: List[SimNode] = []
        self.results: List[MessageResult] = []

        self.nodes_killed: List[str] = []
        self.malicious_nodes: List[str] = []
        self.dropout_events = 0

    # ---- Phase 1: Setup ------------------------------------------------

    def phase_setup(self) -> None:
        print("\nPhase 1: Setup")
        t0 = time.time()

        if self.bottleneck > 0:
            self._setup_bottleneck(t0)
        else:
            self._setup_uniform(t0)

    def _setup_uniform(self, t0: float) -> None:
        """Standard uniform random placement."""
        print(f"  Generating {self.num_nodes} identities...", end="", flush=True)
        for i in range(self.num_nodes):
            x = self.rng.uniform(0, self.area_size)
            y = self.rng.uniform(0, self.area_size)

            if self.range_variance > 0:
                factor = 1.0 + self.rng.uniform(
                    -self.range_variance, self.range_variance)
                eff_range = self.radio_range * factor
            else:
                eff_range = self.radio_range

            node = SimNode(i, (x, y), self.medium, self.rng, eff_range)
            self.nodes.append(node)
            self.medium.register(node)
            if (i + 1) % 500 == 0:
                print(f" {i+1}", end="", flush=True)
        print(f"  done ({time.time()-t0:.1f}s)")
        self._finish_setup(t0)

    def _setup_bottleneck(self, t0: float) -> None:
        """
        Two dense clusters connected by a narrow bridge of N nodes.
        Simulates a worst-case geographic bottleneck (e.g. a mountain
        pass, river crossing, or sparsely populated corridor).

        Layout (area_size × area_size/3):
          Cluster A          Bridge          Cluster B
          [0, 40%]      [40%-60%]         [60%, 100%]
           (half nodes)  (N bridge)        (half nodes)
        """
        num_bridge = self.bottleneck
        num_cluster = (self.num_nodes - num_bridge) // 2
        num_cluster_b = self.num_nodes - num_bridge - num_cluster

        area_w = self.area_size
        area_h = self.area_size * 0.6  # wide enough for reasonable density
        gap_start = area_w * 0.40
        gap_end = area_w * 0.60

        print(f"  Bottleneck topology: {num_cluster}A + {num_bridge} bridge"
              f" + {num_cluster_b}B", flush=True)
        print(f"  Generating {self.num_nodes} identities...", end="", flush=True)

        idx = 0
        # Cluster A: left side
        for i in range(num_cluster):
            x = self.rng.uniform(0, gap_start - self.radio_range * 0.3)
            y = self.rng.uniform(0, area_h)
            eff_range = self._eff_range()
            node = SimNode(idx, (x, y), self.medium, self.rng, eff_range)
            self.nodes.append(node)
            self.medium.register(node)
            idx += 1
            if idx % 500 == 0:
                print(f" {idx}", end="", flush=True)

        # Bridge: narrow corridor between clusters
        # Spaced evenly along the gap, centered vertically
        bridge_spacing = (gap_end - gap_start) / max(1, num_bridge - 1)
        for i in range(num_bridge):
            x = gap_start + i * bridge_spacing
            y = area_h / 2 + self.rng.uniform(-200, 200)  # slight jitter
            eff_range = self.radio_range  # bridge nodes get full range
            node = SimNode(idx, (x, y), self.medium, self.rng, eff_range)
            self.nodes.append(node)
            self.medium.register(node)
            idx += 1

        # Cluster B: right side
        for i in range(num_cluster_b):
            x = self.rng.uniform(gap_end + self.radio_range * 0.3, area_w)
            y = self.rng.uniform(0, area_h)
            eff_range = self._eff_range()
            node = SimNode(idx, (x, y), self.medium, self.rng, eff_range)
            self.nodes.append(node)
            self.medium.register(node)
            idx += 1
            if idx % 500 == 0:
                print(f" {idx}", end="", flush=True)

        print(f"  done ({time.time()-t0:.1f}s)")
        self._finish_setup(t0)

    def _eff_range(self) -> float:
        if self.range_variance > 0:
            factor = 1.0 + self.rng.uniform(
                -self.range_variance, self.range_variance)
            return self.radio_range * factor
        return self.radio_range

    def _finish_setup(self, t0: float) -> None:
        print("  Building neighbour graph...", end="", flush=True)
        self.medium.build_neighbour_graph()

        for node in self.nodes:
            node.direct_peers = {}
            for nb_id in self.medium._neighbours.get(node.node_id, set()):
                nb_node = self.medium.nodes[nb_id]
                node.direct_peers[nb_id] = nb_node.identity.x25519_public_bytes

        self.live_nodes = list(self.nodes)
        avg = self.medium.avg_neighbours()
        print(f" done  (avg neighbours: {avg:.1f})")

        # Designate malicious nodes
        if self.malicious_rate > 0:
            num_malicious = max(1, int(self.num_nodes * self.malicious_rate))
            candidates = list(self.nodes)
            self.rng.shuffle(candidates)
            for node in candidates[:num_malicious]:
                node.is_malicious = True
                self.malicious_nodes.append(node.node_id_short)
            print(f"  Malicious nodes:      {num_malicious} "
                  f"({self.malicious_rate*100:.1f}%, "
                  f"drop rate: {MALICIOUS_DROP_RATE*100:.0f}%)")

        isolated = sum(
            1 for n in self.nodes
            if self.medium.neighbour_count(n.node_id) == 0
        )
        if isolated:
            print(f"  WARNING: {isolated} isolated node(s)")

        if self.range_variance > 0:
            ranges = [n.effective_range for n in self.nodes]
            print(f"  Radio range: {min(ranges):.0f}m - {max(ranges):.0f}m "
                  f"(avg {sum(ranges)/len(ranges):.0f}m)")

        if self.bottleneck > 0:
            # Report bridge connectivity
            bridge_nodes = self.nodes[
                (self.num_nodes - self.bottleneck) // 2:
                (self.num_nodes - self.bottleneck) // 2 + self.bottleneck
            ]
            bridge_ids = {n.node_id for n in bridge_nodes}
            min_nb = min(self.medium.neighbour_count(n.node_id) for n in bridge_nodes)
            max_nb = max(self.medium.neighbour_count(n.node_id) for n in bridge_nodes)
            # Count cross-cluster links (bridge nodes that connect to both sides)
            connecting = 0
            for n in bridge_nodes:
                nbs = self.medium._neighbours.get(n.node_id, set())
                has_left = any(nb not in bridge_ids
                              for nb in nbs
                              if self.medium.nodes[nb].index < bridge_nodes[0].index)
                has_right = any(nb not in bridge_ids
                                for nb in nbs
                                if self.medium.nodes[nb].index >= bridge_nodes[-1].index)
                if has_left and has_right:
                    connecting += 1
            print(f"  Bridge: {self.bottleneck} nodes "
                  f"(neighbours: {min_nb}-{max_nb}, "
                  f"{connecting} fully connecting)")

    # ---- Phase 2: Discovery ---------------------------------------------

    def phase_discovery(self) -> None:
        """Two-phase discovery with per-link encryption.
        
        Phase A (handshake): Anonymous DH beacons establish link sessions.
                             No identity or routing info is exchanged.
        Phase B (identity):  Signed identity + gossip sent over encrypted
                             links.  Populates routing tables.
        """
        handshake_cycles = 4  # enough for all neighbour pairs to link
        identity_cycles = self.beacon_cycles
        total = handshake_cycles + identity_cycles

        print(f"\nPhase 2: Discovery ({handshake_cycles} handshake + "
              f"{identity_cycles} identity cycles)")
        t0 = time.time()

        # Phase A: Handshake establishment
        for cycle in range(1, handshake_cycles + 1):
            for node in self.nodes:
                node.tick_handshake()
            self.medium.deliver_pending()
            for node in self.nodes:
                if node.rx_queue:
                    node.tick_receive()
            for node in self.nodes:
                node._seen.clear()

        # Report link coverage
        link_counts = [len(n.link_sessions) for n in self.nodes]
        avg_links = sum(link_counts) / len(link_counts) if link_counts else 0
        print(f"  Handshake: avg {avg_links:.1f} links/node "
              f"(from avg {self.medium.avg_neighbours():.1f} neighbours)")

        # Phase B: Identity + gossip over encrypted links
        prev_stats = None
        for cycle in range(1, identity_cycles + 1):
            for node in self.nodes:
                node.tick_link_identity()
            self.medium.deliver_pending()
            for node in self.nodes:
                if node.rx_queue:
                    node.tick_receive()
            for node in self.nodes:
                node._seen.clear()

            if cycle % 5 == 0 or cycle == identity_cycles:
                stats = self._discovery_stats()
                stable = ""
                if prev_stats and stats == prev_stats:
                    stable = " (stable)"
                prev_stats = stats
                print(
                    f"  Cycle {cycle:>3}: "
                    f"avg_rt_size={stats['avg_rt']:.1f}, "
                    f"avg_regions={stats['avg_regions']:.1f}, "
                    f"coverage={stats['coverage']:.1f}%"
                    f"{stable}"
                )

        # Phase C: Trust challenges (build initial trust scores)
        if self.malicious_rate > 0:
            challenge_cycles = 8
            for cycle in range(challenge_cycles):
                for node in self.nodes:
                    node.tick_challenges()
                self.medium.deliver_pending()
                for node in self.nodes:
                    if node.rx_queue:
                        node.tick_receive()
                for node in self.nodes:
                    node._seen.clear()
            trust_scores = []
            for node in self.nodes:
                if node._trust:
                    trust_scores.extend(node._trust.values())
            if trust_scores:
                avg_t = sum(trust_scores) / len(trust_scores)
                print(f"  Trust: avg={avg_t:.1f} after {challenge_cycles} challenge cycles")

        elapsed = time.time() - t0
        print(f"  Discovery complete ({elapsed:.1f}s)")

    # ---- Phase 2b: Neighbor Probing (trust calibration) -------------------

    def phase_probes(self) -> None:
        """Probe each neighbor's forwarding honesty using real onion traffic.

        Each node sends 2 probes per neighbor through that specific neighbor
        to a known 2-hop target (learned from gossip).  The probe is a
        standard FRAME_ONION -- indistinguishable from real traffic.

        If the E2E ACK comes back (target confirmed receipt), the neighbor
        forwarded honestly.  If not, the neighbor likely dropped the packet.

        This runs ONCE at setup, giving each node clean per-neighbor trust
        signals before real messaging begins.
        """
        # Scale probe count: more probes = better detection but longer setup
        PROBES_PER_NEIGHBOR = 5 if len(self.nodes) <= 1000 else 3
        PROBE_TIMEOUT_TICKS = 60  # probes are 2-3 hops, 60 ticks is generous

        print(f"\nPhase 2b: Neighbor Probes "
              f"({PROBES_PER_NEIGHBOR} probes/neighbor)")
        t0 = time.time()

        # Collect all probe tasks: (sender_node, neighbor_id, target_entry)
        # Each node probes each of its link-session neighbors using a target
        # that the neighbor reported in gossip (a node 2 hops away).
        probe_tasks: List[Tuple[SimNode, bytes, bytes, bytes]] = []
        for node in self.nodes:
            if node.is_dead:
                continue
            for nb_id in list(node.link_sessions):
                # Find targets: nodes that the neighbor knows about (from
                # the gossip entries in our routing table that came via nb_id)
                # Fall back to any non-self, non-neighbor routing entry.
                all_entries = node.routing_table.get_all_entries()
                # Prefer entries that are not our direct peers (2+ hops away)
                candidates = [
                    e for e in all_entries
                    if (e.node_id != node.node_id
                        and e.node_id != nb_id
                        and e.node_id not in node.direct_peers
                        and e.public_key)
                ]
                if not candidates:
                    # Fall back: any entry with a public key
                    candidates = [
                        e for e in all_entries
                        if (e.node_id != node.node_id
                            and e.node_id != nb_id
                            and e.public_key)
                    ]
                if not candidates:
                    continue
                # Pick PROBES_PER_NEIGHBOR random targets
                self.rng.shuffle(candidates)
                for e in candidates[:PROBES_PER_NEIGHBOR]:
                    probe_tasks.append((node, nb_id, e.node_id, e.public_key))

        if not probe_tasks:
            print("  No probe tasks generated (insufficient routing data)")
            return

        total_probes = len(probe_tasks)
        print(f"  Generated {total_probes} probes across {len(self.nodes)} nodes")

        # Send all probes at once (they're indistinguishable from normal
        # traffic, so simultaneous sending is realistic -- like many users
        # sending messages at once).
        probe_map: Dict[bytes, Tuple[SimNode, bytes]] = {}  # mid -> (sender, via_nb)
        for sender, nb_id, target_id, target_pk in probe_tasks:
            mid = sender.send_probe(nb_id, target_id, target_pk)
            if mid is not None:
                probe_map[mid] = (sender, nb_id)

        probes_sent = len(probe_map)
        print(f"  Sent {probes_sent} probes, propagating...", end="", flush=True)

        # Propagate -- probes only need ~2-3 hops + E2E ACK return (~10-20 hops).
        # 60 ticks is generous for this.
        for tick in range(1, PROBE_TIMEOUT_TICKS + 1):
            self.medium.deliver_pending()
            for node in self.nodes:
                if not node.is_dead and node.rx_queue:
                    node.tick_receive()
            for node in self.nodes:
                if not node.is_dead and node._pending_forwards:
                    node.tick_pending()

            # Early termination check every 10 ticks
            if tick % 10 == 0:
                answered = sum(
                    1 for mid, (sender, _) in probe_map.items()
                    if mid in sender._e2e_confirmed
                )
                if answered == probes_sent:
                    break

        # Clear in-flight state
        for node in self.nodes:
            if not node.is_dead:
                node._seen.clear()
                node._pending_forwards.clear()
                node.tx_queue.clear()
                node.tx_this_tick = 0
        self.medium.pending.clear()

        # Count results
        confirmed = 0
        failed = 0
        nb_pass: Dict[bytes, Dict[bytes, int]] = {}   # sender_nid -> {nb_id -> passes}
        nb_total: Dict[bytes, Dict[bytes, int]] = {}   # sender_nid -> {nb_id -> total}

        for mid, (sender, nb_id) in probe_map.items():
            snid = sender.node_id
            nb_total.setdefault(snid, {}).setdefault(nb_id, 0)
            nb_total[snid][nb_id] += 1
            nb_pass.setdefault(snid, {}).setdefault(nb_id, 0)

            if mid in sender._e2e_confirmed:
                confirmed += 1
                nb_pass[snid][nb_id] += 1
            else:
                failed += 1

        # Apply trust adjustments based on probe results
        # Strong signal: each probe is a clean, isolated test of ONE neighbor
        PROBE_PASS_REWARD = 3       # honest forwarding confirmed
        PROBE_FAIL_PENALTY = -50    # strong evidence of dropping
        trust_changes = 0

        for snid, nbs in nb_total.items():
            sender = self.medium.nodes.get(snid)
            if sender is None:
                continue
            for nb_id, total in nbs.items():
                passes = nb_pass.get(snid, {}).get(nb_id, 0)
                fails = total - passes
                for _ in range(passes):
                    sender._adjust_trust(nb_id, PROBE_PASS_REWARD)
                    trust_changes += 1
                for _ in range(fails):
                    sender._adjust_trust(nb_id, PROBE_FAIL_PENALTY)
                    trust_changes += 1

        elapsed = time.time() - t0
        pct = 100 * confirmed / probes_sent if probes_sent else 0
        print(f"  Probes complete ({elapsed:.1f}s)")
        print(f"  Probes confirmed:     {confirmed}/{probes_sent} ({pct:.1f}%)")
        print(f"  Probes failed:        {failed}/{probes_sent}")
        print(f"  Trust adjustments:    {trust_changes}")

        # Report trust differentiation after probes
        if self.malicious_rate > 0:
            mal_ids = {n.node_id for n in self.nodes
                       if n.is_malicious and not n.is_dead}
            honest_nodes = [n for n in self.nodes
                           if not n.is_dead and not n.is_malicious]
            mal_scores = []
            honest_scores = []
            for node in honest_nodes:
                for nid, score in node._trust.items():
                    if nid in mal_ids:
                        mal_scores.append(score)
                    else:
                        honest_scores.append(score)
            if mal_scores:
                avg_m = sum(mal_scores) / len(mal_scores)
                avg_h = sum(honest_scores) / len(honest_scores) if honest_scores else 0
                avoided = sum(1 for s in mal_scores if s < TRUST_DEPRIORITIZE)
                print(f"  Post-probe trust:     malicious avg={avg_m:.1f}, "
                      f"honest avg={avg_h:.1f}")
                print(f"    Malicious avoided:  {avoided}/{len(mal_scores)}")

        # Clear probe state for clean messaging phase
        for node in self.nodes:
            if not node.is_dead:
                node._seen.clear()
                node._pending_forwards.clear()
                node._pending_e2e.clear()
                node._e2e_confirmed.clear()
                node.tx_queue.clear()
                node.tx_this_tick = 0
        self.medium.pending.clear()

    def _discovery_stats(self) -> Dict:
        total_rt = 0
        total_regions = 0
        total_known = set()
        for node in self.nodes:
            entries = node.routing_table.get_all_entries()
            total_rt += len(entries)
            total_regions += len(node.routing_table.regions_known())
            for e in entries:
                total_known.add(e.node_id)
        n = len(self.nodes)
        return {
            "avg_rt": total_rt / n if n else 0,
            "avg_regions": total_regions / n if n else 0,
            "coverage": 100.0 * len(total_known) / n if n else 0,
        }

    # ---- Phase 3: Messages (with realism) --------------------------------

    def phase_messages(self) -> None:
        print(f"\nPhase 3: Test Messages ({self.num_messages} messages)")
        if self.node_death_rate > 0:
            print(f"  Node death rate:   {self.node_death_rate*100:.1f}%")
        if self.dropout_rate > 0:
            print(f"  Dropout rate:      {self.dropout_rate*100:.1f}%/tick")
        if self.packet_loss > 0:
            print(f"  Packet loss:       {self.packet_loss*100:.1f}%")
        t0 = time.time()

        deaths_remaining = self._schedule_deaths()

        # Enable TX rate limiting during messaging (simulates LoRa bandwidth)
        if self.bottleneck > 0:
            # Increase ACK timeout to account for queue delays at bottleneck
            ack_to = max(HOP_ACK_TIMEOUT, 30)
            print(f"  TX rate limit:     {MAX_TX_PER_TICK}/tick "
                  f"(queue: {MAX_QUEUE_SIZE}, "
                  f"ACK timeout: {ack_to})")
            for node in self.nodes:
                node._rate_limited = True
                node._ack_timeout = ack_to

        gc.disable()  # avoid GC pauses during messaging
        try:
            self._run_messages(deaths_remaining)
        finally:
            gc.enable()
            for node in self.nodes:
                node._rate_limited = False
                node._ack_timeout = HOP_ACK_TIMEOUT

    def _run_messages(self, deaths_remaining):
        t0 = time.time()
        for msg_num in range(1, self.num_messages + 1):
            while deaths_remaining and deaths_remaining[0][0] <= msg_num:
                _, victim = deaths_remaining.pop(0)
                if not victim.is_dead:
                    self._kill_node(victim)

            live = [n for n in self.live_nodes if not n.is_dead]
            if len(live) < 2:
                print("  ERROR: fewer than 2 live nodes remaining!")
                break
            self.live_nodes = live

            sender = self.rng.choice(live)
            recipient = self.rng.choice(live)
            while recipient is sender:
                recipient = self.rng.choice(live)

            # Clear ALL per-message state to prevent ghost traffic
            # (old queued frames being re-processed after _seen is cleared)
            for node in self.nodes:
                if not node.is_dead:
                    node._seen.clear()
                    node.tx_queue.clear()
                    node._pending_forwards.clear()
                    node._pending_e2e.clear()
                    node._e2e_confirmed.clear()
                    node.tx_this_tick = 0
                    node.busy_until = 0
            self.medium.pending.clear()

            payload = f"Msg#{msg_num} from {sender.node_id_short}".encode()
            msg_t0 = time.time()
            result = self._send_and_propagate(
                sender, recipient, payload, msg_num)
            msg_elapsed = time.time() - msg_t0
            self.results.append(result)

            # Warn on slow messages
            if msg_elapsed > 5.0:
                print(f"  ** Msg#{msg_num} took {msg_elapsed:.1f}s "
                      f"({result.hops} ticks, "
                      f"{'OK' if result.delivered else result.error})")

            if self.verbose:
                st = "OK" if result.delivered else "FAIL"
                detail = (
                    f"{result.mode} {result.hops}h"
                    if result.delivered
                    else result.error[:40]
                )
                print(
                    f"  [{msg_num:>{len(str(self.num_messages))}}"
                    f"/{self.num_messages}] "
                    f"{result.sender_short} -> {result.recipient_short}: "
                    f"{st} ({detail})"
                )

            # Periodic trust challenges during messaging
            if self.malicious_rate > 0 and msg_num % 20 == 0:
                for node in live:
                    if not node.is_dead:
                        node.tick_challenges()
                self.medium.deliver_pending()
                for node in live:
                    if not node.is_dead and node.rx_queue:
                        node.tick_receive()
                for node in live:
                    if not node.is_dead:
                        node._seen.clear()

            if not self.verbose and msg_num % max(1, self.num_messages // 4) == 0:
                ok = sum(1 for r in self.results if r.delivered)
                dead = sum(1 for n in self.nodes if n.is_dead)
                print(
                    f"  {msg_num}/{self.num_messages}: "
                    f"{ok} delivered ({100*ok/msg_num:.0f}%) "
                    f"[{dead} dead nodes]"
                )

        elapsed = time.time() - t0
        print(f"  Messaging complete ({elapsed:.1f}s)")

    def _schedule_deaths(self) -> List[Tuple[int, "SimNode"]]:
        if self.node_death_rate <= 0:
            return []

        num_deaths = max(1, int(self.num_nodes * self.node_death_rate))
        candidates = list(self.nodes)
        self.rng.shuffle(candidates)
        victims = candidates[:num_deaths]

        schedule = []
        for victim in victims:
            msg_num = self.rng.randint(1, self.num_messages)
            schedule.append((msg_num, victim))

        schedule.sort(key=lambda x: x[0])
        return schedule

    def _kill_node(self, node: SimNode) -> None:
        node_short = node.node_id_short
        node.kill()
        self.nodes_killed.append(node_short)

        for other in self.nodes:
            if not other.is_dead:
                other.remove_dead_peer(node.node_id)

        if self.verbose:
            live = sum(1 for n in self.nodes if not n.is_dead)
            print(f"  ** Node {node_short} DIED "
                  f"({live} nodes remaining)")

    def _apply_dropouts(self) -> List["SimNode"]:
        if self.dropout_rate <= 0:
            return []

        went_offline = []
        for node in self.live_nodes:
            if node.is_dead or node.is_offline:
                continue
            if self.rng.random() < self.dropout_rate:
                node.is_offline = True
                went_offline.append(node)
                self.dropout_events += 1
        return went_offline

    def _restore_dropouts(self, went_offline: List["SimNode"]) -> None:
        for node in went_offline:
            node.is_offline = False

    def _send_and_propagate(
        self, sender: SimNode, recipient: SimNode,
        payload: bytes, msg_num: int,
    ) -> MessageResult:
        """
        Send a message and propagate it through the network.

        Reliability strategy (no heavy ACK cascade):
          1. Receipt ACK per hop (handles packet loss via same-neighbor retry)
          2. Two copies per attempt through different gateways (multi-path)
          3. E2E retry with gateway exclusion (different paths each time)

        Each attempt sends up to 2 independent copies.  With 6 attempts
        that's up to 12 independent paths, giving near-100% delivery
        even in adverse conditions.
        """
        initial = len(recipient.inbox)
        total_ticks = 0
        last_error = ""
        last_mode = "?"
        last_layers = 0
        failed_via: List[Set[bytes]] = []   # multi-path: first hops in each failed attempt
        prev_gateways: Set[bytes] = set()

        for attempt in range(MAX_E2E_RETRIES + 1):
            # Clear ALL in-flight state from previous attempt
            # (preserve sender._pending_e2e across attempts for ACK matching)
            if attempt > 0:
                for node in self.nodes:
                    if not node.is_dead:
                        node._seen.clear()
                        node._pending_forwards.clear()
                        node.tx_queue.clear()
                        node.tx_this_tick = 0
                        node.busy_until = 0
                self.medium.pending.clear()

            # Exclude gateways from the last 2 failed attempts
            excl_gw: Set[bytes] = set()
            if failed_via:
                for fv in failed_via[-2:]:
                    excl_gw |= fv
            excl_gw |= prev_gateways
            # Reset exclusion if we've excluded too many (>50% of known)
            known_count = len(sender.routing_table.get_all_entries())
            if len(excl_gw) > max(6, known_count // 2):
                excl_gw.clear()
                prev_gateways.clear()

            # Increase routing randomness with each retry to explore
            # genuinely different paths through the network.
            # attempt 0 → 0.0 (pure greedy), attempt 6 → 0.5, attempt 12 → ~0.85
            rand_level = min(0.9, attempt * 0.07)

            # --- Primary copy ---
            res = sender.send_message(
                recipient.node_id, payload,
                exclude_gateways=excl_gw if excl_gw else None,
                randomness=rand_level,
            )

            this_attempt_gateways: Set[bytes] = set()
            this_attempt_first_hops: Set[bytes] = set()  # actual first-hop neighbours
            if "gateway_ids" in res:
                for gid in res["gateway_ids"]:
                    this_attempt_gateways.add(gid)
            if "first_hops" in res:
                this_attempt_first_hops |= res["first_hops"]

            if "error" in res:
                last_error = res["error"]
                last_mode = res.get("mode", "?")
                last_layers = res.get("onion_layers", 0)
                # On gateway error, clear exclusion list for next attempt
                failed_via.append(set())
                continue

            last_mode = res.get("mode", "?")
            last_layers = res.get("onion_layers", 0)

            # --- Additional copies (different gateways + higher randomness) ---
            # Send 2 extra copies for path diversity (total 3 per attempt)
            if last_mode == "onion":
                for copy_i in range(2):
                    res_extra = sender.send_message(
                        recipient.node_id, payload,
                        exclude_gateways=this_attempt_gateways if this_attempt_gateways else None,
                        randomness=min(0.9, rand_level + 0.15 * (copy_i + 1)),
                    )
                    if "gateway_ids" in res_extra:
                        for gid in res_extra["gateway_ids"]:
                            this_attempt_gateways.add(gid)
                    if "first_hops" in res_extra:
                        this_attempt_first_hops |= res_extra["first_hops"]
                # If secondary fails to find gateways, no problem -- primary
                # is already in flight.

            # --- Propagate all copies simultaneously ---
            delivered, ticks = self._propagate(sender, recipient, initial)
            total_ticks += ticks

            if recipient.is_dead:
                return MessageResult(
                    sender.node_id_short, recipient.node_id_short,
                    False, last_mode, last_layers, total_ticks,
                    "recipient_died",
                )

            if delivered:
                # Successful delivery -- reward first-hop neighbours
                if this_attempt_first_hops:
                    for fh in this_attempt_first_hops:
                        sender._record_forward_ok(fh)
                return MessageResult(
                    sender.node_id_short, recipient.node_id_short,
                    True, last_mode, last_layers, total_ticks,
                )

            last_error = f"timeout_attempt_{attempt+1}"

            # E2E failure: penalize first-hop neighbours used in this attempt
            if this_attempt_first_hops:
                for fh in this_attempt_first_hops:
                    sender._record_forward_fail(fh)

            # Track gateways for exclusion in next attempt
            prev_gateways |= this_attempt_gateways

            # Multi-path failure tracking: the first-hop neighbours
            failed_via.append(this_attempt_first_hops)

            if len(failed_via) >= 2:
                # Find common first-hop across the last 2 failed attempts
                common = failed_via[-2] & failed_via[-1]
                for suspect_id in common:
                    sender._record_suspect(suspect_id)

        # All attempts exhausted -- already penalized per attempt above

        return MessageResult(
            sender.node_id_short, recipient.node_id_short,
            False, last_mode, last_layers, total_ticks, last_error,
        )

    def _propagate(
        self, sender: SimNode, recipient: SimNode, initial_inbox: int,
    ) -> Tuple[bool, int]:
        """Run the tick loop for a single send attempt. Returns (delivered, ticks)."""
        # Bottleneck scenarios need MUCH more ticks for queue draining
        max_ticks = MAX_PROPAGATION_TICKS * 20 if self.bottleneck > 0 else MAX_PROPAGATION_TICKS
        nodes_with_pending: Set[SimNode] = set()
        nodes_with_queue: Set[SimNode] = set()
        nodes_got_frames: List[SimNode] = []

        for tick in range(1, max_ticks + 1):
            # Temporary dropouts
            offline_this_tick: List[SimNode] = []
            if self.dropout_rate > 0 and tick % 8 == 0:
                offline_this_tick = self._apply_dropouts()

            # 0. Drain TX queues (congestion management)
            if nodes_with_queue:
                still_queued = []
                for node in nodes_with_queue:
                    if node.is_dead or node.is_offline:
                        continue
                    if node.tick_drain_queue():
                        still_queued.append(node)
                nodes_with_queue = set(still_queued)

            # 1. Deliver queued transmissions with RF realism
            #    - Half-duplex: transmitters are deaf (can't receive)
            #    - Collisions: 2+ sources reaching same receiver = all lost
            #    - Airtime: transmitter stays deaf for BUSY_TICKS after TX
            nodes_got_frames.clear()
            batch = self.medium.pending
            self.medium.pending = []
            pl = self.medium.packet_loss

            # Track which nodes transmitted this tick (half-duplex: deaf)
            transmitters: Set[bytes] = set()
            for tx in batch:
                transmitters.add(tx.source_id)
                # Mark transmitter busy for airtime duration
                src_node = self.medium.nodes.get(tx.source_id)
                if src_node is not None:
                    src_node.busy_until = tick + BUSY_TICKS

            # Build per-receiver delivery list, then check for collisions
            # Key: receiver node_id, Value: list of (source_id, frame)
            receiver_frames: Dict[bytes, List[Tuple[bytes, SimFrame]]] = {}

            for tx in batch:
                frame = tx.frame
                if frame.next_hop:
                    # Unicast
                    if frame.next_hop not in self.medium._neighbours.get(
                            tx.source_id, set()):
                        continue
                    receiver_frames.setdefault(frame.next_hop, []).append(
                        (tx.source_id, frame))
                else:
                    # Broadcast (beacons)
                    for nid in self.medium._neighbours.get(
                            tx.source_id, set()):
                        receiver_frames.setdefault(nid, []).append(
                            (tx.source_id, frame))

            # Deliver frames, applying RF realism
            # ACK frames are IMMUNE to half-duplex & collisions:
            #   - Tiny (~10 bytes, ~10ms airtime vs ~400ms for data)
            #   - Real LoRa uses a dedicated RX window after TX for ACKs
            #   - Collision probability is negligible due to tiny size
            ack_types = (FRAME_HOP_ACK, FRAME_HOP_NACK, FRAME_ACK)

            for recv_id, incoming in receiver_frames.items():
                node = self.medium.nodes.get(recv_id)
                if node is None or node.is_dead or node.is_offline:
                    continue

                is_busy_airtime = node.busy_until > tick
                is_transmitting = recv_id in transmitters

                # Pre-compute collision info (only for data frames)
                recv_neighbours = self.medium._neighbours.get(recv_id, set())
                nearby_tx = len(transmitters & recv_neighbours)
                collision_check = (
                    nearby_tx > 1 and COLLISION_DUTY > 0
                )

                for _src, frame in incoming:
                    # ACKs always get through (dedicated RX window)
                    if frame.frame_type in ack_types:
                        node.rx_queue.append(frame)
                        nodes_got_frames.append(node)
                        continue

                    # Airtime: node still deaf from a PREVIOUS TX
                    if is_busy_airtime:
                        continue

                    # Half-duplex: node TX-ing this tick (probabilistic)
                    if is_transmitting and TX_OVERLAP_PROB > 0:
                        if self.rng.random() < TX_OVERLAP_PROB:
                            continue

                    # Packet loss
                    if pl > 0 and self.rng.random() < pl:
                        continue

                    # ALOHA collision: nearby transmitters interfere
                    if collision_check:
                        survive = (1.0 - COLLISION_DUTY) ** (nearby_tx - 1)
                        if self.rng.random() > survive:
                            continue

                    node.rx_queue.append(frame)
                    nodes_got_frames.append(node)

            # 2. Process received frames
            seen_set: Set[int] = set()
            for node in nodes_got_frames:
                nid = id(node)
                if nid in seen_set:
                    continue
                seen_set.add(nid)
                if not node.is_dead:
                    node.tick_receive()
                    if node._pending_forwards:
                        nodes_with_pending.add(node)
                    if node.tx_queue:
                        nodes_with_queue.add(node)

            # 3. Check ACK timeouts
            expired_nodes = []
            for node in nodes_with_pending:
                if node.is_dead:
                    expired_nodes.append(node)
                    continue
                node.tick_pending()
                if not node._pending_forwards:
                    expired_nodes.append(node)
            for node in expired_nodes:
                nodes_with_pending.discard(node)

            if offline_this_tick:
                self._restore_dropouts(offline_this_tick)

            if recipient.is_dead:
                return False, tick

            if len(recipient.inbox) > initial_inbox:
                return True, tick

            # Termination: nothing in-flight, nothing pending, nothing queued
            if (not self.medium.pending
                    and not nodes_with_pending
                    and not nodes_with_queue):
                break

        return False, tick

    # ---- Phase 4: Report ------------------------------------------------

    def phase_report(self) -> None:
        total = len(self.results)
        ok = [r for r in self.results if r.delivered]
        fail = [r for r in self.results if not r.delivered]

        print(f"\nPhase 4: Results")
        print("=" * 60)
        print(f"  Total messages:       {total}")
        if total:
            print(f"  Delivered:            {len(ok)} ({100*len(ok)/total:.1f}%)")
            print(f"  Failed:               {len(fail)} ({100*len(fail)/total:.1f}%)")

        if ok:
            direct = [r for r in ok if r.mode == "direct"]
            onion1 = [r for r in ok if r.mode == "onion" and r.onion_layers == 1]
            onion2 = [r for r in ok if r.mode == "onion" and r.onion_layers == 2]
            onion3 = [r for r in ok if r.mode == "onion" and r.onion_layers == 3]
            print(f"\n  By mode:")
            if direct:
                print(f"    Direct:             {len(direct)}")
            if onion1:
                print(f"    Onion (1-layer):    {len(onion1)}")
            if onion2:
                print(f"    Onion (2-layer):    {len(onion2)}")
            if onion3:
                print(f"    Onion (3-layer):    {len(onion3)}")

            hops = [r.hops for r in ok]
            print(f"\n  Hop statistics (propagation ticks):")
            print(f"    Min:                {min(hops)}")
            print(f"    Max:                {max(hops)}")
            print(f"    Avg:                {sum(hops)/len(hops):.1f}")
            sorted_hops = sorted(hops)
            mid = len(sorted_hops) // 2
            print(f"    Median:             {sorted_hops[mid]}")

        if fail:
            print(f"\n  Failure reasons:")
            reasons: Dict[str, int] = {}
            for r in fail:
                reasons[r.error] = reasons.get(r.error, 0) + 1
            for reason, cnt in sorted(reasons.items(), key=lambda x: -x[1]):
                print(f"    {reason}: {cnt}")

        dead = sum(1 for n in self.nodes if n.is_dead)
        malicious_alive = sum(1 for n in self.nodes if n.is_malicious and not n.is_dead)
        print(f"\n  Realism:")
        print(f"    Packet loss rate:   {self.packet_loss*100:.1f}%")
        print(f"    Range variance:     \u00b1{self.range_variance*100:.0f}%")
        print(f"    Nodes killed:       {dead} ({100*dead/len(self.nodes):.1f}%)")
        if self.nodes_killed:
            shown = self.nodes_killed[:10]
            extra = (f" +{len(self.nodes_killed)-10} more"
                     if len(self.nodes_killed) > 10 else "")
            print(f"      IDs: {', '.join(shown)}{extra}")
        print(f"    Dropout events:     {self.dropout_events}")

        live = [n for n in self.nodes if not n.is_dead]
        print(f"\n  Network topology (after failures):")
        if live:
            avg_rt = sum(n.routing_table.total_peers() for n in live) / len(live)
            avg_reg = sum(
                len(n.routing_table.regions_known()) for n in live
            ) / len(live)
            print(f"    Live nodes:         {len(live)}")
            print(f"    Avg routing table:  {avg_rt:.1f} peers")
            print(f"    Avg regions known:  {avg_reg:.1f}")

        pct = self._connectivity_pct(live_only=True)
        print(f"    Connected (BFS):    {pct:.1f}%")

        # Trust system report
        if self.malicious_rate > 0:
            print(f"\n  Trust System:")
            print(f"    Malicious nodes:    {len(self.malicious_nodes)} "
                  f"(drop rate: {MALICIOUS_DROP_RATE*100:.0f}%)")
            if malicious_alive:
                print(f"    Malicious alive:    {malicious_alive}")
            
            # Collect trust scores that honest nodes have for malicious nodes
            mal_ids = {n.node_id for n in self.nodes if n.is_malicious and not n.is_dead}
            honest_nodes = [n for n in live if not n.is_malicious]
            if mal_ids and honest_nodes:
                mal_scores = []
                honest_scores = []
                for node in honest_nodes:
                    for nid, score in node._trust.items():
                        if nid in mal_ids:
                            mal_scores.append(score)
                        else:
                            honest_scores.append(score)
                if mal_scores:
                    avg_mal = sum(mal_scores) / len(mal_scores)
                    min_mal = min(mal_scores)
                    max_mal = max(mal_scores)
                    avoided = sum(1 for s in mal_scores if s < TRUST_DEPRIORITIZE)
                    depri = sum(1 for s in mal_scores if TRUST_DEPRIORITIZE <= s < TRUST_NORMAL)
                    print(f"    Malicious trust:    avg={avg_mal:.1f} "
                          f"min={min_mal} max={max_mal}")
                    print(f"      Avoided:          {avoided}/{len(mal_scores)}")
                    print(f"      Deprioritized:    {depri}/{len(mal_scores)}")
                if honest_scores:
                    avg_hon = sum(honest_scores) / len(honest_scores)
                    print(f"    Honest trust:       avg={avg_hon:.1f}")
        print()

    def _connectivity_pct(self, live_only: bool = False) -> float:
        nodes_to_check = (
            [n for n in self.nodes if not n.is_dead] if live_only
            else self.nodes
        )
        if not nodes_to_check:
            return 0.0
        live_ids = {n.node_id for n in nodes_to_check}
        start = nodes_to_check[0].node_id
        visited: Set[bytes] = {start}
        queue = [start]
        while queue:
            nid = queue.pop(0)
            for nb in self.medium._neighbours.get(nid, []):
                if nb not in visited and nb in live_ids:
                    visited.add(nb)
                    queue.append(nb)
        return 100.0 * len(visited) / len(nodes_to_check)

    # ---- run all --------------------------------------------------------

    def run(self) -> None:
        print("=" * 60)
        print("  SPARK Network Simulation")
        print("=" * 60)
        area_h = self.area_size / 1000
        if self.bottleneck > 0:
            area_h_km = self.area_size / 3 / 1000
            print(
                f"  Nodes: {self.num_nodes} | "
                f"Area: {self.area_size/1000:.0f}x{area_h_km:.0f}km | "
                f"Range: {self.radio_range:.0f}m | "
                f"Messages: {self.num_messages}"
            )
            print(f"  Bottleneck: {self.bottleneck} bridge nodes "
                  f"(TX limit: {MAX_TX_PER_TICK}/tick)")
        else:
            print(
                f"  Nodes: {self.num_nodes} | "
                f"Area: {area_h:.0f}x{area_h:.0f}km | "
                f"Range: {self.radio_range:.0f}m | "
                f"Messages: {self.num_messages}"
            )
        if any([self.packet_loss, self.range_variance,
                self.node_death_rate, self.dropout_rate]):
            print(f"  Realism: loss={self.packet_loss*100:.0f}% "
                  f"range=\u00b1{self.range_variance*100:.0f}% "
                  f"death={self.node_death_rate*100:.1f}% "
                  f"dropout={self.dropout_rate*100:.1f}%/tick")
        rf_features = []
        if TX_OVERLAP_PROB > 0:
            rf_features.append(f"half-duplex({TX_OVERLAP_PROB*100:.0f}%)")
        if COLLISION_DUTY > 0:
            rf_features.append(f"collisions({COLLISION_DUTY*100:.0f}%)")
        if BUSY_TICKS > 0:
            rf_features.append(f"airtime({BUSY_TICKS}t)")
        rf_features.append("ACK-immune")
        print(f"  RF model: {', '.join(rf_features)}")
        print(f"  Security: per-link encryption (identity-free beacons, "
              f"{LINK_OVERHEAD}B overhead/frame)")
        if self.malicious_rate > 0:
            print(f"  Trust: challenge-response + traffic analysis + "
                  f"multi-path verification")
            print(f"  Malicious: {self.malicious_rate*100:.1f}% of nodes "
                  f"(selective drop {MALICIOUS_DROP_RATE*100:.0f}%)")
        self.phase_setup()
        self.phase_discovery()
        self.phase_probes()
        self.phase_messages()
        self.phase_report()


# ===================================================================
# CLI
# ===================================================================

def main():
    p = argparse.ArgumentParser(
        description="SPARK Large-Scale Network Simulation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  # Quick test (no realism)
  python3 sim_network.py --nodes 200 --messages 50 --seed 42

  # Medium with realism
  python3 sim_network.py --nodes 1000 --messages 100 \\
      --packet-loss 0.05 --range-var 0.20 --death-rate 0.02

  # Large-scale stress test
  python3 sim_network.py --nodes 5000 --messages 200 \\
      --area-size 30000 --packet-loss 0.05 --range-var 0.20 \\
      --death-rate 0.02 --dropout-rate 0.003

  # Reproducible
  python3 sim_network.py --nodes 500 --seed 42 --verbose
""",
    )
    p.add_argument("--nodes",         type=int,   default=500)
    p.add_argument("--messages",      type=int,   default=100)
    p.add_argument("--area-size",     type=float, default=5000.0)
    p.add_argument("--radio-range",   type=float, default=1500.0)
    p.add_argument("--beacon-cycles", type=int,   default=20)
    p.add_argument("--seed",          type=int,   default=None)
    p.add_argument("--verbose",       action="store_true")

    p.add_argument("--packet-loss",   type=float, default=0.0,
                   help="Probability of dropping each radio delivery (0.0-1.0)")
    p.add_argument("--range-var",     type=float, default=0.0,
                   help="Radio range variance factor (e.g. 0.20 = ±20%%)")
    p.add_argument("--death-rate",    type=float, default=0.0,
                   help="Fraction of nodes that die during messaging (0.0-1.0)")
    p.add_argument("--dropout-rate",  type=float, default=0.0,
                   help="Per-tick probability a node goes briefly offline")
    p.add_argument("--bottleneck",    type=int, default=0, metavar="N",
                   help="Create bottleneck topology with N bridge nodes "
                        "(enables TX rate limiting)")
    p.add_argument("--malicious-rate", type=float, default=0.0,
                   help="Fraction of nodes that are malicious (0.0-1.0)")
    args = p.parse_args()

    NetworkSimulation(
        num_nodes=args.nodes,
        area_size=args.area_size,
        radio_range=args.radio_range,
        beacon_cycles=args.beacon_cycles,
        num_messages=args.messages,
        seed=args.seed,
        verbose=args.verbose,
        packet_loss=args.packet_loss,
        range_variance=args.range_var,
        node_death_rate=args.death_rate,
        dropout_rate=args.dropout_rate,
        bottleneck=args.bottleneck,
        malicious_rate=args.malicious_rate,
    ).run()


if __name__ == "__main__":
    main()
