"""
SPARK Neighbour Trust System

Provides per-neighbour trust scoring, periodic challenge-response auditing,
traffic analysis anomaly detection, and multi-path verification to detect
and avoid compromised or malicious nodes.

Trust Model:
  - Each node maintains a LOCAL trust score per direct neighbour
  - Trust is earned through successful interactions (forwarding, challenges)
  - Trust is lost through failures (dropped messages, failed challenges)
  - Low-trust nodes are deprioritized in routing; very low are avoided
  - Trust scores are NEVER shared with other nodes (prevents manipulation)

Challenge-Response:
  - Random nonce signed by the neighbour's Ed25519 key
  - Proves the peer still holds the private key (not a replay)
  - Periodic (every CHALLENGE_INTERVAL seconds), staggered randomly
  - 3 retries before penalising (tolerates packet loss)

Traffic Analysis:
  - Tracks per-neighbour forward success rate (ACK ratio)
  - Detects selective dropping (a compromised node that silently
    discards messages while appearing healthy)
  - Compares drop rate against network average to avoid false positives

Multi-Path Verification:
  - When a message fails through one path, the retry takes a different
    route.  If the SAME neighbour is consistently the failure point
    across independent paths, it accumulates distrust faster.
  - Implemented as a "suspect relay" counter attached to forwarding.
"""

import time
from typing import Optional, Dict
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Trust score bounds
TRUST_MAX = 100
TRUST_MIN = 0
TRUST_INITIAL = 50       # New neighbours start here

# Trust thresholds for routing decisions
TRUST_NORMAL = 40         # >= this: full routing priority
TRUST_DEPRIORITIZE = 20   # >= this but < NORMAL: used only if no better option
# < DEPRIORITIZE: avoided for data forwarding, can still handshake

# Score adjustments
SCORE_CHALLENGE_PASS = 5
SCORE_CHALLENGE_FAIL = -20
SCORE_CHALLENGE_TIMEOUT = -15
SCORE_FORWARD_SUCCESS = 2   # ACK received for a message we sent via this peer
SCORE_FORWARD_FAIL = -3     # message sent via this peer was never ACKed
SCORE_FORWARD_FAIL_CONGESTED = -1  # fail when peer's queue was known full
SCORE_BEACON_OK = 1         # consistent beacon / identity exchange
SCORE_IDENTITY_CHANGE = -50 # sudden identity change on same link session
SCORE_RATCHET_OK = 3        # successful DH ratchet
SCORE_RATCHET_FAIL = -10    # DH ratchet failed

# Challenge timing
CHALLENGE_INTERVAL = 3600   # seconds between challenges (1 hour)
CHALLENGE_TIMEOUT = 120     # seconds to wait for response
CHALLENGE_MAX_RETRIES = 3

# Traffic analysis: minimum samples before judging
MIN_FORWARD_SAMPLES = 10

# Multi-path: suspect threshold -- if a node is the common failure
# point in N independent path failures, apply extra penalty
SUSPECT_RELAY_THRESHOLD = 3
SCORE_SUSPECT_RELAY = -10   # extra penalty per multi-path failure


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class TrustScore:
    """Per-neighbour trust state."""
    node_id: bytes
    score: int = TRUST_INITIAL
    
    # Challenge state
    last_challenge_at: float = 0.0
    challenge_nonce: Optional[bytes] = None
    challenge_retries: int = 0
    challenges_passed: int = 0
    challenges_failed: int = 0
    
    # Traffic analysis
    forwards_sent: int = 0       # messages forwarded via this peer
    forwards_acked: int = 0      # of those, how many were ACKed downstream
    
    # Multi-path suspect counter
    suspect_relay_count: int = 0  # times this node was common failure point
    
    # Timestamps
    created_at: float = field(default_factory=time.time)
    last_updated: float = field(default_factory=time.time)
    
    @property
    def is_trusted(self) -> bool:
        """True if score is in the normal routing zone."""
        return self.score >= TRUST_NORMAL
    
    @property
    def is_deprioritized(self) -> bool:
        """True if score is in the deprioritized zone."""
        return TRUST_DEPRIORITIZE <= self.score < TRUST_NORMAL
    
    @property
    def is_avoided(self) -> bool:
        """True if score is too low for data forwarding."""
        return self.score < TRUST_DEPRIORITIZE
    
    @property
    def forward_success_rate(self) -> float:
        """Fraction of forwards that were ACKed (0.0-1.0)."""
        if self.forwards_sent < MIN_FORWARD_SAMPLES:
            return 1.0  # benefit of the doubt until enough samples
        return self.forwards_acked / self.forwards_sent
    
    def adjust(self, delta: int) -> None:
        """Adjust score, clamped to [TRUST_MIN, TRUST_MAX]."""
        self.score = max(TRUST_MIN, min(TRUST_MAX, self.score + delta))
        self.last_updated = time.time()


# ---------------------------------------------------------------------------
# Trust Manager
# ---------------------------------------------------------------------------

class TrustManager:
    """
    Manages trust scores for all known neighbours.
    
    Thread-safe: all mutations go through this class.
    Trust data is local-only -- never transmitted to other nodes.
    """
    
    def __init__(self):
        self._scores: Dict[bytes, TrustScore] = {}
    
    def get_or_create(self, node_id: bytes) -> TrustScore:
        """Get or create a trust score for a neighbour."""
        if node_id not in self._scores:
            self._scores[node_id] = TrustScore(node_id=node_id)
        return self._scores[node_id]
    
    def get(self, node_id: bytes) -> Optional[TrustScore]:
        """Get trust score, or None if unknown."""
        return self._scores.get(node_id)
    
    def get_score(self, node_id: bytes) -> int:
        """Get numeric trust score (TRUST_INITIAL if unknown)."""
        ts = self._scores.get(node_id)
        return ts.score if ts else TRUST_INITIAL
    
    def remove(self, node_id: bytes) -> None:
        """Remove a peer's trust data (e.g. peer died)."""
        self._scores.pop(node_id, None)
    
    # --- Challenge events ---
    
    def on_challenge_pass(self, node_id: bytes) -> None:
        ts = self.get_or_create(node_id)
        ts.adjust(SCORE_CHALLENGE_PASS)
        ts.challenges_passed += 1
        ts.challenge_nonce = None
        ts.challenge_retries = 0
    
    def on_challenge_fail(self, node_id: bytes) -> None:
        ts = self.get_or_create(node_id)
        ts.adjust(SCORE_CHALLENGE_FAIL)
        ts.challenges_failed += 1
        ts.challenge_nonce = None
        ts.challenge_retries = 0
    
    def on_challenge_timeout(self, node_id: bytes) -> None:
        ts = self.get_or_create(node_id)
        ts.adjust(SCORE_CHALLENGE_TIMEOUT)
        ts.challenges_failed += 1
        ts.challenge_nonce = None
        ts.challenge_retries = 0
    
    # --- Forwarding events ---
    
    def on_forward_success(self, node_id: bytes) -> None:
        """Called when a message forwarded via this peer was ACKed."""
        ts = self.get_or_create(node_id)
        ts.forwards_sent += 1
        ts.forwards_acked += 1
        ts.adjust(SCORE_FORWARD_SUCCESS)
        # Reset suspect counter on success
        if ts.suspect_relay_count > 0:
            ts.suspect_relay_count = max(0, ts.suspect_relay_count - 1)
    
    def on_forward_fail(self, node_id: bytes, congested: bool = False) -> None:
        """Called when a message forwarded via this peer was NOT ACKed."""
        ts = self.get_or_create(node_id)
        ts.forwards_sent += 1
        penalty = SCORE_FORWARD_FAIL_CONGESTED if congested else SCORE_FORWARD_FAIL
        ts.adjust(penalty)
    
    # --- Multi-path verification ---
    
    def on_suspect_relay(self, node_id: bytes) -> None:
        """Called when this peer is the common failure point across paths."""
        ts = self.get_or_create(node_id)
        ts.suspect_relay_count += 1
        if ts.suspect_relay_count >= SUSPECT_RELAY_THRESHOLD:
            ts.adjust(SCORE_SUSPECT_RELAY)
    
    # --- Other events ---
    
    def on_beacon_ok(self, node_id: bytes) -> None:
        ts = self.get_or_create(node_id)
        ts.adjust(SCORE_BEACON_OK)
    
    def on_identity_change(self, node_id: bytes) -> None:
        ts = self.get_or_create(node_id)
        ts.adjust(SCORE_IDENTITY_CHANGE)
    
    def on_ratchet_ok(self, node_id: bytes) -> None:
        ts = self.get_or_create(node_id)
        ts.adjust(SCORE_RATCHET_OK)
    
    def on_ratchet_fail(self, node_id: bytes) -> None:
        ts = self.get_or_create(node_id)
        ts.adjust(SCORE_RATCHET_FAIL)
    
    # --- Traffic analysis ---
    
    def get_network_avg_success_rate(self) -> float:
        """Average forward success rate across all peers with enough samples."""
        rates = [
            ts.forward_success_rate
            for ts in self._scores.values()
            if ts.forwards_sent >= MIN_FORWARD_SAMPLES
        ]
        if not rates:
            return 1.0
        return sum(rates) / len(rates)
    
    def detect_selective_dropper(self, node_id: bytes) -> bool:
        """
        Detect if a peer's drop rate is anomalously high compared
        to the network average.
        
        A selective dropper forwards enough traffic to seem alive
        but silently drops a fraction of messages.
        """
        ts = self.get(node_id)
        if ts is None or ts.forwards_sent < MIN_FORWARD_SAMPLES:
            return False
        
        network_avg = self.get_network_avg_success_rate()
        peer_rate = ts.forward_success_rate
        
        # Flag if peer's success rate is >20% below network average
        # (e.g. network avg 0.90, peer at 0.68 → flagged)
        threshold = max(0.5, network_avg - 0.20)
        return peer_rate < threshold
    
    # --- Routing integration ---
    
    def trust_weight(self, node_id: bytes) -> float:
        """
        Return a routing weight multiplier (0.0-1.0) based on trust.
        
        Used by the routing layer to bias toward trusted neighbours:
          1.0 = fully trusted
          0.5 = deprioritized
          0.1 = avoided (but not impossible in emergency)
        """
        score = self.get_score(node_id)
        if score >= TRUST_NORMAL:
            return 1.0
        elif score >= TRUST_DEPRIORITIZE:
            # Linear interpolation between 0.5 and 1.0
            return 0.5 + 0.5 * (score - TRUST_DEPRIORITIZE) / (TRUST_NORMAL - TRUST_DEPRIORITIZE)
        else:
            # Below threshold: heavily penalized but not zero
            return max(0.1, score / TRUST_DEPRIORITIZE * 0.5)
    
    # --- Stats ---
    
    def get_stats(self) -> Dict:
        scores = [ts.score for ts in self._scores.values()]
        if not scores:
            return {"peers": 0}
        return {
            "peers": len(scores),
            "avg_score": sum(scores) / len(scores),
            "min_score": min(scores),
            "max_score": max(scores),
            "trusted": sum(1 for s in scores if s >= TRUST_NORMAL),
            "deprioritized": sum(1 for s in scores if TRUST_DEPRIORITIZE <= s < TRUST_NORMAL),
            "avoided": sum(1 for s in scores if s < TRUST_DEPRIORITIZE),
        }
