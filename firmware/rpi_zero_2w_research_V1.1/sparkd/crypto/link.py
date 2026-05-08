"""
SPARK Per-Link Encryption

Provides identity-free radio beacons and per-link encrypted channels
between direct neighbours.

Protocol:
1. Handshake: anonymous ephemeral DH key exchange (cleartext, 33 bytes)
2. Link established: shared secret derived via X25519 ECDH + HKDF
3. All subsequent traffic encrypted with ChaCha20-Poly1305 per-link key
4. Identity (node_id, public keys) exchanged ONLY inside encrypted link

Privacy properties:
- Beacons reveal nothing about node identity
- Encrypted frames are indistinguishable from random bytes
- Each neighbour pair has a unique key (no network-wide secret)
- Compromising one link doesn't affect any other

Wire formats:
  Handshake:  [0x5A] [ephemeral_pubkey (32 bytes)]  = 33 bytes
  Encrypted:  [nonce (12 bytes)] [ciphertext] [tag (16 bytes)]
"""

import os
import struct
import time
from typing import Optional, Tuple, Dict
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import serialization

from .primitives import hkdf_derive, blake2b_hash


# --- Constants -----------------------------------------------------------

# Handshake marker byte (distinguishes handshake from encrypted frames)
HANDSHAKE_MARKER = 0x5A

# Encryption overhead per frame: nonce + Poly1305 tag
LINK_NONCE_SIZE = 12
LINK_TAG_SIZE = 16
LINK_OVERHEAD = LINK_NONCE_SIZE + LINK_TAG_SIZE  # 28 bytes

# How long a link session stays valid without refresh (seconds)
LINK_SESSION_TTL = 600  # 10 minutes

# Maximum number of simultaneous link sessions
MAX_LINK_SESSIONS = 64

# DH ratchet: re-key interval (seconds) for forward secrecy
RATCHET_INTERVAL = 3600  # 1 hour


# --- Data structures -----------------------------------------------------

@dataclass
class LinkSession:
    """
    Symmetric encryption session for a single neighbour link.

    Created after successful DH key exchange.  Uses separate
    directional keys so both sides encrypt with non-overlapping
    key material (prevents reflection attacks).
    """
    peer_radio_id: bytes     # opaque identifier for the radio source
    tx_key: bytes            # 32-byte ChaCha20-Poly1305 key (our TX)
    rx_key: bytes            # 32-byte ChaCha20-Poly1305 key (our RX)
    peer_node_id: Optional[bytes] = None   # learned after identity exchange
    peer_x25519_pubkey: Optional[bytes] = None
    peer_ed25519_pubkey: Optional[bytes] = None
    created_at: float = field(default_factory=time.time)
    last_activity: float = field(default_factory=time.time)
    last_ratchet: float = field(default_factory=time.time)
    ratchet_count: int = 0

    # Cipher objects (lazy-init)
    _tx_cipher: Optional[ChaCha20Poly1305] = field(default=None, repr=False)
    _rx_cipher: Optional[ChaCha20Poly1305] = field(default=None, repr=False)

    @property
    def is_alive(self) -> bool:
        return time.time() - self.last_activity < LINK_SESSION_TTL
    
    @property
    def needs_ratchet(self) -> bool:
        """True when the session keys should be rotated for forward secrecy."""
        return time.time() - self.last_ratchet >= RATCHET_INTERVAL

    @property
    def is_identified(self) -> bool:
        """True once the peer has sent their identity over the link."""
        return self.peer_node_id is not None

    def touch(self) -> None:
        self.last_activity = time.time()

    def channel_binding(self, our_node_id: bytes, peer_node_id: bytes) -> bytes:
        """Compute a channel-binding token for MITM detection.
        
        Both sides compute BLAKE2b(sorted(tx_key, rx_key) || sorted(nodeA, nodeB)).
        Keys are sorted so initiator/responder role (which swaps tx/rx assignment)
        still yields the same binding token.

        Returns a 16-byte binding token.
        """
        keys = sorted([self.tx_key, self.rx_key])
        ids = sorted([our_node_id, peer_node_id])
        material = keys[0] + keys[1] + ids[0] + ids[1]
        return blake2b_hash(material, digest_size=16, person=b"spark-linkbind")

    def ratchet(self, new_shared_secret: bytes) -> None:
        """
        Rotate keys using a new DH shared secret (forward secrecy).
        
        Derives fresh TX/RX keys from the new secret combined with
        the current keys (chain ratchet).  Old keys are overwritten
        so they cannot be recovered from memory.
        """
        chain_material = self.tx_key + self.rx_key + new_shared_secret
        self.tx_key = hkdf_derive(chain_material, 32, b"spark-ratchet-tx")
        self.rx_key = hkdf_derive(chain_material, 32, b"spark-ratchet-rx")
        # Invalidate cached cipher objects so they're rebuilt with new keys
        self._tx_cipher = None
        self._rx_cipher = None
        self.last_ratchet = time.time()
        self.ratchet_count += 1

    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Encrypt a SPARK packet for transmission over this link.

        Returns: nonce (12) || ciphertext || tag (16)
        """
        if self._tx_cipher is None:
            self._tx_cipher = ChaCha20Poly1305(self.tx_key)
        nonce = os.urandom(LINK_NONCE_SIZE)
        ct = self._tx_cipher.encrypt(nonce, plaintext, None)
        return nonce + ct

    def decrypt(self, frame: bytes) -> Optional[bytes]:
        """
        Decrypt a received encrypted frame.

        Args:
            frame: nonce (12) || ciphertext || tag (16)

        Returns:
            Decrypted SPARK packet, or None on failure.
        """
        if len(frame) < LINK_OVERHEAD + 1:
            return None
        if self._rx_cipher is None:
            self._rx_cipher = ChaCha20Poly1305(self.rx_key)
        nonce = frame[:LINK_NONCE_SIZE]
        ct = frame[LINK_NONCE_SIZE:]
        try:
            return self._rx_cipher.decrypt(nonce, ct, None)
        except Exception:
            return None


# --- Handshake -----------------------------------------------------------

def build_handshake() -> Tuple[X25519PrivateKey, bytes]:
    """
    Generate an anonymous handshake beacon.

    Returns:
        (ephemeral_private_key, handshake_bytes)

    The handshake_bytes are broadcast over LoRa (33 bytes total).
    """
    private = X25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return private, bytes([HANDSHAKE_MARKER]) + public


def parse_handshake(data: bytes) -> Optional[bytes]:
    """
    Parse a received handshake beacon.

    Returns the 32-byte ephemeral public key, or None if not a handshake.
    """
    if len(data) < 33:
        return None
    if data[0] != HANDSHAKE_MARKER:
        return None
    return data[1:33]


def complete_handshake(
    our_private: X25519PrivateKey,
    their_public_bytes: bytes,
    we_are_initiator: bool,
) -> LinkSession:
    """
    Complete the DH key exchange and create a LinkSession.

    Both sides derive the same shared secret, but derive TX/RX keys
    with opposite roles so that initiator's TX key == responder's RX key.

    Args:
        our_private: Our ephemeral X25519 private key
        their_public_bytes: Peer's ephemeral X25519 public key (32 bytes)
        we_are_initiator: True selects HKDF init vs resp role; must differ on
            the two peers — we set this from lexicographic pubkey comparison.

    Returns:
        LinkSession with derived keys
    """
    their_public = X25519PublicKey.from_public_bytes(their_public_bytes)
    shared_secret = our_private.exchange(their_public)

    # Derive directional keys using HKDF with role separation
    # Initiator TX = Responder RX and vice versa
    key_a = hkdf_derive(shared_secret, 32, b"spark-link-key-init")
    key_b = hkdf_derive(shared_secret, 32, b"spark-link-key-resp")

    if we_are_initiator:
        tx_key, rx_key = key_a, key_b
    else:
        tx_key, rx_key = key_b, key_a

    return LinkSession(
        peer_radio_id=their_public_bytes,  # use their ephemeral key as radio ID
        tx_key=tx_key,
        rx_key=rx_key,
    )


def is_handshake(data: bytes) -> bool:
    """Check if raw radio data is a handshake beacon (vs encrypted frame)."""
    return len(data) >= 33 and data[0] == HANDSHAKE_MARKER


def is_encrypted_frame(data: bytes) -> bool:
    """Check if raw radio data looks like an encrypted frame."""
    return len(data) >= LINK_OVERHEAD + 1 and data[0] != HANDSHAKE_MARKER


# --- Link Manager --------------------------------------------------------

class LinkManager:
    """
    Manages all per-link encryption sessions for a node.

    Handles:
    - Handshake initiation and completion
    - Frame encryption/decryption
    - Session lifecycle (creation, identity binding, expiry)
    """

    def __init__(self, identity):
        """
        Args:
            identity: Our IdentityKey (for signing identity messages)
        """
        self._identity = identity
        self._sessions: Dict[bytes, LinkSession] = {}  # keyed by peer ephemeral key
        self._sessions_by_node: Dict[bytes, LinkSession] = {}  # keyed by peer node_id
        self._pending_handshakes: Dict[bytes, X25519PrivateKey] = {}  # our pending DH keys

    @property
    def session_count(self) -> int:
        return len(self._sessions)

    def generate_handshake(self) -> bytes:
        """Generate a handshake beacon to broadcast."""
        private, handshake_bytes = build_handshake()
        ephemeral_pub = handshake_bytes[1:33]
        # Only one outstanding initiator ephemeral may be valid: a response
        # must pair with the beacon the peer actually received. Accumulating
        # one key per beacon causes complete_incoming_response to use an
        # arbitrary stale private key and derive wrong link material.
        self._pending_handshakes.clear()
        self._pending_handshakes[ephemeral_pub] = private
        return handshake_bytes

    def handle_handshake(self, handshake_data: bytes) -> Optional[bytes]:
        """
        Handle a received handshake beacon.

        If we don't have a session with this peer, respond with our own
        handshake and establish the link.

        Returns:
            Our handshake response bytes to transmit, or None if already linked.
        """
        their_pubkey = parse_handshake(handshake_data)
        if their_pubkey is None:
            return None

        # Already have a session with this peer?
        if their_pubkey in self._sessions:
            self._sessions[their_pubkey].touch()
            return None

        # Enforce session cap -- evict oldest before adding
        self._enforce_session_cap()

        # Reuse our last beacon ephemeral when present so the peer's
        # complete_incoming_response pairs with the same key we advertised.
        # Otherwise both sides generate fresh keys and derive mismatching secrets
        # when they have each other's beacons (no complementary initiator/responder).
        if self._pending_handshakes:
            our_pub, our_priv = next(iter(self._pending_handshakes.items()))
            we_are_initiator = our_pub < their_pubkey
            session = complete_handshake(our_priv, their_pubkey, we_are_initiator)
            self._sessions[their_pubkey] = session
            self._pending_handshakes.pop(our_pub, None)
            return bytes([HANDSHAKE_MARKER]) + our_pub

        our_private, response_bytes = build_handshake()
        our_pub = response_bytes[1:33]
        we_are_initiator = our_pub < their_pubkey
        session = complete_handshake(our_private, their_pubkey, we_are_initiator)
        self._sessions[their_pubkey] = session

        return response_bytes

    def complete_incoming_response(self, response_data: bytes) -> bool:
        """
        Handle a handshake response to one of our beacons.

        Returns True if a new session was established.
        """
        their_pubkey = parse_handshake(response_data)
        if their_pubkey is None:
            return False

        if their_pubkey in self._sessions:
            return False

        # Enforce session cap before adding
        self._enforce_session_cap()

        # With generate_handshake replacing pending, at most one matches.
        for our_pub, our_priv in list(self._pending_handshakes.items()):
            we_are_initiator = our_pub < their_pubkey
            session = complete_handshake(our_priv, their_pubkey, we_are_initiator)
            self._sessions[their_pubkey] = session
            del self._pending_handshakes[our_pub]
            return True

        return False

    def bind_identity(
        self,
        peer_ephemeral: bytes,
        node_id: bytes,
        x25519_pubkey: bytes,
        ed25519_pubkey: bytes,
        channel_binding_token: bytes = b"",
    ) -> bool:
        """Bind a verified identity to an existing link session.
        
        If *channel_binding_token* is provided (16 bytes), verifies that
        the peer computed the same binding from the shared DH keys.  A
        mismatch means a MITM relay is present and the session is torn down.
        """
        session = self._sessions.get(peer_ephemeral)
        if session is None:
            return False
        
        # Channel binding verification (MITM detection). All-zero token means
        # the sender does not yet know our node id (first identity flight);
        # skip verification in that case.
        if (
            channel_binding_token
            and len(channel_binding_token) == 16
            and channel_binding_token != b"\x00" * 16
        ):
            expected = session.channel_binding(
                our_node_id=self._identity.node_id,
                peer_node_id=node_id,
            )
            if expected != channel_binding_token:
                # MITM detected -- tear down the session
                self._sessions.pop(peer_ephemeral, None)
                return False
        
        session.peer_node_id = node_id
        session.peer_x25519_pubkey = x25519_pubkey
        session.peer_ed25519_pubkey = ed25519_pubkey
        self._sessions_by_node[node_id] = session
        return True
    
    def get_channel_binding(self, peer_node_id: bytes) -> Optional[bytes]:
        """Get the channel binding token for a link session.
        
        The caller includes this in their signed identity message so
        the peer can verify no MITM relay is present.
        """
        session = self._sessions_by_node.get(peer_node_id)
        if session is None:
            return None
        return session.channel_binding(self._identity.node_id, peer_node_id)

    def encrypt_for_peer(self, peer_node_id: bytes, plaintext: bytes) -> Optional[bytes]:
        """Encrypt a SPARK packet for a specific identified peer."""
        session = self._sessions_by_node.get(peer_node_id)
        if session is None or not session.is_alive:
            return None
        session.touch()
        return session.encrypt(plaintext)

    def try_decrypt(self, encrypted_frame: bytes) -> Optional[Tuple[bytes, LinkSession]]:
        """
        Try to decrypt a frame using all active link sessions.

        Returns (plaintext, session) on success, None on failure.
        """
        for session in self._sessions.values():
            if not session.is_alive:
                continue
            plaintext = session.decrypt(encrypted_frame)
            if plaintext is not None:
                session.touch()
                return plaintext, session
        return None

    def get_session_for_node(self, node_id: bytes) -> Optional[LinkSession]:
        """Get the link session for an identified peer."""
        return self._sessions_by_node.get(node_id)

    def get_identified_peers(self) -> Dict[bytes, LinkSession]:
        """Return all sessions where peer identity is known."""
        return {
            nid: s for nid, s in self._sessions_by_node.items()
            if s.is_alive and s.is_identified
        }

    def initiate_ratchet(self, peer_node_id: bytes) -> Optional[bytes]:
        """
        Initiate a DH ratchet with an identified peer.
        
        Returns:
            33-byte handshake (marker + ephemeral pubkey) to send to peer,
            or None if no session exists.
        """
        session = self._sessions_by_node.get(peer_node_id)
        if session is None or not session.is_alive:
            return None
        
        private, handshake_bytes = build_handshake()
        ephemeral_pub = handshake_bytes[1:33]
        self._pending_handshakes[ephemeral_pub] = private
        return handshake_bytes
    
    def complete_ratchet(self, peer_node_id: bytes, their_ratchet_key: bytes) -> bool:
        """
        Complete a DH ratchet step by deriving a new shared secret
        from the peer's new ephemeral key.
        
        Returns True if the ratchet succeeded.
        """
        session = self._sessions_by_node.get(peer_node_id)
        if session is None:
            return False
        
        # Find the corresponding pending handshake
        for our_pub, our_priv in list(self._pending_handshakes.items()):
            try:
                their_pub = X25519PublicKey.from_public_bytes(their_ratchet_key)
                new_secret = our_priv.exchange(their_pub)
                session.ratchet(new_secret)
                del self._pending_handshakes[our_pub]
                return True
            except Exception:
                continue
        
        # If we don't have a pending handshake, create a new DH exchange
        try:
            new_priv = X25519PrivateKey.generate()
            their_pub = X25519PublicKey.from_public_bytes(their_ratchet_key)
            new_secret = new_priv.exchange(their_pub)
            session.ratchet(new_secret)
            return True
        except Exception:
            return False
    
    def get_sessions_needing_ratchet(self) -> list:
        """Return list of peer_node_ids whose sessions need key rotation."""
        result = []
        for nid, session in self._sessions_by_node.items():
            if session.is_alive and session.needs_ratchet:
                result.append(nid)
        return result

    def _enforce_session_cap(self) -> None:
        """Evict oldest sessions when at capacity (MAX_LINK_SESSIONS)."""
        # First, remove any expired sessions
        expired_keys = [k for k, s in self._sessions.items() if not s.is_alive]
        for k in expired_keys:
            session = self._sessions.pop(k)
            if session.peer_node_id:
                self._sessions_by_node.pop(session.peer_node_id, None)

        # If still at cap, evict least-recently-active session
        while len(self._sessions) >= MAX_LINK_SESSIONS:
            oldest_key = min(self._sessions, key=lambda k: self._sessions[k].last_activity)
            session = self._sessions.pop(oldest_key)
            if session.peer_node_id:
                self._sessions_by_node.pop(session.peer_node_id, None)

    def cleanup_expired(self) -> int:
        """Remove expired sessions. Returns count removed."""
        expired_keys = [k for k, s in self._sessions.items() if not s.is_alive]
        for k in expired_keys:
            session = self._sessions.pop(k)
            if session.peer_node_id:
                self._sessions_by_node.pop(session.peer_node_id, None)
        expired_pending = [
            k for k in self._pending_handshakes
            if k not in self._sessions
        ]
        # Limit stale pending handshakes (older than 60s)
        if len(self._pending_handshakes) > 10:
            to_remove = list(self._pending_handshakes.keys())[:-10]
            for k in to_remove:
                del self._pending_handshakes[k]
        return len(expired_keys)
