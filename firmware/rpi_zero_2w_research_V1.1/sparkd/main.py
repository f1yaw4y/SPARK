"""
SPARK Daemon Main Entry Point

The sparkd daemon manages:
- Radio interfaces
- Peer discovery and mesh maintenance
- Onion routing
- Message delivery
- RPC interface for meshctl
"""

import os
import sys
import signal
import time
import zlib
import random
import logging
import threading
import argparse
from pathlib import Path
from typing import Optional, Dict

from . import __version__
from .config import Config, DEFAULT_CONFIG_PATH
from .crypto.keys import load_identity, IdentityKey, verify_signature, verify_node_id_binding
from .crypto.link import (
    LinkManager, is_handshake, is_encrypted_frame, LINK_OVERHEAD,
)
from .radio.base import BaseRadio, RadioConfig as HWRadioConfig, RadioPacket
from .radio.loopback import LoopbackRadio
from .packet.format import (
    PacketType, Packet, parse_packet, build_packet, BeaconPayload, PacketFlags,
    DirectMessagePayload, AckPayload, IdentityPayload,
)
from .crypto.envelope import seal_envelope_for_pubkey_bytes, open_envelope, EnvelopeError
from .crypto.primitives import generate_message_id
from .packet.dedup import DeduplicationCache
from .packet.store import MessageStore
from .mesh.peer import PeerManager
from .mesh.submesh import SubMeshManager
from .mesh.region import RegionManager, RegionRole
from .mesh.routing import Router, RoutingDecision
from .onion.layers import OnionBuilder
from .onion.gateway import GatewayProcessor, ProcessingResult
from .onion.delivery import DeliveryManager
from .mesh.trust import TrustManager
from .rpc.server import RPCServer


# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("sparkd")

# LoRa is half-duplex and collision-prone; repeat critical link frames so one
# copy usually gets through (recipient deduplicates on decrypted plaintext).
LINK_TX_REDUNDANCY = 3
LINK_TX_REDUNDANCY_GAP_SEC = 0.15
ACK_TX_REDUNDANCY = 2
ACK_TX_REDUNDANCY_GAP_SEC = 0.12

# Payload type flags for DirectMessagePayload
PAYLOAD_COMPRESSED = 0x01   # Payload is zlib-compressed
PAYLOAD_FRAGMENTED = 0x02   # Payload starts with 2-byte fragment header

# Fragmentation limits
MAX_FRAGMENTS = 5           # Max fragments per message (~840 bytes compressed)
FRAGMENT_HEADER_SIZE = 2    # [index: 1 byte, total: 1 byte]
FRAGMENT_CACHE_TTL = 60.0   # Seconds to keep incomplete fragment sets

# Replay protection: reject messages with timestamps older than this
MAX_MESSAGE_AGE = 600       # 10 minutes


class SparkDaemon:
    """
    Main SPARK daemon class.
    
    Coordinates all subsystems:
    - Radio management
    - Mesh networking
    - Onion routing
    - Message handling
    - RPC interface
    """
    
    def __init__(self, config: Config):
        """
        Initialize daemon with configuration.
        
        Args:
            config: Loaded configuration
        """
        self.config = config
        self._running = False
        self._shutdown_event = threading.Event()
        
        # Core components (initialized in start())
        self._identity: Optional[IdentityKey] = None
        self._radio: Optional[BaseRadio] = None
        self._peer_manager: Optional[PeerManager] = None
        self._submesh_manager: Optional[SubMeshManager] = None
        self._region_manager: Optional[RegionManager] = None
        self._router: Optional[Router] = None
        self._onion_builder: Optional[OnionBuilder] = None
        self._gateway_processor: Optional[GatewayProcessor] = None
        self._delivery_manager: Optional[DeliveryManager] = None
        self._dedup_cache: Optional[DeduplicationCache] = None
        self._message_store: Optional[MessageStore] = None
        self._rpc_server: Optional[RPCServer] = None
        self._link_manager: Optional[LinkManager] = None
        self._trust_manager: Optional[TrustManager] = None
        
        # Worker threads
        self._beacon_thread: Optional[threading.Thread] = None
        self._maintenance_thread: Optional[threading.Thread] = None
        self._rx_thread: Optional[threading.Thread] = None
        
        # Beacon sequence counter
        self._beacon_seq = 0
        
        # Fragment reassembly cache
        # Key: message_id (bytes), Value: {total, payload_type, fragments: {idx: data}, first_seen}
        self._fragment_cache: Dict[bytes, dict] = {}
        self._fragment_lock = threading.Lock()
        
        # Pending receipt tokens for authenticated E2E ACK verification
        # Key: message_id (bytes), Value: receipt_token (bytes)
        self._pending_receipt_tokens: Dict[bytes, bytes] = {}
    
    def start(self) -> None:
        """Start the daemon."""
        logger.info(f"Starting SPARK daemon v{__version__}")
        
        # Ensure directories exist
        self.config.storage.data_dir.mkdir(parents=True, exist_ok=True)
        self.config.socket_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Load or generate identity
        logger.info("Loading identity...")
        self._identity = load_identity(
            self.config.storage.data_dir,
            create_if_missing=True,
        )
        logger.info(f"Node ID: {self._identity.node_id.hex()}")
        
        # Initialize storage
        logger.info("Initializing storage...")
        self._message_store = MessageStore(
            db_path=self.config.storage.data_dir / "messages.db",
            retention_seconds=self.config.storage.message_retention,
        )
        
        self._dedup_cache = DeduplicationCache(
            ttl_seconds=self.config.storage.dedup_cache_ttl,
            max_entries=self.config.storage.dedup_cache_size,
        )
        self._dedup_cache.start()
        
        # Initialize mesh components
        logger.info("Initializing mesh...")
        self._peer_manager = PeerManager(
            db_path=self.config.storage.data_dir / "peers.db",
        )
        
        self._submesh_manager = SubMeshManager(
            peer_manager=self._peer_manager,
            local_node_id=self._identity.node_id,
        )
        
        self._region_manager = RegionManager(
            peer_manager=self._peer_manager,
            submesh_manager=self._submesh_manager,
            local_node_id=self._identity.node_id,
        )
        
        self._router = Router(
            peer_manager=self._peer_manager,
            region_manager=self._region_manager,
            local_node_id=self._identity.node_id,
        )
        
        # Initialize onion routing
        logger.info("Initializing onion routing...")
        self._onion_builder = OnionBuilder(
            identity=self._identity,
            peer_manager=self._peer_manager,
            region_manager=self._region_manager,
        )
        
        self._gateway_processor = GatewayProcessor(
            identity=self._identity,
            region_manager=self._region_manager,
        )
        
        self._delivery_manager = DeliveryManager(
            delivery_timeout=self.config.storage.message_retention,
        )
        
        # Initialize link encryption
        logger.info("Initializing link encryption...")
        self._link_manager = LinkManager(self._identity)
        self._trust_manager = TrustManager()
        
        # Initialize radio
        logger.info("Initializing radio...")
        self._init_radio()
        
        # Initialize RPC server
        logger.info("Starting RPC server...")
        self._rpc_server = RPCServer(socket_path=self.config.socket_path)
        self._register_rpc_handlers()
        self._rpc_server.start()
        
        # Start worker threads
        self._running = True
        
        self._beacon_thread = threading.Thread(
            target=self._beacon_loop,
            daemon=True,
            name="beacon",
        )
        self._beacon_thread.start()
        
        self._maintenance_thread = threading.Thread(
            target=self._maintenance_loop,
            daemon=True,
            name="maintenance",
        )
        self._maintenance_thread.start()
        
        self._rx_thread = threading.Thread(
            target=self._receive_loop,
            daemon=True,
            name="radio-rx",
        )
        self._rx_thread.start()
        
        logger.info("SPARK daemon started")
    
    def stop(self) -> None:
        """Stop the daemon."""
        logger.info("Stopping SPARK daemon...")
        
        self._running = False
        self._shutdown_event.set()
        
        # Stop RPC server
        if self._rpc_server:
            self._rpc_server.stop()
        
        # Stop radio
        if self._radio:
            self._radio.stop_receive()
            self._radio.sleep()
        
        # Stop dedup cache
        if self._dedup_cache:
            self._dedup_cache.stop()
        
        # Wait for threads
        if self._beacon_thread:
            self._beacon_thread.join(timeout=5.0)
        if self._maintenance_thread:
            self._maintenance_thread.join(timeout=5.0)
        if self._rx_thread:
            self._rx_thread.join(timeout=5.0)
        
        logger.info("SPARK daemon stopped")
    
    def _init_radio(self) -> None:
        """Initialize radio interface."""
        if not self.config.radio.enabled:
            logger.warning("Radio disabled in configuration")
            self._radio = LoopbackRadio("loopback")
        else:
            radio_type = self.config.radio.type.lower()
            
            if radio_type == "loopback":
                self._radio = LoopbackRadio("loopback")
            elif radio_type == "lora_sx1262":
                try:
                    from .radio.lora_sx1262 import LoRaSX1262Radio
                    self._radio = LoRaSX1262Radio("lora")
                except Exception as e:
                    logger.error(f"Failed to initialize LoRa radio: {e}")
                    logger.warning("Falling back to loopback radio")
                    self._radio = LoopbackRadio("loopback")
            else:
                logger.warning(f"Unknown radio type: {radio_type}, using loopback")
                self._radio = LoopbackRadio("loopback")
        
        # Configure radio
        hw_config = HWRadioConfig(
            frequency=self.config.radio.frequency,
            tx_power=self.config.radio.tx_power,
            spreading_factor=self.config.radio.spreading_factor,
            bandwidth=self.config.radio.bandwidth,
            coding_rate=self.config.radio.coding_rate,
        )
        self._radio.configure(hw_config)
        self._radio.start_receive()
    
    def _register_rpc_handlers(self) -> None:
        """Register RPC method handlers."""
        self._rpc_server.register("status", self._rpc_status)
        self._rpc_server.register("peers", self._rpc_peers)
        self._rpc_server.register("regions", self._rpc_regions)
        self._rpc_server.register("routes", self._rpc_routes)
        self._rpc_server.register("send", self._rpc_send)
        self._rpc_server.register("inbox", self._rpc_inbox)
        self._rpc_server.register("read_message", self._rpc_read_message)
        self._rpc_server.register("delete_message", self._rpc_delete_message)
        self._rpc_server.register("clear_inbox", self._rpc_clear_inbox)
        self._rpc_server.register("message_status", self._rpc_message_status)
        self._rpc_server.register("debug", self._rpc_debug)
    
    # === Worker Loops ===
    
    def _beacon_loop(self) -> None:
        """Periodic beacon transmission."""
        while self._running:
            try:
                self._send_beacon()
            except Exception as e:
                logger.error(f"Beacon error: {e}")
            
            # Wait for interval or shutdown
            self._shutdown_event.wait(self.config.mesh.beacon_interval)
    
    def _maintenance_loop(self) -> None:
        """Periodic mesh maintenance."""
        while self._running:
            try:
                # Update peer states
                self._peer_manager.update_peer_states()
                
                # Recalculate regions
                self._region_manager.recalculate()
                
                # Clean up routing
                self._router.cleanup_expired()
                
                # Clean up storage
                self._message_store.cleanup_expired()
                self._dedup_cache.cleanup()
                
                # Process delivery retries
                self._delivery_manager.cleanup_expired()
                
                # Clean up expired link sessions
                removed = self._link_manager.cleanup_expired()
                if removed:
                    logger.debug(f"Cleaned up {removed} expired link sessions")
                
                # DH key ratchet for forward secrecy
                for peer_id in self._link_manager.get_sessions_needing_ratchet():
                    ratchet_data = self._link_manager.initiate_ratchet(peer_id)
                    if ratchet_data:
                        logger.debug(f"Initiating key ratchet with {peer_id.hex()[:8]}")
                        self._trust_manager.on_ratchet_ok(peer_id)
                
                # Clean up incomplete fragment sets
                self._cleanup_fragment_cache()
                
                # Clean up stale pending receipt tokens (older entries are
                # removed when the dict grows beyond a reasonable cap)
                if len(self._pending_receipt_tokens) > 500:
                    # Keep only the most recent 250 entries
                    keys = list(self._pending_receipt_tokens.keys())
                    for k in keys[:len(keys) - 250]:
                        self._pending_receipt_tokens.pop(k, None)
                
            except Exception as e:
                logger.error(f"Maintenance error: {e}")
            
            self._shutdown_event.wait(60)  # Run every minute
    
    def _receive_loop(self) -> None:
        """Radio receive loop."""
        error_backoff = 0.0
        while self._running:
            try:
                packet = self._radio.receive(timeout_ms=1000)
                if packet:
                    self._handle_radio_packet(packet)
                error_backoff = 0.0  # Reset on success
            except Exception as e:
                if error_backoff == 0.0:
                    logger.error(f"Receive error: {e}")
                # Exponential backoff on repeated errors to prevent log spam
                error_backoff = min(error_backoff + 1.0, 10.0)
                self._shutdown_event.wait(error_backoff)
    
    # === Link-encrypted transmit helper ===
    
    def _link_transmit(self, recipient_node_id: bytes, packet: Packet) -> bool:
        """Encrypt a SPARK packet with the link key for a specific peer and transmit.
        
        All non-handshake traffic MUST go through this method to ensure
        per-link encryption is applied.  Falls back to raw transmit only
        if no link session exists (e.g. during initial setup).
        
        Returns True if sent successfully.
        """
        raw = packet.to_bytes()
        encrypted = self._link_manager.encrypt_for_peer(recipient_node_id, raw)
        if encrypted:
            self._radio.transmit(encrypted)
            return True
        # No link session -- cannot send securely; log and drop
        logger.warning(
            "No link session for %s; dropping packet (peer may need fresh handshake)",
            recipient_node_id.hex()[:16],
        )
        return False
    
    def _link_transmit_burst(
        self,
        recipient_node_id: bytes,
        packet: Packet,
        *,
        copies: int,
        gap_sec: float,
    ) -> bool:
        """Transmit the same logical packet several times on the link layer.
        
        Each attempt uses a fresh ChaCha20 nonce (see LinkSession.encrypt).
        The peer deduplicates on inner plaintext after decryption.
        """
        for i in range(copies):
            if not self._link_transmit(recipient_node_id, packet):
                return False
            if i < copies - 1:
                jitter = random.uniform(0, gap_sec * 0.35)
                time.sleep(gap_sec + jitter)
        return True
    
    def _link_broadcast(self, packet: Packet) -> None:
        """Encrypt and transmit a packet to ALL identified link partners.
        
        Used for packets where we don't know the specific next-hop
        (e.g. ACKs that need to reach direct neighbours).
        """
        raw = packet.to_bytes()
        for node_id in list(self._link_manager.get_identified_peers().keys()):
            encrypted = self._link_manager.encrypt_for_peer(node_id, raw)
            if encrypted:
                self._radio.transmit(encrypted)
    
    # === Packet Handling ===
    
    def _send_beacon(self) -> None:
        """Send an anonymous handshake beacon (identity-free).
        
        The beacon is just an ephemeral X25519 DH key (33 bytes).
        No node_id, no public key, no region -- observers see only
        random bytes prefixed with 0x5A.  Identity is exchanged
        only over established encrypted links.
        """
        handshake_bytes = self._link_manager.generate_handshake()
        self._radio.transmit(handshake_bytes)
        
        # After sending handshake, send identity to all established links
        self._send_identity_to_links()
    
    def _send_identity_to_links(self) -> None:
        """Send signed identity to all link partners.
        
        Includes a per-session channel binding token so each peer can
        detect MITM relays (the token is derived from the DH shared
        secret + both node IDs).
        """
        region_id = self._region_manager.get_local_region_id() or b"\x00" * 16
        capabilities = 0
        role = self._region_manager.get_local_role()
        if role == RegionRole.GATEWAY:
            capabilities |= BeaconPayload.CAPABILITIES_GATEWAY
        if role in (RegionRole.RELAY, RegionRole.GATEWAY):
            capabilities |= BeaconPayload.CAPABILITIES_RELAY
        
        self._beacon_seq = (self._beacon_seq + 1) & 0xFFFF
        
        # Send to all sessions (identified or not -- identity exchange
        # is how they become identified)
        for _ephemeral, session in list(self._link_manager._sessions.items()):
            if not session.is_alive:
                continue
            
            # Compute per-session channel binding token
            peer_nid = session.peer_node_id or b"\x00" * 16
            cb_token = session.channel_binding(self._identity.node_id, peer_nid) if peer_nid != b"\x00" * 16 else b"\x00" * 16
            
            identity = IdentityPayload(
                node_id=self._identity.node_id,
                x25519_key=self._identity.x25519_public_bytes,
                ed25519_key=self._identity.public_key_bytes,
                region_id=region_id,
                capabilities=capabilities,
                radio_type=1,
                sequence=self._beacon_seq,
                signature=b"\x00" * 64,
                channel_binding=cb_token,
            )
            identity.signature = self._identity.sign(identity.signed_data())
            
            inner = build_packet(
                packet_type=PacketType.BEACON,
                payload=identity.to_bytes(),
                ttl=1,
            )
            encrypted = session.encrypt(inner.to_bytes())
            self._radio.transmit(encrypted)
    
    def _handle_radio_packet(self, radio_packet: RadioPacket) -> None:
        """Handle a received radio packet.
        
        Two types of frames arrive:
        1. Handshake beacons (33 bytes, cleartext, identity-free)
        2. Link-encrypted frames (nonce + ciphertext + tag)
        """
        data = radio_packet.data
        
        # --- Handshake beacon (identity-free, cleartext) ---
        if is_handshake(data):
            response = self._link_manager.handle_handshake(data)
            if response:
                # Send our handshake response
                self._radio.transmit(response)
            else:
                # Might be a response to one of our handshakes
                self._link_manager.complete_incoming_response(data)
            return
        
        # --- Link-encrypted frame ---
        if is_encrypted_frame(data):
            result = self._link_manager.try_decrypt(data)
            if result is None:
                return  # Can't decrypt with any link key -- not for us
            
            plaintext, session = result
            
            # Check for duplicates on the decrypted inner packet
            if self._dedup_cache.check_and_add(plaintext):
                return
            
            try:
                packet = parse_packet(
                    plaintext,
                    rssi=radio_packet.rssi,
                    snr=radio_packet.snr,
                    received_at=radio_packet.timestamp,
                )
            except Exception as e:
                logger.debug(f"Failed to parse decrypted packet: {e}")
                return
            
            # Handle identity exchange (beacon inside encrypted link)
            if packet.packet_type == PacketType.BEACON:
                self._handle_link_identity(packet, session)
                return
            
            # Route based on packet type
            if packet.packet_type == PacketType.DIRECT:
                self._handle_direct(packet)
            elif packet.packet_type == PacketType.ONION:
                self._handle_onion(packet)
            elif packet.packet_type == PacketType.ACK:
                self._handle_ack(packet)
            else:
                logger.warning(f"Unhandled packet type: {packet.packet_type}")
            return
        
        # --- Unknown frame format ---
        # No legacy/cleartext fallback -- all traffic must use link encryption.
        # Silently discard to prevent cleartext injection attacks.
        logger.debug("Dropping unrecognised frame (not handshake or encrypted)")
    
    def _handle_link_identity(self, packet: Packet, session) -> None:
        """Handle a signed identity payload received over an encrypted link."""
        try:
            ident = IdentityPayload.from_bytes(packet.payload)
        except Exception as e:
            logger.debug(f"Failed to parse identity payload: {e}")
            return
        
        # Verify node_id binding
        if not verify_node_id_binding(ident.node_id, ident.ed25519_key):
            logger.debug("Link identity rejected: node_id mismatch")
            return
        
        # Verify signature
        if not verify_signature(ident.ed25519_key, ident.signed_data(), ident.signature):
            logger.debug("Link identity rejected: bad signature")
            return
        
        # Bind identity to the link session (with channel binding MITM check)
        if not self._link_manager.bind_identity(
            peer_ephemeral=session.peer_radio_id,
            node_id=ident.node_id,
            x25519_pubkey=ident.x25519_key,
            ed25519_pubkey=ident.ed25519_key,
            channel_binding_token=ident.channel_binding,
        ):
            logger.warning("Link identity rejected: channel binding mismatch (possible MITM)")
            return
        
        # Update peer manager (same as old beacon handler)
        self._peer_manager.add_or_update_peer(
            node_id=ident.node_id,
            public_key=ident.x25519_key,
            region_id=ident.region_id,
            capabilities=ident.capabilities,
            rssi=packet.rssi,
            snr=packet.snr,
            beacon_seq=ident.sequence,
        )
        
        # Update trust: successful identity exchange
        self._trust_manager.on_beacon_ok(ident.node_id)
        
        logger.debug(f"Link identity established: {ident.node_id.hex()[:16]}...")
    
    def _handle_direct(self, packet: Packet) -> None:
        """Handle a direct (non-onion) encrypted message."""
        try:
            # Decrypt envelope with our private key
            plaintext = open_envelope(
                envelope=packet.payload,
                recipient_identity=self._identity,
                associated_data=b"spark-direct-v1",
            )
        except EnvelopeError:
            # Not for us (encrypted to someone else's key)
            logger.debug("Direct message: decryption failed (not for us)")
            return
        except Exception as e:
            logger.debug(f"Direct message: error: {e}")
            return
        
        try:
            msg = DirectMessagePayload.from_bytes(plaintext)
        except Exception as e:
            logger.debug(f"Direct message: failed to parse: {e}")
            return
        
        # Replay protection: reject messages with stale timestamps
        now = int(time.time())
        age = abs(now - msg.timestamp)
        if age > MAX_MESSAGE_AGE:
            logger.debug(
                f"Direct message rejected: timestamp too far off "
                f"(age={age}s, max={MAX_MESSAGE_AGE}s)"
            )
            return
        
        payload_type = msg.payload_type
        
        # Fragmented message -- buffer and reassemble
        if payload_type & PAYLOAD_FRAGMENTED:
            self._buffer_fragment(msg)
            return
        
        # Single-packet message -- decompress if needed
        payload_data = msg.payload
        if payload_type & PAYLOAD_COMPRESSED:
            try:
                payload_data = zlib.decompress(payload_data)
            except zlib.error as e:
                logger.debug(f"Direct message: decompression failed: {e}")
                return
        
        logger.info(f"Received direct message: {msg.message_id.hex()[:16]}...")
        
        # Store in inbox
        self._message_store.store_incoming(
            message_id=msg.message_id,
            sender_id=b"\x00" * 16,  # Unknown (privacy)
            recipient_id=self._identity.node_id,
            payload=payload_data,
        )
        
        # Send delivery receipt
        self._send_ack(msg.message_id)
    
    def _buffer_fragment(self, msg: DirectMessagePayload) -> None:
        """Buffer a message fragment and reassemble when all parts arrive."""
        if len(msg.payload) < FRAGMENT_HEADER_SIZE:
            return
        
        frag_index = msg.payload[0]
        frag_total = msg.payload[1]
        frag_data = msg.payload[FRAGMENT_HEADER_SIZE:]
        
        if frag_total < 1 or frag_total > MAX_FRAGMENTS or frag_index >= frag_total:
            logger.debug(f"Fragment: invalid header idx={frag_index} total={frag_total}")
            return
        
        msg_key = msg.message_id
        
        with self._fragment_lock:
            if msg_key not in self._fragment_cache:
                self._fragment_cache[msg_key] = {
                    'total': frag_total,
                    'payload_type': msg.payload_type,
                    'fragments': {},
                    'first_seen': time.time(),
                }
            
            entry = self._fragment_cache[msg_key]
            entry['fragments'][frag_index] = frag_data
            
            received = len(entry['fragments'])
            logger.debug(
                f"Fragment {frag_index+1}/{frag_total} for "
                f"{msg.message_id.hex()[:16]}... ({received}/{frag_total})"
            )
            
            # Not complete yet
            if received < entry['total']:
                return
            
            # All fragments received -- reassemble
            reassembled = b''.join(
                entry['fragments'][i] for i in range(entry['total'])
            )
            payload_type = entry['payload_type']
            del self._fragment_cache[msg_key]
        
        # Decompress if needed (outside lock)
        if payload_type & PAYLOAD_COMPRESSED:
            try:
                reassembled = zlib.decompress(reassembled)
            except zlib.error as e:
                logger.debug(f"Fragment reassembly: decompression failed: {e}")
                return
        
        logger.info(
            f"Received message ({frag_total} fragments, "
            f"{len(reassembled)} bytes): {msg.message_id.hex()[:16]}..."
        )
        
        # Store in inbox
        self._message_store.store_incoming(
            message_id=msg.message_id,
            sender_id=b"\x00" * 16,  # Unknown (privacy)
            recipient_id=self._identity.node_id,
            payload=reassembled,
        )
        
        # Send delivery receipt (only after full reassembly)
        self._send_ack(msg.message_id)
    
    def _cleanup_fragment_cache(self) -> None:
        """Remove incomplete fragment sets that have timed out."""
        now = time.time()
        with self._fragment_lock:
            expired = [
                key for key, entry in self._fragment_cache.items()
                if now - entry['first_seen'] > FRAGMENT_CACHE_TTL
            ]
            for key in expired:
                logger.debug(f"Fragment cache: expired incomplete set {key.hex()[:16]}...")
                del self._fragment_cache[key]
    
    def _handle_onion(self, packet: Packet) -> None:
        """Handle an onion-routed packet.
        
        Tries to peel each layer. If we get a FORWARD result, we first
        attempt to process the inner envelope locally (handles the case
        where the same node is the gateway for multiple layers, e.g. in
        small networks). Only if local processing fails do we forward
        over the air.
        """
        self._process_onion_envelope(packet.payload)
    
    def _process_onion_envelope(self, envelope: bytes, depth: int = 0) -> bool:
        """Recursively process an onion envelope.
        
        Args:
            envelope: The encrypted onion envelope
            depth: Recursion depth (safety limit)
            
        Returns:
            True if the envelope was handled (delivered or forwarded)
        """
        if depth > 3:
            logger.warning("Onion processing exceeded max depth")
            return False
        
        for layer in (1, 2, 3):
            result = self._gateway_processor.process(envelope, layer)
            
            if result.result == ProcessingResult.DROP_DECRYPT:
                continue  # Not for us at this layer
            
            if result.result == ProcessingResult.FORWARD:
                # Try to process the inner envelope locally first.
                # This handles small networks where we are the gateway
                # for multiple (or all) layers of the same onion.
                if self._process_onion_envelope(result.inner_envelope, depth + 1):
                    return True
                
                # Could not process locally — forward over the air
                logger.debug(f"Onion layer {layer}: forwarding to region {result.next_region_id.hex()[:8]}...")
                self._forward_to_region(
                    result.next_region_id,
                    result.inner_envelope,
                    result.ttl,
                )
                return True
            
            if result.result == ProcessingResult.DELIVER_LOCAL:
                # Message for us
                self._deliver_local(
                    result.message_id,
                    result.payload,
                    result.payload_type,
                    result.timestamp,
                    result.receipt_token,
                )
                return True
            
            if result.result == ProcessingResult.DELIVER_REGION:
                # Deliver to someone in our region
                self._deliver_in_region(
                    result.dest_node_id,
                    result.message_id,
                    result.payload,
                )
                return True
            
            if result.result in (ProcessingResult.DROP_EXPIRED, ProcessingResult.DROP_INVALID):
                logger.warning(f"Onion layer {layer}: dropped: {result.error_message}")
                return True  # Handled (dropped intentionally)
        
        # Could not decrypt any layer — not for us
        return False
    
    def _handle_ack(self, packet: Packet) -> None:
        """Handle an acknowledgment packet.
        
        Verifies the receipt token to ensure the ACK came from the
        real recipient (not a malicious node forging delivery confirmation).
        """
        try:
            ack = AckPayload.from_bytes(packet.payload)
        except Exception:
            return
        
        # Verify receipt token if we have one stored for this message
        expected_token = self._pending_receipt_tokens.pop(ack.message_id, None)
        if expected_token is not None:
            if ack.receipt_token != expected_token:
                logger.warning(
                    f"ACK receipt token mismatch for {ack.message_id.hex()[:16]} "
                    f"-- possible forged ACK, ignoring"
                )
                return
        
        if self._delivery_manager.handle_ack(ack.message_id, ack.hop_count):
            logger.info(f"Delivery receipt verified: {ack.message_id.hex()[:16]}...")
    
    def _send_ack(self, message_id: bytes, receipt_token: bytes = None) -> None:
        """Send a link-encrypted delivery acknowledgment.
        
        ACKs are broadcast to all link partners (encrypted per-link)
        so the sender knows the message was delivered.  No cleartext
        metadata leaves the radio.
        
        The receipt_token (when present) proves to the sender that the
        real recipient received the message.  Without it, a malicious
        node could forge an ACK.
        """
        ack = AckPayload(
            message_id=message_id,
            status=AckPayload.STATUS_SUCCESS,
            hop_count=0,
            receipt_token=receipt_token or b"\x00" * 16,
        )
        
        packet = build_packet(
            packet_type=PacketType.ACK,
            payload=ack.to_bytes(),
            ttl=1,
        )
        
        try:
            for r in range(ACK_TX_REDUNDANCY):
                self._link_broadcast(packet)
                if r < ACK_TX_REDUNDANCY - 1:
                    time.sleep(
                        ACK_TX_REDUNDANCY_GAP_SEC
                        + random.uniform(0, ACK_TX_REDUNDANCY_GAP_SEC * 0.35)
                    )
            logger.debug(f"Sent delivery ACK for {message_id.hex()[:16]}...")
        except Exception as e:
            logger.debug(f"Failed to send ACK: {e}")
    
    def _forward_to_region(
        self,
        region_id: bytes,
        envelope: bytes,
        ttl: int,
    ) -> None:
        """Forward an onion packet to another region (link-encrypted)."""
        packet = build_packet(
            packet_type=PacketType.ONION,
            payload=envelope,
            ttl=ttl,
        )
        
        # Find best peer for region
        peer = self._region_manager.get_gateway_for_region(region_id)
        
        if peer:
            self._link_transmit(peer.node_id, packet)
        else:
            # No specific gateway -- broadcast to all link partners
            self._link_broadcast(packet)
    
    def _deliver_local(
        self,
        message_id: bytes,
        payload: bytes,
        payload_type: int,
        timestamp: int = 0,
        receipt_token: bytes = None,
    ) -> None:
        """Handle a message delivered to us (onion path)."""
        # Replay protection: reject messages with stale timestamps
        if timestamp > 0:
            now = int(time.time())
            age = abs(now - timestamp)
            if age > MAX_MESSAGE_AGE:
                logger.debug(
                    f"Onion delivery rejected: timestamp too far off "
                    f"(age={age}s, max={MAX_MESSAGE_AGE}s)"
                )
                return
        
        # Decompress if payload was compressed by sender
        if payload_type & PAYLOAD_COMPRESSED:
            try:
                payload = zlib.decompress(payload)
            except zlib.error as e:
                logger.debug(f"Onion delivery: decompression failed: {e}")
                return
        
        logger.info(f"Received message: {message_id.hex()[:16]}...")
        
        # Store in inbox
        # Note: sender_id not known at this layer (intentional for privacy)
        self._message_store.store_incoming(
            message_id=message_id,
            sender_id=b"\x00" * 16,  # Unknown
            recipient_id=self._identity.node_id,
            payload=payload,
        )
        
        # Send delivery receipt with the receipt token extracted from the
        # onion layer -- this proves to the sender that we (the real
        # recipient) actually received the message.
        self._send_ack(message_id, receipt_token=receipt_token)
    
    def _deliver_in_region(
        self,
        dest_node_id: bytes,
        message_id: bytes,
        payload: bytes,
    ) -> None:
        """Deliver a message to another node in our region."""
        # For now, broadcast (flood) within region
        # TODO: Use routing table for directed delivery
        pass
    
    # === RPC Handlers ===
    
    def _rpc_status(self, params: dict) -> dict:
        """Handle status RPC."""
        return {
            "version": __version__,
            "node_id": self._identity.node_id.hex(),
            "role": self._region_manager.get_local_role().name,
            "peers": len(self._peer_manager),
            "region_id": (
                self._region_manager.get_local_region_id().hex()
                if self._region_manager.get_local_region_id()
                else None
            ),
            "radio": self._radio.get_statistics() if self._radio else None,
        }
    
    def _rpc_peers(self, params: dict) -> dict:
        """Handle peers RPC."""
        peers = []
        for peer in self._peer_manager.get_all_peers():
            peers.append({
                "node_id": peer.node_id.hex(),
                "state": peer.state.name,
                "rssi": peer.link_quality.rssi,
                "snr": peer.link_quality.snr,
                "quality": peer.link_quality.quality_score,
                "last_seen": peer.last_seen,
                "is_gateway": peer.is_gateway,
            })
        return {"peers": peers, "count": len(peers)}
    
    def _rpc_regions(self, params: dict) -> dict:
        """Handle regions RPC."""
        regions = []
        for region in self._region_manager.get_all_regions():
            regions.append({
                "region_id": region.region_id.hex(),
                "is_local": region.is_local,
                "submesh_count": len(region.submesh_ids),
                "gateway_count": len(region.gateway_ids),
            })
        return {"regions": regions, "count": len(regions)}
    
    def _rpc_routes(self, params: dict) -> dict:
        """Handle routes RPC."""
        routes = []
        for dest_id, route_list in self._router.get_all_routes().items():
            for route in route_list:
                routes.append({
                    "dest": dest_id.hex(),
                    "next_hop": route.next_hop_id.hex(),
                    "hops": route.hop_count,
                    "quality": route.quality_score,
                })
        return {"routes": routes, "count": len(routes)}
    
    def _rpc_send(self, params: dict) -> dict:
        """Handle send RPC.
        
        Uses direct encrypted messaging when the recipient is a known
        direct peer (1-hop). Falls back to onion routing when regions
        are available for multi-hop delivery.
        """
        recipient_hex = params.get("recipient")
        message = params.get("message", "")
        
        if not recipient_hex:
            return {"error": "Missing recipient"}
        
        try:
            recipient_id = bytes.fromhex(recipient_hex)
        except ValueError:
            return {"error": "Invalid recipient ID"}
        
        payload_bytes = message.encode()
        
        # Check if recipient is a direct peer
        peer = self._peer_manager.get_peer(recipient_id)
        
        if peer and peer.public_key:
            # Direct peer — use direct encrypted messaging
            return self._send_direct(recipient_id, peer.public_key, payload_bytes)
        
        # Not a direct peer — try onion routing
        try:
            packet, message_id, num_layers, receipt_token = (
                self._onion_builder.build_message(
                    recipient_id=recipient_id,
                    payload=payload_bytes,
                )
            )
            
            # Track delivery
            self._delivery_manager.track_message(message_id, recipient_id)
            
            # Store receipt token for verification when ACK arrives
            self._pending_receipt_tokens[message_id] = receipt_token
            
            # Transmit
            wrapped = build_packet(
                packet_type=PacketType.ONION,
                payload=packet.to_bytes(),
                flags=PacketFlags.RELIABLE,
            )
            # Broadcast onion to all link partners (first hop picks it up)
            self._link_broadcast(wrapped)
            
            return {
                "message_id": message_id.hex(),
                "status": "sent",
                "mode": "onion",
                "onion_layers": num_layers,
            }
        except Exception as e:
            return {"error": str(e)}
    
    def _send_direct(self, recipient_id: bytes, recipient_pubkey: bytes, payload: bytes) -> dict:
        """Send a direct encrypted message to a peer.
        
        Compresses the payload with zlib when beneficial, and automatically
        fragments the message across multiple LoRa packets when needed.
        
        Args:
            recipient_id: Recipient's node ID
            recipient_pubkey: Recipient's X25519 public key (from beacon)
            payload: Message payload bytes
        
        Returns:
            dict: RPC result with message_id, status, mode, and fragments count
        """
        max_single = DirectMessagePayload.max_payload_size()
        
        # Try compression
        compressed = zlib.compress(payload, level=9)
        if len(compressed) < len(payload):
            msg_data = compressed
            base_type = PAYLOAD_COMPRESSED
        else:
            msg_data = payload
            base_type = 0x00
        
        # Generate message ID
        timestamp = int(time.time())
        message_id = generate_message_id(
            self._identity.node_id,
            recipient_id,
            timestamp,
        )
        
        # === Single-packet path ===
        if len(msg_data) <= max_single:
            direct_msg = DirectMessagePayload(
                message_id=message_id,
                timestamp=timestamp,
                payload_type=base_type,
                payload=msg_data,
            )
            
            try:
                envelope = seal_envelope_for_pubkey_bytes(
                    plaintext=direct_msg.to_bytes(),
                    recipient_public_bytes=recipient_pubkey,
                    associated_data=b"spark-direct-v1",
                )
                
                wrapped = build_packet(
                    packet_type=PacketType.DIRECT,
                    payload=envelope,
                    ttl=1,
                )
                
                self._delivery_manager.track_message(message_id, recipient_id)
                if not self._link_transmit_burst(
                    recipient_id,
                    wrapped,
                    copies=LINK_TX_REDUNDANCY,
                    gap_sec=LINK_TX_REDUNDANCY_GAP_SEC,
                ):
                    return {
                        "error": (
                            "No link session with this peer; wait until the "
                            "mesh re-establishes the encrypted link (or restart "
                            "sparkd after a cold boot)."
                        ),
                    }
                
                return {
                    "message_id": message_id.hex(),
                    "status": "sent",
                    "mode": "direct",
                    "fragments": 1,
                }
            except Exception as e:
                return {"error": str(e)}
        
        # === Multi-fragment path ===
        frag_payload_max = max_single - FRAGMENT_HEADER_SIZE
        chunks = [
            msg_data[i:i + frag_payload_max]
            for i in range(0, len(msg_data), frag_payload_max)
        ]
        
        if len(chunks) > MAX_FRAGMENTS:
            # Calculate effective max for user feedback
            max_compressed = frag_payload_max * MAX_FRAGMENTS
            return {
                "error": (
                    f"Message too large: {len(payload)} bytes "
                    f"({len(msg_data)} compressed) exceeds "
                    f"{MAX_FRAGMENTS}-fragment limit (~{max_compressed} bytes compressed)"
                )
            }
        
        frag_type = base_type | PAYLOAD_FRAGMENTED
        total = len(chunks)
        
        self._delivery_manager.track_message(message_id, recipient_id)
        
        for idx, chunk in enumerate(chunks):
            frag_payload = bytes([idx, total]) + chunk
            
            direct_msg = DirectMessagePayload(
                message_id=message_id,
                timestamp=timestamp,
                payload_type=frag_type,
                payload=frag_payload,
            )
            
            try:
                envelope = seal_envelope_for_pubkey_bytes(
                    plaintext=direct_msg.to_bytes(),
                    recipient_public_bytes=recipient_pubkey,
                    associated_data=b"spark-direct-v1",
                )
                
                wrapped = build_packet(
                    packet_type=PacketType.DIRECT,
                    payload=envelope,
                    ttl=1,
                )
                
                if not self._link_transmit_burst(
                    recipient_id,
                    wrapped,
                    copies=LINK_TX_REDUNDANCY,
                    gap_sec=LINK_TX_REDUNDANCY_GAP_SEC,
                ):
                    return {
                        "error": (
                            f"No link session on fragment {idx + 1}/{total}; "
                            "wait for link to re-establish."
                        ),
                    }
                
                # Brief pause between fragments to let radio settle
                if idx < total - 1:
                    time.sleep(0.1)
            except Exception as e:
                return {"error": f"Send failed on fragment {idx+1}/{total}: {e}"}
        
        return {
            "message_id": message_id.hex(),
            "status": "sent",
            "mode": "direct",
            "fragments": total,
        }
    
    def _rpc_inbox(self, params: dict) -> dict:
        """Handle inbox RPC."""
        messages = self._message_store.get_inbox(
            self._identity.node_id,
            limit=params.get("limit", 20),
        )
        
        result = []
        for msg in messages:
            result.append({
                "message_id": msg.message_id.hex(),
                "sender_id": msg.sender_id.hex(),
                "received_at": msg.delivered_at,
                "payload_size": len(msg.payload),
            })
        
        return {"messages": result, "count": len(result)}
    
    def _rpc_read_message(self, params: dict) -> dict:
        """Handle read_message RPC -- return full message content."""
        message_id_hex = params.get("message_id")
        if not message_id_hex:
            return {"error": "Missing message_id"}
        
        try:
            message_id = bytes.fromhex(message_id_hex)
        except ValueError:
            return {"error": "Invalid message_id"}
        
        msg = self._message_store.get_message(message_id)
        if not msg:
            return {"error": "Message not found"}
        
        # Try to decode payload as UTF-8 text, fall back to hex
        try:
            text = msg.payload.decode("utf-8")
        except UnicodeDecodeError:
            text = None
        
        return {
            "message_id": msg.message_id.hex(),
            "received_at": msg.delivered_at,
            "payload_size": len(msg.payload),
            "payload_hex": msg.payload.hex(),
            "payload_text": text,
        }
    
    def _rpc_delete_message(self, params: dict) -> dict:
        """Handle delete_message RPC -- delete a single message."""
        message_id_hex = params.get("message_id")
        if not message_id_hex:
            return {"error": "Missing message_id"}
        
        try:
            message_id = bytes.fromhex(message_id_hex)
        except ValueError:
            return {"error": "Invalid message_id"}
        
        deleted = self._message_store.delete_message(message_id)
        if not deleted:
            return {"error": "Message not found"}
        
        return {"deleted": 1}
    
    def _rpc_clear_inbox(self, params: dict) -> dict:
        """Handle clear_inbox RPC -- delete all delivered messages."""
        count = self._message_store.clear_inbox(self._identity.node_id)
        return {"deleted": count}
    
    def _rpc_message_status(self, params: dict) -> dict:
        """Handle message_status RPC -- check delivery status of a sent message."""
        message_id_hex = params.get("message_id")
        if not message_id_hex:
            return {"error": "Missing message_id"}
        
        try:
            message_id = bytes.fromhex(message_id_hex)
        except ValueError:
            return {"error": "Invalid message_id"}
        
        msg = self._delivery_manager.get_message(message_id)
        if not msg:
            return {"status": "unknown", "message_id": message_id_hex}
        
        result = {
            "message_id": message_id_hex,
            "status": msg.status.name.lower(),
            "send_count": msg.send_count,
        }
        
        if msg.ack_received_at:
            result["ack_received_at"] = msg.ack_received_at
            result["ack_hop_count"] = msg.ack_hop_count
        
        return result
    
    def _rpc_debug(self, params: dict) -> dict:
        """Handle debug RPC."""
        return {
            "peer_stats": self._peer_manager.get_stats(),
            "submesh_stats": self._submesh_manager.get_stats(),
            "region_stats": self._region_manager.get_stats(),
            "router_stats": self._router.get_stats(),
            "dedup_stats": self._dedup_cache.get_stats(),
            "delivery_stats": self._delivery_manager.get_stats(),
            "storage_stats": self._message_store.get_stats(),
        }


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="SPARK mesh router daemon")
    parser.add_argument(
        "-c", "--config",
        type=Path,
        default=DEFAULT_CONFIG_PATH,
        help="Configuration file path",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose logging",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"sparkd {__version__}",
    )
    
    args = parser.parse_args()
    
    # Set log level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Load configuration
    config = Config.load(args.config)
    
    try:
        config.validate()
    except ValueError as e:
        logger.error(f"Configuration error: {e}")
        sys.exit(1)
    
    # Create and start daemon
    daemon = SparkDaemon(config)
    
    # Signal handlers
    def handle_signal(signum, frame):
        logger.info(f"Received signal {signum}")
        daemon.stop()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)
    
    try:
        daemon.start()
        
        # Wait for shutdown
        while daemon._running:
            time.sleep(1)
            
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        daemon.stop()
        sys.exit(1)


if __name__ == "__main__":
    main()
