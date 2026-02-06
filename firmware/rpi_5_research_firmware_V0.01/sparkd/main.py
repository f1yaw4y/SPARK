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
import logging
import threading
import argparse
from pathlib import Path
from typing import Optional

from . import __version__
from .config import Config, DEFAULT_CONFIG_PATH
from .crypto.keys import load_identity, IdentityKey
from .radio.base import BaseRadio, RadioConfig as HWRadioConfig, RadioPacket
from .radio.loopback import LoopbackRadio
from .packet.format import (
    PacketType, Packet, parse_packet, build_packet, BeaconPayload, PacketFlags
)
from .packet.dedup import DeduplicationCache
from .packet.store import MessageStore
from .mesh.peer import PeerManager
from .mesh.submesh import SubMeshManager
from .mesh.region import RegionManager, RegionRole
from .mesh.routing import Router, RoutingDecision
from .onion.layers import OnionBuilder
from .onion.gateway import GatewayProcessor, ProcessingResult
from .onion.delivery import DeliveryManager
from .rpc.server import RPCServer


# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("sparkd")


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
        
        # Worker threads
        self._beacon_thread: Optional[threading.Thread] = None
        self._maintenance_thread: Optional[threading.Thread] = None
        self._rx_thread: Optional[threading.Thread] = None
        
        # Beacon sequence counter
        self._beacon_seq = 0
    
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
                
            except Exception as e:
                logger.error(f"Maintenance error: {e}")
            
            self._shutdown_event.wait(60)  # Run every minute
    
    def _receive_loop(self) -> None:
        """Radio receive loop."""
        while self._running:
            try:
                packet = self._radio.receive(timeout_ms=1000)
                if packet:
                    self._handle_radio_packet(packet)
            except Exception as e:
                logger.error(f"Receive error: {e}")
    
    # === Packet Handling ===
    
    def _send_beacon(self) -> None:
        """Send a beacon packet."""
        region_id = self._region_manager.get_local_region_id() or b"\x00" * 16
        
        # Build capabilities
        capabilities = 0
        role = self._region_manager.get_local_role()
        if role == RegionRole.GATEWAY:
            capabilities |= BeaconPayload.CAPABILITIES_GATEWAY
        if role in (RegionRole.RELAY, RegionRole.GATEWAY):
            capabilities |= BeaconPayload.CAPABILITIES_RELAY
        
        # Build beacon payload
        beacon = BeaconPayload(
            node_id=self._identity.node_id,
            public_key=self._identity.x25519_public_bytes,
            region_id=region_id,
            capabilities=capabilities,
            radio_type=1,  # LoRa
            sequence=self._beacon_seq,
        )
        self._beacon_seq = (self._beacon_seq + 1) & 0xFFFF
        
        # Build packet
        packet = build_packet(
            packet_type=PacketType.BEACON,
            payload=beacon.to_bytes(),
            ttl=1,  # Beacons don't need to travel far
        )
        
        # Transmit
        self._radio.transmit(packet.to_bytes())
    
    def _handle_radio_packet(self, radio_packet: RadioPacket) -> None:
        """Handle a received radio packet."""
        # Check for duplicates
        if self._dedup_cache.check_and_add(radio_packet.data):
            return  # Duplicate
        
        try:
            packet = parse_packet(
                radio_packet.data,
                rssi=radio_packet.rssi,
                snr=radio_packet.snr,
                received_at=radio_packet.timestamp,
            )
        except Exception as e:
            logger.debug(f"Failed to parse packet: {e}")
            return
        
        # Route based on packet type
        if packet.packet_type == PacketType.BEACON:
            self._handle_beacon(packet)
        elif packet.packet_type == PacketType.ONION:
            self._handle_onion(packet)
        elif packet.packet_type == PacketType.ACK:
            self._handle_ack(packet)
        else:
            logger.debug(f"Unhandled packet type: {packet.packet_type}")
    
    def _handle_beacon(self, packet: Packet) -> None:
        """Handle a beacon packet."""
        try:
            beacon = BeaconPayload.from_bytes(packet.payload)
        except Exception as e:
            logger.debug(f"Failed to parse beacon: {e}")
            return
        
        # Update peer manager
        self._peer_manager.add_or_update_peer(
            node_id=beacon.node_id,
            public_key=beacon.public_key,
            region_id=beacon.region_id,
            capabilities=beacon.capabilities,
            rssi=packet.rssi,
            snr=packet.snr,
            beacon_seq=beacon.sequence,
        )
    
    def _handle_onion(self, packet: Packet) -> None:
        """Handle an onion-routed packet."""
        # Try to process at each layer
        for layer in (1, 2, 3):
            result = self._gateway_processor.process(packet.payload, layer)
            
            if result.result == ProcessingResult.DROP_DECRYPT:
                continue  # Not for us at this layer
            
            if result.result == ProcessingResult.FORWARD:
                # Forward to next region
                self._forward_to_region(
                    result.next_region_id,
                    result.inner_envelope,
                    result.ttl,
                )
                return
            
            if result.result == ProcessingResult.DELIVER_LOCAL:
                # Message for us
                self._deliver_local(
                    result.message_id,
                    result.payload,
                    result.payload_type,
                )
                return
            
            if result.result == ProcessingResult.DELIVER_REGION:
                # Deliver to someone in our region
                self._deliver_in_region(
                    result.dest_node_id,
                    result.message_id,
                    result.payload,
                )
                return
            
            if result.result in (ProcessingResult.DROP_EXPIRED, ProcessingResult.DROP_INVALID):
                logger.debug(f"Dropped packet: {result.error_message}")
                return
        
        # Could not process - not for us
        logger.debug("Received onion packet not addressed to us")
    
    def _handle_ack(self, packet: Packet) -> None:
        """Handle an acknowledgment packet."""
        from .packet.format import AckPayload
        
        try:
            ack = AckPayload.from_bytes(packet.payload)
        except Exception:
            return
        
        self._delivery_manager.handle_ack(ack.message_id, ack.hop_count)
    
    def _forward_to_region(
        self,
        region_id: bytes,
        envelope: bytes,
        ttl: int,
    ) -> None:
        """Forward an onion packet to another region."""
        # Build packet
        packet = build_packet(
            packet_type=PacketType.ONION,
            payload=envelope,
            ttl=ttl,
        )
        
        # Find best peer for region
        peer = self._region_manager.get_gateway_for_region(region_id)
        
        if peer:
            # Send to specific peer (TODO: implement directed sending)
            self._radio.transmit(packet.to_bytes())
        else:
            # Broadcast
            self._radio.transmit(packet.to_bytes())
    
    def _deliver_local(
        self,
        message_id: bytes,
        payload: bytes,
        payload_type: int,
    ) -> None:
        """Handle a message delivered to us."""
        logger.info(f"Received message: {message_id.hex()[:16]}...")
        
        # Store in inbox
        # Note: sender_id not known at this layer (intentional for privacy)
        self._message_store.store_incoming(
            message_id=message_id,
            sender_id=b"\x00" * 16,  # Unknown
            recipient_id=self._identity.node_id,
            payload=payload,
        )
        
        # TODO: Send ACK
    
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
        """Handle send RPC."""
        recipient_hex = params.get("recipient")
        message = params.get("message", "")
        
        if not recipient_hex:
            return {"error": "Missing recipient"}
        
        try:
            recipient_id = bytes.fromhex(recipient_hex)
        except ValueError:
            return {"error": "Invalid recipient ID"}
        
        # Build and send message
        try:
            packet, message_id = self._onion_builder.build_message(
                recipient_id=recipient_id,
                payload=message.encode(),
            )
            
            # Track delivery
            self._delivery_manager.track_message(message_id, recipient_id)
            
            # Transmit
            wrapped = build_packet(
                packet_type=PacketType.ONION,
                payload=packet.to_bytes(),
                flags=PacketFlags.RELIABLE,
            )
            self._radio.transmit(wrapped.to_bytes())
            
            return {
                "message_id": message_id.hex(),
                "status": "sent",
            }
        except Exception as e:
            return {"error": str(e)}
    
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
                "received_at": msg.delivered_at,
                "payload_size": len(msg.payload),
            })
        
        return {"messages": result, "count": len(result)}
    
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
