"""
SPARK Mesh Node Implementation
Main node logic for message processing, forwarding, and routing
"""

import os
import time
import random
import logging
import hashlib
import struct
from typing import Optional
from network import NodeAddress, RoutingHeader, MeshMessage
from crypto import CryptographyManager
from routing import RoutingTable
from replay import ReplayCache
from radio import LoRaRadio
import config

logger = logging.getLogger(__name__)


class SparkMeshNode:
    """Main SPARK mesh network node"""
    
    def __init__(self):
        """Initialize mesh node"""
        # Load or generate node private key
        self.node_private_key = self._generate_or_load_key()
        
        # Generate node address from key
        self.my_address = self._generate_node_address()
        
        # Initialize components
        self.crypto = CryptographyManager(self.node_private_key, self.my_address)
        self.routing_table = RoutingTable(self.my_address)
        self.replay_cache = ReplayCache()
        self.radio = LoRaRadio()
        
        # Broadcast storm prevention
        self.last_broadcast_id = 0
        self.last_broadcast_time = 0.0
        
        # Forward buffer (prevents concurrent forwarding issues)
        self.forward_buffer_in_use = False
        
        logger.info(f"SPARK node initialized: {self.my_address}")
    
    def _generate_or_load_key(self) -> bytes:
        """Generate or load node's private key from persistent storage"""
        key_path = config.KEY_STORAGE_PATH
        
        if os.path.exists(key_path):
            # Load existing key
            try:
                with open(key_path, 'rb') as f:
                    key = f.read(32)
                if len(key) == 32:
                    logger.info("Loaded existing node key from storage")
                    return key
            except Exception as e:
                logger.warning(f"Failed to load key: {e}")
        
        # Generate new key
        # Use MAC address + system info as seed for deterministic but unique key
        try:
            # Get MAC address from system
            import subprocess
            result = subprocess.run(['cat', '/sys/class/net/eth0/address'], 
                                  capture_output=True, text=True)
            mac_str = result.stdout.strip() if result.returncode == 0 else "unknown"
        except:
            mac_str = "unknown"
        
        # Combine MAC + system info for seed
        seed = f"{mac_str}{time.time()}{os.urandom(16)}".encode()
        
        # Generate 32-byte key using SHA-256
        key = hashlib.sha256(seed).digest()
        
        # Store key persistently
        try:
            os.makedirs(os.path.dirname(key_path), exist_ok=True)
            with open(key_path, 'wb') as f:
                f.write(key)
            logger.info("Generated new node key and saved to storage")
        except Exception as e:
            logger.warning(f"Failed to save key: {e}")
        
        return key
    
    def _generate_node_address(self) -> NodeAddress:
        """Generate node address from key-based identity"""
        # Derive public key (simplified: hash of private key)
        # In production, use proper ECC or Ed25519 key derivation
        node_public_key = hashlib.sha256(self.node_private_key).digest()
        
        # Submesh ID: derived from public key hash (first 2 bytes)
        submesh_id = (node_public_key[0] << 8) | node_public_key[1]
        
        # Node ID: derived from public key hash (next 2 bytes)
        node_id = (node_public_key[2] << 8) | node_public_key[3]
        
        address = NodeAddress(submesh_id, node_id)
        
        logger.info(f"Node address (key-based): Sub-mesh {submesh_id}, Node {node_id}")
        logger.debug(f"Public key fingerprint: {node_public_key[:8].hex()}")
        
        return address
    
    def build_layered_message(self, destination: NodeAddress, payload: bytes) -> MeshMessage:
        """
        Build a layered encrypted message
        
        Args:
            destination: Destination node address
            payload: Payload data to send
        
        Returns:
            MeshMessage with all encryption layers
        """
        if len(payload) > config.MAX_PAYLOAD_SIZE:
            raise ValueError(f"Payload too large: {len(payload)} bytes")
        
        msg = MeshMessage()
        
        # Initialize header
        msg.header = RoutingHeader(
            source=self.my_address,
            destination=destination,
            next_hop=NodeAddress(0, 0),
            previous_submesh=NodeAddress(self.my_address.submesh_id, 0),
            hop_count=0,
            layers_remaining=config.ENCRYPTION_LAYERS,
            submesh_crossings=0,
            message_id=random.randint(0, 0xFFFFFFFF)
        )
        
        msg.payload = payload
        
        # Generate nonces for each layer
        for i in range(config.ENCRYPTION_LAYERS):
            if i == config.ENCRYPTION_LAYERS - 1:
                # GCM nonce (12 bytes) for outermost layer
                nonce = self.crypto.generate_gcm_nonce(
                    msg.header.message_id,
                    msg.header.hop_count,
                    msg.header.submesh_crossings
                )
            else:
                # CTR nonce (16 bytes) for inner layers
                nonce = self.crypto.generate_nonce(
                    i, msg.header.message_id,
                    msg.header.hop_count,
                    msg.header.submesh_crossings
                )
            msg.nonces.append(nonce)
        
        # Build layers from innermost to outermost
        # Layer 0: Header + payload
        layer0_data = msg.header.to_bytes() + payload
        encrypted_layer0 = self.crypto.encrypt_layer_ctr(
            layer0_data, 0, msg.nonces[0]
        )
        msg.encrypted_layers.append(encrypted_layer0)
        msg.layer_sizes.append(len(encrypted_layer0))
        
        # Layer 1: Header + nonce_0 + encrypted layer 0
        layer1_header = RoutingHeader(
            source=msg.header.source,
            destination=msg.header.destination,
            next_hop=msg.header.next_hop,
            previous_submesh=msg.header.previous_submesh,
            hop_count=msg.header.hop_count,
            layers_remaining=1,
            submesh_crossings=msg.header.submesh_crossings,
            message_id=msg.header.message_id
        )
        layer1_data = layer1_header.to_bytes() + msg.nonces[0] + encrypted_layer0
        encrypted_layer1 = self.crypto.encrypt_layer_ctr(
            layer1_data, 1, msg.nonces[1]
        )
        msg.encrypted_layers.append(encrypted_layer1)
        msg.layer_sizes.append(len(encrypted_layer1))
        
        # Layer 2 (outermost): Use GCM for authentication
        layer2_header = RoutingHeader(
            source=msg.header.source,
            destination=msg.header.destination,
            next_hop=msg.header.next_hop,
            previous_submesh=msg.header.previous_submesh,
            hop_count=msg.header.hop_count,
            layers_remaining=2,
            submesh_crossings=msg.header.submesh_crossings,
            message_id=msg.header.message_id
        )
        layer2_payload = msg.nonces[1] + encrypted_layer1
        
        encrypted_layer2, auth_tag = self.crypto.encrypt_layer_gcm(
            layer2_payload,
            layer2_header.to_bytes(),
            msg.nonces[2]  # 12-byte GCM nonce
        )
        msg.encrypted_layers.append(encrypted_layer2)
        msg.layer_sizes.append(len(encrypted_layer2))
        msg.auth_tag = auth_tag
        
        return msg
    
    def send_mesh_message(self, destination: NodeAddress, payload: bytes) -> bool:
        """
        Send a message to a destination through the mesh
        
        Args:
            destination: Destination node address
            payload: Payload data
        
        Returns:
            True if message was sent, False otherwise
        """
        try:
            # Build layered message
            msg = self.build_layered_message(destination, payload)
            
            # Find next hop
            msg.header.next_hop = self.routing_table.find_next_hop(destination)
            
            # Prepare transmission data
            # Format: [Header][Nonce 12 bytes][Encrypted Data][Auth Tag 16 bytes]
            tx_header = RoutingHeader(
                source=msg.header.source,
                destination=msg.header.destination,
                next_hop=msg.header.next_hop,
                previous_submesh=NodeAddress(self.my_address.submesh_id, 0),
                hop_count=msg.header.hop_count,
                layers_remaining=config.ENCRYPTION_LAYERS,
                submesh_crossings=msg.header.submesh_crossings,
                message_id=msg.header.message_id
            )
            
            tx_data = (
                tx_header.to_bytes() +
                msg.nonces[2] +  # 12-byte GCM nonce
                msg.encrypted_layers[2] +
                msg.auth_tag
            )
            
            logger.info(f"Sending mesh message to {destination} ({len(tx_data)} bytes)")
            
            return self.radio.transmit(tx_data)
            
        except Exception as e:
            logger.error(f"Failed to send message: {e}")
            return False
    
    def process_received_message(self, data: bytes) -> bool:
        """
        Process a received message (decrypt, forward, or deliver)
        
        Args:
            data: Received packet data
        
        Returns:
            True if message was processed, False if dropped
        """
        try:
            # Extract outermost routing header
            if len(data) < RoutingHeader.HEADER_SIZE:
                logger.warning("Message too short")
                return False
            
            header = RoutingHeader.from_bytes(data[:RoutingHeader.HEADER_SIZE])
            
            # Extract GCM components
            gcm_data_start = RoutingHeader.HEADER_SIZE + 12  # Header + nonce
            if len(data) < gcm_data_start + 16:  # Need at least auth tag
                logger.warning("Message too short for GCM authentication")
                return False
            
            gcm_nonce = data[RoutingHeader.HEADER_SIZE:gcm_data_start]
            gcm_encrypted_data = data[gcm_data_start:-16]
            gcm_auth_tag = data[-16:]
            
            # Verify GCM authentication
            try:
                decrypted_layer = self.crypto.decrypt_layer_gcm(
                    gcm_encrypted_data,
                    data[:RoutingHeader.HEADER_SIZE],  # Header as AAD
                    gcm_nonce,
                    gcm_auth_tag
                )
            except ValueError as e:
                logger.warning(f"GCM authentication failed: {e}")
                return False
            
            # Check for replay attacks
            if self.replay_cache.is_replay(header.source, header.message_id):
                logger.warning("Replay attack detected - dropping message")
                return False
            
            # Record message to prevent replays
            self.replay_cache.record_message(header.source, header.message_id)
            
            # Check if we crossed a sub-mesh boundary
            crossed_submesh = False
            if header.hop_count > 0 and header.previous_submesh.submesh_id != 0:
                crossed_submesh = (
                    header.previous_submesh.submesh_id != self.my_address.submesh_id
                )
            
            current_data = decrypted_layer
            current_len = len(decrypted_layer)
            
            # If we crossed sub-mesh boundary and have layers remaining, decrypt next layer
            if crossed_submesh and header.layers_remaining > 0:
                layer_to_decrypt = config.ENCRYPTION_LAYERS - header.layers_remaining
                
                logger.debug(f"Crossing sub-mesh boundary, decrypting layer {layer_to_decrypt}")
                
                # Extract nonce (16 bytes) before encrypted data
                if current_len < 16:
                    logger.warning("Not enough data for nonce")
                    return False
                
                nonce = current_data[:16]
                encrypted_len = current_len - 16
                
                # Decrypt the encrypted payload (skip nonce)
                decrypted = self.crypto.decrypt_layer_ctr(
                    current_data[16:], layer_to_decrypt, nonce
                )
                
                # Extract new header
                header = RoutingHeader.from_bytes(decrypted[:RoutingHeader.HEADER_SIZE])
                current_data = decrypted[RoutingHeader.HEADER_SIZE:]
                current_len = len(current_data)
                header.layers_remaining -= 1
                header.submesh_crossings += 1
            
            # Check if message is for us
            if header.destination == self.my_address or header.destination.is_broadcast():
                # Decrypt all remaining layers to get final payload
                while header.layers_remaining > 0:
                    layer = config.ENCRYPTION_LAYERS - header.layers_remaining
                    
                    logger.debug(f"Final decryption, layer {layer}")
                    
                    if current_len < 16:
                        logger.warning("Not enough data for nonce in final decryption")
                        return False
                    
                    nonce = current_data[:16]
                    encrypted_len = current_len - 16
                    
                    decrypted = self.crypto.decrypt_layer_ctr(
                        current_data[16:], layer, nonce
                    )
                    
                    header = RoutingHeader.from_bytes(decrypted[:RoutingHeader.HEADER_SIZE])
                    current_data = decrypted[RoutingHeader.HEADER_SIZE:]
                    current_len = len(current_data)
                    header.layers_remaining -= 1
                
                # Extract final payload
                payload_len = min(current_len, config.MAX_PAYLOAD_SIZE)
                payload = current_data[:payload_len]
                
                logger.info(f"Received message ({payload_len} bytes): {payload[:50]}")
                
                # Update routing table
                self.routing_table.update_routing_table(
                    header.source, header.source, header.hop_count
                )
                
                return True  # Message consumed
            
            # Message needs forwarding
            return self._forward_message(header, current_data, current_len)
            
        except Exception as e:
            logger.error(f"Error processing message: {e}", exc_info=True)
            return False
    
    def _forward_message(self, header: RoutingHeader, current_data: bytes, 
                        current_len: int) -> bool:
        """Forward a message to the next hop"""
        
        if header.hop_count >= config.MAX_ROUTING_HOPS:
            logger.warning("Message dropped: too many hops")
            return False
        
        if self.forward_buffer_in_use:
            logger.warning("Forward buffer in use, dropping message")
            return False
        
        self.forward_buffer_in_use = True
        
        try:
            header.hop_count += 1
            
            # Find next hop
            next_hop = self.routing_table.find_next_hop(header.destination)
            is_broadcast = next_hop.is_broadcast()
            
            # Broadcast storm prevention
            if is_broadcast:
                now = time.time()
                if (header.message_id == self.last_broadcast_id and
                    now - self.last_broadcast_time < config.BROADCAST_SUPPRESSION_SECONDS):
                    logger.debug("Broadcast storm prevention (local) - dropping")
                    return False
                self.last_broadcast_id = header.message_id
                self.last_broadcast_time = now
            
            # Check if next hop will cross sub-mesh boundary
            will_cross_submesh = False
            if not self.routing_table.is_in_same_submesh(self.my_address, header.destination):
                will_cross_submesh = not self.routing_table.is_in_same_submesh(
                    self.my_address, next_hop
                )
            
            # If we will cross sub-mesh and have layers, decrypt next layer
            if will_cross_submesh and header.layers_remaining > 0:
                layer = config.ENCRYPTION_LAYERS - header.layers_remaining
                
                logger.debug(f"Will cross sub-mesh, decrypting layer {layer} for forwarding")
                
                if current_len < 16:
                    logger.warning("Not enough data for nonce in forwarding decryption")
                    return False
                
                nonce = current_data[:16]
                encrypted_len = current_len - 16
                
                decrypted = self.crypto.decrypt_layer_ctr(
                    current_data[16:], layer, nonce
                )
                
                header = RoutingHeader.from_bytes(decrypted[:RoutingHeader.HEADER_SIZE])
                current_data = decrypted[RoutingHeader.HEADER_SIZE:]
                current_len = len(current_data)
                header.layers_remaining -= 1
                header.submesh_crossings += 1
            
            # Update routing header
            header.next_hop = next_hop
            header.previous_submesh = NodeAddress(self.my_address.submesh_id, 0)
            
            # Re-encrypt with GCM for forwarding (ensures header authenticity)
            gcm_nonce = self.crypto.generate_gcm_nonce(
                header.message_id,
                header.hop_count,
                header.submesh_crossings
            )
            
            encrypted_data, auth_tag = self.crypto.encrypt_layer_gcm(
                current_data,
                header.to_bytes(),
                gcm_nonce
            )
            
            # Prepare forward packet
            forward_data = (
                header.to_bytes() +
                gcm_nonce +
                encrypted_data +
                auth_tag
            )
            
            logger.debug(f"Forwarding message (hop {header.hop_count}, "
                        f"layers remaining: {header.layers_remaining})")
            
            # Transmit
            success = self.radio.transmit(forward_data)
            
            # Update routing table
            self.routing_table.update_routing_table(
                header.source, header.source, header.hop_count
            )
            
            return success
            
        finally:
            self.forward_buffer_in_use = False
    
    def run_maintenance(self):
        """Perform periodic maintenance tasks"""
        self.routing_table.decay()
        self.replay_cache.cleanup()
    
    def get_address(self) -> NodeAddress:
        """Get this node's address"""
        return self.my_address
