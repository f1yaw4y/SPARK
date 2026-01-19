"""
SPARK Cryptography Module
Handles AES-CTR encryption for inner layers and AES-GCM for outer layer authentication
"""

import os
import time
import struct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import config


class CryptographyManager:
    """Manages encryption keys and operations for SPARK network"""
    
    def __init__(self, node_private_key: bytes, my_address):
        """
        Initialize cryptography manager with node's private key and address
        
        Args:
            node_private_key: 32-byte private key for this node
            my_address: NodeAddress instance for this node
        """
        if len(node_private_key) != 32:
            raise ValueError("Node private key must be 32 bytes")
        
        self.node_private_key = node_private_key
        self.my_address = my_address
        self.encryption_keys = []
        self._derive_encryption_keys()
    
    def _derive_encryption_keys(self):
        """Derive encryption keys for each layer from node private key"""
        for layer in range(config.ENCRYPTION_LAYERS):
            # Derive layer key: SHA-256(node_private_key + layer + submesh_id)
            digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
            digest.update(self.node_private_key)
            digest.update(struct.pack('B', layer))
            digest.update(struct.pack('>H', self.my_address.submesh_id))
            key = digest.finalize()
            self.encryption_keys.append(key)
    
    def generate_nonce(self, layer: int, message_id: int, hop_count: int, 
                       submesh_crossings: int) -> bytes:
        """
        Generate a unique 16-byte nonce for CTR mode encryption
        
        Nonce structure (16 bytes):
        - bytes 0-3: message_id
        - bytes 4-5: node submesh_id
        - bytes 6-7: node_id
        - byte 8: layer number
        - byte 9: hop_count
        - byte 10: submesh_crossings
        - byte 11: time component (low byte)
        - bytes 12-15: counter (starts at 0, incremented per 16-byte block)
        """
        nonce = bytearray(16)
        struct.pack_into('>I', nonce, 0, message_id & 0xFFFFFFFF)
        struct.pack_into('>H', nonce, 4, self.my_address.submesh_id)
        struct.pack_into('>H', nonce, 6, self.my_address.node_id)
        nonce[8] = layer & 0xFF
        nonce[9] = hop_count & 0xFF
        nonce[10] = submesh_crossings & 0xFF
        nonce[11] = int(time.time() * 1000) & 0xFF  # Low byte of milliseconds
        # Counter (bytes 12-15) starts at 0, handled by CTR mode
        return bytes(nonce)
    
    def generate_gcm_nonce(self, message_id: int, hop_count: int, 
                           submesh_crossings: int) -> bytes:
        """
        Generate a 12-byte nonce for GCM mode (outermost layer)
        
        Nonce structure (12 bytes):
        - bytes 0-3: message_id
        - bytes 4-5: node submesh_id
        - bytes 6-7: node_id
        - byte 8: hop_count
        - byte 9: submesh_crossings
        - bytes 10-11: time component
        """
        nonce = bytearray(12)
        struct.pack_into('>I', nonce, 0, message_id & 0xFFFFFFFF)
        struct.pack_into('>H', nonce, 4, self.my_address.submesh_id)
        struct.pack_into('>H', nonce, 6, self.my_address.node_id)
        nonce[8] = hop_count & 0xFF
        nonce[9] = submesh_crossings & 0xFF
        time_ms = int(time.time() * 1000)
        nonce[10] = time_ms & 0xFF
        nonce[11] = (time_ms >> 8) & 0xFF
        return bytes(nonce)
    
    def encrypt_layer_ctr(self, data: bytes, layer: int, nonce: bytes) -> bytes:
        """
        Encrypt data using AES-256-CTR mode (for inner layers)
        
        Args:
            data: Data to encrypt
            layer: Encryption layer number (0 to ENCRYPTION_LAYERS-2)
            nonce: 16-byte nonce (full nonce with counter)
        
        Returns:
            Encrypted data (same size as input)
        """
        if layer >= len(self.encryption_keys):
            raise ValueError(f"Invalid layer {layer}")
        
        key = self.encryption_keys[layer]
        iv = nonce[:16]  # Use first 16 bytes as IV (CTR mode uses full 16-byte IV)
        
        # Create cipher
        cipher = Cipher(
            algorithms.AES(key),
            modes.CTR(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        # Encrypt
        ciphertext = encryptor.update(data) + encryptor.finalize()
        return ciphertext
    
    def decrypt_layer_ctr(self, encrypted_data: bytes, layer: int, nonce: bytes) -> bytes:
        """
        Decrypt data using AES-256-CTR mode (same as encryption in CTR mode)
        
        Args:
            encrypted_data: Encrypted data
            layer: Encryption layer number
            nonce: 16-byte nonce
        
        Returns:
            Decrypted data
        """
        # CTR mode is symmetric
        return self.encrypt_layer_ctr(encrypted_data, layer, nonce)
    
    def encrypt_layer_gcm(self, data: bytes, header: bytes, nonce: bytes) -> tuple:
        """
        Encrypt data using AES-256-GCM mode (for outermost layer)
        Authenticates both header and encrypted data
        
        Args:
            data: Data to encrypt
            header: Routing header (Additional Authenticated Data)
            nonce: 12-byte nonce for GCM
        
        Returns:
            Tuple of (encrypted_data, auth_tag)
        """
        if len(nonce) != 12:
            raise ValueError("GCM nonce must be 12 bytes")
        
        key = self.encryption_keys[config.ENCRYPTION_LAYERS - 1]  # Outermost layer
        aesgcm = AESGCM(key)
        
        # Encrypt and authenticate
        ciphertext = aesgcm.encrypt(nonce, data, header)
        
        # Extract auth tag (last 16 bytes) and encrypted data
        auth_tag = ciphertext[-16:]
        encrypted_data = ciphertext[:-16]
        
        return encrypted_data, auth_tag
    
    def decrypt_layer_gcm(self, encrypted_data: bytes, header: bytes, 
                         nonce: bytes, auth_tag: bytes) -> bytes:
        """
        Decrypt and verify data using AES-256-GCM mode
        
        Args:
            encrypted_data: Encrypted data
            header: Routing header (Additional Authenticated Data)
            nonce: 12-byte nonce
            auth_tag: 16-byte authentication tag
        
        Returns:
            Decrypted data
        
        Raises:
            Exception: If authentication fails
        """
        if len(nonce) != 12:
            raise ValueError("GCM nonce must be 12 bytes")
        if len(auth_tag) != 16:
            raise ValueError("Auth tag must be 16 bytes")
        
        key = self.encryption_keys[config.ENCRYPTION_LAYERS - 1]
        aesgcm = AESGCM(key)
        
        # Combine encrypted data and auth tag for decryption
        ciphertext = encrypted_data + auth_tag
        
        # Decrypt and verify
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, header)
            return plaintext
        except Exception as e:
            raise ValueError(f"GCM authentication failed: {e}") from e
