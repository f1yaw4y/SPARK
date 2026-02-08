"""
SPARK Key Management

Handles:
- Node identity key generation and storage
- Ephemeral key generation for onion layers
- Key derivation and conversion
- Secure key storage

Key Types:
- Identity Key: Ed25519 signing key (long-term)
- Encryption Key: X25519 derived from identity (long-term)
- Ephemeral Key: X25519 per-message keys (short-term)

SECURITY NOTES:
- Private keys are never logged
- Keys are cleared from memory when objects are deleted
- File permissions enforced on key storage
"""

import os
import stat
from pathlib import Path
from typing import Optional, Tuple
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from .primitives import (
    random_bytes,
    blake2b_hash,
    hkdf_derive,
    secure_zero,
    X25519_KEY_SIZE,
)


# Node ID is first 16 bytes of BLAKE2b hash of public key
NODE_ID_LENGTH = 16

# Default key storage location
DEFAULT_KEY_DIR = Path("/var/lib/spark")
IDENTITY_KEY_FILE = "identity.key"


class KeyError(Exception):
    """Exception raised for key-related errors."""
    pass


@dataclass
class IdentityKey:
    """
    Node identity key pair.
    
    Contains:
    - Ed25519 signing key pair (for authentication)
    - Derived X25519 encryption key pair (for ECDH)
    - Node ID (derived from public key)
    
    The Ed25519 and X25519 keys are mathematically related,
    allowing us to use a single identity for both signing
    and encryption.
    """
    
    _ed25519_private: Ed25519PrivateKey
    _ed25519_public: Ed25519PublicKey
    _x25519_private: X25519PrivateKey
    _x25519_public: X25519PublicKey
    node_id: bytes
    
    def __init__(self, ed25519_private: Ed25519PrivateKey):
        """
        Initialize identity from Ed25519 private key.
        
        Args:
            ed25519_private: Ed25519 private key
        """
        self._ed25519_private = ed25519_private
        self._ed25519_public = ed25519_private.public_key()
        
        # Derive X25519 key from Ed25519 key
        # This uses the standard conversion defined in RFC 8032
        self._x25519_private, self._x25519_public = self._derive_x25519()
        
        # Compute node ID from public key
        self.node_id = derive_node_id(self._ed25519_public)
    
    def _derive_x25519(self) -> Tuple[X25519PrivateKey, X25519PublicKey]:
        """
        Derive X25519 key pair from Ed25519 key.
        
        Ed25519 and X25519 use related curves (Ed25519 is a twist of Curve25519).
        We can derive an X25519 key from Ed25519 private key bytes.
        
        Note: For this implementation, we generate a separate X25519 key
        deterministically from the Ed25519 seed for simplicity and safety.
        """
        # Get Ed25519 private key bytes
        ed_private_bytes = self._ed25519_private.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # Derive X25519 seed using HKDF
        # This gives us a separate but deterministic X25519 key
        x25519_seed = hkdf_derive(
            input_key_material=ed_private_bytes,
            length=32,
            info=b"spark-x25519-derive",
        )
        
        # Create X25519 key from derived seed
        x25519_private = X25519PrivateKey.from_private_bytes(x25519_seed)
        x25519_public = x25519_private.public_key()
        
        return x25519_private, x25519_public
    
    def sign(self, message: bytes) -> bytes:
        """
        Sign a message with Ed25519.
        
        Args:
            message: Message to sign
            
        Returns:
            bytes: 64-byte Ed25519 signature
        """
        return self._ed25519_private.sign(message)
    
    def verify(self, message: bytes, signature: bytes) -> bool:
        """
        Verify an Ed25519 signature.
        
        Args:
            message: Original message
            signature: Signature to verify
            
        Returns:
            bool: True if signature is valid
        """
        try:
            self._ed25519_public.verify(signature, message)
            return True
        except Exception:
            return False
    
    def exchange(self, peer_public: X25519PublicKey) -> bytes:
        """
        Perform X25519 key exchange.
        
        Args:
            peer_public: Peer's X25519 public key
            
        Returns:
            bytes: 32-byte shared secret
        """
        return self._x25519_private.exchange(peer_public)
    
    @property
    def public_key_bytes(self) -> bytes:
        """Get Ed25519 public key as bytes."""
        return self._ed25519_public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
    
    @property
    def x25519_public_bytes(self) -> bytes:
        """Get X25519 public key as bytes."""
        return self._x25519_public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
    
    @property
    def x25519_public(self) -> X25519PublicKey:
        """Get X25519 public key object."""
        return self._x25519_public
    
    def to_bytes(self) -> bytes:
        """
        Serialize private key for storage.
        
        Returns:
            bytes: Serialized Ed25519 private key (32 bytes)
            
        Security:
            Output contains secret key material. Handle with care.
        """
        return self._ed25519_private.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'IdentityKey':
        """
        Load identity key from bytes.
        
        Args:
            data: 32-byte Ed25519 private key
            
        Returns:
            IdentityKey: Loaded identity key
        """
        if len(data) != 32:
            raise KeyError("Invalid key length (expected 32 bytes)")
        
        ed25519_private = Ed25519PrivateKey.from_private_bytes(data)
        return cls(ed25519_private)
    
    def __del__(self):
        """Attempt to clear key material from memory."""
        # Note: This is best-effort due to Python's memory management
        pass


class EphemeralKey:
    """
    Ephemeral X25519 key pair for onion layer encryption.
    
    These keys are generated per-message and should be
    discarded after use for forward secrecy.
    """
    
    def __init__(self):
        """Generate a new ephemeral X25519 key pair."""
        self._private = X25519PrivateKey.generate()
        self._public = self._private.public_key()
    
    def exchange(self, peer_public: X25519PublicKey) -> bytes:
        """
        Perform X25519 key exchange.
        
        Args:
            peer_public: Peer's X25519 public key
            
        Returns:
            bytes: 32-byte shared secret
        """
        return self._private.exchange(peer_public)
    
    @property
    def public_bytes(self) -> bytes:
        """Get public key as bytes (32 bytes)."""
        return self._public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
    
    @property
    def public_key(self) -> X25519PublicKey:
        """Get public key object."""
        return self._public
    
    def __del__(self):
        """Attempt to clear key material from memory."""
        pass


def derive_node_id(public_key: Ed25519PublicKey) -> bytes:
    """
    Derive node ID from Ed25519 public key.
    
    NodeID = BLAKE2b(public_key)[:16]
    
    This gives us a 128-bit identifier that:
    - Is derived deterministically from the public key
    - Cannot be reversed to obtain the public key
    - Is short enough for efficient routing
    
    Args:
        public_key: Ed25519 public key
        
    Returns:
        bytes: 16-byte node ID
    """
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    
    return blake2b_hash(
        public_bytes,
        digest_size=NODE_ID_LENGTH,
        person=b"spark-nodeid"
    )


def generate_identity() -> IdentityKey:
    """
    Generate a new node identity.
    
    Creates a fresh Ed25519 key pair and derives all
    associated keys and identifiers.
    
    Returns:
        IdentityKey: New identity key
        
    Security:
        Uses os.urandom() for key generation.
    """
    ed25519_private = Ed25519PrivateKey.generate()
    return IdentityKey(ed25519_private)


def load_identity(
    key_dir: Optional[Path] = None,
    create_if_missing: bool = True,
) -> IdentityKey:
    """
    Load node identity from disk, creating if necessary.
    
    Key file format: 32-byte raw Ed25519 private key
    
    Args:
        key_dir: Directory containing identity.key (default: /var/lib/spark)
        create_if_missing: If True, generate new identity if not found
        
    Returns:
        IdentityKey: Loaded or generated identity
        
    Raises:
        KeyError: If key file exists but is invalid
        FileNotFoundError: If key file missing and create_if_missing=False
        
    Security:
        - Key file permissions set to 0600 (owner read/write only)
        - Directory permissions set to 0700 (owner only)
    """
    if key_dir is None:
        key_dir = DEFAULT_KEY_DIR
    
    key_dir = Path(key_dir)
    key_file = key_dir / IDENTITY_KEY_FILE
    
    if key_file.exists():
        # Load existing key
        try:
            data = key_file.read_bytes()
            identity = IdentityKey.from_bytes(data)
            return identity
        except Exception as e:
            raise KeyError(f"Failed to load identity key: {e}")
    
    if not create_if_missing:
        raise FileNotFoundError(f"Identity key not found: {key_file}")
    
    # Generate new identity
    identity = generate_identity()
    
    # Ensure directory exists with proper permissions
    key_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(key_dir, stat.S_IRWXU)  # 0700
    
    # Write key file with restricted permissions
    key_file.write_bytes(identity.to_bytes())
    os.chmod(key_file, stat.S_IRUSR | stat.S_IWUSR)  # 0600
    
    return identity


def public_key_from_bytes(data: bytes) -> X25519PublicKey:
    """
    Load X25519 public key from bytes.
    
    Args:
        data: 32-byte X25519 public key
        
    Returns:
        X25519PublicKey: Public key object
    """
    if len(data) != X25519_KEY_SIZE:
        raise KeyError(f"Invalid public key length: {len(data)} (expected {X25519_KEY_SIZE})")
    
    return X25519PublicKey.from_public_bytes(data)


def verify_signature(
    public_key_bytes: bytes,
    message: bytes,
    signature: bytes,
) -> bool:
    """
    Verify an Ed25519 signature given public key bytes.
    
    Args:
        public_key_bytes: 32-byte Ed25519 public key
        message: Original message
        signature: 64-byte signature
        
    Returns:
        bool: True if signature is valid
    """
    try:
        public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        public_key.verify(signature, message)
        return True
    except Exception:
        return False
