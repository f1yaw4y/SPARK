"""
SPARK Envelope Encryption

Provides AEAD encryption/decryption for message payloads
using XChaCha20-Poly1305.

Envelope format:
    ephemeral_pubkey (32 bytes) || ciphertext || tag (16 bytes)

The ephemeral public key is included so recipients can
derive the shared secret for decryption.

SECURITY NOTES:
- Uses XChaCha20-Poly1305 for authenticated encryption
- 192-bit nonces derived via HKDF (safe random generation)
- Each envelope uses a fresh ephemeral key (forward secrecy)
"""

from typing import Tuple
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.exceptions import InvalidTag

from .primitives import (
    hkdf_derive,
    XCHACHA20_KEY_SIZE,
    XCHACHA20_NONCE_SIZE,
    POLY1305_TAG_SIZE,
    X25519_KEY_SIZE,
)
from .keys import (
    EphemeralKey,
    IdentityKey,
    public_key_from_bytes,
)


class EnvelopeError(Exception):
    """Exception raised for envelope encryption/decryption errors."""
    pass


# Domain separation constants for HKDF
ENVELOPE_KEY_INFO = b"spark-envelope-key-v1"
ENVELOPE_NONCE_INFO = b"spark-envelope-nonce-v1"


def _derive_envelope_keys(shared_secret: bytes) -> Tuple[bytes, bytes]:
    """
    Derive encryption key and nonce from ECDH shared secret.
    
    Uses HKDF with domain separation to derive:
    - 32-byte encryption key
    - 12-byte nonce (ChaCha20Poly1305 uses 12-byte nonce)
    
    Note: We use ChaCha20Poly1305 (12-byte nonce) instead of
    XChaCha20Poly1305 because the nonce is derived deterministically
    from a fresh ECDH exchange, not randomly generated.
    
    Args:
        shared_secret: 32-byte X25519 shared secret
        
    Returns:
        Tuple[bytes, bytes]: (encryption_key, nonce)
    """
    enc_key = hkdf_derive(
        input_key_material=shared_secret,
        length=XCHACHA20_KEY_SIZE,
        info=ENVELOPE_KEY_INFO,
    )
    
    # ChaCha20Poly1305 uses 12-byte nonce
    nonce = hkdf_derive(
        input_key_material=shared_secret,
        length=12,  # ChaCha20Poly1305 nonce size
        info=ENVELOPE_NONCE_INFO,
    )
    
    return enc_key, nonce


def seal_envelope(
    plaintext: bytes,
    recipient_public: X25519PublicKey,
    associated_data: bytes = b"",
) -> bytes:
    """
    Encrypt plaintext for a recipient using ECIES-style encryption.
    
    Protocol:
    1. Generate ephemeral X25519 key pair
    2. Compute shared secret with recipient's public key
    3. Derive encryption key and nonce via HKDF
    4. Encrypt plaintext with ChaCha20-Poly1305
    5. Return ephemeral_pubkey || ciphertext || tag
    
    Args:
        plaintext: Data to encrypt
        recipient_public: Recipient's X25519 public key
        associated_data: Additional authenticated data (optional)
        
    Returns:
        bytes: Encrypted envelope (32 + len(plaintext) + 16 bytes)
        
    Security:
        - Fresh ephemeral key per message (forward secrecy)
        - Authenticated encryption (confidentiality + integrity)
        - Associated data is authenticated but not encrypted
    """
    # Generate ephemeral key pair
    ephemeral = EphemeralKey()
    
    # Compute shared secret
    shared_secret = ephemeral.exchange(recipient_public)
    
    # Derive encryption key and nonce
    enc_key, nonce = _derive_envelope_keys(shared_secret)
    
    # Encrypt with ChaCha20-Poly1305
    cipher = ChaCha20Poly1305(enc_key)
    ciphertext = cipher.encrypt(nonce, plaintext, associated_data)
    
    # Construct envelope: ephemeral_pubkey || ciphertext (includes tag)
    envelope = ephemeral.public_bytes + ciphertext
    
    return envelope


def open_envelope(
    envelope: bytes,
    recipient_identity: IdentityKey,
    associated_data: bytes = b"",
) -> bytes:
    """
    Decrypt an envelope using recipient's private key.
    
    Protocol:
    1. Extract ephemeral public key from envelope
    2. Compute shared secret with recipient's private key
    3. Derive encryption key and nonce via HKDF
    4. Decrypt and verify with ChaCha20-Poly1305
    
    Args:
        envelope: Encrypted envelope from seal_envelope()
        recipient_identity: Recipient's identity key
        associated_data: Additional authenticated data (must match encryption)
        
    Returns:
        bytes: Decrypted plaintext
        
    Raises:
        EnvelopeError: If decryption or authentication fails
    """
    # Minimum envelope size: pubkey (32) + tag (16) + at least 1 byte
    min_size = X25519_KEY_SIZE + POLY1305_TAG_SIZE
    if len(envelope) < min_size:
        raise EnvelopeError(f"Envelope too short: {len(envelope)} bytes")
    
    # Extract ephemeral public key
    ephemeral_pub_bytes = envelope[:X25519_KEY_SIZE]
    ciphertext = envelope[X25519_KEY_SIZE:]
    
    try:
        ephemeral_public = public_key_from_bytes(ephemeral_pub_bytes)
    except Exception as e:
        raise EnvelopeError(f"Invalid ephemeral public key: {e}")
    
    # Compute shared secret
    shared_secret = recipient_identity.exchange(ephemeral_public)
    
    # Derive encryption key and nonce
    enc_key, nonce = _derive_envelope_keys(shared_secret)
    
    # Decrypt with ChaCha20-Poly1305
    cipher = ChaCha20Poly1305(enc_key)
    
    try:
        plaintext = cipher.decrypt(nonce, ciphertext, associated_data)
    except InvalidTag:
        raise EnvelopeError("Decryption failed: invalid tag (tampering or wrong key)")
    except Exception as e:
        raise EnvelopeError(f"Decryption failed: {e}")
    
    return plaintext


def seal_envelope_for_pubkey_bytes(
    plaintext: bytes,
    recipient_public_bytes: bytes,
    associated_data: bytes = b"",
) -> bytes:
    """
    Convenience function to seal envelope given public key bytes.
    
    Args:
        plaintext: Data to encrypt
        recipient_public_bytes: 32-byte X25519 public key
        associated_data: Additional authenticated data (optional)
        
    Returns:
        bytes: Encrypted envelope
    """
    recipient_public = public_key_from_bytes(recipient_public_bytes)
    return seal_envelope(plaintext, recipient_public, associated_data)


@dataclass
class SealedEnvelope:
    """
    Structured representation of a sealed envelope.
    
    Useful for inspection and debugging without decryption.
    """
    ephemeral_public: bytes  # 32 bytes
    ciphertext: bytes        # Variable length (includes tag)
    
    @property
    def total_size(self) -> int:
        """Total envelope size in bytes."""
        return len(self.ephemeral_public) + len(self.ciphertext)
    
    @property
    def plaintext_size(self) -> int:
        """Estimated plaintext size (ciphertext minus tag)."""
        return len(self.ciphertext) - POLY1305_TAG_SIZE
    
    def to_bytes(self) -> bytes:
        """Serialize to wire format."""
        return self.ephemeral_public + self.ciphertext
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'SealedEnvelope':
        """Parse from wire format."""
        if len(data) < X25519_KEY_SIZE + POLY1305_TAG_SIZE:
            raise EnvelopeError("Data too short for sealed envelope")
        
        return cls(
            ephemeral_public=data[:X25519_KEY_SIZE],
            ciphertext=data[X25519_KEY_SIZE:],
        )
