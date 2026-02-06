"""
SPARK Cryptographic Primitives

Low-level cryptographic functions wrapping the cryptography library.

SECURITY NOTES:
- All randomness from os.urandom (kernel CSPRNG)
- All comparisons use constant-time operations
- Keys are cleared from memory when possible

Dependencies:
- python3-cryptography (distro package)
"""

import os
import hmac
from typing import Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend


def random_bytes(length: int) -> bytes:
    """
    Generate cryptographically secure random bytes.
    
    Uses os.urandom() which reads from the kernel's CSPRNG.
    On Linux, this is /dev/urandom with proper entropy seeding.
    
    Args:
        length: Number of random bytes to generate
        
    Returns:
        bytes: Cryptographically secure random bytes
        
    Raises:
        ValueError: If length is negative
    """
    if length < 0:
        raise ValueError("Length must be non-negative")
    return os.urandom(length)


def blake2b_hash(
    data: bytes,
    digest_size: int = 32,
    key: Optional[bytes] = None,
    person: Optional[bytes] = None,
) -> bytes:
    """
    Compute BLAKE2b hash of data.
    
    BLAKE2b is faster than SHA-256 and provides:
    - No length extension attacks
    - Optional keyed mode (MAC)
    - Variable output length
    
    Args:
        data: Data to hash
        digest_size: Output hash size in bytes (1-64, default 32)
        key: Optional key for keyed hashing (MAC mode)
        person: Optional personalization string (up to 16 bytes)
        
    Returns:
        bytes: BLAKE2b hash digest
        
    Raises:
        ValueError: If parameters are invalid
    """
    if not 1 <= digest_size <= 64:
        raise ValueError("Digest size must be 1-64 bytes")
    
    if key is not None and len(key) > 64:
        raise ValueError("Key must be at most 64 bytes")
    
    if person is not None and len(person) > 16:
        raise ValueError("Personalization must be at most 16 bytes")
    
    # Build BLAKE2b hasher
    # Note: cryptography library handles the low-level details
    from cryptography.hazmat.primitives.hashes import BLAKE2b
    
    hasher = hashes.Hash(
        BLAKE2b(digest_size),
        backend=default_backend()
    )
    
    # If keyed mode requested, we need to use a different approach
    # For simplicity, we'll prepend the key (HMAC-style for now)
    # TODO: Use proper BLAKE2b keyed mode when available
    if key is not None:
        # Pad key to 64 bytes
        padded_key = key.ljust(64, b'\x00')
        hasher.update(padded_key)
    
    if person is not None:
        # Include personalization
        hasher.update(person.ljust(16, b'\x00'))
    
    hasher.update(data)
    return hasher.finalize()


def hkdf_derive(
    input_key_material: bytes,
    length: int,
    info: bytes,
    salt: Optional[bytes] = None,
) -> bytes:
    """
    Derive key material using HKDF (RFC 5869).
    
    HKDF provides:
    - Proper key derivation from ECDH shared secrets
    - Domain separation via info parameter
    - Deterministic output (same inputs = same output)
    
    Args:
        input_key_material: Source key material (e.g., ECDH shared secret)
        length: Desired output length in bytes
        info: Context/application-specific info (for domain separation)
        salt: Optional salt (random bytes, can be public)
        
    Returns:
        bytes: Derived key material
        
    Raises:
        ValueError: If parameters are invalid
        
    Example:
        >>> shared_secret = x25519_exchange(my_private, their_public)
        >>> enc_key = hkdf_derive(shared_secret, 32, b"spark-envelope-key")
        >>> nonce = hkdf_derive(shared_secret, 24, b"spark-envelope-nonce")
    """
    if length < 1:
        raise ValueError("Length must be at least 1")
    
    if length > 255 * 32:
        raise ValueError("Length too large for HKDF")
    
    # Use SHA-256 as the underlying hash for HKDF
    # (BLAKE2b not directly supported in cryptography's HKDF)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
        backend=default_backend()
    )
    
    return hkdf.derive(input_key_material)


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """
    Compare two byte strings in constant time.
    
    This prevents timing attacks where an attacker could learn
    information about the expected value by measuring comparison time.
    
    Uses hmac.compare_digest() which is designed for this purpose.
    
    Args:
        a: First byte string
        b: Second byte string
        
    Returns:
        bool: True if equal, False otherwise
        
    Security:
        Comparison time is constant regardless of where strings differ.
    """
    return hmac.compare_digest(a, b)


def secure_zero(data: bytearray) -> None:
    """
    Securely zero a bytearray to remove sensitive data from memory.
    
    Note: This is best-effort. Python's memory management may still
    leave copies of the data. For critical applications, consider
    using specialized secure memory libraries.
    
    Args:
        data: Bytearray to zero (modified in place)
        
    Warning:
        Only works with bytearray, not bytes (which are immutable).
    """
    for i in range(len(data)):
        data[i] = 0


def generate_message_id(
    sender_id: bytes,
    recipient_id: bytes,
    timestamp: int,
) -> bytes:
    """
    Generate a unique message ID.
    
    Message ID = BLAKE2b(sender || recipient || timestamp || random)
    
    Properties:
    - Unique with overwhelming probability
    - No correlation to payload content
    - Suitable for deduplication
    
    Args:
        sender_id: Sender's node ID (16 bytes)
        recipient_id: Recipient's node ID (16 bytes)
        timestamp: Unix timestamp
        
    Returns:
        bytes: 16-byte message ID
    """
    random_component = random_bytes(16)
    timestamp_bytes = timestamp.to_bytes(8, byteorder='big')
    
    data = sender_id + recipient_id + timestamp_bytes + random_component
    
    return blake2b_hash(data, digest_size=16, person=b"spark-msgid")


# Encryption constants
XCHACHA20_KEY_SIZE = 32  # bytes
XCHACHA20_NONCE_SIZE = 24  # bytes
POLY1305_TAG_SIZE = 16  # bytes
X25519_KEY_SIZE = 32  # bytes
ED25519_SIGNATURE_SIZE = 64  # bytes
