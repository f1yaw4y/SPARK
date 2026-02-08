"""
SPARK Cryptographic Module

Provides all cryptographic operations for SPARK:
- Key generation and management
- ECDH key agreement (X25519)
- Authenticated encryption (XChaCha20-Poly1305)
- Digital signatures (Ed25519)
- Hashing (BLAKE2b)
- Key derivation (HKDF)

Security Level: 128-bit equivalent throughout.

All implementations use python3-cryptography (OpenSSL backend).
"""

from .primitives import (
    random_bytes,
    blake2b_hash,
    hkdf_derive,
    constant_time_compare,
)

from .keys import (
    IdentityKey,
    EphemeralKey,
    load_identity,
    generate_identity,
    derive_node_id,
)

from .envelope import (
    seal_envelope,
    open_envelope,
    EnvelopeError,
)

from .onion import (
    OnionPacket,
    OnionLayer,
    build_onion,
    peel_layer,
    OnionError,
)

__all__ = [
    # Primitives
    'random_bytes',
    'blake2b_hash',
    'hkdf_derive',
    'constant_time_compare',
    # Keys
    'IdentityKey',
    'EphemeralKey',
    'load_identity',
    'generate_identity',
    'derive_node_id',
    # Envelope
    'seal_envelope',
    'open_envelope',
    'EnvelopeError',
    # Onion
    'OnionPacket',
    'OnionLayer',
    'build_onion',
    'peel_layer',
    'OnionError',
]
