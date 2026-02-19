# SPARK Cryptographic Design

## Overview

This document describes the cryptographic primitives, protocols, and security
properties of the SPARK mesh routing system.

**Security Level**: 128-bit equivalent security throughout.

## Primitive Selection

### Key Agreement: X25519

**Why X25519**:
- Constant-time implementation in OpenSSL
- 128-bit security level
- Small key size (32 bytes)
- Widely audited

**Usage**:
- Ephemeral key agreement for each onion layer
- Deriving shared secrets for envelope encryption

### Digital Signatures: Ed25519

**Why Ed25519**:
- Deterministic signatures (no RNG needed at signing time)
- Fast verification
- Small signatures (64 bytes)
- Same curve family as X25519 (key derivation possible)

**Usage**:
- Node identity attestation
- Message authentication (optional)
- Future: signed announcements

### Authenticated Encryption: XChaCha20-Poly1305

**Why XChaCha20-Poly1305**:
- 192-bit nonces (safe random nonce generation)
- No weak keys
- Constant-time implementation
- Resistant to timing attacks

**Usage**:
- All payload encryption
- Routing envelope encryption

### Hashing: BLAKE2b

**Why BLAKE2b**:
- Faster than SHA-256
- Keyed mode available
- Variable output length
- No length extension attacks

**Usage**:
- NodeID derivation
- Message ID generation
- Deduplication hashing

### Key Derivation: HKDF with BLAKE2b

**Why HKDF**:
- Proven security reduction
- Separable extract/expand phases
- Standard construction

**Usage**:
- Deriving encryption keys from ECDH shared secrets
- Deriving multiple keys from single secret

## Key Hierarchy

```
Identity Key (Ed25519)
    │
    ├── NodeID = BLAKE2b(pubkey)[:16]
    │
    └── Encryption Key (X25519)
            │
            └── Derived via RFC 8032 conversion
```

### Identity Key Generation

```python
# On first boot:
private_key = Ed25519PrivateKey.generate()
public_key = private_key.public_key()
node_id = blake2b(public_key.public_bytes_raw(), digest_size=16)
```

### X25519 Key Derivation from Ed25519

For encryption, we derive an X25519 key from the Ed25519 identity:

```python
# Ed25519 private key (scalar) can be converted to X25519
# This is a standard conversion defined in RFC 8032
x25519_private = ed25519_to_x25519(ed25519_private)
```

## Onion Encryption Protocol

### Layer Construction (Sender Side)

For each layer L in [3, 2, 1] (inside-out):

```
1. Generate ephemeral X25519 keypair (eph_priv, eph_pub)
2. Look up destination region's gateway public key (dest_pub)
3. Compute shared_secret = X25519(eph_priv, dest_pub)
4. Derive keys:
   - enc_key = HKDF(shared_secret, info="spark-envelope-key", length=32)
   - nonce = HKDF(shared_secret, info="spark-envelope-nonce", length=24)
5. Construct plaintext routing info:
   - next_region_id (16 bytes)
   - scope (1 byte)
   - ttl (1 byte)
   - inner_envelope (variable)
6. Ciphertext = XChaCha20-Poly1305(enc_key, nonce, plaintext)
7. Layer envelope = eph_pub || ciphertext
```

### Layer Peeling (Gateway Side)

```
1. Extract eph_pub from envelope
2. Compute shared_secret = X25519(gateway_priv, eph_pub)
3. Derive keys (same HKDF as sender)
4. Decrypt ciphertext
5. Parse routing info
6. Forward inner_envelope to next_region_id
```

### Security Properties

- **Perfect Forward Secrecy**: Ephemeral keys per layer
- **Sender Anonymity**: Gateway cannot derive sender from eph_pub
- **Unlinkability**: Different ephemeral keys prevent correlation

## Envelope Format

### Onion Layer Envelope

```
┌─────────────────────────────────────────────────────────┐
│ Ephemeral X25519 Public Key            (32 bytes)      │
├─────────────────────────────────────────────────────────┤
│ Encrypted Payload (XChaCha20-Poly1305)                 │
│ ┌─────────────────────────────────────────────────────┐│
│ │ Next Region ID                       (16 bytes)     ││
│ ├─────────────────────────────────────────────────────┤│
│ │ Scope                                (1 byte)       ││
│ ├─────────────────────────────────────────────────────┤│
│ │ TTL                                  (1 byte)       ││
│ ├─────────────────────────────────────────────────────┤│
│ │ Flags                                (1 byte)       ││
│ ├─────────────────────────────────────────────────────┤│
│ │ Inner Envelope Length                (2 bytes)      ││
│ ├─────────────────────────────────────────────────────┤│
│ │ Inner Envelope                       (variable)     ││
│ └─────────────────────────────────────────────────────┘│
│ Poly1305 Tag                           (16 bytes)      │
└─────────────────────────────────────────────────────────┘
```

### Final Payload Envelope (Layer 3 Inner)

```
┌─────────────────────────────────────────────────────────┐
│ Ephemeral X25519 Public Key            (32 bytes)      │
├─────────────────────────────────────────────────────────┤
│ Encrypted Payload (XChaCha20-Poly1305)                 │
│ ┌─────────────────────────────────────────────────────┐│
│ │ Destination NodeID                   (16 bytes)     ││
│ ├─────────────────────────────────────────────────────┤│
│ │ Message ID                           (16 bytes)     ││
│ ├─────────────────────────────────────────────────────┤│
│ │ Timestamp                            (8 bytes)      ││
│ ├─────────────────────────────────────────────────────┤│
│ │ Payload Type                         (1 byte)       ││
│ ├─────────────────────────────────────────────────────┤│
│ │ Payload Length                       (2 bytes)      ││
│ ├─────────────────────────────────────────────────────┤│
│ │ Payload                              (variable)     ││
│ └─────────────────────────────────────────────────────┘│
│ Poly1305 Tag                           (16 bytes)      │
└─────────────────────────────────────────────────────────┘
```

## Message ID Generation

```python
message_id = BLAKE2b(
    sender_node_id ||
    recipient_node_id ||
    timestamp ||
    random_bytes(16),
    digest_size=16
)
```

This ensures:
- Uniqueness across messages
- No correlation to payload content
- Suitable for deduplication

## Acknowledgment Encryption

ACKs are encrypted end-to-end from recipient to sender:

```
1. Recipient generates ephemeral X25519 keypair
2. Recipient looks up sender's public key (from message)
3. ACK payload = message_id || status || timestamp
4. Encrypt ACK with sender's public key
5. Route back through onion (reversed path or new path)
```

## Key Rotation

### Identity Keys

- **Rotation**: Manual only (requires announcement to peers)
- **Revocation**: Not currently supported (future work)

### Ephemeral Keys

- **Rotation**: Per-message (automatic)
- **Destruction**: Immediately after use

## Threat Model Considerations

### Protected Against

- Passive eavesdropping
- Single compromised node
- Traffic content analysis
- Message modification

### Not Protected Against

- Global passive adversary (timing analysis)
- Compromised endpoints
- Long-term key compromise (past messages)
- Side-channel attacks on implementation

## Implementation Notes

### Constant-Time Operations

All operations on secret data use constant-time implementations:
- `cryptography` library uses OpenSSL constant-time functions
- No branching on secret data in Python layer

### Random Number Generation

All randomness from `os.urandom()` (kernel CSPRNG):
- Ephemeral key generation
- Nonce generation (where needed)
- Message ID randomness

### Memory Handling

- Secret keys wrapped in classes with `__del__` clearing
- No logging of key material
- Minimal key lifetime in memory

## References

- RFC 7748: Elliptic Curves for Security (X25519)
- RFC 8032: Edwards-Curve Digital Signature Algorithm (Ed25519)
- RFC 8439: ChaCha20 and Poly1305 for IETF Protocols
- RFC 5869: HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
