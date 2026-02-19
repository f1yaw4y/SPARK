# SPARK Threat Model

## Overview

This document describes the security assumptions, threat model, and limitations
of the SPARK mesh routing system. Understanding these is critical for operators
deploying SPARK in adversarial environments.

## System Goals

SPARK aims to provide:

1. **Message Confidentiality**: Only the intended recipient can read message content
2. **Sender Anonymity**: Observers cannot determine who sent a message
3. **Recipient Privacy**: Intermediate nodes cannot determine final recipient
4. **Path Obfuscation**: No single node learns the full routing path
5. **Perfect Forward Secrecy**: Compromise of long-term keys doesn't expose past messages

## Adversary Models

### Adversary Capabilities Spectrum

```
Weakest                                                    Strongest
   │                                                           │
   ▼                                                           ▼
Local      Regional      Multiple       Global        Global
Passive    Passive       Compromised    Passive       Active
Observer   Observer      Nodes          Adversary     Adversary
```

### Level 1: Local Passive Observer

**Capabilities**:
- Can observe radio traffic in one geographic area
- Cannot decrypt traffic
- Can perform traffic analysis on observed packets

**What they learn**:
- Radio activity patterns in their area
- Packet sizes and timing
- Which nodes are transmitting

**What they DON'T learn**:
- Message contents
- Sender/recipient relationships
- Routing paths

**SPARK Protection**: FULL

### Level 2: Regional Passive Observer

**Capabilities**:
- Can observe all traffic within one region
- Cannot decrypt traffic
- Can correlate packets across the region

**What they learn**:
- All Level 1 information
- Traffic flow patterns within region
- Gateway activity levels

**What they DON'T learn**:
- Which packets are related
- Cross-region routing
- Message contents

**SPARK Protection**: STRONG

### Level 3: Multiple Compromised Nodes

**Capabilities**:
- Controls multiple nodes in the network
- Can decrypt onion layers at controlled gateways
- Can correlate traffic at controlled nodes

**What they learn**:
- Routing info for packets through controlled gateways
- If controls both L1 and L2 gateway: regional correlation
- Link between adjacent regions

**What they DON'T learn**:
- Original sender (unless L1 gateway AND in sender's submesh)
- Final recipient (unless in recipient's submesh)
- Message content (unless recipient compromised)

**SPARK Protection**: PARTIAL (depends on gateway distribution)

### Level 4: Global Passive Adversary

**Capabilities**:
- Can observe ALL network traffic everywhere
- Cannot inject or modify traffic
- Can perform timing correlation

**What they learn**:
- Statistical traffic patterns
- Potential correlation via timing analysis
- Network topology

**What they DON'T learn**:
- Message contents
- Definitive sender-recipient links (without timing analysis)

**SPARK Protection**: LIMITED (timing correlation possible)

### Level 5: Global Active Adversary

**Capabilities**:
- All Level 4 capabilities
- Can inject, modify, or drop traffic
- Can perform active attacks

**What they learn**:
- Everything Level 4 learns
- Can confirm suspicions via active probing
- Can deny service

**SPARK Protection**: MINIMAL (out of scope)

## Explicit Non-Goals

SPARK explicitly does NOT protect against:

### 1. Endpoint Compromise

If the sender or recipient device is compromised:
- Adversary has full access to plaintext
- Adversary can impersonate the user
- No protocol can protect against this

### 2. Global Passive Adversary Timing Analysis

With observation of all network traffic:
- Statistical correlation of packet timing possible
- Long-term traffic pattern analysis
- This is a fundamental limitation of low-latency networks

### 3. Cryptographic Breaks

If underlying primitives (X25519, XChaCha20, etc.) are broken:
- All confidentiality lost
- This is unlikely given current cryptographic understanding

### 4. Implementation Bugs

Side-channel attacks, buffer overflows, etc.:
- Mitigated by conservative implementation
- Using well-audited cryptographic libraries
- Not cryptographically prevented

### 5. Rubber Hose Cryptanalysis

Physical coercion to reveal keys:
- Out of scope for any software system
- Operational security is user's responsibility

## Attack Scenarios

### A1: Traffic Correlation Attack

**Scenario**: Adversary observes traffic entering and leaving the network at 
different points, correlating by timing.

**Mitigation**:
- Region-based batching at gateways
- Future: delay randomization
- Future: cover traffic

**Residual Risk**: MEDIUM

### A2: Predecessor Attack

**Scenario**: Adversary observes many messages to same recipient, statistically
determines likely senders.

**Mitigation**:
- Region mixing (many senders per gateway)
- Unlinkable message IDs
- No sender information in outer layers

**Residual Risk**: LOW (requires many observations)

### A3: Intersection Attack

**Scenario**: Adversary correlates sender online times with message receipt times.

**Mitigation**:
- Delay-tolerant delivery
- Store-and-forward at intermediate nodes
- Future: scheduled transmission windows

**Residual Risk**: MEDIUM

### A4: Sybil Attack

**Scenario**: Adversary creates many fake nodes to dominate routing.

**Mitigation**:
- Gateway selection prefers established nodes
- Proof-of-work for announcements (future)
- Local reputation tracking

**Residual Risk**: MEDIUM-HIGH (fundamental DHT problem)

### A5: Eclipse Attack

**Scenario**: Adversary surrounds target node with malicious peers.

**Mitigation**:
- Diverse peer selection
- Multiple radio types
- Manual trusted peer configuration

**Residual Risk**: LOW (geographic distribution helps)

### A6: Denial of Service

**Scenario**: Adversary floods network with traffic.

**Mitigation**:
- Rate limiting per peer
- Packet size limits
- Bandwidth prioritization

**Residual Risk**: HIGH (inherent to open networks)

## Trust Assumptions

### A1: Cryptographic Assumptions

We assume:
- X25519 ECDH is secure (CDH assumption)
- XChaCha20-Poly1305 provides IND-CCA2 security
- BLAKE2b is collision-resistant
- Ed25519 provides EUF-CMA security

### A2: Random Number Generation

We assume:
- `/dev/urandom` provides cryptographically secure random bytes
- Kernel entropy pool is adequately seeded

### A3: Honest Gateway Distribution

We assume:
- Not all gateways are compromised
- At least one gateway per layer is honest
- Gateways are geographically distributed

### A4: System Integrity

We assume:
- Operating system is not compromised
- No malicious kernel modules
- Physical device security maintained

## Security Invariants

The following must ALWAYS hold:

### I1: Key Isolation

Private keys are NEVER:
- Logged
- Transmitted
- Copied to other processes
- Stored unencrypted on disk (except ephemeral)

### I2: Metadata Minimization

No packet contains:
- Full routing path
- Original sender (after L1)
- Final recipient (before L3)
- Timing information traceable to sender

### I3: Forward Secrecy

Compromise of current keys reveals:
- NOTHING about past messages
- At most current in-flight messages

### I4: Layered Decryption

Each onion layer:
- Can only be decrypted by intended gateway
- Reveals only next hop information
- Never reveals full path

## Recommendations for Operators

### High-Security Deployments

1. Use dedicated hardware (not shared systems)
2. Enable full-disk encryption
3. Use hardware RNG if available
4. Physically secure devices
5. Regular key rotation
6. Monitor for anomalous traffic patterns

### Standard Deployments

1. Keep system updated
2. Use firewall (default deny)
3. Don't expose RPC interface
4. Regular log review
5. Backup identity keys securely

### Low-Security / Testing

1. Use loopback radio for testing
2. Never use test keys in production
3. Isolate test network from production

## Incident Response

### Key Compromise Detected

1. Immediately generate new identity
2. Notify known peers of key change
3. Investigate compromise vector
4. Assume all current messages compromised
5. Past messages remain secure (PFS)

### Node Compromise Detected

1. Isolate node from network
2. Forensic analysis if possible
3. Generate new identity on clean install
4. Report to peer operators

### Network-Wide Attack Detected

1. Document attack patterns
2. Coordinate with other operators
3. Consider emergency protocol update
4. Preserve evidence

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-02 | Initial threat model |
