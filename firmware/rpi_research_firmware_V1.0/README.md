# SPARK — Secure Private Autonomous Routing Kernel

**A decentralized, privacy-first mesh networking firmware for Raspberry Pi 5**

## Overview

SPARK is a purpose-built mesh networking system designed for:
- **Censorship resistance**
- **Disaster communications**
- **Off-grid coordination**

This is NOT a consumer router OS. It is a delay-tolerant, privacy-preserving mesh network node implementing fixed 3-layer onion routing.

## Design Principles

1. **Privacy by default** — All routing metadata is encrypted
2. **No central servers** — Fully decentralized operation
3. **No plaintext routing** — Onion routing at the region level
4. **Perfect Forward Secrecy** — Ephemeral keys for every message
5. **Offline-first** — Delay-tolerant message delivery
6. **Auditable code** — Conservative, well-documented implementation

## Hardware Requirements

- Raspberry Pi 5
- Debian-based OS (Raspberry Pi OS Lite or Debian Bookworm)
- Waveshare SX1262 LoRa HAT (868/915 MHz)
- Optional: Additional radios, battery/solar

## Architecture

### Network Model

The network is an unbounded mesh composed of dynamic sub-meshes. However:
- **Onion routing depth is FIXED at 3 layers**
- **Mesh size is UNBOUNDED**
- **Sub-mesh count is UNBOUNDED**

### Onion Routing

SPARK implements region-based onion routing, NOT per-node routing:

```
Layer 1 (Local Region)    → Sender's local sub-mesh cluster
Layer 2 (Transit Region)  → Intermediary mixing region
Layer 3 (Destination)     → Recipient's local region
```

Each layer corresponds to a GROUP of sub-meshes, not individual nodes.

### Node Roles

Nodes dynamically assume roles based on connectivity:
- **LEAF** — Local-only communication
- **RELAY** — Intra-region forwarding
- **GATEWAY** — Inter-region handoff (peels onion layers)

## Installation

### Prerequisites

```bash
# Install system dependencies (Debian/Raspberry Pi OS)
sudo apt update
sudo apt install -y python3 python3-cryptography python3-toml python3-spidev
```

### Install SPARK

```bash
cd /home/Spark
sudo ./install.sh
```

### Configuration

Edit `/etc/spark/config.toml` to configure:
- Radio settings
- Region sizing heuristics
- Retry thresholds
- Storage limits

### Start the Daemon

```bash
sudo systemctl enable sparkd
sudo systemctl start sparkd
```

## Usage

### CLI Commands

```bash
# Node status
meshctl status

# List discovered peers (numbered)
meshctl peers

# Show region topology
meshctl regions

# View routing table
meshctl routes

# Send encrypted message (three ways to specify recipient)
meshctl send '#1' "message"                         # by peer number
meshctl send 0e6c "message"                         # by unique hex prefix
meshctl send 0e6c7822f3f0c212b157e7de8550e6e9 "message"  # by full node ID

# Check inbox
meshctl inbox

# Debug information
meshctl debug
```

### Sending Messages

The `meshctl send` command accepts three recipient formats:

| Format | Example | Description |
|--------|---------|-------------|
| `#N` | `#1` | Peer number from `meshctl peers` list |
| Hex prefix | `0e6c` | Shortest unique prefix of a peer's node ID |
| Full ID | `0e6c7822...e6e9` | Complete 32-character hex node ID |

Typical workflow:

```bash
meshctl peers               # see who's around
meshctl send '#1' "hello"   # send to the first peer
```

> **Note:** The `#` must be quoted (`'#1'` or `"#1"`) so the shell doesn't treat it as a comment.

## Security Model

### Guarantees

- No node sees the full routing path
- No region sees both sender and destination
- Layer 2 provides mixing and unlinkability
- Fixed depth prevents traffic analysis amplification

### Non-Guarantees (Documented Tradeoffs)

- No infinite anonymity depth
- No resistance to global passive adversary
- Regional boundaries are heuristic, not cryptographic

See `docs/THREAT_MODEL.md` for full security analysis.

## Project Structure

```
Spark/
├── sparkd/                 # Core daemon
│   ├── crypto/            # Cryptographic primitives
│   ├── radio/             # Radio abstraction layer
│   ├── mesh/              # Mesh networking logic
│   ├── onion/             # Onion routing implementation
│   ├── packet/            # Packet format and storage
│   └── rpc/               # IPC for meshctl
├── meshctl/               # CLI tool
├── etc/                   # Configuration examples
├── systemd/               # Service files
└── docs/                  # Documentation
```



## Contributing

This is security-critical infrastructure. All contributions must:
1. Follow the existing code style
2. Include comprehensive comments
3. Pass security review
4. Not introduce external dependencies without justification

## Acknowledgments

Built for those who need to communicate when traditional infrastructure fails.
