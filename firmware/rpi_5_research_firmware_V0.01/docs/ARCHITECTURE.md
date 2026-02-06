# SPARK Architecture

## System Overview

SPARK (Secure Private Autonomous Routing Kernel) is a decentralized mesh networking
system implementing region-based onion routing over low-bandwidth radio links.

## Core Components

### 1. sparkd — The Core Daemon

The main daemon process responsible for:
- Radio management and packet transmission/reception
- Peer discovery and mesh topology maintenance
- Region grouping and boundary detection
- Onion routing construction and peeling
- Message delivery and acknowledgment tracking
- RPC interface for meshctl

### 2. meshctl — Command Line Interface

User-facing CLI tool communicating with sparkd via Unix domain socket.

## Data Flow

```
┌──────────────────────────────────────────────────────────────────────────┐
│                              USER SPACE                                   │
│                                                                          │
│  ┌─────────────┐         ┌─────────────────────────────────────────┐    │
│  │  meshctl    │◄───────►│              sparkd                      │    │
│  │  (CLI)      │  Unix   │                                         │    │
│  └─────────────┘  Socket │  ┌─────────┐  ┌─────────┐  ┌─────────┐ │    │
│                          │  │ Crypto  │  │  Mesh   │  │  Onion  │ │    │
│                          │  │ Module  │  │ Manager │  │ Router  │ │    │
│                          │  └────┬────┘  └────┬────┘  └────┬────┘ │    │
│                          │       │            │            │       │    │
│                          │  ┌────▼────────────▼────────────▼────┐ │    │
│                          │  │         Packet Handler            │ │    │
│                          │  └────────────────┬──────────────────┘ │    │
│                          │                   │                     │    │
│                          │  ┌────────────────▼──────────────────┐ │    │
│                          │  │         Radio Abstraction          │ │    │
│                          │  └────────────────┬──────────────────┘ │    │
│                          └───────────────────┼───────────────────┘     │
└──────────────────────────────────────────────┼─────────────────────────┘
                                               │
┌──────────────────────────────────────────────┼─────────────────────────┐
│                            KERNEL / HARDWARE │                          │
│                                              │                          │
│  ┌───────────────────────────────────────────▼───────────────────────┐ │
│  │                     SPI Bus (spidev)                               │ │
│  └───────────────────────────────────────────┬───────────────────────┘ │
│                                              │                          │
│  ┌───────────────────────────────────────────▼───────────────────────┐ │
│  │                    Waveshare SX1262 LoRa HAT                       │ │
│  └───────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────┘
```

## Module Responsibilities

### crypto/

**Purpose**: All cryptographic operations

| File | Responsibility |
|------|----------------|
| `primitives.py` | Low-level wrappers around cryptography library |
| `keys.py` | Key generation, storage, derivation |
| `envelope.py` | AEAD encryption/decryption of payloads |
| `onion.py` | Onion layer construction and peeling |

**Design Principles**:
- All crypto uses `python3-cryptography` (OpenSSL backend)
- Ephemeral keys generated per-message
- HKDF for all key derivation
- Constant-time operations where possible

### radio/

**Purpose**: Hardware abstraction for radio transceivers

| File | Responsibility |
|------|----------------|
| `base.py` | Abstract base class defining radio interface |
| `lora_sx1262.py` | Waveshare SX1262 HAT driver |
| `loopback.py` | Local loopback for testing |

**Design Principles**:
- All radios implement common interface
- Configurable parameters per radio type
- Clean separation from mesh logic

### mesh/

**Purpose**: Mesh topology management

| File | Responsibility |
|------|----------------|
| `peer.py` | Peer discovery, tracking, link quality |
| `submesh.py` | Sub-mesh formation and consensus |
| `region.py` | Region grouping heuristics |
| `routing.py` | Intra-region packet forwarding |

**Design Principles**:
- Regions are probabilistic, not deterministic
- No global coordination required
- Graceful handling of topology changes

### onion/

**Purpose**: 3-layer onion routing implementation

| File | Responsibility |
|------|----------------|
| `layers.py` | Onion packet construction |
| `gateway.py` | Layer peeling at region boundaries |
| `delivery.py` | End-to-end delivery tracking |

**Design Principles**:
- Fixed 3-layer depth
- Regions, not nodes, are onion layers
- Gateways only see adjacent regions

### packet/

**Purpose**: Packet format and persistence

| File | Responsibility |
|------|----------------|
| `format.py` | Wire format definitions |
| `dedup.py` | Duplicate detection cache |
| `store.py` | Persistent message storage |

**Design Principles**:
- Fixed-size headers for radio efficiency
- Time-bounded deduplication
- Persistent storage for delay tolerance

### rpc/

**Purpose**: Inter-process communication

| File | Responsibility |
|------|----------------|
| `server.py` | Unix socket RPC server |

**Design Principles**:
- Simple JSON-RPC over Unix socket
- No network exposure
- Authentication via Unix permissions

## State Management

### Persistent State (`/var/lib/spark/`)

| File | Contents |
|------|----------|
| `identity.key` | Node Ed25519 private key |
| `peers.db` | SQLite database of known peers |
| `messages.db` | SQLite database of pending messages |
| `config_state.json` | Runtime configuration state |

### Volatile State (Memory)

- Active radio sessions
- Current peer reachability
- Region membership cache
- Deduplication cache

## Threading Model

```
Main Thread
    │
    ├── Radio RX Thread (per radio)
    │       └── Receives packets, queues for processing
    │
    ├── Packet Processor Thread
    │       └── Processes incoming packets
    │
    ├── Mesh Maintenance Thread
    │       └── Periodic peer probing, region updates
    │
    └── RPC Server Thread
            └── Handles meshctl requests
```

All inter-thread communication via thread-safe queues.

## Startup Sequence

1. Load configuration from `/etc/spark/config.toml`
2. Load or generate node identity
3. Initialize storage databases
4. Initialize radio interfaces
5. Start radio RX threads
6. Start packet processor
7. Start mesh maintenance
8. Start RPC server
9. Begin peer discovery

## Shutdown Sequence

1. Stop accepting new RPC connections
2. Flush pending messages to storage
3. Stop mesh maintenance
4. Stop packet processor
5. Stop radio interfaces
6. Close databases
7. Exit

## Configuration Hierarchy

```
/etc/spark/config.toml          # System configuration
    │
    ▼
/var/lib/spark/config_state.json # Runtime state
    │
    ▼
Command-line arguments           # Override for debugging
```
