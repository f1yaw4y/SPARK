# SPARK
The SPARK project aims to explore and develop the foundation for large-scale, user-operated radio mesh networks. SPARK defines early architecture for decentralized identity, sub-mesh formation, and probabilistic routing under real-world radio and adversarial constraints.

#### SPARK is in it's earliest stages and is highly experimental. The current implementation focuses on establishing the foundational cryptographic and routing function before optimizing for large scale deployment. At this time, this project is not intended for production use.

### This project was based on the ESP32 being used as a router. However, it is clear that the requirements of a SPARK router are too much for an ESP32. ESP32's will be only used as clients, and the routing firmware is currently being ported to the Raspberry Pi Zero 2 W, as these processors contain much more RAM, and SRAM. They also contain a faster clock speed which will be useful for speeding up the complex encryption

## Design Goals
* Dynamic infrastructure with no global authority
* Precise and private P2P routing over untrusted intermediate nodes
* Private identities
* Redundant and fallback operations under packet loss, retransmission, and node movement

## Address-based Routing
SPARK uses a cryptographically derived addressing method rather than fixed hardware or positional-based identifiers.

Each node maintains a long-term cryptographic identity. From this identity, nodes derive dynamic, ephemeral addresses that do not reveal the underlying identity. This allows routing decisions to be made without revealing fingerprints or identifiers that could be used for tracking or correlation

### Sub-Mesh Design
The network is autonomously and dynamically segmented into sub-meshes. These sub-meshes are based on topology, where reliability and trusted nodes are prioritized utilizing a "trust score"

Sub-mesh boundaries also act as routing domains
* Traffic crossing a boundary incurs additional cryptographic layers, obscuring the identity and route of all data
* Routing confidence decays with distance from the originating sub-mesh
* This allows efficient and private routing without any node acquiring global network knowledge
* Allows for a dynamic and expanding network to thrive without any manual configurations

### Packet Structure and Cryptography
SPARK packets use a layered encryption model inspired by extsting onion routing protocols, and adapted for mass deployment across hundreds of nodes
* Inner payloads are AES-CTR encrypted
* Outer layers utilize AES-GCM for authenticating routing headers
* Routing headers are intentionally mutable between hops and only authenticated at the outer layer
* Each layer utilizes unique nonces to prevent keystream reuse and replay

This structire allows intermediate nodes to make routing decisions without having any knowledge as to the origin, destination, or data contents
