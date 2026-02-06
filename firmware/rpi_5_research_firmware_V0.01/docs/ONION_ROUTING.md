# SPARK Onion Routing Protocol

## Overview

SPARK implements a **fixed 3-layer region-based onion routing protocol**. This is
fundamentally different from Tor-style per-hop onion routing.

## Key Distinction: Regions vs Nodes

### Tor Model (Not Used)
```
Sender → Node A → Node B → Node C → Recipient
         Layer3   Layer2   Layer1
```
Each onion layer = one node.

### SPARK Model
```
Sender → [Region 1] → [Region 2] → [Region 3] → Recipient
          (Local)      (Transit)    (Destination)
         
Within each region:
  Multiple nodes, normal mesh routing, NO onion peeling
```
Each onion layer = one REGION (group of sub-meshes).

## Why Region-Based Routing?

### 1. Bandwidth Efficiency

LoRa radios operate at 0.3-50 kbps. Per-hop onion routing would require:
- Full onion packet at every hop
- Cryptographic operations at every hop
- Massive bandwidth amplification

Region-based routing:
- Onion peeled only at region boundaries (3 times total)
- Normal small-packet forwarding within regions

### 2. Bounded Anonymity

Fixed 3-layer depth provides:
- Predictable anonymity guarantees
- Consistent performance characteristics
- Resistance to topology-based attacks

Variable-depth routing would create:
- Unpredictable latency
- Traffic analysis opportunities
- Resource exhaustion attacks

### 3. Scalability

The network can grow infinitely:
- Add more nodes to existing regions
- Create new sub-meshes
- Form new regions

But anonymity properties remain constant:
- Always 3 layers
- Always region-level mixing
- Always bounded metadata exposure

## Layer Definitions

### Layer 1: Local Region

**Characteristics**:
- Sender's immediate sub-mesh and nearby connected sub-meshes
- High probability of direct radio contact
- Dense connectivity graph
- Short hop counts (1-3 hops typical)

**Trust Model**:
- High trust in reachability
- Low trust in anonymity (nodes know sender)
- Suitable for initial packet injection

**Boundary Detection**:
- Nodes with peers in multiple sub-meshes
- Connectivity drops below threshold
- Different radio characteristics observed

### Layer 2: Transit Region

**Characteristics**:
- Large, well-connected intermediary zone
- Multiple gateway paths available
- Primary mixing layer
- Unknown to both sender and recipient

**Trust Model**:
- Provides unlinkability
- Multiple competing paths
- Traffic mixing

**Selection Criteria**:
- High node count
- Multiple entry/exit gateways
- Good overall connectivity
- Not adjacent to sender or recipient regions

### Layer 3: Destination Region

**Characteristics**:
- Recipient's local mesh
- Final delivery zone
- Similar to Layer 1 but for recipient

**Trust Model**:
- Nodes know recipient
- No knowledge of original sender
- Final hop anonymity preserved

## Region Grouping Algorithm

### Overview

Regions are NOT globally agreed upon. Each node maintains its own view of regional
boundaries based on local observations.

### Grouping Heuristics

```
FUNCTION determine_regions():
    # Start with directly reachable peers
    local_peers = get_direct_peers()
    
    # Group into sub-meshes by connectivity density
    submeshes = cluster_by_density(local_peers)
    
    # Group sub-meshes into regions by gateway connectivity
    regions = []
    FOR submesh IN submeshes:
        gateways = find_gateways(submesh)
        IF gateways connect to existing region:
            existing_region.add(submesh)
        ELSE:
            regions.append(new_region(submesh))
    
    RETURN regions
```

### Connectivity Density Calculation

```
density(submesh) = edges_within(submesh) / possible_edges(submesh)

IF density > DENSITY_THRESHOLD:
    # Keep as single sub-mesh
ELSE:
    # Consider splitting
```

### Gateway Detection

A node is a gateway if:
1. It has peers in multiple sub-meshes
2. Those sub-meshes have low direct connectivity
3. It can route between them

```
is_gateway(node) = 
    len(node.submeshes) > 1 AND
    cross_submesh_density(node.submeshes) < GATEWAY_THRESHOLD
```

## Onion Packet Construction

### Step 1: Region Selection

```
sender_region = my_region()
dest_region = lookup_region(recipient_node_id)
transit_region = select_transit_region(sender_region, dest_region)
```

Transit region selection criteria:
- Not sender_region
- Not dest_region
- Good connectivity to both
- High node count (better mixing)

### Step 2: Gateway Selection

For each layer, select gateway nodes:

```
layer1_gateway = select_gateway(sender_region, transit_region)
layer2_gateway = select_gateway(transit_region, dest_region)
# Layer 3 delivers directly, no gateway needed
```

### Step 3: Layer Construction (Inside-Out)

```
# Layer 3: Destination delivery
layer3_payload = encrypt_for_recipient(
    dest_node_id=recipient,
    message_id=msg_id,
    payload=user_message
)

# Layer 2: Transit → Destination
layer2_envelope = encrypt_for_gateway(
    gateway=layer2_gateway,
    next_region=dest_region.id,
    inner=layer3_payload
)

# Layer 1: Local → Transit  
layer1_envelope = encrypt_for_gateway(
    gateway=layer1_gateway,
    next_region=transit_region.id,
    inner=layer2_envelope
)

final_packet = layer1_envelope
```

## Packet Flow

### 1. Sender Injects Packet

```
Sender creates 3-layer onion
    │
    ▼
Forwards to local peers using normal mesh routing
Target: layer1_gateway
```

### 2. Layer 1 Gateway Processes

```
Packet arrives at layer1_gateway
    │
    ▼
Gateway peels Layer 1:
  - Decrypts envelope
  - Extracts next_region (transit)
  - Extracts inner envelope (Layer 2)
    │
    ▼
Forwards inner envelope toward transit region
Using normal mesh routing to any known transit gateway
```

### 3. Layer 2 Gateway Processes

```
Packet arrives at layer2_gateway (in transit region)
    │
    ▼
Gateway peels Layer 2:
  - Decrypts envelope
  - Extracts next_region (destination)
  - Extracts inner envelope (Layer 3)
    │
    ▼
Forwards inner envelope toward destination region
Using normal mesh routing
```

### 4. Destination Region Delivery

```
Packet arrives in destination region
    │
    ▼
Normal mesh routing to recipient node
    │
    ▼
Recipient decrypts Layer 3:
  - Extracts message_id
  - Extracts payload
  - Processes message
```

## Gateway Knowledge Boundaries

### What Layer 1 Gateway Knows
- Packet came from sender's region (but not which node)
- Packet is going to transit region
- Nothing about final destination

### What Layer 2 Gateway Knows
- Packet came from sender's region
- Packet is going to destination region
- Nothing about original sender node
- Nothing about final recipient node

### What Destination Node Knows
- Packet was delivered to them
- Message contents
- Nothing about original sender
- Nothing about routing path

## Anonymity Analysis

### Single Honest Gateway

Even if one gateway is compromised:
- Layer 1 compromise: Transit and destination unknown
- Layer 2 compromise: Sender and recipient unknown
- Both L1 and L2 compromise: Can correlate regions but not nodes

### Traffic Analysis Resistance

Region-based routing provides mixing:
- Multiple senders → same L1 gateway → indistinguishable
- Multiple packets → same transit region → mixed
- Multiple exits → same destination region → unlinkable

### Timing Analysis

**Vulnerable to**: Global passive adversary timing correlation

**Mitigation** (future work):
- Packet delay randomization
- Dummy traffic injection
- Batch processing at gateways

## Failure Handling

### Gateway Unreachable

```
IF gateway unreachable:
    # Try alternate gateway to same region
    alt_gateway = select_alternate_gateway(target_region)
    IF alt_gateway exists:
        reroute_packet(packet, alt_gateway)
    ELSE:
        # Region unreachable
        queue_for_retry(packet)
        notify_sender(DELIVERY_DELAYED)
```

### Region Partitioned

```
IF region partitioned:
    # Wait for reconnection
    queue_for_retry(packet)
    # Notify after timeout
    IF timeout exceeded:
        notify_sender(DELIVERY_FAILED)
```

### Path Loop Detection

```
IF packet.seen_regions contains current_region:
    drop_packet(packet)
    log_warning("loop detected")
```

## Configuration Parameters

```toml
[onion]
# Minimum nodes to consider a region
min_region_size = 3

# Connectivity threshold for sub-mesh detection
density_threshold = 0.6

# Gateway detection threshold
gateway_threshold = 0.3

# Maximum time to cache region topology (seconds)
region_cache_ttl = 300

# Retry attempts for gateway failure
gateway_retry_attempts = 3

# Backoff multiplier for retries
gateway_retry_backoff = 2.0
```

## Protocol Evolution

### Current: Version 1

- Fixed 3-layer depth
- Region-based routing
- Single transit region

### Future Considerations

- Multi-path routing (multiple transit regions)
- Cover traffic generation
- Region reputation tracking
- Dynamic layer depth (with tradeoff awareness)
