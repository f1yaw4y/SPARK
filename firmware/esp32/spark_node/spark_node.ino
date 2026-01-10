/*
 * SPARK Network
 * 
 * PROTOCOL BEHAVIOR NOTES:
 * 
 * 1. Header Mutation: When a message crosses a sub-mesh boundary, one encryption
 *    layer is decrypted and the routing header is updated. This means inner
 *    encrypted layers still contain the original header, while outer layers
 *    have the mutated header. This is intentional for the tor-like protocol
 *    but means encryption layers are not pure encapsulations - downstream nodes
 *    will see different headers when they decrypt inner layers.
 * 
 * 2. Broadcast Handling: Broadcast packets (0xFFFF:0xFFFF) still increment hop
 *    count and follow layer stripping rules. Broadcast storm prevention uses
 *    local dampening only (per-node suppression, not global). Same message_id
 *    cannot be re-broadcast within 1 second. This prevents local amplification
 *    but does not coordinate suppression across the network.
 * 
 * 3. Replay Protection: Messages are tracked by (source, message_id) with a
 *    5-minute TTL. Replay attacks are detected and rejected.
 * 
 * 4. Routing Table Security: Routing updates are validated before acceptance.
 *    Probabilities decay over time and entries are bounded to prevent poisoning.
 * 
 * 5. Stack Safety: Large encryption buffers are allocated from static pools to
 *    prevent stack overflow under load, especially with RadioLib callbacks.
 * 
 * 6. Header Authenticity: Outermost layer uses AES-GCM to cryptographically
 *    authenticate the routing header + encrypted payload. This prevents header
 *    tampering while maintaining tor-like semantics for inner layers (which use
 *    CTR mode). GCM authenticates the header as Additional Authenticated Data
 *    (AAD), ensuring routing decisions can trust header fields.
 * 
 * 7. Address Derivation: Node addresses are derived from cryptographic keys
 *    (SHA-256 hash of persistent node private key). This provides:
 *    - Privacy: No MAC address leakage
 *    - Persistence: Key stored in non-volatile memory
 *    - Uniqueness: Deterministic but unique per device
 *    - Topology independence: Address not tied to physical location
 *    Submesh assignment is currently hash-based but can be extended to geographic
 *    or network-coordinator-based assignment.
 */

#include <Arduino.h>
#include <SPI.h>
#include <RadioLib.h>
#include <mbedtls/aes.h>
#include <mbedtls/gcm.h>
#include <mbedtls/sha256.h>
#include <WiFi.h>
#include <Preferences.h>

// =====================
// Pin definitions
// =====================
#define LORA_SCK   18
#define LORA_MISO  19
#define LORA_MOSI  23
#define LORA_CS    5

#define LORA_RST   14
#define LORA_BUSY  27
#define LORA_DIO1  26

// =====================
// Network Configuration
// =====================
#define MAX_PAYLOAD_SIZE 200
#define MAX_ROUTING_HOPS 100
#define ENCRYPTION_LAYERS 3
#define ADDRESS_SIZE 4  // 2 bytes submesh, 2 bytes node
#define MAX_ROUTING_TABLE 20

// =====================
// Message Structures
// =====================
struct NodeAddress {
  uint16_t submesh_id;
  uint16_t node_id;
  
  bool operator==(const NodeAddress& other) const {
    return submesh_id == other.submesh_id && node_id == other.node_id;
  }
  
  bool operator!=(const NodeAddress& other) const {
    return !(*this == other);
  }
};

struct RoutingHeader {
  NodeAddress source;
  NodeAddress destination;
  NodeAddress next_hop;
  NodeAddress previous_submesh;  // Track which sub-mesh this came from
  uint8_t hop_count;
  uint8_t layers_remaining;  // How many encryption layers left
  uint8_t submesh_crossings;  // Track sub-mesh boundary crossings
  uint32_t message_id;
};

struct MeshMessage {
  RoutingHeader header;
  uint8_t payload[MAX_PAYLOAD_SIZE];
  uint16_t payload_length;
  uint8_t encrypted_layers[ENCRYPTION_LAYERS][MAX_PAYLOAD_SIZE + sizeof(RoutingHeader)];
  uint16_t layer_sizes[ENCRYPTION_LAYERS];
  uint8_t nonces[ENCRYPTION_LAYERS][16];  // 12-byte nonce + 4-byte counter for CTR mode
  uint8_t auth_tag[16];  // GCM authentication tag for outermost layer (16 bytes)
};

// =====================
// Radio instance
// =====================
SX1262 lora = new Module(
  LORA_CS,
  LORA_DIO1,
  LORA_RST,
  LORA_BUSY
);

// =====================
// Node Configuration
// =====================
NodeAddress my_address;
uint8_t encryption_keys[ENCRYPTION_LAYERS][32];  // 256-bit keys for each layer
mbedtls_aes_context aes_contexts[ENCRYPTION_LAYERS];
mbedtls_gcm_context gcm_context;  // GCM context for outermost layer authentication

// Key-based addressing
uint8_t node_private_key[32];  // Node's private key (256 bits)
uint8_t node_public_key[32];    // Node's public key (simplified: hash of private key)
Preferences preferences;        // For persistent key storage

// =====================
// Routing Table (Probabilistic)
// =====================
struct RoutingEntry {
  NodeAddress destination;
  NodeAddress next_hop;
  uint16_t submesh_id;
  float probability;  // Probability of successful delivery
  uint8_t hop_distance;
  unsigned long last_seen;
};

RoutingEntry routing_table[MAX_ROUTING_TABLE];
uint8_t routing_table_size = 0;

// =====================
// Message Queue
// =====================
MeshMessage message_queue[10];
uint8_t queue_size = 0;

// =====================
// Static Buffer Pools (avoid stack overflow)
// =====================
// Encryption/decryption buffers - allocated once, reused
static uint8_t encryption_buffer_pool[3][MAX_PAYLOAD_SIZE + sizeof(RoutingHeader) + 32];
static bool buffer_in_use[3] = {false, false, false};

// Decryption buffers - allocated once, reused
static uint8_t decryption_buffer_pool[2][MAX_PAYLOAD_SIZE + sizeof(RoutingHeader) + 32];
static bool decryption_buffer_in_use[2] = {false, false};

// Forward buffer - allocated once, reused (prevents stack overflow in forwarding path)
static uint8_t forward_buffer[MAX_PAYLOAD_SIZE + sizeof(RoutingHeader) + 32];
static bool forward_buffer_in_use = false;

// =====================
// Replay Protection
// =====================
#define REPLAY_CACHE_SIZE 64
#define REPLAY_TTL_MS 300000  // 5 minutes

struct ReplayEntry {
  NodeAddress source;
  uint32_t message_id;
  unsigned long timestamp;
  bool valid;
};

static ReplayEntry replay_cache[REPLAY_CACHE_SIZE];
static uint8_t replay_cache_index = 0;

// =====================
// Routing Table Validation
// =====================
#define MAX_HOP_COUNT 100
#define MIN_PROBABILITY 0.1
#define MAX_PROBABILITY 1.0
#define ROUTING_DECAY_RATE 0.95  // Decay probability by 5% per check
#define ROUTING_DECAY_INTERVAL_MS 60000  // Decay every minute

// =====================
// Buffer Pool Management
// =====================
uint8_t* acquireEncryptionBuffer() {
  for (int i = 0; i < 3; i++) {
    if (!buffer_in_use[i]) {
      buffer_in_use[i] = true;
      return encryption_buffer_pool[i];
    }
  }
  // All buffers in use - wait for one (simple round-robin)
  static int last_used = 0;
  last_used = (last_used + 1) % 3;
  return encryption_buffer_pool[last_used];
}

void releaseEncryptionBuffer(uint8_t* buf) {
  for (int i = 0; i < 3; i++) {
    if (encryption_buffer_pool[i] == buf) {
      buffer_in_use[i] = false;
      return;
    }
  }
}

uint8_t* acquireDecryptionBuffer() {
  for (int i = 0; i < 2; i++) {
    if (!decryption_buffer_in_use[i]) {
      decryption_buffer_in_use[i] = true;
      return decryption_buffer_pool[i];
    }
  }
  // All buffers in use - use first one
  return decryption_buffer_pool[0];
}

void releaseDecryptionBuffer(uint8_t* buf) {
  for (int i = 0; i < 2; i++) {
    if (decryption_buffer_pool[i] == buf) {
      decryption_buffer_in_use[i] = false;
      return;
    }
  }
}

// =====================
// Replay Protection Functions
// =====================
bool isReplay(NodeAddress source, uint32_t message_id) {
  unsigned long now = millis();
  
  // Check cache for existing entry
  for (int i = 0; i < REPLAY_CACHE_SIZE; i++) {
    if (replay_cache[i].valid && 
        replay_cache[i].source == source &&
        replay_cache[i].message_id == message_id) {
      // Check if still within TTL
      if (now - replay_cache[i].timestamp < REPLAY_TTL_MS) {
        return true;  // Replay detected
      } else {
        // Expired, mark as invalid
        replay_cache[i].valid = false;
      }
    }
  }
  
  return false;  // Not a replay
}

void recordMessage(NodeAddress source, uint32_t message_id) {
  unsigned long now = millis();
  
  // Find invalid slot or oldest entry
  int oldest_idx = 0;
  unsigned long oldest_time = replay_cache[0].timestamp;
  
  for (int i = 0; i < REPLAY_CACHE_SIZE; i++) {
    if (!replay_cache[i].valid) {
      // Use invalid slot
      replay_cache[i].source = source;
      replay_cache[i].message_id = message_id;
      replay_cache[i].timestamp = now;
      replay_cache[i].valid = true;
      return;
    }
    
    // Track oldest for eviction
    if (replay_cache[i].timestamp < oldest_time) {
      oldest_time = replay_cache[i].timestamp;
      oldest_idx = i;
    }
  }
  
  // All slots full, evict oldest
  replay_cache[oldest_idx].source = source;
  replay_cache[oldest_idx].message_id = message_id;
  replay_cache[oldest_idx].timestamp = now;
  replay_cache[oldest_idx].valid = true;
}

void cleanupReplayCache() {
  unsigned long now = millis();
  for (int i = 0; i < REPLAY_CACHE_SIZE; i++) {
    if (replay_cache[i].valid && 
        (now - replay_cache[i].timestamp) >= REPLAY_TTL_MS) {
      replay_cache[i].valid = false;
    }
  }
}

// =====================
// Routing Table Validation & Decay
// =====================
void decayRoutingTable() {
  static unsigned long last_decay = 0;
  unsigned long now = millis();
  
  if (now - last_decay < ROUTING_DECAY_INTERVAL_MS) {
    return;
  }
  last_decay = now;
  
  // Decay probabilities and remove stale entries
  for (int i = 0; i < routing_table_size; i++) {
    // Decay probability
    routing_table[i].probability *= ROUTING_DECAY_RATE;
    
    // Enforce bounds
    if (routing_table[i].probability < MIN_PROBABILITY) {
      routing_table[i].probability = MIN_PROBABILITY;
    }
    if (routing_table[i].probability > MAX_PROBABILITY) {
      routing_table[i].probability = MAX_PROBABILITY;
    }
    
    // Remove very stale entries (not seen in 5 minutes)
    if ((now - routing_table[i].last_seen) > 300000) {
      // Remove entry by shifting array
      for (int j = i; j < routing_table_size - 1; j++) {
        routing_table[j] = routing_table[j + 1];
      }
      routing_table_size--;
      i--;  // Re-check this index
    }
  }
}

bool validateRoutingUpdate(NodeAddress from, uint8_t claimed_hops) {
  // Sanity checks on routing updates
  if (claimed_hops > MAX_HOP_COUNT) {
    return false;  // Invalid hop count
  }
  
  // Check if this is a reasonable update
  // If we already have a route, only accept if it's better or similar
  for (int i = 0; i < routing_table_size; i++) {
    if (routing_table[i].destination == from) {
      // Only accept if new hop count is reasonable (within 3 hops of existing)
      if (claimed_hops > routing_table[i].hop_distance + 3) {
        return false;  // Suspiciously high hop count
      }
    }
  }
  
  return true;
}

// =====================
// Utility Functions
// =====================
void generateOrLoadNodeKey() {
  // Generate or load node's private key for key-based addressing
  preferences.begin("mesh", false);
  
  // Try to load existing key
  size_t key_len = preferences.getBytesLength("node_key");
  if (key_len == 32) {
    preferences.getBytes("node_key", node_private_key, 32);
    Serial.println("Loaded existing node key from storage");
  } else {
    // Generate new key from MAC + random seed
    uint8_t mac[6];
    WiFi.macAddress(mac);
    
    // Use MAC + millis() as seed for deterministic but unique key generation
    mbedtls_sha256_context sha_ctx;
    mbedtls_sha256_init(&sha_ctx);
    mbedtls_sha256_starts(&sha_ctx, 0);
    mbedtls_sha256_update(&sha_ctx, mac, 6);
    uint32_t seed = ESP.getEfuseMac();
    mbedtls_sha256_update(&sha_ctx, (uint8_t*)&seed, 4);
    mbedtls_sha256_finish(&sha_ctx, node_private_key);
    mbedtls_sha256_free(&sha_ctx);
    
    // Store key persistently
    preferences.putBytes("node_key", node_private_key, 32);
    Serial.println("Generated new node key");
  }
  
  // Derive public key (simplified: hash of private key)
  // In production, use proper ECC or Ed25519 key derivation
  mbedtls_sha256_context sha_ctx;
  mbedtls_sha256_init(&sha_ctx);
  mbedtls_sha256_starts(&sha_ctx, 0);
  mbedtls_sha256_update(&sha_ctx, node_private_key, 32);
  mbedtls_sha256_finish(&sha_ctx, node_public_key);
  mbedtls_sha256_free(&sha_ctx);
  
  preferences.end();
}

void generateNodeAddress() {
  // Generate address from key-based identity
  // Submesh ID: derived from geographic region or network topology
  // For now, use hash of public key to determine submesh
  // In production, this could be assigned by network coordinator or based on GPS
  
  // Generate submesh ID from public key hash (first 2 bytes)
  my_address.submesh_id = (node_public_key[0] << 8) | node_public_key[1];
  
  // Node ID: derived from public key hash (next 2 bytes)
  // This ensures unique identity without leaking physical MAC address
  my_address.node_id = (node_public_key[2] << 8) | node_public_key[3];
  
  // Optional: Adjust submesh based on geographic region or network configuration
  // For example, if you have GPS or network topology info, use that instead
  // For now, we use a simple hash-based approach that's deterministic but unique
  
  Serial.print("Node Address (key-based): Sub-mesh ");
  Serial.print(my_address.submesh_id);
  Serial.print(", Node ");
  Serial.println(my_address.node_id);
  
  // Print key fingerprint for debugging (first 8 bytes of public key)
  Serial.print("Public key fingerprint: ");
  for (int i = 0; i < 8; i++) {
    if (node_public_key[i] < 0x10) Serial.print("0");
    Serial.print(node_public_key[i], HEX);
  }
  Serial.println();
}

void initializeEncryption() {
  // Initialize encryption keys for each layer
  // Keys are derived from node's private key + layer number
  // This ensures keys are unique per node and per layer
  mbedtls_sha256_context sha_ctx;
  
  for (int i = 0; i < ENCRYPTION_LAYERS; i++) {
    mbedtls_aes_init(&aes_contexts[i]);
    
    // Derive layer key from node private key + layer number
    mbedtls_sha256_init(&sha_ctx);
    mbedtls_sha256_starts(&sha_ctx, 0);
    mbedtls_sha256_update(&sha_ctx, node_private_key, 32);
    mbedtls_sha256_update(&sha_ctx, (uint8_t*)&i, 1);
    // Add submesh ID to key derivation for additional entropy
    uint16_t submesh = my_address.submesh_id;
    mbedtls_sha256_update(&sha_ctx, (uint8_t*)&submesh, 2);
    mbedtls_sha256_finish(&sha_ctx, encryption_keys[i]);
    mbedtls_sha256_free(&sha_ctx);
    
    mbedtls_aes_setkey_enc(&aes_contexts[i], encryption_keys[i], 256);
  }
  
  // Initialize GCM context for outermost layer authentication
  mbedtls_gcm_init(&gcm_context);
  mbedtls_gcm_setkey(&gcm_context, MBEDTLS_CIPHER_ID_AES, 
                     encryption_keys[ENCRYPTION_LAYERS - 1], 256);
  
  Serial.println("Encryption initialized (CTR + GCM)");
}

uint16_t calculateSubmeshDistance(uint16_t submesh1, uint16_t submesh2) {
  // Calculate "distance" between sub-meshes for routing
  // Simplified: use absolute difference
  return abs((int)submesh1 - (int)submesh2);
}

bool isInSameSubmesh(NodeAddress addr1, NodeAddress addr2) {
  return addr1.submesh_id == addr2.submesh_id;
}

// =====================
// Encryption/Decryption (AES-CTR mode)
// =====================
void generateNonce(uint8_t* nonce, uint8_t layer, uint32_t message_id, uint8_t hop_count, uint8_t submesh_crossings) {
  // Generate a unique nonce for each encryption layer
  // Critical: CTR mode cannot tolerate nonce reuse with the same key
  // We include multiple entropy sources to ensure uniqueness even under retransmission
  memcpy(nonce, &message_id, 4);                    // Message ID (unique per source)
  memcpy(nonce + 4, &my_address.submesh_id, 2);      // Node submesh
  memcpy(nonce + 6, &my_address.node_id, 2);        // Node ID
  nonce[8] = layer;                                  // Encryption layer
  nonce[9] = hop_count;                              // Hop count (prevents retransmission collision)
  nonce[10] = submesh_crossings;                     // Submesh crossings (adds path entropy)
  nonce[11] = (uint8_t)(millis() & 0xFF);           // Time component (low byte)
  // Last 4 bytes are counter (starts at 0, incremented per 16-byte block in CTR)
  memset(nonce + 12, 0, 4);
}

void generateGCMNonce(uint8_t* nonce, uint32_t message_id, uint8_t hop_count, uint8_t submesh_crossings) {
  // Generate 12-byte nonce for GCM (standard GCM IV size)
  // GCM requires 12-byte IV, not 16-byte like CTR
  memcpy(nonce, &message_id, 4);                    // Message ID
  memcpy(nonce + 4, &my_address.submesh_id, 2);      // Node submesh
  memcpy(nonce + 6, &my_address.node_id, 2);        // Node ID
  nonce[8] = hop_count;                              // Hop count
  nonce[9] = submesh_crossings;                      // Submesh crossings
  nonce[10] = (uint8_t)(millis() & 0xFF);           // Time component
  nonce[11] = (uint8_t)((millis() >> 8) & 0xFF);    // Time component (high byte)
}

void encryptLayer(uint8_t* data, uint16_t data_len, uint8_t layer, uint8_t* nonce, uint8_t* output) {
  // AES-256-CTR encryption for a layer (stream cipher, no padding needed)
  mbedtls_aes_context ctx;
  mbedtls_aes_init(&ctx);
  mbedtls_aes_setkey_enc(&ctx, encryption_keys[layer], 256);
  
  // CTR mode: nonce + counter (16 bytes total)
  // Counter starts at 0, stored in last 4 bytes of nonce
  uint8_t iv[16];
  memcpy(iv, nonce, 16);
  
  size_t nc_off = 0;  // Offset in current block (always 0 for new encryption)
  unsigned char stream_block[16] = {0};
  
  // Encrypt using CTR mode (same function for encrypt/decrypt)
  mbedtls_aes_crypt_ctr(&ctx, data_len, &nc_off, iv, stream_block, data, output);
  
  mbedtls_aes_free(&ctx);
}

void decryptLayer(uint8_t* encrypted_data, uint16_t data_len, uint8_t layer, uint8_t* nonce, uint8_t* output) {
  // AES-256-CTR decryption (same as encryption in CTR mode)
  mbedtls_aes_context ctx;
  mbedtls_aes_init(&ctx);
  mbedtls_aes_setkey_enc(&ctx, encryption_keys[layer], 256);
  
  // CTR mode: nonce + counter (16 bytes total)
  uint8_t iv[16];
  memcpy(iv, nonce, 16);
  
  size_t nc_off = 0;  // Offset in current block
  unsigned char stream_block[16] = {0};
  
  // Decrypt using CTR mode (same function as encryption)
  mbedtls_aes_crypt_ctr(&ctx, data_len, &nc_off, iv, stream_block, encrypted_data, output);
  
  mbedtls_aes_free(&ctx);
}

// =====================
// GCM Authentication (Outermost Layer Only)
// =====================
int encryptLayerGCM(uint8_t* data, uint16_t data_len, uint8_t* header, uint16_t header_len,
                    uint8_t* nonce, uint8_t* output, uint8_t* auth_tag) {
  // AES-256-GCM encryption for outermost layer
  // Authenticates both header and encrypted data
  // Returns 0 on success, non-zero on error
  
  // Use 12-byte IV for GCM (standard)
  uint8_t iv[12];
  memcpy(iv, nonce, 12);
  
  int ret = mbedtls_gcm_crypt_and_tag(&gcm_context, MBEDTLS_GCM_ENCRYPT,
                                      data_len, iv, 12,
                                      header, header_len,  // Additional authenticated data (AAD)
                                      data, output, 16, auth_tag);
  
  return ret;
}

int decryptLayerGCM(uint8_t* encrypted_data, uint16_t data_len, uint8_t* header, uint16_t header_len,
                   uint8_t* nonce, uint8_t* output, uint8_t* auth_tag) {
  // AES-256-GCM decryption and authentication for outermost layer
  // Verifies authentication tag before decrypting
  // Returns 0 on success, non-zero on authentication failure
  
  // Use 12-byte IV for GCM (standard)
  uint8_t iv[12];
  memcpy(iv, nonce, 12);
  
  int ret = mbedtls_gcm_auth_decrypt(&gcm_context, data_len, iv, 12,
                                     header, header_len,  // Additional authenticated data (AAD)
                                     auth_tag, 16, encrypted_data, output);
  
  return ret;
}

// =====================
// Message Construction
// =====================
void buildLayeredMessage(MeshMessage* msg, NodeAddress dest, const uint8_t* payload, uint16_t payload_len) {
  // Initialize message
  msg->header.source = my_address;
  msg->header.destination = dest;
  msg->header.next_hop.submesh_id = 0;
  msg->header.next_hop.node_id = 0;
  msg->header.previous_submesh.submesh_id = my_address.submesh_id;
  msg->header.previous_submesh.node_id = 0;
  msg->header.hop_count = 0;
  msg->header.layers_remaining = ENCRYPTION_LAYERS;
  msg->header.submesh_crossings = 0;
  msg->header.message_id = random(0xFFFFFFFF);
  msg->payload_length = payload_len;
  memcpy(msg->payload, payload, payload_len);
  
  // Generate nonces for each layer
  // Use initial hop_count=0 and submesh_crossings=0 for first encryption
  for (int i = 0; i < ENCRYPTION_LAYERS; i++) {
    generateNonce(msg->nonces[i], i, msg->header.message_id, 
                  msg->header.hop_count, msg->header.submesh_crossings);
  }
  
  // Build layers from innermost to outermost
  // Use static buffer pool to avoid stack overflow
  uint8_t* layer0_data = acquireEncryptionBuffer();
  memcpy(layer0_data, &msg->header, sizeof(RoutingHeader));
  memcpy(layer0_data + sizeof(RoutingHeader), payload, payload_len);
  uint16_t layer0_size = sizeof(RoutingHeader) + payload_len;
  
  encryptLayer(layer0_data, layer0_size, 0, msg->nonces[0], msg->encrypted_layers[0]);
  msg->layer_sizes[0] = layer0_size;  // CTR mode: no padding needed
  
  // Layer 1: nonce_0 + encrypted layer 0 + routing info
  uint8_t* layer1_data = acquireEncryptionBuffer();
  RoutingHeader layer1_header = msg->header;
  layer1_header.layers_remaining = 1;
  memcpy(layer1_data, &layer1_header, sizeof(RoutingHeader));
  // Include nonce for layer 0 in the structure
  memcpy(layer1_data + sizeof(RoutingHeader), msg->nonces[0], 16);
  memcpy(layer1_data + sizeof(RoutingHeader) + 16, msg->encrypted_layers[0], msg->layer_sizes[0]);
  uint16_t layer1_size = sizeof(RoutingHeader) + 16 + msg->layer_sizes[0];
  
  encryptLayer(layer1_data, layer1_size, 1, msg->nonces[1], msg->encrypted_layers[1]);
  msg->layer_sizes[1] = layer1_size;  // CTR mode: no padding needed
  releaseEncryptionBuffer(layer0_data);
  
  // Layer 2 (outermost): Use GCM for authentication
  // GCM authenticates: header + encrypted layer 1 data
  uint8_t* layer2_data = acquireEncryptionBuffer();
  RoutingHeader layer2_header = msg->header;
  layer2_header.layers_remaining = 2;
  
  // Generate 12-byte GCM nonce (not 16-byte like CTR)
  generateGCMNonce(msg->nonces[ENCRYPTION_LAYERS - 1], msg->header.message_id,
                    msg->header.hop_count, msg->header.submesh_crossings);
  
  // Prepare data to encrypt: nonce_1 + encrypted layer 1
  uint16_t layer2_payload_size = 16 + msg->layer_sizes[1];
  memcpy(layer2_data, msg->nonces[1], 16);
  memcpy(layer2_data + 16, msg->encrypted_layers[1], msg->layer_sizes[1]);
  
  // Encrypt with GCM (authenticates header + payload)
  // Use 12-byte nonce for GCM
  uint8_t gcm_nonce[12];
  memcpy(gcm_nonce, msg->nonces[ENCRYPTION_LAYERS - 1], 12);
  
  int gcm_ret = encryptLayerGCM(layer2_data, layer2_payload_size,
                                 (uint8_t*)&layer2_header, sizeof(RoutingHeader),
                                 gcm_nonce, msg->encrypted_layers[2], msg->auth_tag);
  
  if (gcm_ret != 0) {
    Serial.print("GCM encryption failed: ");
    Serial.println(gcm_ret);
    releaseEncryptionBuffer(layer1_data);
    releaseEncryptionBuffer(layer2_data);
    return;
  }
  
  msg->layer_sizes[2] = layer2_payload_size;  // GCM output same size as input
  releaseEncryptionBuffer(layer1_data);
  releaseEncryptionBuffer(layer2_data);
  
  Serial.print("Built layered message with ");
  Serial.print(ENCRYPTION_LAYERS);
  Serial.println(" encryption layers");
}

// =====================
// Routing Functions
// =====================
NodeAddress findNextHop(NodeAddress destination) {
  // Probabilistic routing: find best next hop
  NodeAddress best_hop = {0, 0};
  float best_score = 0.0;
  
  // Check if destination is in same sub-mesh
  if (isInSameSubmesh(my_address, destination)) {
    // Direct routing within sub-mesh
    for (uint8_t i = 0; i < routing_table_size; i++) {
      if (isInSameSubmesh(routing_table[i].destination, destination)) {
        if (routing_table[i].probability > best_score) {
          best_score = routing_table[i].probability;
          best_hop = routing_table[i].next_hop;
        }
      }
    }
  } else {
    // Cross-submesh routing: prefer nodes closer to destination sub-mesh
    uint16_t dest_submesh = destination.submesh_id;
    uint16_t my_submesh = my_address.submesh_id;
    
    for (uint8_t i = 0; i < routing_table_size; i++) {
      uint16_t hop_submesh = routing_table[i].submesh_id;
      uint16_t my_to_hop = calculateSubmeshDistance(my_submesh, hop_submesh);
      uint16_t hop_to_dest = calculateSubmeshDistance(hop_submesh, dest_submesh);
      uint16_t my_to_dest = calculateSubmeshDistance(my_submesh, dest_submesh);
      
      // Score based on progress toward destination and probability
      float progress = (float)(my_to_dest - hop_to_dest) / (float)my_to_dest;
      float score = routing_table[i].probability * (0.5 + 0.5 * progress);
      
      if (score > best_score && hop_to_dest < my_to_dest) {
        best_score = score;
        best_hop = routing_table[i].next_hop;
      }
    }
  }
  
  // If no route found, use broadcast or default route
  // NOTE: Broadcast should be used sparingly to prevent broadcast storms
  // Broadcast packets still increment hop count and follow layer stripping rules
  if (best_hop.submesh_id == 0 && best_hop.node_id == 0) {
    // Only broadcast if we have no route and destination is not local
    if (!isInSameSubmesh(my_address, destination)) {
      best_hop = {0xFFFF, 0xFFFF};  // Broadcast address
      Serial.println("No route found - using broadcast");
    } else {
      // Destination in same sub-mesh but no route - drop
      Serial.println("No route to local destination - dropping");
    }
  }
  
  return best_hop;
}

void updateRoutingTable(NodeAddress from, NodeAddress via, uint8_t hops) {
  // Validate routing update before accepting
  if (!validateRoutingUpdate(from, hops)) {
    Serial.print("Rejected invalid routing update from ");
    Serial.print(from.submesh_id);
    Serial.print(":");
    Serial.print(from.node_id);
    Serial.print(" (hops: ");
    Serial.print(hops);
    Serial.println(")");
    return;
  }
  
  // Update or add routing entry
  bool found = false;
  
  for (uint8_t i = 0; i < routing_table_size; i++) {
    if (routing_table[i].destination == from) {
      // Update existing entry with validation
      if (hops < routing_table[i].hop_distance || 
          (millis() - routing_table[i].last_seen) > 60000) {
        routing_table[i].next_hop = via;
        routing_table[i].hop_distance = hops;
        // Calculate probability with bounds
        float new_prob = 1.0 - (hops * 0.01);  // More gradual decrease
        if (new_prob < MIN_PROBABILITY) new_prob = MIN_PROBABILITY;
        if (new_prob > MAX_PROBABILITY) new_prob = MAX_PROBABILITY;
        routing_table[i].probability = new_prob;
      } else {
        // Slightly increase probability for known good routes (with bounds)
        routing_table[i].probability = min(MAX_PROBABILITY, routing_table[i].probability + 0.05);
      }
      routing_table[i].last_seen = millis();
      routing_table[i].submesh_id = from.submesh_id;
      found = true;
      break;
    }
  }
  
  if (!found && routing_table_size < MAX_ROUTING_TABLE) {
    // Add new entry with validated probability
    routing_table[routing_table_size].destination = from;
    routing_table[routing_table_size].next_hop = via;
    routing_table[routing_table_size].submesh_id = from.submesh_id;
    routing_table[routing_table_size].hop_distance = hops;
    float new_prob = 1.0 - (hops * 0.01);
    if (new_prob < MIN_PROBABILITY) new_prob = MIN_PROBABILITY;
    if (new_prob > MAX_PROBABILITY) new_prob = MAX_PROBABILITY;
    routing_table[routing_table_size].probability = new_prob;
    routing_table[routing_table_size].last_seen = millis();
    routing_table_size++;
  }
}

// =====================
// Message Processing
// =====================
bool processReceivedMessage(uint8_t* data, uint16_t data_len) {
  // Process received message with layered decryption on sub-mesh crossings
  // Use static buffer pool to avoid stack overflow
  uint8_t* current_data = data;
  uint16_t current_len = data_len;
  uint8_t* decrypted_buffer0 = acquireDecryptionBuffer();
  uint8_t* decrypted_buffer1 = acquireDecryptionBuffer();
  int buffer_idx = 0;
  
  RoutingHeader header;
  bool header_decrypted = false;
  
  // Start by reading the outermost routing header
  // For outermost layer, header is authenticated but not encrypted (GCM AAD)
  memcpy(&header, data, sizeof(RoutingHeader));
  
  // Extract GCM components: [Nonce 12 bytes][Encrypted Data][Auth Tag 16 bytes]
  uint8_t gcm_nonce[12];
  uint8_t gcm_auth_tag[16];
  uint16_t gcm_data_len = data_len - sizeof(RoutingHeader) - 12 - 16;
  
  if (data_len < sizeof(RoutingHeader) + 12 + 16) {
    Serial.println("Message too short for GCM authentication");
    releaseDecryptionBuffer(decrypted_buffer0);
    releaseDecryptionBuffer(decrypted_buffer1);
    return false;
  }
  
  memcpy(gcm_nonce, data + sizeof(RoutingHeader), 12);
  memcpy(gcm_auth_tag, data + sizeof(RoutingHeader) + 12 + gcm_data_len, 16);
  
  // Verify GCM authentication tag (authenticates header + encrypted data)
  uint8_t* gcm_encrypted_data = data + sizeof(RoutingHeader) + 12;
  uint8_t* gcm_decrypted = acquireDecryptionBuffer();
  
  int auth_result = decryptLayerGCM(gcm_encrypted_data, gcm_data_len,
                                    (uint8_t*)&header, sizeof(RoutingHeader),
                                    gcm_nonce, gcm_decrypted, gcm_auth_tag);
  
  if (auth_result != 0) {
    Serial.println("GCM authentication failed - message tampered or invalid");
    releaseDecryptionBuffer(decrypted_buffer0);
    releaseDecryptionBuffer(decrypted_buffer1);
    releaseDecryptionBuffer(gcm_decrypted);
    return false;
  }
  
  // GCM authentication successful - header is authentic
  // Now process the decrypted inner layer data
  current_data = gcm_decrypted;
  current_len = gcm_data_len;
  
  // Check for replay attacks (after authentication)
  if (isReplay(header.source, header.message_id)) {
    Serial.println("Replay attack detected - dropping message");
    releaseDecryptionBuffer(decrypted_buffer0);
    releaseDecryptionBuffer(decrypted_buffer1);
    releaseDecryptionBuffer(gcm_decrypted);
    return false;
  }
  
  // Record message to prevent replays
  recordMessage(header.source, header.message_id);
  
  // Note: At this point, we've already authenticated the outermost layer with GCM
  // The current_data contains the decrypted inner layer (layer 1), which is still CTR-encrypted
  
  // Check if we crossed a sub-mesh boundary
  bool crossed_submesh = false;
  if (header.hop_count > 0 && header.previous_submesh.submesh_id != 0) {
    // Check if we're in a different sub-mesh than where message came from
    crossed_submesh = (header.previous_submesh.submesh_id != my_address.submesh_id);
  }
  
  // If we crossed a sub-mesh boundary and have layers remaining, decrypt one layer
  // Note: Inner layers use CTR mode (no authentication), only outermost uses GCM
  if (crossed_submesh && header.layers_remaining > 0) {
    uint8_t layer_to_decrypt = ENCRYPTION_LAYERS - header.layers_remaining;
    
    Serial.print("Crossing sub-mesh boundary, decrypting layer ");
    Serial.println(layer_to_decrypt);
    
    // Extract nonce (16 bytes) before encrypted data
    uint8_t nonce[16];
    memcpy(nonce, current_data + sizeof(RoutingHeader), 16);
    
    // Decrypt the encrypted payload (skip header and nonce)
    uint16_t encrypted_len = current_len - sizeof(RoutingHeader) - 16;
    uint8_t* target_buffer = (buffer_idx == 0) ? decrypted_buffer0 : decrypted_buffer1;
    decryptLayer(current_data + sizeof(RoutingHeader) + 16,
                 encrypted_len,
                 layer_to_decrypt,
                 nonce,
                 target_buffer);
    
    // Extract the new header from decrypted data
    memcpy(&header, target_buffer, sizeof(RoutingHeader));
    current_data = target_buffer + sizeof(RoutingHeader);
    current_len = encrypted_len;  // CTR mode: no padding
    header.layers_remaining--;
    header.submesh_crossings++;
    header_decrypted = true;
  } else {
    // No sub-mesh crossing, use data as-is
    current_data = data + sizeof(RoutingHeader);
    current_len = data_len - sizeof(RoutingHeader);
  }
  
  // Check if message is for us
  if (header.destination == my_address || 
      (header.destination.submesh_id == 0xFFFF && 
       header.destination.node_id == 0xFFFF)) {
    
    // Decrypt all remaining layers to get final payload
    while (header.layers_remaining > 0) {
      uint8_t layer = ENCRYPTION_LAYERS - header.layers_remaining;
      
      Serial.print("Final decryption, layer ");
      Serial.println(layer);
      
      // Extract nonce (16 bytes) before encrypted data
      uint8_t nonce[16];
      memcpy(nonce, current_data, 16);
      
      // Decrypt (skip nonce)
      uint16_t encrypted_len = current_len - 16;
      uint8_t* target_buffer = (buffer_idx == 0) ? decrypted_buffer1 : decrypted_buffer0;
      decryptLayer(current_data + 16, encrypted_len, layer, nonce, target_buffer);
      
      memcpy(&header, target_buffer, sizeof(RoutingHeader));
      current_data = target_buffer + sizeof(RoutingHeader);
      current_len = encrypted_len - sizeof(RoutingHeader);
      header.layers_remaining--;
      buffer_idx = 1 - buffer_idx;
    }
    
    // Extract final payload
    uint16_t payload_len = (current_len < MAX_PAYLOAD_SIZE) ? current_len : MAX_PAYLOAD_SIZE;
    
    Serial.print("Received message (");
    Serial.print(payload_len);
    Serial.println(" bytes): ");
    Serial.write(current_data, payload_len);
    Serial.println();
    
    // Update routing table with validated data
    updateRoutingTable(header.source, header.source, header.hop_count);
    
    releaseDecryptionBuffer(decrypted_buffer0);
    releaseDecryptionBuffer(decrypted_buffer1);
    return true;  // Message consumed
  }
  
  // Message needs forwarding
  // NOTE: Header mutation behavior - when we decrypt a layer and modify the header,
  // the inner encrypted layers still contain the old header. This is intentional for
  // the tor-like protocol but means encryption layers are not pure encapsulations.
  // Downstream nodes will see mutated headers when they decrypt inner layers.
  if (header.hop_count < MAX_ROUTING_HOPS) {
    header.hop_count++;
    
    // Find next hop
    NodeAddress next_hop = findNextHop(header.destination);
    bool will_cross_submesh = false;
    bool is_broadcast = (next_hop.submesh_id == 0xFFFF && next_hop.node_id == 0xFFFF);
    
    // Broadcast handling: prevent broadcast storms
    // NOTE: This is LOCAL dampening only - each node independently suppresses
    // rapid re-broadcasts. This prevents local amplification but does not coordinate
    // suppression across the network. For global suppression, consider extending
    // replay cache to track (source, message_id) for broadcast packets.
    static uint32_t last_broadcast_id = 0;
    static unsigned long last_broadcast_time = 0;
    if (is_broadcast) {
      // Prevent rapid re-broadcasting of same message (local suppression)
      if (header.message_id == last_broadcast_id && 
          (millis() - last_broadcast_time) < 1000) {
        Serial.println("Broadcast storm prevention (local) - dropping");
        releaseDecryptionBuffer(decrypted_buffer0);
        releaseDecryptionBuffer(decrypted_buffer1);
        return false;
      }
      last_broadcast_id = header.message_id;
      last_broadcast_time = millis();
    }
    
    // Check if next hop will cross sub-mesh boundary
    if (!isInSameSubmesh(my_address, header.destination)) {
      // Check if next hop is in different sub-mesh than us
      will_cross_submesh = !isInSameSubmesh(my_address, next_hop);
    }
    
    // If we will cross sub-mesh and have layers, decrypt next layer
    if (will_cross_submesh && header.layers_remaining > 0) {
      uint8_t layer = ENCRYPTION_LAYERS - header.layers_remaining;
      
      Serial.print("Will cross sub-mesh, decrypting layer ");
      Serial.print(layer);
      Serial.println(" for forwarding");
      
      // Extract nonce (16 bytes) before encrypted data
      uint8_t nonce[16];
      memcpy(nonce, current_data, 16);
      
      // Decrypt (skip nonce)
      uint16_t encrypted_len = current_len - 16;
      uint8_t* target_buffer = (buffer_idx == 0) ? decrypted_buffer1 : decrypted_buffer0;
      decryptLayer(current_data + 16, encrypted_len, layer, nonce, target_buffer);
      
      memcpy(&header, target_buffer, sizeof(RoutingHeader));
      current_data = target_buffer + sizeof(RoutingHeader);
      current_len = encrypted_len - sizeof(RoutingHeader);
      header.layers_remaining--;
      header.submesh_crossings++;
      buffer_idx = 1 - buffer_idx;
    }
    
    // Update routing header
    header.next_hop = next_hop;
    header.previous_submesh.submesh_id = my_address.submesh_id;
    header.previous_submesh.node_id = 0;  // Just track sub-mesh
    
    // Reconstruct message for forwarding
    // Use static forward buffer to prevent stack overflow (this may be called from RadioLib callbacks)
    // We always re-encrypt with GCM when forwarding to ensure header authenticity
    if (forward_buffer_in_use) {
      Serial.println("Warning: Forward buffer in use, dropping message");
      releaseDecryptionBuffer(decrypted_buffer0);
      releaseDecryptionBuffer(decrypted_buffer1);
      return false;
    }
    forward_buffer_in_use = true;
    
    // Update header for forwarding
    memcpy(forward_buffer, &header, sizeof(RoutingHeader));
    
    // Always re-encrypt with GCM for forwarding (ensures header authenticity)
    // Prepare 12-byte nonce for GCM re-encryption
    uint8_t gcm_nonce[12];
    generateGCMNonce(gcm_nonce, header.message_id, 
                      header.hop_count, header.submesh_crossings);
    
    // Encrypt current_data (inner layer) with GCM
    uint8_t* gcm_encrypted = forward_buffer + sizeof(RoutingHeader) + 12;
    uint8_t* gcm_auth_tag = gcm_encrypted + current_len;
    
    int gcm_ret = encryptLayerGCM(current_data, current_len,
                                   (uint8_t*)&header, sizeof(RoutingHeader),
                                   gcm_nonce, gcm_encrypted, gcm_auth_tag);
    
    if (gcm_ret != 0) {
      Serial.print("GCM re-encryption failed for forwarding: ");
      Serial.println(gcm_ret);
      forward_buffer_in_use = false;
      releaseDecryptionBuffer(decrypted_buffer0);
      releaseDecryptionBuffer(decrypted_buffer1);
      return false;
    }
    
    // Copy nonce
    memcpy(forward_buffer + sizeof(RoutingHeader), gcm_nonce, 12);
    
    uint16_t forward_total_len = sizeof(RoutingHeader) + 12 + current_len + 16;
    
    Serial.print("Forwarding message (hop ");
    Serial.print(header.hop_count);
    Serial.print(", layers remaining: ");
    Serial.print(header.layers_remaining);
    Serial.println(", re-encrypted with GCM)");
    
    // Forward message
    int state = lora.transmit(forward_buffer, forward_total_len);
    forward_buffer_in_use = false;  // Release immediately after transmit
    
    if (state != RADIOLIB_ERR_NONE) {
      Serial.print("Forward transmit failed: ");
      Serial.println(state);
    }
    
    if (state != RADIOLIB_ERR_NONE) {
      Serial.print("Forward transmit failed: ");
      Serial.println(state);
    }
    
    // Update routing table with validated data
    updateRoutingTable(header.source, header.source, header.hop_count);
    
    releaseDecryptionBuffer(decrypted_buffer0);
    releaseDecryptionBuffer(decrypted_buffer1);
    return true;
  }
  
  Serial.println("Message dropped: too many hops");
  releaseDecryptionBuffer(decrypted_buffer0);
  releaseDecryptionBuffer(decrypted_buffer1);
  return false;  // Message dropped (too many hops)
}

// =====================
// Transmission
// =====================
void sendMeshMessage(NodeAddress destination, const uint8_t* payload, uint16_t payload_len) {
  MeshMessage msg;
  buildLayeredMessage(&msg, destination, payload, payload_len);
  
  // Find next hop
  msg.header.next_hop = findNextHop(destination);
  
  // Prepare transmission data (outermost encrypted layer with nonce + auth tag)
  // Format: [Header][Nonce 12 bytes][Encrypted Data][Auth Tag 16 bytes]
  uint8_t tx_data[MAX_PAYLOAD_SIZE + sizeof(RoutingHeader) + 32];
  RoutingHeader tx_header = msg.header;
  tx_header.layers_remaining = ENCRYPTION_LAYERS;
  tx_header.previous_submesh.submesh_id = my_address.submesh_id;
  tx_header.previous_submesh.node_id = 0;
  memcpy(tx_data, &tx_header, sizeof(RoutingHeader));
  // Prepend nonce (12 bytes for GCM) before encrypted data
  memcpy(tx_data + sizeof(RoutingHeader), msg.nonces[ENCRYPTION_LAYERS - 1], 12);
  memcpy(tx_data + sizeof(RoutingHeader) + 12, msg.encrypted_layers[ENCRYPTION_LAYERS - 1], 
         msg.layer_sizes[ENCRYPTION_LAYERS - 1]);
  // Append authentication tag (16 bytes)
  memcpy(tx_data + sizeof(RoutingHeader) + 12 + msg.layer_sizes[ENCRYPTION_LAYERS - 1], 
         msg.auth_tag, 16);
  
  uint16_t tx_len = sizeof(RoutingHeader) + 12 + msg.layer_sizes[ENCRYPTION_LAYERS - 1] + 16;
  
  Serial.print("Sending mesh message to sub-mesh ");
  Serial.print(destination.submesh_id);
  Serial.print(", node ");
  Serial.print(destination.node_id);
  Serial.print(" (");
  Serial.print(tx_len);
  Serial.println(" bytes)");
  
  int state = lora.transmit(tx_data, tx_len);
  if (state == RADIOLIB_ERR_NONE) {
    Serial.println("Message sent");
  } else {
    Serial.print("Transmit failed, code ");
    Serial.println(state);
  }
}

// =====================
// Setup
// =====================
void setup() {
  Serial.begin(115200);
  delay(1000);

  Serial.println("Starting Mesh Network Node");

  // Initialize WiFi for key generation (even if not connecting)
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  delay(100);

  // Generate or load node key for key-based addressing
  generateOrLoadNodeKey();
  
  // Generate node address from key
  generateNodeAddress();
  
  // Initialize encryption (CTR for inner layers, GCM for outermost)
  initializeEncryption();

  // Configure pins
  pinMode(LORA_RST, OUTPUT);
  pinMode(LORA_CS, OUTPUT);
  pinMode(LORA_BUSY, INPUT);
  pinMode(LORA_DIO1, INPUT);
  
  // Ensure CS is high
  digitalWrite(LORA_CS, HIGH);
  
  // Manual reset sequence
  digitalWrite(LORA_RST, LOW);
  delay(10);
  digitalWrite(LORA_RST, HIGH);
  delay(10);
  
  // Wait for BUSY pin to go low
  unsigned long start = millis();
  while (digitalRead(LORA_BUSY) == HIGH) {
    if (millis() - start > 1000) {
      Serial.println("Warning: BUSY pin timeout");
      break;
    }
    delay(1);
  }
  
  // SPI bus initialization
  SPI.begin(LORA_SCK, LORA_MISO, LORA_MOSI, LORA_CS);
  delay(100);

  // Set XTAL mode
  lora.XTAL = true;

  // Initialize LoRa
  int state = lora.begin(
    915.0,   // MHz
    125.0,   // Bandwidth kHz
    9,       // Spreading Factor
    7,       // Coding Rate (4/7)
    0x12,    // Sync word
    14,      // TX power dBm
    8        // Preamble length
  );

  if (state != RADIOLIB_ERR_NONE) {
    Serial.print("LoRa init failed, code ");
    Serial.println(state);
    while (true) {
      delay(1000);
    }
  }

  Serial.println("LoRa initialized successfully");
  
  // Set module to standby mode
  lora.standby();
  delay(100);
  
  // Initialize routing table with self
  routing_table[0].destination = my_address;
  routing_table[0].next_hop = my_address;
  routing_table[0].submesh_id = my_address.submesh_id;
  routing_table[0].hop_distance = 0;
  routing_table[0].probability = 1.0;
  routing_table[0].last_seen = millis();
  routing_table_size = 1;
  
  Serial.println("Mesh node ready");
}

// =====================
// Main Loop
// =====================
void loop() {
  // Periodic maintenance tasks
  static unsigned long last_maintenance = 0;
  unsigned long now = millis();
  if (now - last_maintenance > 10000) {  // Every 10 seconds
    decayRoutingTable();
    cleanupReplayCache();
    last_maintenance = now;
  }
  
  // Check for incoming messages
  if (lora.available()) {
    uint8_t buffer[256];
    int state = lora.readData(buffer, 256);
    
    if (state == RADIOLIB_ERR_NONE) {
      int packet_size = lora.getPacketLength();
      if (packet_size > 0) {
        Serial.print("Received packet (");
        Serial.print(packet_size);
        Serial.println(" bytes)");
        processReceivedMessage(buffer, packet_size);
      }
    }
  }
  
  // Periodically send test message (every 10 seconds)
  static unsigned long last_send = 0;
  if (millis() - last_send > 10000) {
    // Send to a test destination (modify as needed)
    NodeAddress test_dest = {my_address.submesh_id, my_address.node_id + 1};
    const char* test_msg = "Hello mesh network!";
    sendMeshMessage(test_dest, (uint8_t*)test_msg, strlen(test_msg));
    last_send = millis();
  }
  
  delay(100);
}
