"""
SPARK Network Configuration
Configuration constants and pin definitions for Raspberry Pi Zero 2W with Waveshare SX1262 LoRa Hat
"""

import os

# =====================
# Pin definitions for Waveshare SX1262 LoRa Hat
# =====================
# Note: Waveshare SX1262 Hat uses SPI interface
# Typical pinout (may vary by Hat version):
# - SPI: MOSI, MISO, SCLK, CE0 (CS)
# - GPIO: RST, BUSY, DIO1
# These need to be configured based on your specific Hat version

LORA_CS = 8      # Chip Select (CE0 on SPI0)
LORA_RST = 22    # Reset pin (typical GPIO)
LORA_BUSY = 23   # Busy pin (typical GPIO)
LORA_DIO1 = 24   # DIO1 interrupt pin (typical GPIO)

# SPI bus (typically SPI0 on Raspberry Pi)
SPI_BUS = 0
SPI_DEVICE = 0

# =====================
# Network Configuration
# =====================
MAX_PAYLOAD_SIZE = 200
MAX_ROUTING_HOPS = 100
ENCRYPTION_LAYERS = 3
ADDRESS_SIZE = 4  # 2 bytes submesh, 2 bytes node
MAX_ROUTING_TABLE = 20

# =====================
# LoRa Radio Configuration
# =====================
LORA_FREQUENCY = 915.0      # MHz (adjust for your region)
LORA_BANDWIDTH = 125.0      # kHz
LORA_SPREADING_FACTOR = 9   # SF9
LORA_CODING_RATE = 7        # 4/7
LORA_SYNC_WORD = 0x12
LORA_TX_POWER = 14          # dBm
LORA_PREAMBLE_LENGTH = 8

# =====================
# Replay Protection
# =====================
REPLAY_CACHE_SIZE = 64
REPLAY_TTL_SECONDS = 300  # 5 minutes

# =====================
# Routing Table Configuration
# =====================
MAX_HOP_COUNT = 100
MIN_PROBABILITY = 0.1
MAX_PROBABILITY = 1.0
ROUTING_DECAY_RATE = 0.95  # Decay probability by 5% per check
ROUTING_DECAY_INTERVAL_SECONDS = 60  # Decay every minute
ROUTING_STALE_TIMEOUT_SECONDS = 300  # Remove entries not seen in 5 minutes

# =====================
# Broadcast Storm Prevention
# =====================
BROADCAST_SUPPRESSION_SECONDS = 1  # Same message_id cannot be re-broadcast within 1 second

# =====================
# Maintenance Intervals
# =====================
MAINTENANCE_INTERVAL_SECONDS = 10  # Periodic maintenance every 10 seconds
TEST_MESSAGE_INTERVAL_SECONDS = 10  # Send test message every 10 seconds

# =====================
# Key Storage
# =====================
KEY_STORAGE_PATH = os.path.expanduser("~/.spark_node_key")  # Path to store node private key
