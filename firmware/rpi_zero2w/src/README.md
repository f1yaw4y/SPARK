# SPARK Mesh Network Node - Raspberry Pi Implementation

Python implementation of the SPARK mesh network node for Raspberry Pi Zero 2W with Waveshare SX1262 LoRa Hat.

## Design Goals

This implementation maintains the same design goals as the original Arduino/ESP32 firmware:

- **Dynamic infrastructure** with no global authority
- **Precise and private P2P routing** over untrusted intermediate nodes
- **Private identities** using cryptographically derived addresses
- **Redundant and fallback operations** under packet loss, retransmission, and node movement
- **Capabilities to transmit data reliably** across nationwide/global infrastructure

## Architecture

The implementation is modular and consists of:

- `config.py` - Configuration constants and pin definitions
- `network.py` - Network data structures (NodeAddress, RoutingHeader, etc.)
- `crypto.py` - AES-CTR and AES-GCM encryption/decryption
- `replay.py` - Replay attack protection
- `routing.py` - Probabilistic routing table management
- `radio.py` - LoRa radio interface abstraction
- `node.py` - Main mesh node implementation
- `main.py` - Entry point and main loop

## Installation

### Prerequisites

1. **Hardware Setup:**
   - Raspberry Pi Zero 2W
   - Waveshare SX1262 LoRa Hat
   - Ensure SPI is enabled on your Raspberry Pi:
     ```bash
     sudo raspi-config
     # Navigate to Interface Options > SPI > Enable
     ```

2. **Python Dependencies:**
   ```bash
   pip3 install -r requirements.txt
   ```

3. **LoRa Library:**
   The code expects a Python library for SX1262. You have a few options:
   
   **Option A:** Use Waveshare's official library:
   - Download from Waveshare's GitHub repository
   - Follow their installation instructions
   - Update `radio.py` imports accordingly
   
   **Option B:** Use a compatible SX126x library:
   ```bash
   pip3 install sx126x  # If available
   ```
   
   **Option C:** Implement manual SPI interface using `spidev` and `RPi.GPIO`:
   ```bash
   pip3 install spidev RPi.GPIO
   ```

### Configuration

Edit `config.py` to match your hardware setup:

- **Pin Definitions:** Adjust `LORA_CS`, `LORA_RST`, `LORA_BUSY`, `LORA_DIO1` based on your Hat's pinout
- **Radio Parameters:** Set frequency, bandwidth, spreading factor, etc. according to your region's regulations
- **Network Parameters:** Adjust `MAX_PAYLOAD_SIZE`, `ENCRYPTION_LAYERS`, etc. as needed

### Key Storage

Node private keys are stored at `/home/pi/.spark_node_key` by default. Ensure the directory exists and is writable:

```bash
mkdir -p ~/.spark
# The key will be generated automatically on first run
```

## Usage

### Running the Node

```bash
# Run as regular user (recommended for development)
python3 main.py

# Or run as a service (production)
sudo systemctl start spark-node.service  # After creating systemd service
```

### Running as a Service

Create a systemd service file `/etc/systemd/system/spark-node.service`:

```ini
[Unit]
Description=SPARK Mesh Network Node
After=network.target

[Service]
Type=simple
User=pi
WorkingDirectory=/home/flyaw4y/projects/SPARK-main/firmware/rpi_zero2w
ExecStart=/usr/bin/python3 /home/flyaw4y/projects/SPARK-main/firmware/rpi_zero2w/main.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Then:
```bash
sudo systemctl daemon-reload
sudo systemctl enable spark-node.service
sudo systemctl start spark-node.service
```

## Protocol Details

### Address-based Routing

Each node maintains a long-term cryptographic identity (32-byte private key). Node addresses are derived from this key using SHA-256, ensuring:
- No MAC address leakage
- Deterministic but unique addresses
- Privacy-preserving routing

### Sub-Mesh Design

The network is dynamically segmented into sub-meshes based on topology:
- Traffic crossing sub-mesh boundaries incurs additional cryptographic layers
- Routing confidence decays with distance from originating sub-mesh
- Efficient routing without global network knowledge

### Packet Structure and Cryptography

SPARK packets use layered encryption:
- **Inner layers:** AES-256-CTR mode for stream encryption
- **Outer layer:** AES-256-GCM for authentication of routing headers
- Each layer uses unique nonces to prevent keystream reuse
- Routing headers are mutable between hops (only authenticated at outer layer)

This allows intermediate nodes to make routing decisions without knowledge of origin, destination, or data contents.

### Security Features

- **Replay Protection:** Messages tracked by (source, message_id) with 5-minute TTL
- **Routing Validation:** Updates validated before acceptance
- **Broadcast Storm Prevention:** Local suppression of rapid re-broadcasts
- **Header Authentication:** Outermost layer uses GCM to authenticate headers

## Limitations

This Python implementation is a **proof of concept** for a small number of nodes. For production use with many nodes, consider:

- Porting to Rust (as mentioned in original requirements)
- Optimizing encryption/decryption operations
- Implementing asynchronous I/O for better concurrency
- Memory optimization for routing tables and replay cache

## Troubleshooting

### Radio Initialization Fails

1. Check SPI is enabled: `lsmod | grep spi`
2. Verify pin connections match `config.py`
3. Check Waveshare Hat documentation for correct pinout
4. Ensure you have appropriate permissions (may need `sudo` or add user to `spi` group)

### Import Errors

If you get import errors for `SX126x`:
- Install Waveshare's library or a compatible alternative
- Update `radio.py` to use the correct import path
- Or implement manual SPI interface in `radio.py`

### Permission Errors

If key storage fails:
```bash
mkdir -p ~/.spark
chmod 700 ~/.spark
```

## Logging

Logs are written to both stdout and `/var/log/spark_node.log`. Adjust logging level in `main.py`:

```python
logging.basicConfig(level=logging.DEBUG)  # For verbose debugging
```

## Development

The code is modular to allow easy testing and modification:

- Each module can be tested independently
- Crypto operations use standard Python `cryptography` library
- Radio interface is abstracted for easy hardware swapping

## License

Same license as the original SPARK project.

## References

- Waveshare SX1262 Hat Documentation: https://www.waveshare.com/wiki/SX1262_XXXM_LoRaWAN/GNSS_HAT
- Python Cryptography Library: https://cryptography.io/
