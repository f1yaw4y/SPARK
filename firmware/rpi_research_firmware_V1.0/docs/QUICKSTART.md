# SPARK Quick Start Guide

This guide will get you running a SPARK mesh node in under 10 minutes.

## Hardware Requirements

- Raspberry Pi 5 (or 4B)
- Raspberry Pi OS Lite (64-bit recommended)
- Waveshare SX1262 LoRa HAT
- MicroSD card (16GB+)
- Power supply

## Installation

### 1. Prepare the Raspberry Pi

Flash Raspberry Pi OS Lite to your SD card and boot.

Enable SSH and configure your network as needed.

### 2. Install Dependencies

```bash
sudo apt update
sudo apt install -y python3 python3-cryptography python3-toml python3-spidev git
```

### 3. Clone and Install SPARK

```bash
cd ~
git clone https://github.com/spark-mesh/spark.git
cd spark
sudo ./install.sh
```

### 4. Configure

Edit the configuration file:

```bash
sudo nano /etc/spark/config.toml
```

Key settings to check:

```toml
[radio]
# Set your region's frequency
# US: 915000000, EU: 868000000, AS: 923000000
frequency = 915000000

# Adjust power for your needs (max 22)
tx_power = 17
```

### 5. Start the Daemon

```bash
sudo systemctl enable sparkd
sudo systemctl start sparkd
```

### 6. Verify Operation

```bash
meshctl status
```

You should see output like:

```
SPARK Node Status
========================================
Version:   0.1.0
Node ID:   a1b2c3d4e5f6...
Role:      LEAF
Peers:     0
Region:    (not assigned)
```

## Using meshctl

### Check Status

```bash
meshctl status
```

### View Discovered Peers

```bash
meshctl peers
```

### Send a Message

```bash
meshctl send <recipient_node_id> "Hello, mesh!"
```

### Check Your Inbox

```bash
meshctl inbox
```

### View Debug Information

```bash
meshctl debug
```

## Troubleshooting

### Radio Not Working

1. Check SPI is enabled:
   ```bash
   ls /dev/spidev*
   ```
   You should see `/dev/spidev0.0`

2. Check the LoRa HAT connections

3. View daemon logs:
   ```bash
   journalctl -u sparkd -f
   ```

### No Peers Discovered

1. Ensure another SPARK node is within radio range
2. Check both nodes are on the same frequency
3. Increase tx_power in config
4. Check for physical obstructions

### Permission Errors

Check that the sparkd service is running:
```bash
systemctl status sparkd
```

## Next Steps

- Read the full [Architecture Documentation](ARCHITECTURE.md)
- Understand the [Cryptographic Design](CRYPTO.md)
- Review the [Threat Model](THREAT_MODEL.md)
- Learn about [Onion Routing](ONION_ROUTING.md)

## Network of Two

To test with two nodes:

1. Set up two Raspberry Pis with SPARK
2. Ensure both use the same frequency
3. Place them within LoRa range (can be kilometers with clear line of sight)
4. Watch peers appear:
   ```bash
   watch meshctl peers
   ```
5. Note the other node's Node ID and send a message:
   ```bash
   meshctl send <other_node_id> "Test message"
   ```

## Getting Help

- GitHub Issues: Report bugs and request features
- Documentation: /docs/ directory
- Logs: `journalctl -u sparkd`
