#!/bin/bash
# SPARK Mesh Router Installation Script
# Run as root: sudo ./install.sh

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== SPARK Mesh Router Installation ===${NC}"
echo

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: Please run as root (sudo ./install.sh)${NC}"
    exit 1
fi

# Detect the source directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo "Installing from: $SCRIPT_DIR"

# Check for required system packages
echo -e "\n${YELLOW}Checking dependencies...${NC}"

PACKAGES="python3 python3-cryptography"
MISSING=""

for pkg in $PACKAGES; do
    if ! dpkg -s "$pkg" >/dev/null 2>&1; then
        MISSING="$MISSING $pkg"
    fi
done

if [ -n "$MISSING" ]; then
    echo "Installing missing packages:$MISSING"
    apt-get update
    apt-get install -y $MISSING
fi

# Optional packages
OPTIONAL="python3-toml python3-spidev"
for pkg in $OPTIONAL; do
    if ! dpkg -s "$pkg" >/dev/null 2>&1; then
        echo "Installing optional package: $pkg"
        apt-get install -y "$pkg" || true
    fi
done

# Create directories
echo -e "\n${YELLOW}Creating directories...${NC}"
mkdir -p /etc/spark
mkdir -p /var/lib/spark
mkdir -p /run/spark
mkdir -p /usr/local/lib/spark

# Set permissions
chmod 755 /etc/spark
chmod 700 /var/lib/spark
chmod 755 /run/spark
chmod 755 /usr/local/lib/spark

# Copy Python modules
echo -e "\n${YELLOW}Installing Python modules...${NC}"
cp -r "$SCRIPT_DIR/sparkd" /usr/local/lib/spark/
cp -r "$SCRIPT_DIR/meshctl" /usr/local/lib/spark/

# Create wrapper scripts
echo -e "\n${YELLOW}Installing executables...${NC}"

# sparkd wrapper
cat > /usr/local/bin/sparkd << 'EOF'
#!/usr/bin/env python3
import sys
sys.path.insert(0, '/usr/local/lib/spark')
from sparkd.main import main
main()
EOF
chmod 755 /usr/local/bin/sparkd

# meshctl wrapper
cat > /usr/local/bin/meshctl << 'EOF'
#!/usr/bin/env python3
import sys
sys.path.insert(0, '/usr/local/lib/spark')
from meshctl.main import main
sys.exit(main())
EOF
chmod 755 /usr/local/bin/meshctl

# Install configuration
echo -e "\n${YELLOW}Installing configuration...${NC}"
if [ ! -f /etc/spark/config.toml ]; then
    cp "$SCRIPT_DIR/etc/spark/config.toml.example" /etc/spark/config.toml
    echo "Created /etc/spark/config.toml"
else
    echo "Configuration already exists, not overwriting"
fi

# Install systemd service
echo -e "\n${YELLOW}Installing systemd service...${NC}"
cp "$SCRIPT_DIR/systemd/sparkd.service" /etc/systemd/system/
systemctl daemon-reload

# Enable SPI if on Raspberry Pi
if [ -f /boot/config.txt ] || [ -f /boot/firmware/config.txt ]; then
    echo -e "\n${YELLOW}Configuring SPI for LoRa radio...${NC}"
    CONFIG_FILE="/boot/config.txt"
    [ -f /boot/firmware/config.txt ] && CONFIG_FILE="/boot/firmware/config.txt"
    
    if ! grep -q "^dtparam=spi=on" "$CONFIG_FILE"; then
        echo "dtparam=spi=on" >> "$CONFIG_FILE"
        echo "SPI enabled in $CONFIG_FILE"
        echo -e "${YELLOW}NOTE: Reboot required for SPI changes${NC}"
    else
        echo "SPI already enabled"
    fi
fi

# Print completion message
echo -e "\n${GREEN}=== Installation Complete ===${NC}"
echo
echo "Configuration file: /etc/spark/config.toml"
echo "Data directory:     /var/lib/spark"
echo "Executables:        /usr/local/bin/sparkd"
echo "                    /usr/local/bin/meshctl"
echo
echo "To start SPARK:"
echo "  sudo systemctl enable sparkd"
echo "  sudo systemctl start sparkd"
echo
echo "To check status:"
echo "  meshctl status"
echo
echo "To view logs:"
echo "  journalctl -u sparkd -f"
echo
