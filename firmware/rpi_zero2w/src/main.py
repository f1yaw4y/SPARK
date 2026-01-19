#!/usr/bin/env python3
"""
SPARK Mesh Network Node - Main Entry Point
Raspberry Pi Zero 2W with Waveshare SX1262 LoRa Hat
"""

import sys
import time
import logging
import signal
from node import SparkMeshNode
from network import NodeAddress
import config

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('/var/log/spark_node.log', mode='a')
    ]
)

logger = logging.getLogger(__name__)

# Global node instance for signal handlers
node = None


def signal_handler(sig, frame):
    """Handle shutdown signals gracefully"""
    logger.info("Shutting down SPARK node...")
    if node:
        node.radio.standby()
    sys.exit(0)


def main():
    """Main entry point"""
    global node
    
    logger.info("Starting SPARK Mesh Network Node")
    logger.info(f"Node configuration: {config.MAX_PAYLOAD_SIZE}B payload, "
                f"{config.ENCRYPTION_LAYERS} encryption layers, "
                f"{config.MAX_ROUTING_TABLE} max routing entries")
    
    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        # Initialize node
        node = SparkMeshNode()
        my_address = node.get_address()
        logger.info(f"Node ready: {my_address}")
        
        # Main loop
        last_maintenance = time.time()
        last_test_send = time.time()
        
        logger.info("Entering main loop...")
        
        while True:
            now = time.time()
            
            # Periodic maintenance tasks
            if now - last_maintenance >= config.MAINTENANCE_INTERVAL_SECONDS:
                node.run_maintenance()
                last_maintenance = now
                
                # Log routing table status
                entries = node.routing_table.get_all_entries()
                logger.debug(f"Routing table: {len(entries)} entries")
            
            # Check for incoming messages
            if node.radio.available():
                data, packet_len = node.radio.receive(timeout=0.1)
                if data and packet_len > 0:
                    logger.debug(f"Received packet ({packet_len} bytes)")
                    node.process_received_message(data[:packet_len])
            
            # Periodically send test message (every 10 seconds)
            if now - last_test_send >= config.TEST_MESSAGE_INTERVAL_SECONDS:
                # Send to a test destination
                test_dest = NodeAddress(
                    my_address.submesh_id,
                    my_address.node_id + 1
                )
                test_msg = b"Hello mesh network!"
                logger.info(f"Sending test message to {test_dest}")
                node.send_mesh_message(test_dest, test_msg)
                last_test_send = now
            
            # Small delay to prevent busy-waiting
            time.sleep(0.1)
    
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)
    finally:
        if node:
            logger.info("Cleaning up...")
            node.radio.standby()
        logger.info("SPARK node stopped")


if __name__ == "__main__":
    main()
