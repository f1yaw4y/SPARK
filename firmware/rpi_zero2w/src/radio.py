"""
SPARK LoRa Radio Interface
Abstraction layer for Waveshare SX1262 LoRa Hat on Raspberry Pi
"""

import time
import logging
try:
    from SX126x import SX126x
except ImportError:
    # Fallback if SX126x library is not available
    # User will need to install: pip install sx126x
    SX126x = None

import config

logger = logging.getLogger(__name__)


class LoRaRadio:
    """LoRa radio interface for SX1262"""
    
    def __init__(self):
        """Initialize LoRa radio"""
        self.module = None
        self._initialized = False
        self._initialize_radio()
    
    def _initialize_radio(self):
        """Initialize SX1262 LoRa module"""
        if SX126x is None:
            raise ImportError(
                "SX126x library not found. "
                "Install with: pip install sx126x or use Waveshare's library"
            )
        
        try:
            # Initialize SX1262 module
            # Note: Pin configuration may vary by Hat version
            # Adjust these based on your specific Waveshare Hat documentation
            self.module = SX126x(
                csPin=config.LORA_CS,
                resetPin=config.LORA_RST,
                busyPin=config.LORA_BUSY,
                irqPin=config.LORA_DIO1,
                txenPin=-1,  # Set if available on your Hat
                rxenPin=-1   # Set if available on your Hat
            )
            
            # Configure LoRa parameters
            state = self.module.begin(
                freq=config.LORA_FREQUENCY,
                bw=config.LORA_BANDWIDTH,
                sf=config.LORA_SPREADING_FACTOR,
                cr=config.LORA_CODING_RATE,
                syncWord=config.LORA_SYNC_WORD,
                power=config.LORA_TX_POWER,
                preambleLength=config.LORA_PREAMBLE_LENGTH,
                tcxoVoltage=1.6,  # Typical for SX1262
                useRegulatorLDO=False,  # Use DCDC regulator
                blocking=True
            )
            
            if state != 0:  # 0 = SUCCESS
                raise RuntimeError(f"LoRa initialization failed with code {state}")
            
            # Set module to standby mode
            self.module.standby()
            self._initialized = True
            logger.info("LoRa radio initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize LoRa radio: {e}")
            raise
    
    def transmit(self, data: bytes) -> bool:
        """
        Transmit data over LoRa
        
        Args:
            data: Data bytes to transmit
        
        Returns:
            True if transmission succeeded, False otherwise
        """
        if not self._initialized:
            logger.error("Radio not initialized")
            return False
        
        if len(data) > config.MAX_PAYLOAD_SIZE + 64:  # Add some headroom for headers
            logger.error(f"Packet too large: {len(data)} bytes")
            return False
        
        try:
            state = self.module.transmit(data)
            if state == 0:  # SUCCESS
                logger.debug(f"Transmitted {len(data)} bytes")
                return True
            else:
                logger.warning(f"Transmission failed with code {state}")
                return False
        except Exception as e:
            logger.error(f"Transmission error: {e}")
            return False
    
    def receive(self, timeout: float = None) -> tuple[bytes, int]:
        """
        Receive data from LoRa
        
        Args:
            timeout: Timeout in seconds (None for blocking)
        
        Returns:
            Tuple of (received_data, packet_length)
            Returns (None, 0) if no data received or error
        """
        if not self._initialized:
            logger.error("Radio not initialized")
            return None, 0
        
        try:
            # Check if data is available
            if timeout is not None:
                start_time = time.time()
                while not self.module.available():
                    if time.time() - start_time > timeout:
                        return None, 0
                    time.sleep(0.01)  # Small delay
            
            # Read data
            data = bytearray(256)  # Maximum packet size
            state = self.module.readData(data, len(data))
            
            if state == 0:  # SUCCESS
                packet_length = self.module.getPacketLength()
                if packet_length > 0:
                    return bytes(data[:packet_length]), packet_length
            
            return None, 0
            
        except Exception as e:
            logger.error(f"Receive error: {e}")
            return None, 0
    
    def available(self) -> bool:
        """Check if data is available for reception"""
        if not self._initialized:
            return False
        try:
            return self.module.available()
        except:
            return False
    
    def standby(self):
        """Set module to standby mode"""
        if self._initialized:
            try:
                self.module.standby()
            except Exception as e:
                logger.warning(f"Standby error: {e}")
    
    def __del__(self):
        """Cleanup on destruction"""
        if self._initialized and self.module:
            try:
                self.module.standby()
            except:
                pass


class LoRaRadioSimple:
    """
    Simplified LoRa radio interface using spidev and RPi.GPIO
    This is a fallback if the SX126x library is not available.
    Users should implement this based on Waveshare's SX1262 documentation.
    """
    
    def __init__(self):
        """Initialize with basic SPI/GPIO access"""
        logger.warning("Using simplified LoRa interface - implement full SPI driver")
        self._initialized = False
    
    def transmit(self, data: bytes) -> bool:
        """Placeholder - implement SPI communication"""
        logger.warning("LoRa transmit not implemented in fallback mode")
        return False
    
    def receive(self, timeout: float = None) -> tuple[bytes, int]:
        """Placeholder - implement SPI communication"""
        logger.warning("LoRa receive not implemented in fallback mode")
        return None, 0
    
    def available(self) -> bool:
        """Placeholder"""
        return False
    
    def standby(self):
        """Placeholder"""
        pass
