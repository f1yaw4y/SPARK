"""
SPARK Radio Base Class

Defines the abstract interface that all radio implementations must follow.

Design Principles:
- Simple, blocking interface (async handled at higher level)
- Clear error handling
- Configuration validation
- State tracking
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional, Callable, List
import time


class RadioError(Exception):
    """Exception raised for radio-related errors."""
    pass


class RadioState(Enum):
    """Radio operational state."""
    UNINITIALIZED = auto()  # Not yet configured
    IDLE = auto()           # Ready to transmit or receive
    TRANSMITTING = auto()   # Currently transmitting
    RECEIVING = auto()      # Actively receiving
    SLEEPING = auto()       # Low-power sleep mode
    ERROR = auto()          # Error state, needs reset


@dataclass
class RadioConfig:
    """
    Radio configuration parameters.
    
    These are the common parameters across radio types.
    Specific radios may have additional configuration.
    """
    # Frequency in Hz (e.g., 915000000 for 915 MHz)
    frequency: int = 915000000
    
    # Transmit power in dBm
    tx_power: int = 17
    
    # Bandwidth in Hz (LoRa-specific, ignored for others)
    bandwidth: int = 125000
    
    # Spreading factor (LoRa-specific)
    spreading_factor: int = 9
    
    # Coding rate (LoRa-specific, 5-8 for 4/5 to 4/8)
    coding_rate: int = 5
    
    # Preamble length in symbols
    preamble_length: int = 8
    
    # Enable CRC
    crc_enabled: bool = True
    
    # Sync word for packet filtering
    sync_word: int = 0x12
    
    # Receive timeout in milliseconds (0 = continuous)
    rx_timeout_ms: int = 0
    
    # Maximum packet size
    max_packet_size: int = 255


@dataclass
class RadioPacket:
    """
    Received or transmitted radio packet.
    
    Includes metadata about the transmission.
    """
    # Packet payload
    data: bytes
    
    # Receive timestamp (Unix time with microseconds)
    timestamp: float = field(default_factory=time.time)
    
    # Received Signal Strength Indicator (dBm)
    rssi: Optional[int] = None
    
    # Signal-to-Noise Ratio (dB)
    snr: Optional[float] = None
    
    # Frequency error (Hz)
    freq_error: Optional[int] = None
    
    @property
    def size(self) -> int:
        """Packet size in bytes."""
        return len(self.data)


class BaseRadio(ABC):
    """
    Abstract base class for radio transceivers.
    
    All radio implementations must inherit from this class
    and implement the abstract methods.
    
    Usage:
        radio = ConcreteRadio()
        radio.configure(RadioConfig(frequency=915000000))
        radio.start_receive()
        
        while True:
            packet = radio.receive(timeout_ms=1000)
            if packet:
                process(packet)
    """
    
    def __init__(self, name: str = "radio"):
        """
        Initialize radio base class.
        
        Args:
            name: Human-readable name for this radio instance
        """
        self.name = name
        self._state = RadioState.UNINITIALIZED
        self._config: Optional[RadioConfig] = None
        self._rx_callback: Optional[Callable[[RadioPacket], None]] = None
        
        # Statistics
        self._packets_sent = 0
        self._packets_received = 0
        self._tx_errors = 0
        self._rx_errors = 0
    
    @property
    def state(self) -> RadioState:
        """Current radio state."""
        return self._state
    
    @property
    def config(self) -> Optional[RadioConfig]:
        """Current radio configuration."""
        return self._config
    
    @property
    def is_initialized(self) -> bool:
        """Whether radio has been configured."""
        return self._state != RadioState.UNINITIALIZED
    
    @abstractmethod
    def configure(self, config: RadioConfig) -> None:
        """
        Configure radio parameters.
        
        Must be called before transmit/receive operations.
        
        Args:
            config: Radio configuration
            
        Raises:
            RadioError: If configuration fails
        """
        pass
    
    @abstractmethod
    def transmit(self, data: bytes) -> bool:
        """
        Transmit a packet.
        
        Blocks until transmission completes.
        
        Args:
            data: Packet payload (must be <= max_packet_size)
            
        Returns:
            bool: True if transmission successful
            
        Raises:
            RadioError: If transmission fails
        """
        pass
    
    @abstractmethod
    def receive(self, timeout_ms: int = 1000) -> Optional[RadioPacket]:
        """
        Receive a packet.
        
        Blocks until a packet is received or timeout expires.
        
        Args:
            timeout_ms: Receive timeout in milliseconds (0 = no timeout)
            
        Returns:
            RadioPacket if received, None if timeout
            
        Raises:
            RadioError: If receive fails
        """
        pass
    
    @abstractmethod
    def start_receive(self) -> None:
        """
        Start continuous receive mode.
        
        Radio will listen for packets until stop_receive() is called.
        Use receive() to get packets, or set a callback with set_rx_callback().
        
        Raises:
            RadioError: If starting receive fails
        """
        pass
    
    @abstractmethod
    def stop_receive(self) -> None:
        """
        Stop continuous receive mode.
        
        Radio enters idle state.
        """
        pass
    
    @abstractmethod
    def sleep(self) -> None:
        """
        Put radio into low-power sleep mode.
        
        Call configure() or start_receive() to wake up.
        """
        pass
    
    @abstractmethod
    def reset(self) -> None:
        """
        Reset radio to initial state.
        
        Useful for recovering from errors.
        """
        pass
    
    def set_rx_callback(self, callback: Optional[Callable[[RadioPacket], None]]) -> None:
        """
        Set callback for received packets.
        
        If set, callback is invoked for each received packet
        in addition to returning from receive().
        
        Args:
            callback: Function to call with received packet, or None to clear
        """
        self._rx_callback = callback
    
    def get_statistics(self) -> dict:
        """
        Get radio statistics.
        
        Returns:
            dict: Statistics including packets sent/received, errors
        """
        return {
            "name": self.name,
            "state": self._state.name,
            "packets_sent": self._packets_sent,
            "packets_received": self._packets_received,
            "tx_errors": self._tx_errors,
            "rx_errors": self._rx_errors,
        }
    
    def _validate_config(self, config: RadioConfig) -> None:
        """
        Validate configuration parameters.
        
        Args:
            config: Configuration to validate
            
        Raises:
            RadioError: If configuration is invalid
        """
        if config.frequency < 100000000 or config.frequency > 1000000000:
            raise RadioError(f"Invalid frequency: {config.frequency}")
        
        if config.tx_power < -10 or config.tx_power > 22:
            raise RadioError(f"Invalid TX power: {config.tx_power}")
        
        if config.max_packet_size < 1 or config.max_packet_size > 255:
            raise RadioError(f"Invalid max packet size: {config.max_packet_size}")
    
    def _validate_packet(self, data: bytes) -> None:
        """
        Validate packet for transmission.
        
        Args:
            data: Packet data
            
        Raises:
            RadioError: If packet is invalid
        """
        if not self._config:
            raise RadioError("Radio not configured")
        
        if len(data) == 0:
            raise RadioError("Empty packet")
        
        if len(data) > self._config.max_packet_size:
            raise RadioError(
                f"Packet too large: {len(data)} > {self._config.max_packet_size}"
            )
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - ensure cleanup."""
        try:
            self.sleep()
        except Exception:
            pass
        return False
    
    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} name={self.name} state={self._state.name}>"
