"""
SPARK Loopback Radio

A virtual radio for testing that loops packets back to itself
or to other loopback radios in the same process.

Useful for:
- Unit testing
- Integration testing
- Development without hardware
- Simulating multi-node scenarios

Features:
- Configurable latency
- Configurable packet loss
- Support for multiple virtual radios
"""

import time
import queue
import threading
from typing import Optional, Dict, List, ClassVar
from dataclasses import dataclass

from .base import (
    BaseRadio,
    RadioConfig,
    RadioState,
    RadioError,
    RadioPacket,
)


@dataclass
class LoopbackConfig:
    """Additional configuration for loopback radio."""
    
    # Simulated transmission latency (milliseconds)
    latency_ms: int = 10
    
    # Packet loss probability (0.0 - 1.0)
    loss_probability: float = 0.0
    
    # Simulated RSSI value
    simulated_rssi: int = -50
    
    # Simulated SNR value
    simulated_snr: float = 10.0
    
    # Whether to echo packets back to sender
    echo_to_sender: bool = False


class LoopbackRadio(BaseRadio):
    """
    Virtual loopback radio for testing.
    
    All loopback radios in the same process share a virtual medium.
    Packets transmitted by one are received by all others (including
    optionally the sender).
    
    Usage:
        # Create two virtual radios
        radio1 = LoopbackRadio("node1")
        radio2 = LoopbackRadio("node2")
        
        # Configure both
        config = RadioConfig()
        radio1.configure(config)
        radio2.configure(config)
        
        # Start receiving on radio2
        radio2.start_receive()
        
        # Transmit from radio1
        radio1.transmit(b"Hello!")
        
        # Receive on radio2
        packet = radio2.receive(timeout_ms=1000)
        assert packet.data == b"Hello!"
    """
    
    # Class-level registry of all loopback radios
    # Keyed by frequency to simulate channel separation
    _radios: ClassVar[Dict[int, List['LoopbackRadio']]] = {}
    _registry_lock: ClassVar[threading.Lock] = threading.Lock()
    
    def __init__(self, name: str = "loopback", loopback_config: Optional[LoopbackConfig] = None):
        """
        Initialize loopback radio.
        
        Args:
            name: Radio instance name
            loopback_config: Optional loopback-specific configuration
        """
        super().__init__(name)
        
        self._loopback_config = loopback_config or LoopbackConfig()
        self._rx_queue: queue.Queue[RadioPacket] = queue.Queue()
        self._receiving = False
        self._rx_thread: Optional[threading.Thread] = None
        
        # Register this radio
        self._registered_frequency: Optional[int] = None
    
    def configure(self, config: RadioConfig) -> None:
        """Configure the loopback radio."""
        self._validate_config(config)
        
        # Unregister from old frequency if changing
        if self._registered_frequency is not None:
            self._unregister()
        
        self._config = config
        self._state = RadioState.IDLE
        
        # Register at new frequency
        self._register(config.frequency)
    
    def _register(self, frequency: int) -> None:
        """Register this radio at a frequency."""
        with self._registry_lock:
            if frequency not in self._radios:
                self._radios[frequency] = []
            self._radios[frequency].append(self)
            self._registered_frequency = frequency
    
    def _unregister(self) -> None:
        """Unregister this radio from its frequency."""
        if self._registered_frequency is not None:
            with self._registry_lock:
                freq = self._registered_frequency
                if freq in self._radios and self in self._radios[freq]:
                    self._radios[freq].remove(self)
                self._registered_frequency = None
    
    def transmit(self, data: bytes) -> bool:
        """Transmit a packet to all other radios on same frequency."""
        self._validate_packet(data)
        
        if self._state == RadioState.SLEEPING:
            raise RadioError("Radio is sleeping")
        
        self._state = RadioState.TRANSMITTING
        
        # Simulate transmission time
        time.sleep(self._loopback_config.latency_ms / 1000.0)
        
        # Create packet
        packet = RadioPacket(
            data=data,
            timestamp=time.time(),
            rssi=self._loopback_config.simulated_rssi,
            snr=self._loopback_config.simulated_snr,
        )
        
        # Deliver to all other radios on same frequency
        delivered = False
        with self._registry_lock:
            freq = self._registered_frequency
            if freq in self._radios:
                for radio in self._radios[freq]:
                    # Skip self unless echo enabled
                    if radio is self and not self._loopback_config.echo_to_sender:
                        continue
                    
                    # Skip if not receiving
                    if not radio._receiving:
                        continue
                    
                    # Simulate packet loss
                    import random
                    if random.random() < self._loopback_config.loss_probability:
                        continue
                    
                    # Deliver packet
                    radio._deliver_packet(packet)
                    delivered = True
        
        self._state = RadioState.RECEIVING if self._receiving else RadioState.IDLE
        self._packets_sent += 1
        
        return delivered
    
    def _deliver_packet(self, packet: RadioPacket) -> None:
        """Deliver a packet to this radio's receive queue."""
        try:
            self._rx_queue.put_nowait(packet)
            self._packets_received += 1
            
            # Call callback if set
            if self._rx_callback:
                self._rx_callback(packet)
        except queue.Full:
            self._rx_errors += 1
    
    def receive(self, timeout_ms: int = 1000) -> Optional[RadioPacket]:
        """Receive a packet from the queue."""
        if self._state == RadioState.SLEEPING:
            raise RadioError("Radio is sleeping")
        
        if not self._receiving:
            raise RadioError("Radio not in receive mode")
        
        try:
            if timeout_ms == 0:
                # Non-blocking
                return self._rx_queue.get_nowait()
            else:
                return self._rx_queue.get(timeout=timeout_ms / 1000.0)
        except queue.Empty:
            return None
    
    def start_receive(self) -> None:
        """Start continuous receive mode."""
        if self._state == RadioState.UNINITIALIZED:
            raise RadioError("Radio not configured")
        
        self._receiving = True
        self._state = RadioState.RECEIVING
    
    def stop_receive(self) -> None:
        """Stop continuous receive mode."""
        self._receiving = False
        if self._state == RadioState.RECEIVING:
            self._state = RadioState.IDLE
    
    def sleep(self) -> None:
        """Put radio into sleep mode."""
        self.stop_receive()
        self._state = RadioState.SLEEPING
    
    def reset(self) -> None:
        """Reset radio to initial state."""
        self.stop_receive()
        
        # Clear receive queue
        while not self._rx_queue.empty():
            try:
                self._rx_queue.get_nowait()
            except queue.Empty:
                break
        
        self._state = RadioState.IDLE if self._config else RadioState.UNINITIALIZED
    
    def set_loopback_config(self, config: LoopbackConfig) -> None:
        """Update loopback-specific configuration."""
        self._loopback_config = config
    
    def get_queue_depth(self) -> int:
        """Get number of packets waiting in receive queue."""
        return self._rx_queue.qsize()
    
    def __del__(self):
        """Cleanup on deletion."""
        self._unregister()
    
    @classmethod
    def get_radio_count(cls, frequency: Optional[int] = None) -> int:
        """
        Get count of registered loopback radios.
        
        Args:
            frequency: Specific frequency to count, or None for all
            
        Returns:
            Number of registered radios
        """
        with cls._registry_lock:
            if frequency is not None:
                return len(cls._radios.get(frequency, []))
            else:
                return sum(len(radios) for radios in cls._radios.values())
    
    @classmethod
    def clear_all(cls) -> None:
        """Clear all registered radios (for test cleanup)."""
        with cls._registry_lock:
            cls._radios.clear()
