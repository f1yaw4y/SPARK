"""
SPARK Radio Abstraction Layer

Provides a unified interface for different radio transceivers:
- LoRa (Waveshare SX1262)
- Loopback (testing)
- Future: WiFi, Ethernet, other radios

All radios implement the BaseRadio interface, allowing the mesh
layer to work with any supported hardware.
"""

from .base import (
    BaseRadio,
    RadioConfig,
    RadioState,
    RadioError,
    RadioPacket,
)

from .loopback import LoopbackRadio

# Conditional imports for hardware-specific radios
# Catch all exceptions: lgpio may raise OSError/FileNotFoundError
# during module init if GPIO hardware or pipes are inaccessible
try:
    from .lora_sx1262 import LoRaSX1262Radio
    HAS_LORA = True
except Exception:
    HAS_LORA = False
    LoRaSX1262Radio = None

__all__ = [
    'BaseRadio',
    'RadioConfig',
    'RadioState',
    'RadioError',
    'RadioPacket',
    'LoopbackRadio',
    'LoRaSX1262Radio',
    'HAS_LORA',
]
