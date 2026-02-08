"""
SPARK Onion Routing Module

Implements the 3-layer region-based onion routing protocol.

Components:
- layers.py: Onion packet construction at sender
- gateway.py: Layer peeling at region boundaries
- delivery.py: End-to-end delivery tracking and ACKs
"""

from .layers import (
    OnionBuilder,
    OnionPath,
    OnionBuildError,
)

from .gateway import (
    GatewayProcessor,
    ProcessingResult,
    ProcessedPacket,
    LayerDetector,
)

from .delivery import (
    DeliveryManager,
    DeliveryStatus,
    PendingMessage,
)

__all__ = [
    # Layers
    'OnionBuilder',
    'OnionPath',
    'OnionBuildError',
    # Gateway
    'GatewayProcessor',
    'ProcessingResult',
    'ProcessedPacket',
    'LayerDetector',
    # Delivery
    'DeliveryManager',
    'DeliveryStatus',
    'PendingMessage',
]
