"""
SPARK RPC Module

Provides IPC interface for meshctl CLI via Unix domain socket.

Protocol: Simple JSON-RPC over Unix socket.
"""

from .server import (
    RPCServer,
    RPCClient,
    RPCError,
    RPCErrorCode,
)

__all__ = [
    'RPCServer',
    'RPCClient',
    'RPCError',
    'RPCErrorCode',
]
