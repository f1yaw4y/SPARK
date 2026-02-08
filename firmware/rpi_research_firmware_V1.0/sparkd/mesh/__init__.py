"""
SPARK Mesh Networking Module

Handles peer discovery, sub-mesh formation, region grouping,
and intra-region packet routing.

Components:
- peer.py: Peer discovery and link quality tracking
- submesh.py: Sub-mesh formation and membership
- region.py: Region grouping for onion routing
- routing.py: Intra-region packet forwarding
"""

from .peer import (
    Peer,
    PeerState,
    PeerManager,
    LinkQuality,
)

from .submesh import (
    SubMesh,
    SubMeshManager,
)

from .region import (
    Region,
    RegionManager,
    RegionRole,
)

from .routing import (
    Router,
    RouteEntry,
    RoutingDecision,
)

__all__ = [
    # Peer
    'Peer',
    'PeerState',
    'PeerManager',
    'LinkQuality',
    # SubMesh
    'SubMesh',
    'SubMeshManager',
    # Region
    'Region',
    'RegionManager',
    'RegionRole',
    # Routing
    'Router',
    'RouteEntry',
    'RoutingDecision',
]
