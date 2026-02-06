"""
SPARK Configuration Management

Handles loading and validation of configuration from TOML file.
"""

import os
from pathlib import Path
from typing import Any, Dict, Optional
from dataclasses import dataclass, field

try:
    import toml
    HAS_TOML = True
except ImportError:
    HAS_TOML = False


# Default configuration path
DEFAULT_CONFIG_PATH = Path("/etc/spark/config.toml")

# Default data directory
DEFAULT_DATA_DIR = Path("/var/lib/spark")

# Default run directory
DEFAULT_RUN_DIR = Path("/run/spark")


@dataclass
class RadioConfig:
    """Radio-specific configuration."""
    enabled: bool = True
    type: str = "lora_sx1262"
    frequency: int = 915000000  # 915 MHz (US)
    tx_power: int = 17  # dBm
    spreading_factor: int = 9
    bandwidth: int = 125000  # Hz
    coding_rate: int = 5  # 4/5


@dataclass
class MeshConfig:
    """Mesh networking configuration."""
    beacon_interval: int = 30  # seconds
    peer_timeout: int = 300  # seconds
    region_recalc_interval: int = 120  # seconds
    max_peers: int = 100


@dataclass
class OnionConfig:
    """Onion routing configuration."""
    default_ttl: int = 64
    min_region_size: int = 3
    density_threshold: float = 0.6
    gateway_threshold: float = 0.3
    region_cache_ttl: int = 300  # seconds


@dataclass
class StorageConfig:
    """Storage configuration."""
    data_dir: Path = field(default_factory=lambda: DEFAULT_DATA_DIR)
    message_retention: int = 604800  # 7 days in seconds
    dedup_cache_ttl: int = 300  # seconds
    dedup_cache_size: int = 10000


@dataclass
class SecurityConfig:
    """Security configuration."""
    # Key rotation (future)
    key_rotation_days: int = 0  # 0 = disabled


@dataclass
class Config:
    """
    Complete SPARK configuration.
    """
    # Node name (for display)
    node_name: str = ""
    
    # Sub-configurations
    radio: RadioConfig = field(default_factory=RadioConfig)
    mesh: MeshConfig = field(default_factory=MeshConfig)
    onion: OnionConfig = field(default_factory=OnionConfig)
    storage: StorageConfig = field(default_factory=StorageConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    
    # Paths
    config_path: Path = field(default_factory=lambda: DEFAULT_CONFIG_PATH)
    socket_path: Path = field(default_factory=lambda: DEFAULT_RUN_DIR / "sparkd.sock")
    pid_file: Path = field(default_factory=lambda: DEFAULT_RUN_DIR / "sparkd.pid")
    
    # Logging
    log_level: str = "INFO"
    log_file: Optional[Path] = None
    
    @classmethod
    def load(cls, config_path: Optional[Path] = None) -> 'Config':
        """
        Load configuration from file.
        
        Args:
            config_path: Path to config file (default: /etc/spark/config.toml)
            
        Returns:
            Loaded configuration
        """
        path = config_path or DEFAULT_CONFIG_PATH
        config = cls()
        config.config_path = path
        
        if not path.exists():
            return config
        
        if not HAS_TOML:
            # Fall back to basic parsing or skip
            return config
        
        try:
            data = toml.load(path)
            config._apply_dict(data)
        except Exception:
            pass
        
        return config
    
    def _apply_dict(self, data: Dict[str, Any]) -> None:
        """Apply dictionary data to config."""
        # Top-level settings
        if "node_name" in data:
            self.node_name = str(data["node_name"])
        if "log_level" in data:
            self.log_level = str(data["log_level"]).upper()
        if "log_file" in data:
            self.log_file = Path(data["log_file"])
        
        # Radio config
        if "radio" in data:
            r = data["radio"]
            if "enabled" in r:
                self.radio.enabled = bool(r["enabled"])
            if "type" in r:
                self.radio.type = str(r["type"])
            if "frequency" in r:
                self.radio.frequency = int(r["frequency"])
            if "tx_power" in r:
                self.radio.tx_power = int(r["tx_power"])
            if "spreading_factor" in r:
                self.radio.spreading_factor = int(r["spreading_factor"])
            if "bandwidth" in r:
                self.radio.bandwidth = int(r["bandwidth"])
            if "coding_rate" in r:
                self.radio.coding_rate = int(r["coding_rate"])
        
        # Mesh config
        if "mesh" in data:
            m = data["mesh"]
            if "beacon_interval" in m:
                self.mesh.beacon_interval = int(m["beacon_interval"])
            if "peer_timeout" in m:
                self.mesh.peer_timeout = int(m["peer_timeout"])
            if "region_recalc_interval" in m:
                self.mesh.region_recalc_interval = int(m["region_recalc_interval"])
            if "max_peers" in m:
                self.mesh.max_peers = int(m["max_peers"])
        
        # Onion config
        if "onion" in data:
            o = data["onion"]
            if "default_ttl" in o:
                self.onion.default_ttl = int(o["default_ttl"])
            if "min_region_size" in o:
                self.onion.min_region_size = int(o["min_region_size"])
            if "density_threshold" in o:
                self.onion.density_threshold = float(o["density_threshold"])
            if "gateway_threshold" in o:
                self.onion.gateway_threshold = float(o["gateway_threshold"])
        
        # Storage config
        if "storage" in data:
            s = data["storage"]
            if "data_dir" in s:
                self.storage.data_dir = Path(s["data_dir"])
            if "message_retention" in s:
                self.storage.message_retention = int(s["message_retention"])
            if "dedup_cache_ttl" in s:
                self.storage.dedup_cache_ttl = int(s["dedup_cache_ttl"])
            if "dedup_cache_size" in s:
                self.storage.dedup_cache_size = int(s["dedup_cache_size"])
    
    def validate(self) -> None:
        """
        Validate configuration.
        
        Raises:
            ValueError: If configuration is invalid
        """
        # Validate radio frequency
        if self.radio.frequency < 100000000 or self.radio.frequency > 1000000000:
            raise ValueError(f"Invalid radio frequency: {self.radio.frequency}")
        
        # Validate TX power
        if self.radio.tx_power < -10 or self.radio.tx_power > 22:
            raise ValueError(f"Invalid TX power: {self.radio.tx_power}")
        
        # Validate spreading factor
        if self.radio.spreading_factor < 6 or self.radio.spreading_factor > 12:
            raise ValueError(f"Invalid spreading factor: {self.radio.spreading_factor}")
        
        # Validate TTL
        if self.onion.default_ttl < 1 or self.onion.default_ttl > 255:
            raise ValueError(f"Invalid TTL: {self.onion.default_ttl}")
