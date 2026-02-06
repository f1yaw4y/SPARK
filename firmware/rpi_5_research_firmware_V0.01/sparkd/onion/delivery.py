"""
SPARK Delivery Management

Tracks message delivery status and handles acknowledgments.

Features:
- Pending message tracking
- ACK processing
- Retry management
- Backtracking on failure
"""

import time
import threading
from typing import Dict, List, Optional, Set, Callable
from dataclasses import dataclass, field
from enum import IntEnum


# Default delivery timeout (seconds)
DEFAULT_DELIVERY_TIMEOUT = 300  # 5 minutes

# Maximum retry attempts
MAX_RETRIES = 5

# Retry backoff base (seconds)
RETRY_BACKOFF_BASE = 30


class DeliveryStatus(IntEnum):
    """Message delivery status."""
    PENDING = 0          # Awaiting first send
    SENT = 1             # Sent, awaiting ACK
    ACKNOWLEDGED = 2     # ACK received
    FAILED = 3           # Delivery failed
    EXPIRED = 4          # Timeout expired


@dataclass
class PendingMessage:
    """
    Tracks a pending outgoing message.
    """
    # Message identity
    message_id: bytes
    recipient_id: bytes
    
    # Status
    status: DeliveryStatus = DeliveryStatus.PENDING
    
    # Retry tracking
    send_count: int = 0
    last_send_time: float = 0.0
    next_retry_time: float = 0.0
    
    # Path tracking (for backtracking)
    last_path_region1: Optional[bytes] = None
    last_path_region2: Optional[bytes] = None
    failed_paths: Set[bytes] = field(default_factory=set)
    
    # Timestamps
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    expires_at: float = 0.0
    
    # ACK info
    ack_received_at: Optional[float] = None
    ack_hop_count: int = 0
    
    # Error info
    last_error: Optional[str] = None
    
    def __post_init__(self):
        if self.expires_at == 0.0:
            self.expires_at = self.created_at + DEFAULT_DELIVERY_TIMEOUT
    
    @property
    def is_expired(self) -> bool:
        """Check if message has expired."""
        return time.time() > self.expires_at
    
    @property
    def can_retry(self) -> bool:
        """Check if message can be retried."""
        if self.status not in (DeliveryStatus.PENDING, DeliveryStatus.SENT):
            return False
        if self.send_count >= MAX_RETRIES:
            return False
        if self.is_expired:
            return False
        if time.time() < self.next_retry_time:
            return False
        return True
    
    def record_send(self, region1: bytes, region2: bytes) -> None:
        """Record a send attempt."""
        now = time.time()
        self.send_count += 1
        self.last_send_time = now
        self.updated_at = now
        self.status = DeliveryStatus.SENT
        self.last_path_region1 = region1
        self.last_path_region2 = region2
        
        # Calculate next retry time with exponential backoff
        backoff = RETRY_BACKOFF_BASE * (2 ** min(self.send_count - 1, 5))
        self.next_retry_time = now + backoff
    
    def record_failure(self, error: str) -> None:
        """Record a delivery failure."""
        now = time.time()
        self.updated_at = now
        self.last_error = error
        
        # Mark path as failed
        if self.last_path_region1 and self.last_path_region2:
            path_key = self.last_path_region1 + self.last_path_region2
            self.failed_paths.add(path_key)
        
        # Check if we've exhausted retries
        if self.send_count >= MAX_RETRIES:
            self.status = DeliveryStatus.FAILED
    
    def record_ack(self, hop_count: int = 0) -> None:
        """Record ACK receipt."""
        now = time.time()
        self.updated_at = now
        self.ack_received_at = now
        self.ack_hop_count = hop_count
        self.status = DeliveryStatus.ACKNOWLEDGED


# Callback types
AckCallback = Callable[[bytes, DeliveryStatus], None]


class DeliveryManager:
    """
    Manages message delivery tracking.
    
    Tracks outgoing messages, processes ACKs, and manages retries.
    
    Usage:
        manager = DeliveryManager()
        
        # Track outgoing message
        manager.track_message(message_id, recipient_id)
        
        # Record send
        manager.record_send(message_id, transit_region, dest_region)
        
        # Handle ACK
        manager.handle_ack(message_id, hop_count)
        
        # Get messages needing retry
        for msg in manager.get_messages_for_retry():
            retry_send(msg)
    """
    
    def __init__(
        self,
        delivery_timeout: int = DEFAULT_DELIVERY_TIMEOUT,
    ):
        """
        Initialize delivery manager.
        
        Args:
            delivery_timeout: Default timeout for delivery (seconds)
        """
        self._timeout = delivery_timeout
        self._messages: Dict[bytes, PendingMessage] = {}
        self._lock = threading.RLock()
        
        # Callbacks
        self._ack_callbacks: List[AckCallback] = []
    
    def track_message(
        self,
        message_id: bytes,
        recipient_id: bytes,
        timeout: Optional[int] = None,
    ) -> PendingMessage:
        """
        Start tracking a new outgoing message.
        
        Args:
            message_id: Message identifier
            recipient_id: Recipient's node ID
            timeout: Optional custom timeout
            
        Returns:
            PendingMessage tracker
        """
        now = time.time()
        expires = now + (timeout or self._timeout)
        
        msg = PendingMessage(
            message_id=message_id,
            recipient_id=recipient_id,
            created_at=now,
            expires_at=expires,
        )
        
        with self._lock:
            self._messages[message_id] = msg
        
        return msg
    
    def record_send(
        self,
        message_id: bytes,
        transit_region: bytes,
        dest_region: bytes,
    ) -> bool:
        """
        Record that a message was sent.
        
        Args:
            message_id: Message identifier
            transit_region: Transit region used
            dest_region: Destination region
            
        Returns:
            True if recorded, False if message not found
        """
        with self._lock:
            msg = self._messages.get(message_id)
            if not msg:
                return False
            
            msg.record_send(transit_region, dest_region)
            return True
    
    def record_failure(
        self,
        message_id: bytes,
        error: str,
    ) -> bool:
        """
        Record a delivery failure.
        
        Args:
            message_id: Message identifier
            error: Error description
            
        Returns:
            True if recorded, False if message not found
        """
        with self._lock:
            msg = self._messages.get(message_id)
            if not msg:
                return False
            
            msg.record_failure(error)
            
            # Notify callbacks if failed
            if msg.status == DeliveryStatus.FAILED:
                self._notify_callbacks(message_id, msg.status)
            
            return True
    
    def handle_ack(
        self,
        message_id: bytes,
        hop_count: int = 0,
    ) -> bool:
        """
        Handle an acknowledgment for a message.
        
        Args:
            message_id: Message identifier
            hop_count: Number of hops from recipient
            
        Returns:
            True if ACK processed, False if message not found
        """
        with self._lock:
            msg = self._messages.get(message_id)
            if not msg:
                return False
            
            msg.record_ack(hop_count)
            self._notify_callbacks(message_id, msg.status)
            
            return True
    
    def get_message(self, message_id: bytes) -> Optional[PendingMessage]:
        """Get a tracked message by ID."""
        with self._lock:
            return self._messages.get(message_id)
    
    def get_messages_for_retry(self) -> List[PendingMessage]:
        """
        Get messages that need to be retried.
        
        Returns:
            List of messages ready for retry
        """
        with self._lock:
            return [
                msg for msg in self._messages.values()
                if msg.can_retry
            ]
    
    def get_pending_messages(self) -> List[PendingMessage]:
        """Get all pending messages."""
        with self._lock:
            return [
                msg for msg in self._messages.values()
                if msg.status in (DeliveryStatus.PENDING, DeliveryStatus.SENT)
            ]
    
    def cleanup_completed(self) -> int:
        """
        Remove completed (acknowledged or failed) messages.
        
        Returns:
            Number of messages removed
        """
        completed = (DeliveryStatus.ACKNOWLEDGED, DeliveryStatus.FAILED, DeliveryStatus.EXPIRED)
        
        with self._lock:
            to_remove = [
                msg_id for msg_id, msg in self._messages.items()
                if msg.status in completed
            ]
            
            for msg_id in to_remove:
                del self._messages[msg_id]
            
            return len(to_remove)
    
    def cleanup_expired(self) -> int:
        """
        Mark and clean up expired messages.
        
        Returns:
            Number of messages expired
        """
        now = time.time()
        count = 0
        
        with self._lock:
            for msg in self._messages.values():
                if msg.status in (DeliveryStatus.PENDING, DeliveryStatus.SENT):
                    if now > msg.expires_at:
                        msg.status = DeliveryStatus.EXPIRED
                        msg.last_error = "Delivery timeout"
                        self._notify_callbacks(msg.message_id, msg.status)
                        count += 1
        
        return count
    
    def get_failed_paths(self, message_id: bytes) -> Set[bytes]:
        """
        Get paths that have failed for a message.
        
        Used for backtracking - avoiding previously failed routes.
        
        Args:
            message_id: Message identifier
            
        Returns:
            Set of failed path keys
        """
        with self._lock:
            msg = self._messages.get(message_id)
            if not msg:
                return set()
            return msg.failed_paths.copy()
    
    def register_callback(self, callback: AckCallback) -> None:
        """Register a callback for delivery status changes."""
        self._ack_callbacks.append(callback)
    
    def _notify_callbacks(self, message_id: bytes, status: DeliveryStatus) -> None:
        """Notify registered callbacks of status change."""
        for callback in self._ack_callbacks:
            try:
                callback(message_id, status)
            except Exception:
                pass  # Don't let callback errors break delivery tracking
    
    def get_stats(self) -> dict:
        """Get delivery manager statistics."""
        with self._lock:
            by_status = {}
            for status in DeliveryStatus:
                by_status[status.name.lower()] = sum(
                    1 for msg in self._messages.values() if msg.status == status
                )
            
            return {
                "total_tracked": len(self._messages),
                "by_status": by_status,
                "avg_retries": (
                    sum(msg.send_count for msg in self._messages.values()) /
                    len(self._messages) if self._messages else 0
                ),
            }
