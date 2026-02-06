"""
SPARK Message Storage

Persistent storage for messages supporting delay-tolerant delivery.

Features:
- SQLite-based persistence
- Message status tracking
- Retry management
- Automatic cleanup of old messages
- Thread-safe operations

Design:
- Messages stored until delivered or expired
- Supports offline-first operation
- Tracks delivery attempts and failures
"""

import sqlite3
import time
import threading
from pathlib import Path
from typing import Optional, List, Iterator
from dataclasses import dataclass
from enum import IntEnum
from contextlib import contextmanager


# Default storage location
DEFAULT_STORE_PATH = Path("/var/lib/spark/messages.db")

# Default message retention in seconds (7 days)
DEFAULT_RETENTION = 7 * 24 * 60 * 60

# Maximum retry attempts
DEFAULT_MAX_RETRIES = 10

# Retry backoff base (seconds)
RETRY_BACKOFF_BASE = 30


class MessageStatus(IntEnum):
    """Message delivery status."""
    PENDING = 0       # Awaiting delivery
    FORWARDED = 1     # Forwarded, awaiting ACK
    DELIVERED = 2     # Successfully delivered
    FAILED = 3        # Delivery failed
    EXPIRED = 4       # TTL expired
    CANCELLED = 5     # Manually cancelled


@dataclass
class StoredMessage:
    """
    Stored message record.
    """
    # Identifiers
    message_id: bytes         # 16 bytes
    
    # Routing
    sender_id: bytes          # 16 bytes
    recipient_id: bytes       # 16 bytes
    
    # Content
    payload: bytes            # Encrypted payload
    
    # Status
    status: MessageStatus
    
    # Timestamps
    created_at: float         # When message was created
    updated_at: float         # Last status update
    expires_at: float         # When message expires
    next_retry_at: Optional[float]  # Next retry time
    
    # Retry tracking
    retry_count: int          # Number of delivery attempts
    last_error: Optional[str] # Last error message
    
    # Delivery info
    delivered_at: Optional[float]   # When delivered
    ack_received_at: Optional[float] # When ACK received
    
    @property
    def is_pending(self) -> bool:
        """Check if message is pending delivery."""
        return self.status in (MessageStatus.PENDING, MessageStatus.FORWARDED)
    
    @property
    def is_expired(self) -> bool:
        """Check if message has expired."""
        return time.time() > self.expires_at
    
    @property
    def can_retry(self) -> bool:
        """Check if message can be retried."""
        if self.status != MessageStatus.PENDING:
            return False
        if self.retry_count >= DEFAULT_MAX_RETRIES:
            return False
        if self.next_retry_at and time.time() < self.next_retry_at:
            return False
        return True


class MessageStore:
    """
    Persistent message storage for delay-tolerant delivery.
    
    Usage:
        store = MessageStore()
        
        # Store outgoing message
        store.store_outgoing(message_id, sender_id, recipient_id, payload)
        
        # Get messages to send
        for msg in store.get_pending_messages():
            send(msg)
            store.mark_forwarded(msg.message_id)
        
        # Handle ACK
        store.mark_delivered(message_id)
    """
    
    def __init__(
        self,
        db_path: Optional[Path] = None,
        retention_seconds: int = DEFAULT_RETENTION,
    ):
        """
        Initialize message store.
        
        Args:
            db_path: Path to SQLite database
            retention_seconds: How long to keep messages
        """
        self._db_path = db_path or DEFAULT_STORE_PATH
        self._retention = retention_seconds
        self._lock = threading.RLock()
        
        # Ensure directory exists
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Initialize database
        self._init_db()
    
    def _init_db(self) -> None:
        """Initialize database schema."""
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS messages (
                    message_id BLOB PRIMARY KEY,
                    sender_id BLOB NOT NULL,
                    recipient_id BLOB NOT NULL,
                    payload BLOB NOT NULL,
                    status INTEGER NOT NULL DEFAULT 0,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    next_retry_at REAL,
                    retry_count INTEGER NOT NULL DEFAULT 0,
                    last_error TEXT,
                    delivered_at REAL,
                    ack_received_at REAL
                )
            """)
            
            # Index for efficient queries
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_messages_status
                ON messages(status, next_retry_at)
            """)
            
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_messages_recipient
                ON messages(recipient_id)
            """)
            
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_messages_expires
                ON messages(expires_at)
            """)
            
            conn.commit()
    
    @contextmanager
    def _get_connection(self):
        """Get database connection with context manager."""
        conn = sqlite3.connect(
            str(self._db_path),
            timeout=30.0,
            isolation_level=None,  # Autocommit
        )
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()
    
    def _row_to_message(self, row: sqlite3.Row) -> StoredMessage:
        """Convert database row to StoredMessage."""
        return StoredMessage(
            message_id=row["message_id"],
            sender_id=row["sender_id"],
            recipient_id=row["recipient_id"],
            payload=row["payload"],
            status=MessageStatus(row["status"]),
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            expires_at=row["expires_at"],
            next_retry_at=row["next_retry_at"],
            retry_count=row["retry_count"],
            last_error=row["last_error"],
            delivered_at=row["delivered_at"],
            ack_received_at=row["ack_received_at"],
        )
    
    def store_outgoing(
        self,
        message_id: bytes,
        sender_id: bytes,
        recipient_id: bytes,
        payload: bytes,
        ttl_seconds: Optional[int] = None,
    ) -> StoredMessage:
        """
        Store an outgoing message.
        
        Args:
            message_id: Unique message identifier
            sender_id: Sender's node ID
            recipient_id: Recipient's node ID
            payload: Encrypted message payload
            ttl_seconds: Time-to-live (default: retention time)
            
        Returns:
            StoredMessage: Stored message record
        """
        now = time.time()
        ttl = ttl_seconds or self._retention
        
        with self._lock:
            with self._get_connection() as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO messages
                    (message_id, sender_id, recipient_id, payload, status,
                     created_at, updated_at, expires_at, retry_count)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)
                """, (
                    message_id,
                    sender_id,
                    recipient_id,
                    payload,
                    MessageStatus.PENDING,
                    now,
                    now,
                    now + ttl,
                ))
        
        return StoredMessage(
            message_id=message_id,
            sender_id=sender_id,
            recipient_id=recipient_id,
            payload=payload,
            status=MessageStatus.PENDING,
            created_at=now,
            updated_at=now,
            expires_at=now + ttl,
            next_retry_at=None,
            retry_count=0,
            last_error=None,
            delivered_at=None,
            ack_received_at=None,
        )
    
    def store_incoming(
        self,
        message_id: bytes,
        sender_id: bytes,
        recipient_id: bytes,
        payload: bytes,
    ) -> StoredMessage:
        """
        Store an incoming message (for inbox).
        
        Args:
            message_id: Unique message identifier
            sender_id: Sender's node ID
            recipient_id: Recipient's node ID (should be us)
            payload: Encrypted message payload
            
        Returns:
            StoredMessage: Stored message record
        """
        now = time.time()
        
        with self._lock:
            with self._get_connection() as conn:
                conn.execute("""
                    INSERT OR IGNORE INTO messages
                    (message_id, sender_id, recipient_id, payload, status,
                     created_at, updated_at, expires_at, delivered_at, retry_count)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
                """, (
                    message_id,
                    sender_id,
                    recipient_id,
                    payload,
                    MessageStatus.DELIVERED,
                    now,
                    now,
                    now + self._retention,
                    now,
                ))
        
        return StoredMessage(
            message_id=message_id,
            sender_id=sender_id,
            recipient_id=recipient_id,
            payload=payload,
            status=MessageStatus.DELIVERED,
            created_at=now,
            updated_at=now,
            expires_at=now + self._retention,
            next_retry_at=None,
            retry_count=0,
            last_error=None,
            delivered_at=now,
            ack_received_at=None,
        )
    
    def get_message(self, message_id: bytes) -> Optional[StoredMessage]:
        """Get a message by ID."""
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM messages WHERE message_id = ?",
                (message_id,)
            ).fetchone()
            
            if row:
                return self._row_to_message(row)
            return None
    
    def get_pending_messages(self, limit: int = 100) -> List[StoredMessage]:
        """
        Get messages pending delivery.
        
        Returns messages that:
        - Are in PENDING status
        - Have not exceeded retry limit
        - Are due for retry (or never tried)
        - Have not expired
        
        Args:
            limit: Maximum number of messages to return
            
        Returns:
            List of messages ready for delivery attempt
        """
        now = time.time()
        
        with self._get_connection() as conn:
            rows = conn.execute("""
                SELECT * FROM messages
                WHERE status = ?
                  AND retry_count < ?
                  AND (next_retry_at IS NULL OR next_retry_at <= ?)
                  AND expires_at > ?
                ORDER BY created_at ASC
                LIMIT ?
            """, (
                MessageStatus.PENDING,
                DEFAULT_MAX_RETRIES,
                now,
                now,
                limit,
            )).fetchall()
            
            return [self._row_to_message(row) for row in rows]
    
    def get_inbox(self, recipient_id: bytes, limit: int = 100) -> List[StoredMessage]:
        """
        Get received messages for a recipient.
        
        Args:
            recipient_id: Recipient's node ID
            limit: Maximum number of messages
            
        Returns:
            List of received messages
        """
        with self._get_connection() as conn:
            rows = conn.execute("""
                SELECT * FROM messages
                WHERE recipient_id = ?
                  AND status = ?
                ORDER BY delivered_at DESC
                LIMIT ?
            """, (recipient_id, MessageStatus.DELIVERED, limit)).fetchall()
            
            return [self._row_to_message(row) for row in rows]
    
    def mark_forwarded(self, message_id: bytes) -> None:
        """Mark message as forwarded (awaiting ACK)."""
        now = time.time()
        
        with self._lock:
            with self._get_connection() as conn:
                conn.execute("""
                    UPDATE messages
                    SET status = ?, updated_at = ?, retry_count = retry_count + 1
                    WHERE message_id = ?
                """, (MessageStatus.FORWARDED, now, message_id))
    
    def mark_delivered(self, message_id: bytes) -> None:
        """Mark message as successfully delivered."""
        now = time.time()
        
        with self._lock:
            with self._get_connection() as conn:
                conn.execute("""
                    UPDATE messages
                    SET status = ?, updated_at = ?, ack_received_at = ?
                    WHERE message_id = ?
                """, (MessageStatus.DELIVERED, now, now, message_id))
    
    def mark_failed(self, message_id: bytes, error: str) -> None:
        """Mark message as failed."""
        now = time.time()
        
        with self._lock:
            with self._get_connection() as conn:
                conn.execute("""
                    UPDATE messages
                    SET status = ?, updated_at = ?, last_error = ?
                    WHERE message_id = ?
                """, (MessageStatus.FAILED, now, error, message_id))
    
    def schedule_retry(self, message_id: bytes, error: Optional[str] = None) -> None:
        """
        Schedule message for retry with exponential backoff.
        
        Args:
            message_id: Message to retry
            error: Optional error message
        """
        now = time.time()
        
        with self._lock:
            with self._get_connection() as conn:
                # Get current retry count
                row = conn.execute(
                    "SELECT retry_count FROM messages WHERE message_id = ?",
                    (message_id,)
                ).fetchone()
                
                if not row:
                    return
                
                retry_count = row["retry_count"]
                
                # Calculate next retry time with exponential backoff
                backoff = RETRY_BACKOFF_BASE * (2 ** min(retry_count, 8))
                next_retry = now + backoff
                
                conn.execute("""
                    UPDATE messages
                    SET status = ?, updated_at = ?, next_retry_at = ?,
                        retry_count = retry_count + 1, last_error = ?
                    WHERE message_id = ?
                """, (MessageStatus.PENDING, now, next_retry, error, message_id))
    
    def cleanup_expired(self) -> int:
        """
        Remove expired messages.
        
        Returns:
            Number of messages removed
        """
        now = time.time()
        
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.execute(
                    "DELETE FROM messages WHERE expires_at < ?",
                    (now,)
                )
                return cursor.rowcount
    
    def get_stats(self) -> dict:
        """Get storage statistics."""
        with self._get_connection() as conn:
            stats = {}
            
            # Count by status
            for status in MessageStatus:
                row = conn.execute(
                    "SELECT COUNT(*) as count FROM messages WHERE status = ?",
                    (status,)
                ).fetchone()
                stats[f"status_{status.name.lower()}"] = row["count"]
            
            # Total count
            row = conn.execute("SELECT COUNT(*) as count FROM messages").fetchone()
            stats["total"] = row["count"]
            
            # Database size
            stats["db_path"] = str(self._db_path)
            if self._db_path.exists():
                stats["db_size_bytes"] = self._db_path.stat().st_size
            
            return stats
    
    def close(self) -> None:
        """Close the message store."""
        # SQLite connections are closed after each operation
        pass
