"""
Security Audit Logging with Cryptographic Integrity

Provides tamper-evident, append-only audit logging with hash chain integrity.
All security-sensitive operations are logged with full context.

Features:
- Hash chain: Each entry's hash includes previous entry's hash
- Merkle checkpoints: Efficient verification of log segments
- Rich metadata: Category, severity, source, operator tracking
- GUID linking: Events linked to entities across key rotations

Event Categories:
- security: Key rotations, access changes, encryption operations
- configuration: Peer add/remove, config deployment
- access: Login attempts, API token usage
- system: Startup, shutdown, errors

Usage:
    from audit_log import AuditLogger, EventType, Severity

    logger = AuditLogger(db_path)

    # Log an event
    logger.log(
        event_type=EventType.KEY_ROTATION,
        entity_type='remote',
        entity_id=5,
        entity_guid='abc123...',
        details={'old_key': 'xxx...', 'new_key': 'yyy...'},
        operator='cli'
    )

    # Verify integrity
    valid, message = logger.verify_integrity()
"""

import hashlib
import json
import logging
import os
import sqlite3
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple
from dataclasses import dataclass, asdict

logger = logging.getLogger(__name__)


class EventType(str, Enum):
    """Audit event types"""
    # Security events
    KEY_ROTATION = "key_rotation"
    ACCESS_LEVEL_CHANGE = "access_level_change"
    ENCRYPTION_ENABLED = "encryption_enabled"
    ENCRYPTION_DISABLED = "encryption_disabled"
    PASSPHRASE_CHANGED = "passphrase_changed"

    # Configuration events
    PEER_ADDED = "peer_added"
    PEER_REMOVED = "peer_removed"
    PEER_UPDATED = "peer_updated"
    CONFIG_DEPLOYED = "config_deployed"
    CONFIG_GENERATED = "config_generated"
    EXIT_NODE_ASSIGNED = "exit_node_assigned"
    FAILOVER_TRIGGERED = "failover_triggered"

    # Access events
    DATABASE_UNLOCKED = "database_unlocked"
    DATABASE_LOCKED = "database_locked"
    API_TOKEN_CREATED = "api_token_created"
    API_TOKEN_REVOKED = "api_token_revoked"

    # System events
    SYSTEM_STARTUP = "system_startup"
    SYSTEM_SHUTDOWN = "system_shutdown"
    BACKUP_CREATED = "backup_created"
    BACKUP_RESTORED = "backup_restored"
    IMPORT_COMPLETED = "import_completed"
    ERROR_OCCURRED = "error_occurred"


class EventCategory(str, Enum):
    """Event categories for filtering and reporting"""
    SECURITY = "security"
    CONFIGURATION = "configuration"
    ACCESS = "access"
    SYSTEM = "system"


class Severity(str, Enum):
    """Event severity levels"""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


# Map event types to categories and default severity
EVENT_METADATA = {
    EventType.KEY_ROTATION: (EventCategory.SECURITY, Severity.INFO),
    EventType.ACCESS_LEVEL_CHANGE: (EventCategory.SECURITY, Severity.WARNING),
    EventType.ENCRYPTION_ENABLED: (EventCategory.SECURITY, Severity.CRITICAL),
    EventType.ENCRYPTION_DISABLED: (EventCategory.SECURITY, Severity.CRITICAL),
    EventType.PASSPHRASE_CHANGED: (EventCategory.SECURITY, Severity.CRITICAL),

    EventType.PEER_ADDED: (EventCategory.CONFIGURATION, Severity.INFO),
    EventType.PEER_REMOVED: (EventCategory.CONFIGURATION, Severity.WARNING),
    EventType.PEER_UPDATED: (EventCategory.CONFIGURATION, Severity.INFO),
    EventType.CONFIG_DEPLOYED: (EventCategory.CONFIGURATION, Severity.INFO),
    EventType.CONFIG_GENERATED: (EventCategory.CONFIGURATION, Severity.INFO),
    EventType.EXIT_NODE_ASSIGNED: (EventCategory.CONFIGURATION, Severity.INFO),
    EventType.FAILOVER_TRIGGERED: (EventCategory.CONFIGURATION, Severity.WARNING),

    EventType.DATABASE_UNLOCKED: (EventCategory.ACCESS, Severity.INFO),
    EventType.DATABASE_LOCKED: (EventCategory.ACCESS, Severity.INFO),
    EventType.API_TOKEN_CREATED: (EventCategory.ACCESS, Severity.WARNING),
    EventType.API_TOKEN_REVOKED: (EventCategory.ACCESS, Severity.WARNING),

    EventType.SYSTEM_STARTUP: (EventCategory.SYSTEM, Severity.INFO),
    EventType.SYSTEM_SHUTDOWN: (EventCategory.SYSTEM, Severity.INFO),
    EventType.BACKUP_CREATED: (EventCategory.SYSTEM, Severity.INFO),
    EventType.BACKUP_RESTORED: (EventCategory.SYSTEM, Severity.WARNING),
    EventType.IMPORT_COMPLETED: (EventCategory.SYSTEM, Severity.INFO),
    EventType.ERROR_OCCURRED: (EventCategory.SYSTEM, Severity.WARNING),
}


@dataclass
class AuditEntry:
    """Represents a single audit log entry"""
    id: int
    event_type: str
    event_category: str
    severity: str
    entity_type: Optional[str]
    entity_id: Optional[int]
    entity_permanent_guid: Optional[str]
    operator: str
    operator_ip: Optional[str]
    operator_source: str
    details: Dict[str, Any]
    timestamp: str
    entry_hash: str
    previous_hash: Optional[str]
    client_version: str


class AuditLogger:
    """
    Tamper-evident audit logging with hash chain integrity.

    Each log entry includes:
    - SHA-256 hash of entry contents
    - Reference to previous entry's hash (chain)
    - Rich metadata for compliance reporting
    """

    # Current client version (update with releases)
    CLIENT_VERSION = "1.2.0"

    # Checkpoint frequency (entries between checkpoints)
    CHECKPOINT_INTERVAL = 1000

    def __init__(self, db_path: Path | str):
        self.db_path = Path(db_path) if isinstance(db_path, str) else db_path
        self._init_schema()

    def _get_connection(self):
        """Get database connection"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def _init_schema(self):
        """Initialize audit log schema"""
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            # Main audit log table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY,

                    -- What happened
                    event_type TEXT NOT NULL,
                    event_category TEXT NOT NULL,
                    severity TEXT NOT NULL,

                    -- Who/what it affected
                    entity_type TEXT,
                    entity_id INTEGER,
                    entity_permanent_guid TEXT,

                    -- Who did it
                    operator TEXT NOT NULL,
                    operator_ip TEXT,
                    operator_source TEXT NOT NULL,

                    -- Details
                    details TEXT NOT NULL,

                    -- When
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

                    -- Cryptographic integrity (hash chain)
                    entry_hash TEXT NOT NULL,
                    previous_hash TEXT,

                    -- Merkle tree positioning
                    merkle_root TEXT,
                    merkle_tree_index INTEGER,

                    -- Metadata
                    client_version TEXT NOT NULL,
                    schema_version INTEGER DEFAULT 1
                )
            """)

            # Merkle tree checkpoints
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS audit_checkpoint (
                    id INTEGER PRIMARY KEY,
                    start_entry_id INTEGER NOT NULL,
                    end_entry_id INTEGER NOT NULL,
                    entry_count INTEGER NOT NULL,
                    merkle_root TEXT NOT NULL,
                    checkpoint_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (start_entry_id) REFERENCES audit_log(id),
                    FOREIGN KEY (end_entry_id) REFERENCES audit_log(id)
                )
            """)

            # Indexes for efficient queries
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_audit_timestamp
                ON audit_log(timestamp DESC)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_audit_entity
                ON audit_log(entity_type, entity_id, timestamp DESC)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_audit_operator
                ON audit_log(operator, timestamp DESC)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_audit_category
                ON audit_log(event_category, severity, timestamp DESC)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_audit_guid
                ON audit_log(entity_permanent_guid, timestamp DESC)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_audit_event_type
                ON audit_log(event_type, timestamp DESC)
            """)

            conn.commit()
            logger.debug("Audit log schema initialized")

        finally:
            conn.close()

    def _compute_entry_hash(
        self,
        entry_id: int,
        event_type: str,
        timestamp: str,
        details: str,
        previous_hash: Optional[str]
    ) -> str:
        """
        Compute SHA-256 hash for entry.

        Hash includes:
        - Entry ID
        - Event type
        - Timestamp
        - Details JSON
        - Previous entry's hash (chain link)
        """
        hash_input = f"{entry_id}|{event_type}|{timestamp}|{details}|{previous_hash or 'genesis'}"
        return hashlib.sha256(hash_input.encode('utf-8')).hexdigest()

    def _get_previous_hash(self, conn) -> Optional[str]:
        """Get hash of most recent entry"""
        cursor = conn.cursor()
        cursor.execute("""
            SELECT entry_hash FROM audit_log
            ORDER BY id DESC LIMIT 1
        """)
        row = cursor.fetchone()
        return row['entry_hash'] if row else None

    def _get_next_id(self, conn) -> int:
        """Get next entry ID"""
        cursor = conn.cursor()
        cursor.execute("SELECT MAX(id) FROM audit_log")
        row = cursor.fetchone()
        return (row[0] or 0) + 1

    def log(
        self,
        event_type: EventType,
        details: Dict[str, Any],
        entity_type: Optional[str] = None,
        entity_id: Optional[int] = None,
        entity_guid: Optional[str] = None,
        operator: str = "system",
        operator_ip: Optional[str] = None,
        operator_source: str = "cli",
        severity: Optional[Severity] = None
    ) -> int:
        """
        Log an audit event.

        Args:
            event_type: Type of event (from EventType enum)
            details: Dict with event-specific details
            entity_type: Type of affected entity (remote, subnet_router, etc.)
            entity_id: ID of affected entity
            entity_guid: Permanent GUID of affected entity
            operator: Who performed the action
            operator_ip: IP address of operator
            operator_source: Source of action (cli, api, web_ui)
            severity: Override default severity

        Returns:
            ID of created audit entry
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            # Get category and default severity
            category, default_severity = EVENT_METADATA.get(
                event_type,
                (EventCategory.SYSTEM, Severity.INFO)
            )
            actual_severity = severity or default_severity

            # Get previous hash and next ID
            previous_hash = self._get_previous_hash(conn)
            next_id = self._get_next_id(conn)

            # Generate timestamp
            timestamp = datetime.utcnow().isoformat() + 'Z'

            # Serialize details
            details_json = json.dumps(details, sort_keys=True, default=str)

            # Compute entry hash
            entry_hash = self._compute_entry_hash(
                next_id, event_type.value, timestamp, details_json, previous_hash
            )

            # Insert entry
            cursor.execute("""
                INSERT INTO audit_log (
                    id, event_type, event_category, severity,
                    entity_type, entity_id, entity_permanent_guid,
                    operator, operator_ip, operator_source,
                    details, timestamp, entry_hash, previous_hash,
                    client_version
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                next_id, event_type.value, category.value, actual_severity.value,
                entity_type, entity_id, entity_guid,
                operator, operator_ip, operator_source,
                details_json, timestamp, entry_hash, previous_hash,
                self.CLIENT_VERSION
            ))

            conn.commit()

            # Check if checkpoint needed
            if next_id % self.CHECKPOINT_INTERVAL == 0:
                self._create_checkpoint(conn, next_id)

            logger.debug(f"Audit log entry {next_id}: {event_type.value}")
            return next_id

        except Exception as e:
            conn.rollback()
            logger.error(f"Failed to log audit event: {e}")
            raise
        finally:
            conn.close()

    def _create_checkpoint(self, conn, end_id: int):
        """Create Merkle checkpoint for verification efficiency"""
        cursor = conn.cursor()

        # Find start of this checkpoint range
        cursor.execute("""
            SELECT MAX(end_entry_id) FROM audit_checkpoint
        """)
        row = cursor.fetchone()
        start_id = (row[0] or 0) + 1

        # Get all entry hashes in range
        cursor.execute("""
            SELECT entry_hash FROM audit_log
            WHERE id >= ? AND id <= ?
            ORDER BY id
        """, (start_id, end_id))

        hashes = [row['entry_hash'] for row in cursor.fetchall()]

        if not hashes:
            return

        # Compute Merkle root
        merkle_root = self._compute_merkle_root(hashes)

        # Insert checkpoint
        cursor.execute("""
            INSERT INTO audit_checkpoint (
                start_entry_id, end_entry_id, entry_count, merkle_root
            ) VALUES (?, ?, ?, ?)
        """, (start_id, end_id, len(hashes), merkle_root))

        conn.commit()
        logger.info(f"Created audit checkpoint: entries {start_id}-{end_id}")

    def _compute_merkle_root(self, hashes: List[str]) -> str:
        """Compute Merkle tree root from list of hashes"""
        if not hashes:
            return hashlib.sha256(b'empty').hexdigest()

        if len(hashes) == 1:
            return hashes[0]

        # Pad to even length
        if len(hashes) % 2 != 0:
            hashes.append(hashes[-1])

        # Build tree level by level
        while len(hashes) > 1:
            next_level = []
            for i in range(0, len(hashes), 2):
                combined = hashes[i] + hashes[i + 1]
                next_level.append(
                    hashlib.sha256(combined.encode('utf-8')).hexdigest()
                )
            hashes = next_level

        return hashes[0]

    def verify_integrity(self, start_id: Optional[int] = None, end_id: Optional[int] = None) -> Tuple[bool, str]:
        """
        Verify audit log integrity.

        Checks:
        1. Hash chain is unbroken
        2. Entry hashes match computed values
        3. Checkpoint Merkle roots are valid

        Returns:
            (is_valid, message)
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            # Build query
            query = "SELECT * FROM audit_log"
            params = []

            if start_id is not None or end_id is not None:
                conditions = []
                if start_id is not None:
                    conditions.append("id >= ?")
                    params.append(start_id)
                if end_id is not None:
                    conditions.append("id <= ?")
                    params.append(end_id)
                query += " WHERE " + " AND ".join(conditions)

            query += " ORDER BY id"

            cursor.execute(query, params)
            entries = cursor.fetchall()

            if not entries:
                return True, "No entries to verify"

            # Verify hash chain
            expected_prev_hash = None
            for entry in entries:
                # Check previous hash link
                if entry['previous_hash'] != expected_prev_hash:
                    return False, f"Hash chain broken at entry {entry['id']}: expected previous_hash '{expected_prev_hash}', got '{entry['previous_hash']}'"

                # Verify entry hash
                computed_hash = self._compute_entry_hash(
                    entry['id'],
                    entry['event_type'],
                    entry['timestamp'],
                    entry['details'],
                    entry['previous_hash']
                )

                if entry['entry_hash'] != computed_hash:
                    return False, f"Entry hash mismatch at entry {entry['id']}: stored '{entry['entry_hash']}', computed '{computed_hash}'"

                expected_prev_hash = entry['entry_hash']

            # Verify checkpoints
            cursor.execute("SELECT * FROM audit_checkpoint ORDER BY id")
            checkpoints = cursor.fetchall()

            for checkpoint in checkpoints:
                cursor.execute("""
                    SELECT entry_hash FROM audit_log
                    WHERE id >= ? AND id <= ?
                    ORDER BY id
                """, (checkpoint['start_entry_id'], checkpoint['end_entry_id']))

                hashes = [row['entry_hash'] for row in cursor.fetchall()]
                computed_root = self._compute_merkle_root(hashes)

                if checkpoint['merkle_root'] != computed_root:
                    return False, f"Checkpoint {checkpoint['id']} Merkle root mismatch"

            return True, f"Verified {len(entries)} entries, {len(checkpoints)} checkpoints"

        finally:
            conn.close()

    def get_entries(
        self,
        event_type: Optional[EventType] = None,
        category: Optional[EventCategory] = None,
        severity: Optional[Severity] = None,
        entity_type: Optional[str] = None,
        entity_guid: Optional[str] = None,
        operator: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[AuditEntry]:
        """
        Query audit log entries with filters.

        Returns list of AuditEntry objects.
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            query = "SELECT * FROM audit_log WHERE 1=1"
            params = []

            if event_type:
                query += " AND event_type = ?"
                params.append(event_type.value)

            if category:
                query += " AND event_category = ?"
                params.append(category.value)

            if severity:
                query += " AND severity = ?"
                params.append(severity.value)

            if entity_type:
                query += " AND entity_type = ?"
                params.append(entity_type)

            if entity_guid:
                query += " AND entity_permanent_guid = ?"
                params.append(entity_guid)

            if operator:
                query += " AND operator = ?"
                params.append(operator)

            if start_time:
                query += " AND timestamp >= ?"
                params.append(start_time.isoformat())

            if end_time:
                query += " AND timestamp <= ?"
                params.append(end_time.isoformat())

            query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])

            cursor.execute(query, params)

            entries = []
            for row in cursor.fetchall():
                entries.append(AuditEntry(
                    id=row['id'],
                    event_type=row['event_type'],
                    event_category=row['event_category'],
                    severity=row['severity'],
                    entity_type=row['entity_type'],
                    entity_id=row['entity_id'],
                    entity_permanent_guid=row['entity_permanent_guid'],
                    operator=row['operator'],
                    operator_ip=row['operator_ip'],
                    operator_source=row['operator_source'],
                    details=json.loads(row['details']),
                    timestamp=row['timestamp'],
                    entry_hash=row['entry_hash'],
                    previous_hash=row['previous_hash'],
                    client_version=row['client_version']
                ))

            return entries

        finally:
            conn.close()

    def get_entity_history(self, entity_guid: str, limit: int = 50) -> List[AuditEntry]:
        """Get all audit entries for a specific entity"""
        return self.get_entries(entity_guid=entity_guid, limit=limit)

    def get_recent_security_events(self, limit: int = 20) -> List[AuditEntry]:
        """Get recent security-related events"""
        return self.get_entries(category=EventCategory.SECURITY, limit=limit)

    def get_recent_critical_events(self, limit: int = 20) -> List[AuditEntry]:
        """Get recent critical severity events"""
        return self.get_entries(severity=Severity.CRITICAL, limit=limit)

    def export_json(
        self,
        output_path: Path,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None
    ) -> int:
        """
        Export audit log to JSON file.

        Returns number of entries exported.
        """
        entries = self.get_entries(
            start_time=start_time,
            end_time=end_time,
            limit=1000000  # Effectively unlimited
        )

        export_data = {
            'export_timestamp': datetime.utcnow().isoformat() + 'Z',
            'entry_count': len(entries),
            'start_time': start_time.isoformat() if start_time else None,
            'end_time': end_time.isoformat() if end_time else None,
            'entries': [asdict(e) for e in entries]
        }

        with open(output_path, 'w') as f:
            json.dump(export_data, f, indent=2, default=str)

        logger.info(f"Exported {len(entries)} audit entries to {output_path}")
        return len(entries)

    def get_statistics(self) -> Dict[str, Any]:
        """Get audit log statistics"""
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            stats = {}

            # Total entries
            cursor.execute("SELECT COUNT(*) FROM audit_log")
            stats['total_entries'] = cursor.fetchone()[0]

            # Entries by category
            cursor.execute("""
                SELECT event_category, COUNT(*) as count
                FROM audit_log GROUP BY event_category
            """)
            stats['by_category'] = {
                row['event_category']: row['count']
                for row in cursor.fetchall()
            }

            # Entries by severity
            cursor.execute("""
                SELECT severity, COUNT(*) as count
                FROM audit_log GROUP BY severity
            """)
            stats['by_severity'] = {
                row['severity']: row['count']
                for row in cursor.fetchall()
            }

            # Recent activity (last 24 hours)
            cursor.execute("""
                SELECT COUNT(*) FROM audit_log
                WHERE timestamp > datetime('now', '-1 day')
            """)
            stats['last_24h'] = cursor.fetchone()[0]

            # Oldest and newest entries
            cursor.execute("SELECT MIN(timestamp), MAX(timestamp) FROM audit_log")
            row = cursor.fetchone()
            stats['oldest_entry'] = row[0]
            stats['newest_entry'] = row[1]

            # Checkpoint count
            cursor.execute("SELECT COUNT(*) FROM audit_checkpoint")
            stats['checkpoint_count'] = cursor.fetchone()[0]

            return stats

        finally:
            conn.close()


# Convenience functions for common logging operations
_default_logger: Optional[AuditLogger] = None


def set_default_audit_logger(logger: AuditLogger):
    """Set the default audit logger for the session"""
    global _default_logger
    _default_logger = logger


def get_default_audit_logger() -> Optional[AuditLogger]:
    """Get the default audit logger"""
    return _default_logger


def audit_log(
    event_type: EventType,
    details: Dict[str, Any],
    **kwargs
) -> Optional[int]:
    """Log an audit event using the default logger"""
    if _default_logger:
        return _default_logger.log(event_type, details, **kwargs)
    return None


# Decorator for automatic audit logging
def audited(event_type: EventType, entity_arg: str = None, details_fn=None):
    """
    Decorator to automatically audit function calls.

    Usage:
        @audited(EventType.PEER_ADDED, entity_arg='hostname')
        def add_peer(hostname: str, access_level: str):
            ...
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            # Execute function
            result = func(*args, **kwargs)

            # Log if logger available
            if _default_logger:
                details = details_fn(result) if details_fn else {'result': str(result)}
                entity_guid = kwargs.get(entity_arg) if entity_arg else None

                _default_logger.log(
                    event_type=event_type,
                    details=details,
                    entity_guid=entity_guid,
                    operator_source='cli'
                )

            return result
        return wrapper
    return decorator


if __name__ == "__main__":
    # Demo/test
    import tempfile

    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
        db_path = Path(f.name)

    try:
        print("=== Audit Logging Demo ===\n")

        logger = AuditLogger(db_path)

        # Log some events
        print("Logging events...")

        logger.log(
            EventType.SYSTEM_STARTUP,
            details={'version': '1.2.0', 'build': 'harrier'},
            operator='system',
            operator_source='cli'
        )

        logger.log(
            EventType.PEER_ADDED,
            details={'hostname': 'alice-laptop', 'access_level': 'full_access'},
            entity_type='remote',
            entity_id=1,
            entity_guid='abc123...',
            operator='root',
            operator_source='cli'
        )

        logger.log(
            EventType.KEY_ROTATION,
            details={
                'old_key': 'xxx...',
                'new_key': 'yyy...',
                'reason': 'routine_rotation'
            },
            entity_type='remote',
            entity_id=1,
            entity_guid='abc123...',
            operator='root',
            operator_source='cli'
        )

        logger.log(
            EventType.ENCRYPTION_ENABLED,
            details={'algorithm': 'AES-256-GCM', 'keys_encrypted': 12},
            operator='root',
            operator_source='cli'
        )

        print(f"Logged 4 events\n")

        # Verify integrity
        print("Verifying integrity...")
        is_valid, message = logger.verify_integrity()
        print(f"Valid: {is_valid}")
        print(f"Message: {message}\n")

        # Get statistics
        print("Statistics:")
        stats = logger.get_statistics()
        print(f"  Total entries: {stats['total_entries']}")
        print(f"  By category: {stats['by_category']}")
        print(f"  By severity: {stats['by_severity']}\n")

        # Query events
        print("Recent security events:")
        events = logger.get_recent_security_events(limit=5)
        for e in events:
            print(f"  [{e.severity}] {e.event_type}: {e.details}")

        print("\nEntity history for abc123...:")
        history = logger.get_entity_history('abc123...')
        for e in history:
            print(f"  {e.timestamp}: {e.event_type}")

        # Export
        export_path = db_path.with_suffix('.json')
        count = logger.export_json(export_path)
        print(f"\nExported {count} entries to {export_path}")

        # Cleanup export file
        export_path.unlink()

    finally:
        db_path.unlink()
        print("\nDemo complete!")
