"""
PSK (Pre-Shared Key) Management Automation for WireGuard Friend.

Automates the lifecycle of WireGuard pre-shared keys:
- PSK generation using cryptographically secure random
- PSK rotation with configurable schedules
- Per-peer or group-based PSK policies
- PSK distribution tracking
- Compliance reporting for PSK usage

Pre-shared keys add post-quantum resistance to WireGuard connections.
"""

import sqlite3
import secrets
import base64
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum


class PSKPolicy(Enum):
    """PSK usage policies."""
    NONE = "none"           # No PSK (not recommended)
    OPTIONAL = "optional"   # PSK if configured
    REQUIRED = "required"   # PSK mandatory
    UNIQUE = "unique"       # Unique PSK per peer pair


class PSKRotationTrigger(Enum):
    """Triggers for PSK rotation."""
    MANUAL = "manual"
    TIME_BASED = "time_based"
    KEY_ROTATION = "key_rotation"  # Rotate PSK when main keys rotate
    SECURITY_EVENT = "security_event"


@dataclass
class PSKConfig:
    """PSK configuration for a peer or group."""
    id: Optional[int] = None
    entity_type: str = ""  # 'remote', 'subnet_router', 'exit_node', 'group'
    entity_id: Optional[int] = None  # None for groups
    group_name: Optional[str] = None  # For group-based PSK
    policy: PSKPolicy = PSKPolicy.REQUIRED
    rotation_days: int = 90  # Days between rotation
    last_rotation: Optional[datetime] = None
    next_rotation: Optional[datetime] = None
    notify_before_days: int = 7  # Days before rotation to notify


@dataclass
class PSKEntry:
    """A pre-shared key entry."""
    id: Optional[int] = None
    peer1_type: str = ""  # Entity type of first peer
    peer1_id: int = 0     # Entity ID of first peer
    peer2_type: str = ""  # Entity type of second peer (usually CS)
    peer2_id: int = 0     # Entity ID of second peer
    psk_hash: str = ""    # SHA-256 hash (we don't store actual PSK)
    created_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    rotation_count: int = 0
    distributed_to_peer1: bool = False
    distributed_to_peer2: bool = False
    distribution_method: str = ""  # 'manual', 'qr', 'ssh', 'api'


class PSKManager:
    """Manages pre-shared keys for WireGuard peers."""

    SCHEMA = """
    CREATE TABLE IF NOT EXISTS psk_config (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        entity_type TEXT NOT NULL,
        entity_id INTEGER,
        group_name TEXT,
        policy TEXT NOT NULL DEFAULT 'required',
        rotation_days INTEGER NOT NULL DEFAULT 90,
        last_rotation TEXT,
        next_rotation TEXT,
        notify_before_days INTEGER NOT NULL DEFAULT 7,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS psk_entry (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        peer1_type TEXT NOT NULL,
        peer1_id INTEGER NOT NULL,
        peer2_type TEXT NOT NULL,
        peer2_id INTEGER NOT NULL,
        psk_hash TEXT NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT,
        rotation_count INTEGER NOT NULL DEFAULT 0,
        distributed_to_peer1 INTEGER NOT NULL DEFAULT 0,
        distributed_to_peer2 INTEGER NOT NULL DEFAULT 0,
        distribution_method TEXT,
        UNIQUE(peer1_type, peer1_id, peer2_type, peer2_id)
    );

    CREATE TABLE IF NOT EXISTS psk_rotation_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        psk_entry_id INTEGER NOT NULL,
        old_psk_hash TEXT NOT NULL,
        new_psk_hash TEXT NOT NULL,
        trigger TEXT NOT NULL,
        rotated_at TEXT NOT NULL,
        rotated_by TEXT,
        FOREIGN KEY (psk_entry_id) REFERENCES psk_entry(id)
    );

    CREATE TABLE IF NOT EXISTS psk_distribution_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        psk_entry_id INTEGER NOT NULL,
        target_type TEXT NOT NULL,
        target_id INTEGER NOT NULL,
        method TEXT NOT NULL,
        success INTEGER NOT NULL,
        error_message TEXT,
        distributed_at TEXT NOT NULL,
        FOREIGN KEY (psk_entry_id) REFERENCES psk_entry(id)
    );

    CREATE INDEX IF NOT EXISTS idx_psk_entry_peers
        ON psk_entry(peer1_type, peer1_id, peer2_type, peer2_id);
    CREATE INDEX IF NOT EXISTS idx_psk_entry_expires
        ON psk_entry(expires_at);
    """

    def __init__(self, db_path: str):
        """Initialize the PSK manager.

        Args:
            db_path: Path to the database
        """
        self.db_path = db_path
        self._init_schema()

    def _get_connection(self) -> sqlite3.Connection:
        """Get a database connection."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self):
        """Initialize database schema."""
        conn = self._get_connection()
        conn.executescript(self.SCHEMA)
        conn.commit()
        conn.close()

    @staticmethod
    def generate_psk() -> str:
        """Generate a new WireGuard PSK.

        Returns:
            Base64-encoded 256-bit PSK (WireGuard format)
        """
        # WireGuard PSKs are 256 bits (32 bytes)
        psk_bytes = secrets.token_bytes(32)
        return base64.b64encode(psk_bytes).decode('ascii')

    @staticmethod
    def hash_psk(psk: str) -> str:
        """Hash a PSK for storage (we don't store actual PSKs).

        Args:
            psk: The PSK to hash

        Returns:
            SHA-256 hash of the PSK
        """
        return hashlib.sha256(psk.encode()).hexdigest()

    def set_policy(self, entity_type: str, entity_id: Optional[int] = None,
                   group_name: Optional[str] = None,
                   policy: PSKPolicy = PSKPolicy.REQUIRED,
                   rotation_days: int = 90,
                   notify_before_days: int = 7) -> int:
        """Set PSK policy for an entity or group.

        Args:
            entity_type: Type of entity ('remote', 'subnet_router', 'exit_node', 'group')
            entity_id: ID of specific entity (None for groups)
            group_name: Name of group (for group policies)
            policy: PSK policy to apply
            rotation_days: Days between rotation
            notify_before_days: Days before rotation to notify

        Returns:
            Policy config ID
        """
        conn = self._get_connection()
        now = datetime.now()

        # Check for existing policy
        if entity_id:
            existing = conn.execute("""
                SELECT id FROM psk_config
                WHERE entity_type = ? AND entity_id = ?
            """, (entity_type, entity_id)).fetchone()
        elif group_name:
            existing = conn.execute("""
                SELECT id FROM psk_config
                WHERE entity_type = 'group' AND group_name = ?
            """, (group_name,)).fetchone()
        else:
            existing = None

        if existing:
            conn.execute("""
                UPDATE psk_config SET
                    policy = ?, rotation_days = ?, notify_before_days = ?,
                    updated_at = ?
                WHERE id = ?
            """, (policy.value, rotation_days, notify_before_days,
                  now.isoformat(), existing['id']))
            config_id = existing['id']
        else:
            cursor = conn.execute("""
                INSERT INTO psk_config
                (entity_type, entity_id, group_name, policy, rotation_days,
                 notify_before_days, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (entity_type, entity_id, group_name, policy.value,
                  rotation_days, notify_before_days, now.isoformat(), now.isoformat()))
            config_id = cursor.lastrowid

        conn.commit()
        conn.close()
        return config_id

    def get_policy(self, entity_type: str, entity_id: int) -> Optional[PSKConfig]:
        """Get PSK policy for an entity.

        Args:
            entity_type: Type of entity
            entity_id: ID of entity

        Returns:
            PSKConfig or None
        """
        conn = self._get_connection()

        # First check for specific entity policy
        row = conn.execute("""
            SELECT * FROM psk_config
            WHERE entity_type = ? AND entity_id = ?
        """, (entity_type, entity_id)).fetchone()

        if not row:
            # Check for group-wide policy
            row = conn.execute("""
                SELECT * FROM psk_config
                WHERE entity_type = 'group' AND group_name = ?
            """, (entity_type,)).fetchone()

        conn.close()

        if not row:
            return None

        return PSKConfig(
            id=row['id'],
            entity_type=row['entity_type'],
            entity_id=row['entity_id'],
            group_name=row['group_name'],
            policy=PSKPolicy(row['policy']),
            rotation_days=row['rotation_days'],
            last_rotation=datetime.fromisoformat(row['last_rotation']) if row['last_rotation'] else None,
            next_rotation=datetime.fromisoformat(row['next_rotation']) if row['next_rotation'] else None,
            notify_before_days=row['notify_before_days']
        )

    def create_psk(self, peer1_type: str, peer1_id: int,
                   peer2_type: str, peer2_id: int,
                   expiry_days: Optional[int] = None) -> Tuple[str, int]:
        """Create a new PSK for a peer pair.

        Args:
            peer1_type: Type of first peer
            peer1_id: ID of first peer
            peer2_type: Type of second peer
            peer2_id: ID of second peer
            expiry_days: Days until PSK expires (None = no expiry)

        Returns:
            Tuple of (PSK, entry_id) - PSK is only returned once!
        """
        psk = self.generate_psk()
        psk_hash = self.hash_psk(psk)

        conn = self._get_connection()
        now = datetime.now()
        expires_at = (now + timedelta(days=expiry_days)).isoformat() if expiry_days else None

        # Normalize peer order (smaller type first, or smaller ID if same type)
        if (peer1_type > peer2_type) or (peer1_type == peer2_type and peer1_id > peer2_id):
            peer1_type, peer2_type = peer2_type, peer1_type
            peer1_id, peer2_id = peer2_id, peer1_id

        # Check for existing entry
        existing = conn.execute("""
            SELECT id FROM psk_entry
            WHERE peer1_type = ? AND peer1_id = ?
              AND peer2_type = ? AND peer2_id = ?
        """, (peer1_type, peer1_id, peer2_type, peer2_id)).fetchone()

        if existing:
            # Update existing entry
            conn.execute("""
                UPDATE psk_entry SET
                    psk_hash = ?, created_at = ?, expires_at = ?,
                    rotation_count = rotation_count + 1,
                    distributed_to_peer1 = 0, distributed_to_peer2 = 0
                WHERE id = ?
            """, (psk_hash, now.isoformat(), expires_at, existing['id']))
            entry_id = existing['id']
        else:
            cursor = conn.execute("""
                INSERT INTO psk_entry
                (peer1_type, peer1_id, peer2_type, peer2_id, psk_hash,
                 created_at, expires_at, rotation_count)
                VALUES (?, ?, ?, ?, ?, ?, ?, 0)
            """, (peer1_type, peer1_id, peer2_type, peer2_id, psk_hash,
                  now.isoformat(), expires_at))
            entry_id = cursor.lastrowid

        conn.commit()
        conn.close()

        return psk, entry_id

    def rotate_psk(self, peer1_type: str, peer1_id: int,
                   peer2_type: str, peer2_id: int,
                   trigger: PSKRotationTrigger = PSKRotationTrigger.MANUAL,
                   rotated_by: str = "system") -> Tuple[Optional[str], Optional[int]]:
        """Rotate PSK for a peer pair.

        Args:
            peer1_type: Type of first peer
            peer1_id: ID of first peer
            peer2_type: Type of second peer
            peer2_id: ID of second peer
            trigger: What triggered the rotation
            rotated_by: Who/what initiated rotation

        Returns:
            Tuple of (new_PSK, entry_id) or (None, None) if no existing PSK
        """
        conn = self._get_connection()

        # Normalize peer order
        if (peer1_type > peer2_type) or (peer1_type == peer2_type and peer1_id > peer2_id):
            peer1_type, peer2_type = peer2_type, peer1_type
            peer1_id, peer2_id = peer2_id, peer1_id

        # Get existing entry
        existing = conn.execute("""
            SELECT id, psk_hash FROM psk_entry
            WHERE peer1_type = ? AND peer1_id = ?
              AND peer2_type = ? AND peer2_id = ?
        """, (peer1_type, peer1_id, peer2_type, peer2_id)).fetchone()

        if not existing:
            conn.close()
            return None, None

        # Generate new PSK
        new_psk = self.generate_psk()
        new_hash = self.hash_psk(new_psk)
        old_hash = existing['psk_hash']
        entry_id = existing['id']
        now = datetime.now()

        # Update entry
        conn.execute("""
            UPDATE psk_entry SET
                psk_hash = ?, created_at = ?,
                rotation_count = rotation_count + 1,
                distributed_to_peer1 = 0, distributed_to_peer2 = 0
            WHERE id = ?
        """, (new_hash, now.isoformat(), entry_id))

        # Log rotation
        conn.execute("""
            INSERT INTO psk_rotation_history
            (psk_entry_id, old_psk_hash, new_psk_hash, trigger, rotated_at, rotated_by)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (entry_id, old_hash, new_hash, trigger.value, now.isoformat(), rotated_by))

        conn.commit()
        conn.close()

        return new_psk, entry_id

    def mark_distributed(self, entry_id: int, target_type: str, target_id: int,
                         method: str, success: bool = True,
                         error_message: str = None):
        """Mark PSK as distributed to a peer.

        Args:
            entry_id: PSK entry ID
            target_type: Type of target peer
            target_id: ID of target peer
            method: Distribution method ('manual', 'qr', 'ssh', 'api')
            success: Whether distribution was successful
            error_message: Error message if failed
        """
        conn = self._get_connection()
        now = datetime.now()

        # Get entry to determine which peer
        entry = conn.execute(
            "SELECT * FROM psk_entry WHERE id = ?",
            (entry_id,)
        ).fetchone()

        if entry:
            # Update distribution status
            if target_type == entry['peer1_type'] and target_id == entry['peer1_id']:
                conn.execute(
                    "UPDATE psk_entry SET distributed_to_peer1 = 1, distribution_method = ? WHERE id = ?",
                    (method, entry_id)
                )
            elif target_type == entry['peer2_type'] and target_id == entry['peer2_id']:
                conn.execute(
                    "UPDATE psk_entry SET distributed_to_peer2 = 1, distribution_method = ? WHERE id = ?",
                    (method, entry_id)
                )

            # Log distribution
            conn.execute("""
                INSERT INTO psk_distribution_log
                (psk_entry_id, target_type, target_id, method, success, error_message, distributed_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (entry_id, target_type, target_id, method, 1 if success else 0,
                  error_message, now.isoformat()))

        conn.commit()
        conn.close()

    def get_psk_entry(self, peer1_type: str, peer1_id: int,
                      peer2_type: str, peer2_id: int) -> Optional[PSKEntry]:
        """Get PSK entry for a peer pair.

        Args:
            peer1_type: Type of first peer
            peer1_id: ID of first peer
            peer2_type: Type of second peer
            peer2_id: ID of second peer

        Returns:
            PSKEntry or None
        """
        conn = self._get_connection()

        # Normalize peer order
        if (peer1_type > peer2_type) or (peer1_type == peer2_type and peer1_id > peer2_id):
            peer1_type, peer2_type = peer2_type, peer1_type
            peer1_id, peer2_id = peer2_id, peer1_id

        row = conn.execute("""
            SELECT * FROM psk_entry
            WHERE peer1_type = ? AND peer1_id = ?
              AND peer2_type = ? AND peer2_id = ?
        """, (peer1_type, peer1_id, peer2_type, peer2_id)).fetchone()

        conn.close()

        if not row:
            return None

        return PSKEntry(
            id=row['id'],
            peer1_type=row['peer1_type'],
            peer1_id=row['peer1_id'],
            peer2_type=row['peer2_type'],
            peer2_id=row['peer2_id'],
            psk_hash=row['psk_hash'],
            created_at=datetime.fromisoformat(row['created_at']) if row['created_at'] else None,
            expires_at=datetime.fromisoformat(row['expires_at']) if row['expires_at'] else None,
            rotation_count=row['rotation_count'],
            distributed_to_peer1=bool(row['distributed_to_peer1']),
            distributed_to_peer2=bool(row['distributed_to_peer2']),
            distribution_method=row['distribution_method'] or ""
        )

    def get_expiring_psks(self, days_ahead: int = 7) -> List[PSKEntry]:
        """Get PSKs expiring within specified days.

        Args:
            days_ahead: Days to look ahead

        Returns:
            List of PSKEntry objects
        """
        conn = self._get_connection()
        cutoff = (datetime.now() + timedelta(days=days_ahead)).isoformat()

        rows = conn.execute("""
            SELECT * FROM psk_entry
            WHERE expires_at IS NOT NULL AND expires_at <= ?
            ORDER BY expires_at ASC
        """, (cutoff,)).fetchall()

        conn.close()

        return [PSKEntry(
            id=row['id'],
            peer1_type=row['peer1_type'],
            peer1_id=row['peer1_id'],
            peer2_type=row['peer2_type'],
            peer2_id=row['peer2_id'],
            psk_hash=row['psk_hash'],
            created_at=datetime.fromisoformat(row['created_at']) if row['created_at'] else None,
            expires_at=datetime.fromisoformat(row['expires_at']) if row['expires_at'] else None,
            rotation_count=row['rotation_count'],
            distributed_to_peer1=bool(row['distributed_to_peer1']),
            distributed_to_peer2=bool(row['distributed_to_peer2']),
            distribution_method=row['distribution_method'] or ""
        ) for row in rows]

    def get_undistributed_psks(self) -> List[Dict[str, Any]]:
        """Get PSKs that haven't been distributed to all peers.

        Returns:
            List of dicts with PSK entry and missing distribution info
        """
        conn = self._get_connection()

        rows = conn.execute("""
            SELECT * FROM psk_entry
            WHERE distributed_to_peer1 = 0 OR distributed_to_peer2 = 0
        """).fetchall()

        conn.close()

        results = []
        for row in rows:
            missing = []
            if not row['distributed_to_peer1']:
                missing.append({"type": row['peer1_type'], "id": row['peer1_id']})
            if not row['distributed_to_peer2']:
                missing.append({"type": row['peer2_type'], "id": row['peer2_id']})

            results.append({
                "entry_id": row['id'],
                "peer1": {"type": row['peer1_type'], "id": row['peer1_id']},
                "peer2": {"type": row['peer2_type'], "id": row['peer2_id']},
                "missing_distribution": missing,
                "created_at": row['created_at']
            })

        return results

    def get_rotation_history(self, entry_id: Optional[int] = None,
                             limit: int = 50) -> List[Dict[str, Any]]:
        """Get PSK rotation history.

        Args:
            entry_id: Optional specific entry to filter by
            limit: Maximum records to return

        Returns:
            List of rotation history records
        """
        conn = self._get_connection()

        if entry_id:
            rows = conn.execute("""
                SELECT h.*, e.peer1_type, e.peer1_id, e.peer2_type, e.peer2_id
                FROM psk_rotation_history h
                JOIN psk_entry e ON h.psk_entry_id = e.id
                WHERE h.psk_entry_id = ?
                ORDER BY h.rotated_at DESC
                LIMIT ?
            """, (entry_id, limit)).fetchall()
        else:
            rows = conn.execute("""
                SELECT h.*, e.peer1_type, e.peer1_id, e.peer2_type, e.peer2_id
                FROM psk_rotation_history h
                JOIN psk_entry e ON h.psk_entry_id = e.id
                ORDER BY h.rotated_at DESC
                LIMIT ?
            """, (limit,)).fetchall()

        conn.close()
        return [dict(row) for row in rows]

    def get_psk_stats(self) -> Dict[str, Any]:
        """Get PSK usage statistics.

        Returns:
            Dict with various statistics
        """
        conn = self._get_connection()

        stats = {}

        # Total PSKs
        stats['total_psks'] = conn.execute(
            "SELECT COUNT(*) FROM psk_entry"
        ).fetchone()[0]

        # Fully distributed
        stats['fully_distributed'] = conn.execute("""
            SELECT COUNT(*) FROM psk_entry
            WHERE distributed_to_peer1 = 1 AND distributed_to_peer2 = 1
        """).fetchone()[0]

        # Expiring soon (7 days)
        cutoff = (datetime.now() + timedelta(days=7)).isoformat()
        stats['expiring_soon'] = conn.execute("""
            SELECT COUNT(*) FROM psk_entry
            WHERE expires_at IS NOT NULL AND expires_at <= ?
        """, (cutoff,)).fetchone()[0]

        # Total rotations
        stats['total_rotations'] = conn.execute(
            "SELECT COUNT(*) FROM psk_rotation_history"
        ).fetchone()[0]

        # Rotations by trigger
        triggers = conn.execute("""
            SELECT trigger, COUNT(*) as count
            FROM psk_rotation_history
            GROUP BY trigger
        """).fetchall()
        stats['rotations_by_trigger'] = {row['trigger']: row['count'] for row in triggers}

        conn.close()
        return stats

    def delete_psk(self, entry_id: int) -> bool:
        """Delete a PSK entry and its history.

        Args:
            entry_id: PSK entry ID

        Returns:
            True if deleted
        """
        conn = self._get_connection()

        conn.execute("DELETE FROM psk_distribution_log WHERE psk_entry_id = ?", (entry_id,))
        conn.execute("DELETE FROM psk_rotation_history WHERE psk_entry_id = ?", (entry_id,))
        conn.execute("DELETE FROM psk_entry WHERE id = ?", (entry_id,))

        conn.commit()
        conn.close()
        return True


def auto_rotate_psks(db_path: str) -> List[Tuple[int, str]]:
    """Auto-rotate PSKs based on configured policies.

    Args:
        db_path: Path to database

    Returns:
        List of (entry_id, new_psk) tuples for PSKs that were rotated
    """
    manager = PSKManager(db_path)
    rotated = []

    # Get all entries with expiring PSKs
    expiring = manager.get_expiring_psks(days_ahead=0)

    for entry in expiring:
        new_psk, entry_id = manager.rotate_psk(
            entry.peer1_type, entry.peer1_id,
            entry.peer2_type, entry.peer2_id,
            trigger=PSKRotationTrigger.TIME_BASED,
            rotated_by="auto_rotate"
        )
        if new_psk:
            rotated.append((entry_id, new_psk))

    return rotated
