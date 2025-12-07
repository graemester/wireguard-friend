"""
Scheduled Key Rotation Policies

Configurable automatic key rotation schedules based on:
- Time-based: Rotate every N days (30, 60, 90)
- Usage-based: Rotate after N GB transferred (requires bandwidth tracking)
- Event-based: Rotate on specific triggers

Features:
- Policy creation and management
- Schedule tracking per entity
- Automatic rotation with deployment
- Compliance reporting integration

Usage:
    from rotation_policies import RotationPolicyManager, PolicyType

    manager = RotationPolicyManager(db_path)

    # Create policy
    policy_id = manager.create_policy(
        name="Standard 90-day",
        policy_type=PolicyType.TIME_BASED,
        threshold_value=90,
        applies_to='remote'
    )

    # Get pending rotations
    pending = manager.get_pending_rotations()

    # Execute pending rotations
    results = manager.execute_pending_rotations()
"""

import sqlite3
import json
import logging
import shutil
import tempfile
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple
from dataclasses import dataclass

logger = logging.getLogger(__name__)


class PolicyType(str, Enum):
    """Types of rotation policies"""
    TIME_BASED = "time"       # Rotate every N days
    USAGE_BASED = "usage"     # Rotate after N GB transferred
    EVENT_BASED = "event"     # Rotate on specific triggers


class EntityScope(str, Enum):
    """Scope of policy application"""
    ALL = "all"                           # All peer types
    REMOTES = "remotes"                   # Only remote clients
    ROUTERS = "subnet_routers"            # Only subnet routers
    EXIT_NODES = "exit_nodes"             # Only exit nodes
    COORDINATION_SERVER = "coordination_server"
    SPECIFIC = "specific"                 # Specific entity list


@dataclass
class RotationPolicy:
    """Represents a key rotation policy"""
    id: int
    name: str
    policy_type: str
    threshold_value: int      # Days for time-based, GB for usage-based
    threshold_unit: str       # 'days', 'gb', 'count'
    applies_to: str           # EntityScope value
    specific_entities: Optional[List[str]]  # List of permanent_guids if applies_to='specific'
    enabled: bool
    auto_deploy: bool         # Auto-deploy after rotation
    notify_before_days: int   # Warning notification days before rotation
    created_at: str
    last_applied_at: Optional[str]


@dataclass
class ScheduledRotation:
    """Represents a scheduled rotation for a specific entity"""
    id: int
    policy_id: int
    policy_name: str
    entity_type: str
    entity_id: int
    entity_guid: str
    entity_hostname: str
    next_rotation_at: str
    last_rotation_at: Optional[str]
    days_until_rotation: int
    is_overdue: bool


@dataclass
class RotationResult:
    """Result of a rotation operation"""
    entity_type: str
    entity_id: int
    entity_guid: str
    hostname: str
    success: bool
    old_public_key: str
    new_public_key: Optional[str]
    error_message: Optional[str]


class RotationPolicyManager:
    """
    Manages key rotation policies and schedules.

    Tracks when each entity needs rotation based on policy rules,
    and executes rotations when due.
    """

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
        """Initialize rotation policy schema"""
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            # Rotation policies table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS rotation_policy (
                    id INTEGER PRIMARY KEY,
                    name TEXT NOT NULL UNIQUE,
                    policy_type TEXT NOT NULL,
                    threshold_value INTEGER NOT NULL,
                    threshold_unit TEXT NOT NULL,
                    applies_to TEXT NOT NULL,
                    specific_entities TEXT,
                    enabled BOOLEAN DEFAULT 1,
                    auto_deploy BOOLEAN DEFAULT 0,
                    notify_before_days INTEGER DEFAULT 7,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_applied_at TIMESTAMP
                )
            """)

            # Per-entity rotation schedules
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS rotation_schedule (
                    id INTEGER PRIMARY KEY,
                    policy_id INTEGER NOT NULL,
                    entity_type TEXT NOT NULL,
                    entity_id INTEGER NOT NULL,
                    entity_permanent_guid TEXT NOT NULL,
                    next_rotation_at TIMESTAMP NOT NULL,
                    last_rotation_at TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (policy_id) REFERENCES rotation_policy(id) ON DELETE CASCADE,
                    UNIQUE(policy_id, entity_type, entity_id)
                )
            """)

            # Rotation execution history
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS rotation_execution (
                    id INTEGER PRIMARY KEY,
                    policy_id INTEGER,
                    entity_type TEXT NOT NULL,
                    entity_id INTEGER NOT NULL,
                    entity_permanent_guid TEXT NOT NULL,
                    old_public_key TEXT NOT NULL,
                    new_public_key TEXT,
                    success BOOLEAN NOT NULL,
                    error_message TEXT,
                    executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    deployed BOOLEAN DEFAULT 0,
                    FOREIGN KEY (policy_id) REFERENCES rotation_policy(id) ON DELETE SET NULL
                )
            """)

            # Indexes
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_rotation_schedule_next
                ON rotation_schedule(next_rotation_at)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_rotation_schedule_entity
                ON rotation_schedule(entity_type, entity_id)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_rotation_execution_entity
                ON rotation_execution(entity_permanent_guid, executed_at DESC)
            """)

            conn.commit()
            logger.debug("Rotation policy schema initialized")

        finally:
            conn.close()

    def create_policy(
        self,
        name: str,
        policy_type: PolicyType,
        threshold_value: int,
        applies_to: EntityScope = EntityScope.ALL,
        specific_entities: Optional[List[str]] = None,
        enabled: bool = True,
        auto_deploy: bool = False,
        notify_before_days: int = 7
    ) -> int:
        """
        Create a new rotation policy.

        Args:
            name: Policy name (must be unique)
            policy_type: TIME_BASED, USAGE_BASED, or EVENT_BASED
            threshold_value: Days for time-based, GB for usage-based
            applies_to: Scope of application
            specific_entities: List of permanent_guids if applies_to='specific'
            enabled: Whether policy is active
            auto_deploy: Auto-deploy configs after rotation
            notify_before_days: Days before rotation to send notifications

        Returns:
            Policy ID
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            # Determine threshold unit
            if policy_type == PolicyType.TIME_BASED:
                threshold_unit = 'days'
            elif policy_type == PolicyType.USAGE_BASED:
                threshold_unit = 'gb'
            else:
                threshold_unit = 'count'

            # Serialize specific entities
            specific_json = json.dumps(specific_entities) if specific_entities else None

            cursor.execute("""
                INSERT INTO rotation_policy (
                    name, policy_type, threshold_value, threshold_unit,
                    applies_to, specific_entities, enabled, auto_deploy,
                    notify_before_days
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                name, policy_type.value, threshold_value, threshold_unit,
                applies_to.value, specific_json, enabled, auto_deploy,
                notify_before_days
            ))

            policy_id = cursor.lastrowid
            conn.commit()

            # Create initial schedules for applicable entities
            if enabled:
                self._create_schedules_for_policy(policy_id)

            logger.info(f"Created rotation policy: {name} (ID: {policy_id})")
            return policy_id

        except sqlite3.IntegrityError as e:
            raise ValueError(f"Policy name '{name}' already exists") from e
        finally:
            conn.close()

    def _create_schedules_for_policy(self, policy_id: int):
        """Create rotation schedules for all entities covered by a policy"""
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            # Get policy details
            cursor.execute("SELECT * FROM rotation_policy WHERE id = ?", (policy_id,))
            policy = cursor.fetchone()

            if not policy or not policy['enabled']:
                return

            # Get applicable entities
            entities = self._get_applicable_entities(cursor, policy)

            # Create schedules
            now = datetime.utcnow()
            threshold_days = policy['threshold_value']

            for entity_type, entity_id, guid, last_rotation in entities:
                # Calculate next rotation date
                if last_rotation:
                    last_dt = datetime.fromisoformat(last_rotation.replace('Z', '+00:00'))
                    next_rotation = last_dt + timedelta(days=threshold_days)
                else:
                    # No previous rotation - schedule based on creation or now
                    next_rotation = now + timedelta(days=threshold_days)

                cursor.execute("""
                    INSERT OR REPLACE INTO rotation_schedule (
                        policy_id, entity_type, entity_id, entity_permanent_guid,
                        next_rotation_at, last_rotation_at
                    ) VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    policy_id, entity_type, entity_id, guid,
                    next_rotation.isoformat(), last_rotation
                ))

            conn.commit()

        finally:
            conn.close()

    def _get_applicable_entities(self, cursor, policy) -> List[Tuple[str, int, str, Optional[str]]]:
        """
        Get entities applicable to a policy.

        Returns list of (entity_type, entity_id, permanent_guid, last_rotation_at)
        """
        applies_to = policy['applies_to']
        entities = []

        # Helper to get last rotation
        def get_last_rotation(entity_type: str, guid: str) -> Optional[str]:
            cursor.execute("""
                SELECT rotated_at FROM key_rotation_history
                WHERE entity_type = ? AND entity_permanent_guid = ?
                ORDER BY rotated_at DESC LIMIT 1
            """, (entity_type, guid))
            row = cursor.fetchone()
            return row['rotated_at'] if row else None

        if applies_to == 'specific':
            # Specific entities by GUID
            specific = json.loads(policy['specific_entities'] or '[]')
            for guid in specific:
                # Find entity in all tables
                for table, etype in [
                    ('coordination_server', 'coordination_server'),
                    ('subnet_router', 'subnet_router'),
                    ('remote', 'remote'),
                    ('exit_node', 'exit_node')
                ]:
                    cursor.execute(
                        f"SELECT id, permanent_guid FROM {table} WHERE permanent_guid = ?",
                        (guid,)
                    )
                    row = cursor.fetchone()
                    if row:
                        entities.append((
                            etype, row['id'], row['permanent_guid'],
                            get_last_rotation(etype, guid)
                        ))
                        break

        else:
            # Scope-based selection
            table_mapping = {
                'all': [
                    ('coordination_server', 'coordination_server'),
                    ('subnet_router', 'subnet_router'),
                    ('remote', 'remote'),
                    ('exit_node', 'exit_node')
                ],
                'remotes': [('remote', 'remote')],
                'subnet_routers': [('subnet_router', 'subnet_router')],
                'exit_nodes': [('exit_node', 'exit_node')],
                'coordination_server': [('coordination_server', 'coordination_server')]
            }

            tables = table_mapping.get(applies_to, [])

            for table, etype in tables:
                cursor.execute(f"SELECT id, permanent_guid FROM {table}")
                for row in cursor.fetchall():
                    entities.append((
                        etype, row['id'], row['permanent_guid'],
                        get_last_rotation(etype, row['permanent_guid'])
                    ))

        return entities

    def get_policy(self, policy_id: int) -> Optional[RotationPolicy]:
        """Get a rotation policy by ID"""
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("SELECT * FROM rotation_policy WHERE id = ?", (policy_id,))
            row = cursor.fetchone()

            if not row:
                return None

            return RotationPolicy(
                id=row['id'],
                name=row['name'],
                policy_type=row['policy_type'],
                threshold_value=row['threshold_value'],
                threshold_unit=row['threshold_unit'],
                applies_to=row['applies_to'],
                specific_entities=json.loads(row['specific_entities'] or '[]'),
                enabled=bool(row['enabled']),
                auto_deploy=bool(row['auto_deploy']),
                notify_before_days=row['notify_before_days'],
                created_at=row['created_at'],
                last_applied_at=row['last_applied_at']
            )

        finally:
            conn.close()

    def list_policies(self, enabled_only: bool = False) -> List[RotationPolicy]:
        """List all rotation policies"""
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            query = "SELECT * FROM rotation_policy"
            if enabled_only:
                query += " WHERE enabled = 1"
            query += " ORDER BY name"

            cursor.execute(query)

            policies = []
            for row in cursor.fetchall():
                policies.append(RotationPolicy(
                    id=row['id'],
                    name=row['name'],
                    policy_type=row['policy_type'],
                    threshold_value=row['threshold_value'],
                    threshold_unit=row['threshold_unit'],
                    applies_to=row['applies_to'],
                    specific_entities=json.loads(row['specific_entities'] or '[]'),
                    enabled=bool(row['enabled']),
                    auto_deploy=bool(row['auto_deploy']),
                    notify_before_days=row['notify_before_days'],
                    created_at=row['created_at'],
                    last_applied_at=row['last_applied_at']
                ))

            return policies

        finally:
            conn.close()

    def update_policy(self, policy_id: int, **kwargs) -> bool:
        """Update a rotation policy"""
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            # Build update query
            updates = []
            params = []

            allowed_fields = [
                'name', 'threshold_value', 'enabled', 'auto_deploy',
                'notify_before_days', 'applies_to'
            ]

            for field in allowed_fields:
                if field in kwargs:
                    updates.append(f"{field} = ?")
                    params.append(kwargs[field])

            if 'specific_entities' in kwargs:
                updates.append("specific_entities = ?")
                params.append(json.dumps(kwargs['specific_entities']))

            if not updates:
                return False

            params.append(policy_id)
            cursor.execute(
                f"UPDATE rotation_policy SET {', '.join(updates)} WHERE id = ?",
                params
            )

            conn.commit()

            # Rebuild schedules if scope changed
            if 'applies_to' in kwargs or 'specific_entities' in kwargs:
                cursor.execute(
                    "DELETE FROM rotation_schedule WHERE policy_id = ?",
                    (policy_id,)
                )
                conn.commit()
                self._create_schedules_for_policy(policy_id)

            return cursor.rowcount > 0

        finally:
            conn.close()

    def delete_policy(self, policy_id: int) -> bool:
        """Delete a rotation policy"""
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("DELETE FROM rotation_policy WHERE id = ?", (policy_id,))
            conn.commit()
            return cursor.rowcount > 0

        finally:
            conn.close()

    def get_pending_rotations(self, include_upcoming_days: int = 0) -> List[ScheduledRotation]:
        """
        Get all pending/overdue rotations.

        Args:
            include_upcoming_days: Include rotations due within N days

        Returns:
            List of scheduled rotations ordered by urgency
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            now = datetime.utcnow()
            cutoff = now + timedelta(days=include_upcoming_days)

            cursor.execute("""
                SELECT
                    rs.id, rs.policy_id, rp.name as policy_name,
                    rs.entity_type, rs.entity_id, rs.entity_permanent_guid,
                    rs.next_rotation_at, rs.last_rotation_at
                FROM rotation_schedule rs
                JOIN rotation_policy rp ON rs.policy_id = rp.id
                WHERE rp.enabled = 1 AND rs.next_rotation_at <= ?
                ORDER BY rs.next_rotation_at ASC
            """, (cutoff.isoformat(),))

            rotations = []
            for row in cursor.fetchall():
                # Get hostname for entity
                hostname = self._get_entity_hostname(
                    cursor, row['entity_type'], row['entity_id']
                )

                next_dt = datetime.fromisoformat(row['next_rotation_at'].replace('Z', '+00:00'))
                days_until = (next_dt - now).days

                rotations.append(ScheduledRotation(
                    id=row['id'],
                    policy_id=row['policy_id'],
                    policy_name=row['policy_name'],
                    entity_type=row['entity_type'],
                    entity_id=row['entity_id'],
                    entity_guid=row['entity_permanent_guid'],
                    entity_hostname=hostname or row['entity_permanent_guid'][:16],
                    next_rotation_at=row['next_rotation_at'],
                    last_rotation_at=row['last_rotation_at'],
                    days_until_rotation=days_until,
                    is_overdue=days_until < 0
                ))

            return rotations

        finally:
            conn.close()

    def _get_entity_hostname(self, cursor, entity_type: str, entity_id: int) -> Optional[str]:
        """Get hostname for an entity"""
        table_map = {
            'coordination_server': 'coordination_server',
            'subnet_router': 'subnet_router',
            'remote': 'remote',
            'exit_node': 'exit_node'
        }

        table = table_map.get(entity_type)
        if not table:
            return None

        cursor.execute(f"SELECT hostname FROM {table} WHERE id = ?", (entity_id,))
        row = cursor.fetchone()
        return row['hostname'] if row else None

    def get_rotation_schedule_for_entity(
        self,
        entity_type: str,
        entity_id: int
    ) -> List[ScheduledRotation]:
        """Get all rotation schedules for a specific entity"""
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                SELECT
                    rs.id, rs.policy_id, rp.name as policy_name,
                    rs.entity_type, rs.entity_id, rs.entity_permanent_guid,
                    rs.next_rotation_at, rs.last_rotation_at
                FROM rotation_schedule rs
                JOIN rotation_policy rp ON rs.policy_id = rp.id
                WHERE rs.entity_type = ? AND rs.entity_id = ?
                ORDER BY rs.next_rotation_at ASC
            """, (entity_type, entity_id))

            now = datetime.utcnow()
            rotations = []

            for row in cursor.fetchall():
                hostname = self._get_entity_hostname(
                    cursor, row['entity_type'], row['entity_id']
                )

                next_dt = datetime.fromisoformat(row['next_rotation_at'].replace('Z', '+00:00'))
                days_until = (next_dt - now).days

                rotations.append(ScheduledRotation(
                    id=row['id'],
                    policy_id=row['policy_id'],
                    policy_name=row['policy_name'],
                    entity_type=row['entity_type'],
                    entity_id=row['entity_id'],
                    entity_guid=row['entity_permanent_guid'],
                    entity_hostname=hostname or row['entity_permanent_guid'][:16],
                    next_rotation_at=row['next_rotation_at'],
                    last_rotation_at=row['last_rotation_at'],
                    days_until_rotation=days_until,
                    is_overdue=days_until < 0
                ))

            return rotations

        finally:
            conn.close()

    def execute_rotation(
        self,
        entity_type: str,
        entity_id: int,
        policy_id: Optional[int] = None
    ) -> RotationResult:
        """
        Execute key rotation for a specific entity.

        This method integrates with the existing keygen and database modules.
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            # Get entity details
            table_map = {
                'coordination_server': 'coordination_server',
                'subnet_router': 'subnet_router',
                'remote': 'remote',
                'exit_node': 'exit_node'
            }

            table = table_map.get(entity_type)
            if not table:
                return RotationResult(
                    entity_type=entity_type,
                    entity_id=entity_id,
                    entity_guid='',
                    hostname='',
                    success=False,
                    old_public_key='',
                    new_public_key=None,
                    error_message=f"Unknown entity type: {entity_type}"
                )

            cursor.execute(
                f"SELECT permanent_guid, current_public_key, private_key, hostname FROM {table} WHERE id = ?",
                (entity_id,)
            )
            row = cursor.fetchone()

            if not row:
                return RotationResult(
                    entity_type=entity_type,
                    entity_id=entity_id,
                    entity_guid='',
                    hostname='',
                    success=False,
                    old_public_key='',
                    new_public_key=None,
                    error_message=f"Entity not found: {entity_type}:{entity_id}"
                )

            old_public_key = row['current_public_key']
            guid = row['permanent_guid']
            hostname = row['hostname'] or guid[:16]

            # Generate new keypair
            try:
                from keygen import generate_keypair
                new_private_key, new_public_key = generate_keypair()
            except Exception as e:
                return RotationResult(
                    entity_type=entity_type,
                    entity_id=entity_id,
                    entity_guid=guid,
                    hostname=hostname,
                    success=False,
                    old_public_key=old_public_key,
                    new_public_key=None,
                    error_message=f"Key generation failed: {e}"
                )

            # Check if encryption is enabled
            try:
                from encryption import get_active_encryption_manager
                manager = get_active_encryption_manager()
                if manager and manager.is_unlocked:
                    new_private_key = manager.encrypt(new_private_key)
            except ImportError:
                pass

            # Update entity with new keys
            cursor.execute(
                f"UPDATE {table} SET private_key = ?, current_public_key = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (new_private_key, new_public_key, entity_id)
            )

            # Record in key_rotation_history
            cursor.execute("""
                INSERT INTO key_rotation_history (
                    entity_permanent_guid, entity_type,
                    old_public_key, new_public_key, new_private_key,
                    reason
                ) VALUES (?, ?, ?, ?, ?, ?)
            """, (guid, entity_type, old_public_key, new_public_key, new_private_key, 'policy_rotation'))

            # Update rotation schedule
            if policy_id:
                # Get policy threshold
                cursor.execute(
                    "SELECT threshold_value FROM rotation_policy WHERE id = ?",
                    (policy_id,)
                )
                policy_row = cursor.fetchone()
                threshold_days = policy_row['threshold_value'] if policy_row else 90

                now = datetime.utcnow()
                next_rotation = now + timedelta(days=threshold_days)

                cursor.execute("""
                    UPDATE rotation_schedule
                    SET next_rotation_at = ?, last_rotation_at = ?
                    WHERE policy_id = ? AND entity_type = ? AND entity_id = ?
                """, (next_rotation.isoformat(), now.isoformat(), policy_id, entity_type, entity_id))

            # Record execution
            cursor.execute("""
                INSERT INTO rotation_execution (
                    policy_id, entity_type, entity_id, entity_permanent_guid,
                    old_public_key, new_public_key, success
                ) VALUES (?, ?, ?, ?, ?, ?, 1)
            """, (policy_id, entity_type, entity_id, guid, old_public_key, new_public_key))

            conn.commit()

            logger.info(f"Rotated keys for {entity_type}:{entity_id} ({hostname})")

            return RotationResult(
                entity_type=entity_type,
                entity_id=entity_id,
                entity_guid=guid,
                hostname=hostname,
                success=True,
                old_public_key=old_public_key,
                new_public_key=new_public_key,
                error_message=None
            )

        except Exception as e:
            conn.rollback()
            logger.error(f"Rotation failed for {entity_type}:{entity_id}: {e}")

            # Record failed execution
            try:
                cursor.execute("""
                    INSERT INTO rotation_execution (
                        policy_id, entity_type, entity_id, entity_permanent_guid,
                        old_public_key, success, error_message
                    ) VALUES (?, ?, ?, ?, ?, 0, ?)
                """, (policy_id, entity_type, entity_id, guid if 'guid' in dir() else '', old_public_key if 'old_public_key' in dir() else '', str(e)))
                conn.commit()
            except:
                pass

            return RotationResult(
                entity_type=entity_type,
                entity_id=entity_id,
                entity_guid=guid if 'guid' in dir() else '',
                hostname=hostname if 'hostname' in dir() else '',
                success=False,
                old_public_key=old_public_key if 'old_public_key' in dir() else '',
                new_public_key=None,
                error_message=str(e)
            )

        finally:
            conn.close()

    def execute_pending_rotations(
        self,
        auto_deploy: bool = False,
        dry_run: bool = False
    ) -> List[RotationResult]:
        """
        Execute all pending/overdue rotations.

        Args:
            auto_deploy: Deploy configs after rotation
            dry_run: Just report what would be done

        Returns:
            List of rotation results
        """
        pending = self.get_pending_rotations()

        if dry_run:
            results = []
            for rotation in pending:
                results.append(RotationResult(
                    entity_type=rotation.entity_type,
                    entity_id=rotation.entity_id,
                    entity_guid=rotation.entity_guid,
                    hostname=rotation.entity_hostname,
                    success=True,
                    old_public_key='[dry-run]',
                    new_public_key='[dry-run]',
                    error_message=None
                ))
            return results

        results = []
        for rotation in pending:
            result = self.execute_rotation(
                rotation.entity_type,
                rotation.entity_id,
                rotation.policy_id
            )
            results.append(result)

        # Auto-deploy if requested and any rotations succeeded
        if auto_deploy and any(r.success for r in results):
            deploy_result = self._deploy_after_rotation()
            if deploy_result:
                logger.info(f"Auto-deploy completed: {deploy_result}")
            else:
                logger.warning("Auto-deploy failed or skipped")

        return results

    def _deploy_after_rotation(self) -> Optional[Dict[str, Any]]:
        """
        Generate and deploy configs after key rotation.

        Returns:
            Dict with deployment results, or None if deployment failed/skipped
        """
        try:
            # Import deploy modules here to avoid circular imports
            from v1.schema_semantic import WireGuardDBv2
            from v1.cli.config_generator import (
                generate_cs_config,
                generate_router_config,
                generate_remote_config,
                generate_exit_node_config
            )
            from v1.cli.deploy import deploy_all

            db = WireGuardDBv2(self.db_path)

            # Create temp directory for generated configs
            output_dir = Path(tempfile.mkdtemp(prefix='wgf-rotation-deploy-'))

            try:
                # Generate all configs
                configs_written = []

                # Coordination server config
                cs_config = generate_cs_config(db)
                cs_file = output_dir / "coordination.conf"
                cs_file.write_text(cs_config)
                configs_written.append('coordination.conf')

                # Subnet router configs
                with db._connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute("SELECT id, hostname FROM subnet_router")
                    for row in cursor.fetchall():
                        router_id, hostname = row['id'], row['hostname']
                        config = generate_router_config(db, router_id)
                        config_file = output_dir / f"{hostname}.conf"
                        config_file.write_text(config)
                        configs_written.append(f"{hostname}.conf")

                    # Remote configs
                    cursor.execute("SELECT id, hostname FROM remote")
                    for row in cursor.fetchall():
                        remote_id, hostname = row['id'], row['hostname']
                        config = generate_remote_config(db, remote_id)
                        config_file = output_dir / f"{hostname}.conf"
                        config_file.write_text(config)
                        configs_written.append(f"{hostname}.conf")

                    # Exit node configs
                    cursor.execute("SELECT id, hostname FROM exit_node")
                    for row in cursor.fetchall():
                        exit_id, hostname = row['id'], row['hostname']
                        config = generate_exit_node_config(db, exit_id)
                        config_file = output_dir / f"{hostname}.conf"
                        config_file.write_text(config)
                        configs_written.append(f"{hostname}.conf")

                logger.info(f"Generated {len(configs_written)} configs for deployment")

                # Deploy to all hosts (restart to apply new keys)
                failures = deploy_all(db, output_dir, restart=True)

                return {
                    'configs_generated': len(configs_written),
                    'deployment_failures': failures,
                    'success': failures == 0
                }

            finally:
                # Clean up temp directory
                shutil.rmtree(output_dir, ignore_errors=True)

        except ImportError as e:
            logger.error(f"Deploy module not available: {e}")
            return None
        except Exception as e:
            logger.error(f"Deployment failed: {e}")
            return None

    def get_compliance_summary(self) -> Dict[str, Any]:
        """
        Get compliance summary for reporting.

        Returns dict with:
        - Total entities covered by policies
        - Compliance percentage (rotations on schedule)
        - Overdue rotations
        - Upcoming rotations (next 7 days)
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            now = datetime.utcnow()
            week_from_now = now + timedelta(days=7)

            # Total scheduled entities
            cursor.execute("SELECT COUNT(*) FROM rotation_schedule")
            total_scheduled = cursor.fetchone()[0]

            # Overdue count
            cursor.execute("""
                SELECT COUNT(*) FROM rotation_schedule rs
                JOIN rotation_policy rp ON rs.policy_id = rp.id
                WHERE rp.enabled = 1 AND rs.next_rotation_at < ?
            """, (now.isoformat(),))
            overdue_count = cursor.fetchone()[0]

            # Upcoming (next 7 days)
            cursor.execute("""
                SELECT COUNT(*) FROM rotation_schedule rs
                JOIN rotation_policy rp ON rs.policy_id = rp.id
                WHERE rp.enabled = 1
                  AND rs.next_rotation_at >= ?
                  AND rs.next_rotation_at <= ?
            """, (now.isoformat(), week_from_now.isoformat()))
            upcoming_count = cursor.fetchone()[0]

            # Compliance percentage
            compliant = total_scheduled - overdue_count
            compliance_pct = (compliant / total_scheduled * 100) if total_scheduled > 0 else 100

            # Policies summary
            cursor.execute("""
                SELECT
                    rp.name,
                    rp.threshold_value,
                    rp.threshold_unit,
                    COUNT(rs.id) as entity_count,
                    SUM(CASE WHEN rs.next_rotation_at < ? THEN 1 ELSE 0 END) as overdue
                FROM rotation_policy rp
                LEFT JOIN rotation_schedule rs ON rp.id = rs.policy_id
                WHERE rp.enabled = 1
                GROUP BY rp.id
            """, (now.isoformat(),))

            policies = []
            for row in cursor.fetchall():
                policies.append({
                    'name': row['name'],
                    'threshold': f"{row['threshold_value']} {row['threshold_unit']}",
                    'entity_count': row['entity_count'],
                    'overdue': row['overdue']
                })

            return {
                'total_scheduled': total_scheduled,
                'overdue_count': overdue_count,
                'upcoming_count': upcoming_count,
                'compliance_percentage': round(compliance_pct, 1),
                'policies': policies,
                'generated_at': now.isoformat()
            }

        finally:
            conn.close()


if __name__ == "__main__":
    # Demo/test
    import tempfile

    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
        db_path = Path(f.name)

    try:
        print("=== Rotation Policies Demo ===\n")

        # Create mock entity tables
        import sqlite3
        conn = sqlite3.connect(db_path)
        conn.execute("""
            CREATE TABLE remote (
                id INTEGER PRIMARY KEY,
                permanent_guid TEXT NOT NULL UNIQUE,
                current_public_key TEXT NOT NULL,
                private_key TEXT,
                hostname TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE key_rotation_history (
                id INTEGER PRIMARY KEY,
                entity_permanent_guid TEXT NOT NULL,
                entity_type TEXT NOT NULL,
                old_public_key TEXT NOT NULL,
                new_public_key TEXT NOT NULL,
                new_private_key TEXT NOT NULL,
                rotated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                reason TEXT
            )
        """)
        # Insert test remotes
        conn.execute(
            "INSERT INTO remote (permanent_guid, current_public_key, private_key, hostname) VALUES (?, ?, ?, ?)",
            ("guid-alice", "pubkey-alice", "privkey-alice", "alice-laptop")
        )
        conn.execute(
            "INSERT INTO remote (permanent_guid, current_public_key, private_key, hostname) VALUES (?, ?, ?, ?)",
            ("guid-bob", "pubkey-bob", "privkey-bob", "bob-phone")
        )
        conn.commit()
        conn.close()

        manager = RotationPolicyManager(db_path)

        # Create policy
        print("Creating 90-day rotation policy...")
        policy_id = manager.create_policy(
            name="Standard 90-day",
            policy_type=PolicyType.TIME_BASED,
            threshold_value=90,
            applies_to=EntityScope.REMOTES,
            notify_before_days=7
        )
        print(f"Created policy ID: {policy_id}\n")

        # List policies
        print("Policies:")
        for policy in manager.list_policies():
            print(f"  - {policy.name}: {policy.threshold_value} {policy.threshold_unit}")
            print(f"    Applies to: {policy.applies_to}")
            print(f"    Enabled: {policy.enabled}\n")

        # Get pending rotations
        print("Pending rotations (next 100 days):")
        pending = manager.get_pending_rotations(include_upcoming_days=100)
        for r in pending:
            status = "OVERDUE" if r.is_overdue else f"in {r.days_until_rotation} days"
            print(f"  - {r.entity_hostname}: {status} (policy: {r.policy_name})")

        # Get compliance summary
        print("\nCompliance Summary:")
        summary = manager.get_compliance_summary()
        print(f"  Total scheduled: {summary['total_scheduled']}")
        print(f"  Compliance: {summary['compliance_percentage']}%")
        print(f"  Overdue: {summary['overdue_count']}")
        print(f"  Upcoming (7d): {summary['upcoming_count']}")

    finally:
        db_path.unlink()
        print("\nDemo complete!")
