"""
System State / Temporal Awareness

Track the entire network topology as snapshots in time.

Concept: Each time you modify the network (add peer, rotate key, change config),
you create a new "system state" - a complete snapshot of:
- All hostnames
- All public keys
- All roles
- All relationships

Like Git commits for your WireGuard network.

Example timeline:
  State 1 (2025-11-29 10:00) - Initial import: 11 remotes, 1 SNR, 1 CS
  State 2 (2025-11-29 11:30) - Added remote: alice-laptop
  State 3 (2025-11-29 14:00) - Rotated key: bob-phone
  State 4 (2025-11-29 16:15) - Removed remote: old-ipad
"""

import json
import sqlite3
import logging
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional
from dataclasses import dataclass, asdict
from contextlib import contextmanager

logger = logging.getLogger(__name__)


@dataclass
class EntitySnapshot:
    """Snapshot of a single entity at a point in time"""
    entity_type: str  # 'coordination_server', 'subnet_router', 'remote'
    public_key: str  # Immutable identifier
    hostname: Optional[str]
    role_type: Optional[str]
    ipv4_address: Optional[str]
    ipv6_address: Optional[str]
    allowed_ips: List[str]  # For remotes/routers appearing in CS config
    endpoint: Optional[str]


@dataclass
class SystemState:
    """Complete network snapshot at a point in time"""
    state_id: int
    created_at: datetime
    description: str  # What changed? "Added alice-laptop", "Rotated bob key"

    # Complete network topology
    coordination_server: Optional[EntitySnapshot]
    subnet_routers: List[EntitySnapshot]
    remotes: List[EntitySnapshot]

    # Summary stats
    total_entities: int
    total_remotes: int
    total_routers: int


class SystemStateDB:
    """Database for tracking system states over time"""

    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    @contextmanager
    def _connection(self):
        """Database connection"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")

        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()

    def _init_schema(self):
        """Initialize temporal schema"""
        with self._connection() as conn:
            cursor = conn.cursor()

            # System states (timeline of network topology)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS system_state (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    description TEXT NOT NULL,

                    -- Snapshot data (JSON)
                    topology_json TEXT NOT NULL,

                    -- Summary stats
                    total_entities INTEGER NOT NULL,
                    total_remotes INTEGER NOT NULL,
                    total_routers INTEGER NOT NULL
                )
            """)

            # Entity history (tracks which states an entity existed in)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS entity_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    entity_type TEXT NOT NULL,
                    public_key TEXT NOT NULL,
                    hostname TEXT,

                    -- State tracking
                    first_seen_state_id INTEGER NOT NULL,
                    last_seen_state_id INTEGER NOT NULL,

                    -- Change tracking
                    key_rotations INTEGER DEFAULT 0,

                    FOREIGN KEY (first_seen_state_id) REFERENCES system_state(id),
                    FOREIGN KEY (last_seen_state_id) REFERENCES system_state(id)
                )
            """)

            # Change log (what changed between states)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS state_change (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    state_id INTEGER NOT NULL,
                    change_type TEXT NOT NULL,  -- 'add', 'remove', 'rotate_key', 'modify'
                    entity_type TEXT NOT NULL,
                    entity_identifier TEXT NOT NULL,  -- hostname or public key
                    old_value TEXT,  -- For rotations/modifications
                    new_value TEXT,
                    FOREIGN KEY (state_id) REFERENCES system_state(id)
                )
            """)

            # Indexes
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_entity_history_pubkey ON entity_history(public_key)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_state_change_state ON state_change(state_id)")

            logger.info(f"System state database initialized at {self.db_path}")

    def create_state(
        self,
        description: str,
        cs: Optional[EntitySnapshot],
        routers: List[EntitySnapshot],
        remotes: List[EntitySnapshot],
        changes: List[Dict] = None
    ) -> int:
        """
        Create a new system state snapshot.

        Args:
            description: What changed (e.g., "Added alice-laptop")
            cs: Coordination server snapshot
            routers: List of subnet router snapshots
            remotes: List of remote snapshots
            changes: List of changes from previous state

        Returns:
            state_id of new state
        """
        with self._connection() as conn:
            cursor = conn.cursor()

            # Build topology JSON
            topology = {
                'coordination_server': asdict(cs) if cs else None,
                'subnet_routers': [asdict(r) for r in routers],
                'remotes': [asdict(r) for r in remotes]
            }

            # Insert state
            cursor.execute("""
                INSERT INTO system_state (description, topology_json, total_entities, total_remotes, total_routers)
                VALUES (?, ?, ?, ?, ?)
            """, (
                description,
                json.dumps(topology, indent=2),
                1 + len(routers) + len(remotes),  # cs + routers + remotes
                len(remotes),
                len(routers)
            ))

            state_id = cursor.lastrowid

            # Record changes
            if changes:
                for change in changes:
                    cursor.execute("""
                        INSERT INTO state_change (state_id, change_type, entity_type, entity_identifier, old_value, new_value)
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, (
                        state_id,
                        change['type'],
                        change['entity_type'],
                        change['identifier'],
                        change.get('old_value'),
                        change.get('new_value')
                    ))

            # Update entity history
            all_entities = []
            if cs:
                all_entities.append(('coordination_server', cs.public_key, cs.hostname))
            for router in routers:
                all_entities.append(('subnet_router', router.public_key, router.hostname))
            for remote in remotes:
                all_entities.append(('remote', remote.public_key, remote.hostname))

            for entity_type, public_key, hostname in all_entities:
                # Check if entity exists
                cursor.execute("""
                    SELECT id, first_seen_state_id FROM entity_history
                    WHERE entity_type = ? AND public_key = ?
                """, (entity_type, public_key))

                row = cursor.fetchone()

                if row:
                    # Update last_seen
                    cursor.execute("""
                        UPDATE entity_history
                        SET last_seen_state_id = ?, hostname = ?
                        WHERE id = ?
                    """, (state_id, hostname, row['id']))
                else:
                    # First time seeing this entity
                    cursor.execute("""
                        INSERT INTO entity_history (entity_type, public_key, hostname, first_seen_state_id, last_seen_state_id)
                        VALUES (?, ?, ?, ?, ?)
                    """, (entity_type, public_key, hostname, state_id, state_id))

            return state_id

    def get_state(self, state_id: int) -> Optional[SystemState]:
        """Retrieve a specific system state"""
        with self._connection() as conn:
            cursor = conn.cursor()

            cursor.execute("""
                SELECT id, created_at, description, topology_json, total_entities, total_remotes, total_routers
                FROM system_state
                WHERE id = ?
            """, (state_id,))

            row = cursor.fetchone()
            if not row:
                return None

            topology = json.loads(row['topology_json'])

            # Reconstruct entity snapshots
            cs = None
            if topology['coordination_server']:
                cs = EntitySnapshot(**topology['coordination_server'])

            routers = [EntitySnapshot(**r) for r in topology['subnet_routers']]
            remotes = [EntitySnapshot(**r) for r in topology['remotes']]

            return SystemState(
                state_id=row['id'],
                created_at=datetime.fromisoformat(row['created_at']),
                description=row['description'],
                coordination_server=cs,
                subnet_routers=routers,
                remotes=remotes,
                total_entities=row['total_entities'],
                total_remotes=row['total_remotes'],
                total_routers=row['total_routers']
            )

    def get_timeline(self, limit: int = 20) -> List[SystemState]:
        """Get recent system states (timeline)"""
        with self._connection() as conn:
            cursor = conn.cursor()

            cursor.execute("""
                SELECT id FROM system_state
                ORDER BY created_at DESC
                LIMIT ?
            """, (limit,))

            state_ids = [row['id'] for row in cursor.fetchall()]

        return [self.get_state(sid) for sid in state_ids]

    def get_entity_history(self, public_key: str) -> Dict:
        """Get history of a specific entity"""
        with self._connection() as conn:
            cursor = conn.cursor()

            cursor.execute("""
                SELECT * FROM entity_history
                WHERE public_key = ?
            """, (public_key,))

            row = cursor.fetchone()
            if not row:
                return None

            return {
                'entity_type': row['entity_type'],
                'public_key': row['public_key'],
                'hostname': row['hostname'],
                'first_seen_state': row['first_seen_state_id'],
                'last_seen_state': row['last_seen_state_id'],
                'key_rotations': row['key_rotations']
            }

    def get_changes(self, state_id: int) -> List[Dict]:
        """Get changes that created this state"""
        with self._connection() as conn:
            cursor = conn.cursor()

            cursor.execute("""
                SELECT change_type, entity_type, entity_identifier, old_value, new_value
                FROM state_change
                WHERE state_id = ?
                ORDER BY id
            """, (state_id,))

            return [dict(row) for row in cursor.fetchall()]


def demonstrate_system_state():
    """Demonstrate temporal awareness"""
    import tempfile

    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
        db_path = Path(f.name)

    try:
        db = SystemStateDB(db_path)

        print("=" * 80)
        print("SYSTEM STATE / TEMPORAL AWARENESS DEMO")
        print("=" * 80)
        print()

        # State 1: Initial import
        print("State 1: Initial import")
        cs = EntitySnapshot(
            entity_type='coordination_server',
            public_key='SERVER_KEY_ABC123',
            hostname=None,
            role_type=None,
            ipv4_address='10.66.0.1/24',
            ipv6_address='fd66::1/64',
            allowed_ips=[],
            endpoint=None
        )

        router = EntitySnapshot(
            entity_type='subnet_router',
            public_key='ROUTER_KEY_XYZ789',
            hostname='icculus',
            role_type='initiates_only',
            ipv4_address='10.66.0.20/32',
            ipv6_address='fd66::20/128',
            allowed_ips=['10.66.0.20/32', '192.168.12.0/24'],
            endpoint=None
        )

        remote1 = EntitySnapshot(
            entity_type='remote',
            public_key='ALICE_KEY_111',
            hostname='alice-phone',
            role_type='dynamic_endpoint',
            ipv4_address='10.66.0.30/32',
            ipv6_address='fd66::30/128',
            allowed_ips=['10.66.0.30/32'],
            endpoint=None
        )

        state1_id = db.create_state(
            "Initial import: 1 CS, 1 SNR, 1 remote",
            cs=cs,
            routers=[router],
            remotes=[remote1]
        )

        print(f"  Created state {state1_id}")
        print(f"  Entities: 1 CS + 1 router + 1 remote = 3 total")
        print()

        # State 2: Add a remote
        print("State 2: Add remote (bob-laptop)")
        remote2 = EntitySnapshot(
            entity_type='remote',
            public_key='BOB_KEY_222',
            hostname='bob-laptop',
            role_type=None,
            ipv4_address='10.66.0.31/32',
            ipv6_address='fd66::31/128',
            allowed_ips=['10.66.0.31/32'],
            endpoint='bob.example.com:51820'
        )

        state2_id = db.create_state(
            "Added remote: bob-laptop",
            cs=cs,
            routers=[router],
            remotes=[remote1, remote2],
            changes=[{
                'type': 'add',
                'entity_type': 'remote',
                'identifier': 'bob-laptop',
                'new_value': 'BOB_KEY_222'
            }]
        )

        print(f"  Created state {state2_id}")
        print(f"  Entities: 1 CS + 1 router + 2 remotes = 4 total")
        print()

        # State 3: Rotate key
        print("State 3: Rotate alice-phone key")
        remote1_rotated = EntitySnapshot(
            entity_type='remote',
            public_key='ALICE_KEY_ROTATED_333',  # New key!
            hostname='alice-phone',
            role_type='dynamic_endpoint',
            ipv4_address='10.66.0.30/32',
            ipv6_address='fd66::30/128',
            allowed_ips=['10.66.0.30/32'],
            endpoint=None
        )

        state3_id = db.create_state(
            "Rotated key: alice-phone",
            cs=cs,
            routers=[router],
            remotes=[remote1_rotated, remote2],
            changes=[{
                'type': 'rotate_key',
                'entity_type': 'remote',
                'identifier': 'alice-phone',
                'old_value': 'ALICE_KEY_111',
                'new_value': 'ALICE_KEY_ROTATED_333'
            }]
        )

        print(f"  Created state {state3_id}")
        print(f"  Alice's old key: ALICE_KEY_111")
        print(f"  Alice's new key: ALICE_KEY_ROTATED_333")
        print()

        # Show timeline
        print("=" * 80)
        print("TIMELINE")
        print("=" * 80)

        timeline = db.get_timeline()
        for state in reversed(timeline):
            print(f"\nState {state.state_id}: {state.created_at.strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"  {state.description}")
            print(f"  Total: {state.total_entities} entities ({state.total_remotes} remotes, {state.total_routers} routers)")

            changes = db.get_changes(state.state_id)
            if changes:
                print(f"  Changes:")
                for change in changes:
                    print(f"    - {change['change_type']}: {change['entity_identifier']}")

        # Show entity history
        print("\n" + "=" * 80)
        print("ENTITY HISTORY: alice-phone")
        print("=" * 80)

        # Check both keys
        for key in ['ALICE_KEY_111', 'ALICE_KEY_ROTATED_333']:
            history = db.get_entity_history(key)
            if history:
                print(f"\nKey: {key}")
                print(f"  First seen: State {history['first_seen_state']}")
                print(f"  Last seen: State {history['last_seen_state']}")

        print()
        print("=" * 80)
        print("TIME AWARENESS ACHIEVED ✓")
        print("=" * 80)
        print("\nEach state is a complete snapshot of the network.")
        print("We can reconstruct the network at ANY point in time.")
        print("We can see WHAT changed and WHEN.")

    finally:
        db_path.unlink()


if __name__ == "__main__":
    demonstrate_system_state()
