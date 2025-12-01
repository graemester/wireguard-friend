"""
Extramural Configs Database Schema

Schema for managing external WireGuard configurations (commercial VPNs, employer networks).
These configs exist completely independently from the mesh network infrastructure.

Key principles:
- Complete separation from mesh infrastructure
- SSH hosts as shared first-class resources
- Local-only control (you control your endpoint, sponsor controls theirs)
"""

import sqlite3
import logging
from pathlib import Path
from contextlib import contextmanager

logger = logging.getLogger(__name__)


class ExtramuralDB:
    """Database extension for extramural WireGuard configurations"""

    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    @contextmanager
    def _connection(self):
        """Context manager for database connections"""
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
        """Initialize extramural schema tables"""
        with self._connection() as conn:
            cursor = conn.cursor()

            # ===== SSH HOST (Shared Resource) =====
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS ssh_host (
                    id INTEGER PRIMARY KEY,
                    name TEXT NOT NULL UNIQUE,
                    ssh_host TEXT NOT NULL,
                    ssh_port INTEGER DEFAULT 22,
                    ssh_user TEXT,
                    ssh_key_path TEXT,
                    config_directory TEXT DEFAULT '/etc/wireguard',
                    notes TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # ===== SPONSOR (External VPN Provider) =====
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS sponsor (
                    id INTEGER PRIMARY KEY,
                    name TEXT NOT NULL UNIQUE,
                    website TEXT,
                    support_url TEXT,
                    notes TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # ===== LOCAL PEER (Your Devices) =====
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS local_peer (
                    id INTEGER PRIMARY KEY,
                    permanent_guid TEXT NOT NULL UNIQUE,
                    name TEXT NOT NULL UNIQUE,
                    ssh_host_id INTEGER REFERENCES ssh_host(id) ON DELETE SET NULL,
                    notes TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # ===== EXTRAMURAL CONFIG =====
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS extramural_config (
                    id INTEGER PRIMARY KEY,
                    local_peer_id INTEGER NOT NULL REFERENCES local_peer(id) ON DELETE CASCADE,
                    sponsor_id INTEGER NOT NULL REFERENCES sponsor(id) ON DELETE CASCADE,
                    permanent_guid TEXT NOT NULL UNIQUE,
                    interface_name TEXT,
                    local_private_key TEXT NOT NULL,
                    local_public_key TEXT NOT NULL,
                    assigned_ipv4 TEXT,
                    assigned_ipv6 TEXT,
                    dns_servers TEXT,
                    listen_port INTEGER,
                    mtu INTEGER,
                    table_setting TEXT,
                    config_path TEXT,
                    last_deployed_at TIMESTAMP,
                    pending_remote_update BOOLEAN DEFAULT 0,
                    last_key_rotation_at TIMESTAMP,
                    notes TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(local_peer_id, sponsor_id)
                )
            """)

            # Add raw_config and comments columns if they don't exist
            cursor.execute("PRAGMA table_info(extramural_config)")
            columns = [row[1] for row in cursor.fetchall()]

            if 'raw_config' not in columns:
                cursor.execute("""
                    ALTER TABLE extramural_config
                    ADD COLUMN raw_config TEXT
                """)
                logger.info("Added raw_config column to extramural_config table")

            if 'comments' not in columns:
                cursor.execute("""
                    ALTER TABLE extramural_config
                    ADD COLUMN comments TEXT
                """)
                logger.info("Added comments column to extramural_config table")

            # ===== EXTRAMURAL PEER (Sponsor's Servers) =====
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS extramural_peer (
                    id INTEGER PRIMARY KEY,
                    config_id INTEGER NOT NULL REFERENCES extramural_config(id) ON DELETE CASCADE,
                    name TEXT,
                    public_key TEXT NOT NULL,
                    endpoint TEXT,
                    allowed_ips TEXT NOT NULL,
                    preshared_key TEXT,
                    persistent_keepalive INTEGER,
                    is_active BOOLEAN DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # ===== TRIGGER: Ensure single active peer per config =====
            cursor.execute("""
                CREATE TRIGGER IF NOT EXISTS ensure_single_active_peer
                AFTER UPDATE OF is_active ON extramural_peer
                WHEN NEW.is_active = 1
                BEGIN
                    UPDATE extramural_peer
                    SET is_active = 0
                    WHERE config_id = NEW.config_id
                    AND id != NEW.id;
                END
            """)

            # ===== EXTRAMURAL POSTUP/POSTDOWN COMMANDS =====
            # Extension to existing command_pair table (if needed)
            # Check if command_pair exists and add column
            cursor.execute("""
                SELECT sql FROM sqlite_master
                WHERE type='table' AND name='command_pair'
            """)
            result = cursor.fetchone()

            if result:
                # Table exists, check if column exists
                cursor.execute("PRAGMA table_info(command_pair)")
                columns = [row[1] for row in cursor.fetchall()]

                if 'extramural_config_id' not in columns:
                    cursor.execute("""
                        ALTER TABLE command_pair
                        ADD COLUMN extramural_config_id INTEGER
                        REFERENCES extramural_config(id) ON DELETE CASCADE
                    """)
                    logger.info("Added extramural_config_id to command_pair table")

            # ===== EXTRAMURAL STATE TRACKING =====
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS extramural_state_snapshot (
                    id INTEGER PRIMARY KEY,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    description TEXT,
                    snapshot_data TEXT NOT NULL
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS extramural_state_change (
                    id INTEGER PRIMARY KEY,
                    snapshot_id INTEGER NOT NULL REFERENCES extramural_state_snapshot(id),
                    change_type TEXT NOT NULL,
                    entity_type TEXT NOT NULL,
                    entity_id INTEGER,
                    entity_name TEXT,
                    old_value TEXT,
                    new_value TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # ===== INDEXES FOR PERFORMANCE =====
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_local_peer_ssh_host
                ON local_peer(ssh_host_id)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_extramural_config_peer
                ON extramural_config(local_peer_id)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_extramural_config_sponsor
                ON extramural_config(sponsor_id)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_extramural_peer_config
                ON extramural_peer(config_id)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_extramural_peer_active
                ON extramural_peer(config_id, is_active)
            """)

            logger.info(f"Extramural schema initialized at {self.db_path}")

    def get_version(self) -> str:
        """Return extramural schema version"""
        return "1.0.0-extramural"


def demonstrate_schema():
    """Show the extramural schema"""
    import tempfile

    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
        db_path = Path(f.name)

    try:
        db = ExtramuralDB(db_path)

        print("=== Extramural Configs Schema ===\n")
        print(f"Version: {db.get_version()}")
        print(f"Location: {db_path}\n")

        with db._connection() as conn:
            cursor = conn.cursor()

            # List all extramural tables
            cursor.execute("""
                SELECT name FROM sqlite_master
                WHERE type='table' AND name LIKE '%ssh_host%'
                   OR name LIKE '%sponsor%'
                   OR name LIKE '%local_peer%'
                   OR name LIKE '%extramural%'
                ORDER BY name
            """)
            tables = [row[0] for row in cursor.fetchall()]

            print(f"Extramural Tables: {len(tables)}")
            for table in tables:
                cursor.execute(f"PRAGMA table_info({table})")
                cols = cursor.fetchall()
                print(f"\n{table}:")
                for col in cols:
                    col_id, name, type_, notnull, default, pk = col
                    nullable = "" if notnull else "NULL"
                    pk_marker = "PK" if pk else ""
                    default_val = f"= {default}" if default else ""
                    print(f"  {name:30} {type_:15} {nullable:5} {pk_marker:3} {default_val}")

        print("\n=== Key Features ===")
        print("\n1. SSH hosts are shared resources (reusable by mesh and extramural)")
        print("2. Complete separation from mesh infrastructure")
        print("3. Local-only control model (you control your keys, sponsor controls theirs)")
        print("4. Multiple peers per config supported (different sponsor servers)")
        print("5. Single active peer enforced via trigger")
        print("6. Pending remote update flag tracks key rotation status")

    finally:
        db_path.unlink()


if __name__ == "__main__":
    demonstrate_schema()
