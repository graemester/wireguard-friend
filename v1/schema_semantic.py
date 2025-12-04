"""
V2 Database Schema - Unified Semantic Model

No "layers" - just tables with good attributes.
Pattern recognition during import populates semantic fields.

Core insight: Semantic understanding is just well-named columns.
"""

import sqlite3
import logging
from pathlib import Path
from contextlib import contextmanager

logger = logging.getLogger(__name__)


class WireGuardDBv2:
    """V2 Database - semantic attributes, no raw blocks"""

    def __init__(self, db_path: Path | str):
        self.db_path = Path(db_path) if isinstance(db_path, str) else db_path
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
        """Initialize unified semantic schema"""
        with self._connection() as conn:
            cursor = conn.cursor()

            # ===== CORE ENTITIES =====

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS coordination_server (
                    id INTEGER PRIMARY KEY,

                    -- Identity (triple-purpose public key)
                    permanent_guid TEXT NOT NULL UNIQUE,  -- First public key ever seen (immutable)
                    current_public_key TEXT NOT NULL,     -- Active key (changes on rotation)
                    hostname TEXT,                         -- Defaults to permanent_guid if not provided

                    -- Network config
                    endpoint TEXT NOT NULL,
                    listen_port INTEGER,
                    mtu INTEGER,
                    network_ipv4 TEXT NOT NULL,
                    network_ipv6 TEXT NOT NULL,
                    ipv4_address TEXT NOT NULL,
                    ipv6_address TEXT NOT NULL,

                    -- Keys
                    private_key TEXT NOT NULL,

                    -- SSH deployment
                    ssh_host TEXT,
                    ssh_user TEXT,
                    ssh_port INTEGER DEFAULT 22,

                    -- Metadata
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS subnet_router (
                    id INTEGER PRIMARY KEY,
                    cs_id INTEGER NOT NULL,

                    -- Identity (triple-purpose public key)
                    permanent_guid TEXT NOT NULL UNIQUE,  -- First public key ever seen (immutable)
                    current_public_key TEXT NOT NULL,     -- Active key (changes on rotation)
                    hostname TEXT,                         -- Defaults to permanent_guid if not provided

                    -- Network config
                    ipv4_address TEXT NOT NULL,
                    ipv6_address TEXT NOT NULL,
                    endpoint TEXT,
                    mtu INTEGER,
                    persistent_keepalive INTEGER,

                    -- Keys
                    private_key TEXT NOT NULL,
                    preshared_key TEXT,

                    -- LAN interface (for command patterns)
                    lan_interface TEXT,  -- enp1s0, eth1, etc.

                    -- SSH deployment
                    ssh_host TEXT,
                    ssh_user TEXT,
                    ssh_port INTEGER DEFAULT 22,

                    -- Metadata
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

                    FOREIGN KEY (cs_id) REFERENCES coordination_server(id) ON DELETE CASCADE
                )
            """)

            # ===== EXIT NODES =====
            # Dedicated servers for internet egress (separate from coordination server)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS exit_node (
                    id INTEGER PRIMARY KEY,
                    cs_id INTEGER NOT NULL,

                    -- Identity (triple-purpose public key)
                    permanent_guid TEXT NOT NULL UNIQUE,  -- First public key ever seen (immutable)
                    current_public_key TEXT NOT NULL,     -- Active key (changes on rotation)
                    hostname TEXT NOT NULL,               -- e.g., 'exit-us-west', 'exit-eu-central'

                    -- Network config
                    endpoint TEXT NOT NULL,               -- Public IP/domain (e.g., 'us-west.example.com')
                    listen_port INTEGER DEFAULT 51820,
                    ipv4_address TEXT NOT NULL,           -- VPN address (e.g., 10.66.0.100/32)
                    ipv6_address TEXT NOT NULL,           -- VPN address (e.g., fd66::100/128)

                    -- Keys
                    private_key TEXT NOT NULL,

                    -- WAN interface for NAT (e.g., 'eth0')
                    wan_interface TEXT DEFAULT 'eth0',

                    -- SSH deployment
                    ssh_host TEXT,
                    ssh_user TEXT,
                    ssh_port INTEGER DEFAULT 22,

                    -- Metadata
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

                    FOREIGN KEY (cs_id) REFERENCES coordination_server(id) ON DELETE CASCADE
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS remote (
                    id INTEGER PRIMARY KEY,
                    cs_id INTEGER NOT NULL,

                    -- Identity (triple-purpose public key)
                    permanent_guid TEXT NOT NULL UNIQUE,  -- First public key ever seen (immutable)
                    current_public_key TEXT NOT NULL,     -- Active key (changes on rotation)
                    hostname TEXT,                         -- Defaults to permanent_guid if not provided

                    -- Network config
                    ipv4_address TEXT NOT NULL,
                    ipv6_address TEXT NOT NULL,
                    dns_servers TEXT,
                    persistent_keepalive INTEGER,

                    -- Keys (NULL private_key = provisional peer from CS config)
                    private_key TEXT,
                    preshared_key TEXT,

                    -- Access control
                    access_level TEXT NOT NULL,  -- 'full_access', 'vpn_only', 'lan_only', 'custom', 'exit_only'
                    allowed_ips TEXT,            -- Stored AllowedIPs from config (e.g., "10.66.0.0/24, 192.168.1.0/24")

                    -- Exit node routing (optional - NULL means split tunnel/no exit)
                    exit_node_id INTEGER,        -- Foreign key to exit_node table

                    -- Metadata
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

                    FOREIGN KEY (cs_id) REFERENCES coordination_server(id) ON DELETE CASCADE,
                    FOREIGN KEY (exit_node_id) REFERENCES exit_node(id) ON DELETE SET NULL
                )
            """)

            # ===== ADVERTISED NETWORKS =====

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS advertised_network (
                    id INTEGER PRIMARY KEY,
                    subnet_router_id INTEGER NOT NULL,
                    network_cidr TEXT NOT NULL,
                    description TEXT,
                    FOREIGN KEY (subnet_router_id) REFERENCES subnet_router(id) ON DELETE CASCADE
                )
            """)

            # ===== COMMAND PAIRS (semantic attributes) =====

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS command_pair (
                    id INTEGER PRIMARY KEY,
                    entity_type TEXT NOT NULL,  -- 'coordination_server', 'subnet_router'
                    entity_id INTEGER NOT NULL,

                    -- Semantic attributes (populated by pattern recognizer)
                    pattern_name TEXT NOT NULL,  -- 'nat_masquerade_ipv4', 'mss_clamping_ipv4', etc.
                    rationale TEXT NOT NULL,     -- 'NAT for VPN subnet (IPv4)'
                    scope TEXT NOT NULL,         -- 'environment-wide', 'peer-specific'

                    -- Commands (can be multiple per up/down)
                    up_commands TEXT NOT NULL,   -- JSON array: ["cmd1", "cmd2"]
                    down_commands TEXT NOT NULL, -- JSON array: ["cmd1", "cmd2"]

                    -- Variables extracted from pattern
                    variables TEXT,              -- JSON object: {"wan_iface": "eth0", "port": "5432"}

                    -- Execution order
                    execution_order INTEGER NOT NULL,

                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS command_singleton (
                    id INTEGER PRIMARY KEY,
                    entity_type TEXT NOT NULL,
                    entity_id INTEGER NOT NULL,

                    -- Semantic attributes
                    pattern_name TEXT NOT NULL,  -- 'enable_ip_forwarding'
                    rationale TEXT NOT NULL,     -- 'Enable kernel IP forwarding'
                    scope TEXT NOT NULL,

                    -- Commands
                    up_commands TEXT NOT NULL,   -- JSON array

                    -- Variables
                    variables TEXT,              -- JSON object

                    -- Execution order
                    execution_order INTEGER NOT NULL,

                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # ===== COMMENTS (semantic categories) =====

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS comment (
                    id INTEGER PRIMARY KEY,

                    -- Links to permanent GUID (survives key rotations)
                    entity_permanent_guid TEXT NOT NULL,
                    entity_type TEXT NOT NULL,  -- 'coordination_server', 'subnet_router', 'remote'

                    -- Semantic category (populated by comment categorizer)
                    category TEXT NOT NULL,     -- 'hostname', 'role', 'rationale', 'custom', 'unclassified', 'permanent_guid'

                    -- Content
                    text TEXT NOT NULL,

                    -- Role-specific attributes
                    role_type TEXT,             -- 'initiates_only', 'dynamic_endpoint', etc. (nullable)

                    -- Rationale-specific attributes
                    applies_to_pattern TEXT,    -- 'mss_clamping_ipv4', etc. (nullable)

                    -- Display order (hostname=1, role=2, permanent_guid=3, custom=999)
                    display_order INTEGER NOT NULL,

                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # ===== PEER ORDERING =====
            # Preserve order of peers/routers in CS config

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS cs_peer_order (
                    cs_id INTEGER NOT NULL,
                    entity_type TEXT NOT NULL,  -- 'subnet_router' or 'remote'
                    entity_id INTEGER NOT NULL,
                    display_order INTEGER NOT NULL,
                    FOREIGN KEY (cs_id) REFERENCES coordination_server(id) ON DELETE CASCADE,
                    PRIMARY KEY (cs_id, entity_type, entity_id)
                )
            """)

            # ===== KEY ROTATION HISTORY =====
            # Track key rotations over time

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS key_rotation_history (
                    id INTEGER PRIMARY KEY,

                    -- Entity identification (via permanent GUID)
                    entity_permanent_guid TEXT NOT NULL,
                    entity_type TEXT NOT NULL,

                    -- Key change
                    old_public_key TEXT NOT NULL,
                    new_public_key TEXT NOT NULL,

                    -- When and why
                    rotated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    reason TEXT,  -- 'security_incident', 'routine_rotation', 'device_compromise', etc.

                    -- New keys generated
                    new_private_key TEXT NOT NULL
                )
            """)

            # ===== PROVENANCE =====
            # Track where data came from

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS import_session (
                    id INTEGER PRIMARY KEY,
                    source_file TEXT NOT NULL,
                    imported_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    file_size INTEGER NOT NULL,
                    checksum TEXT NOT NULL  -- SHA256
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS entity_provenance (
                    id INTEGER PRIMARY KEY,
                    entity_type TEXT NOT NULL,
                    entity_permanent_guid TEXT NOT NULL,  -- Links via permanent GUID
                    import_session_id INTEGER,
                    creation_method TEXT NOT NULL,  -- 'import', 'manual', 'wizard'
                    source_line_start INTEGER,
                    source_line_end INTEGER,
                    FOREIGN KEY (import_session_id) REFERENCES import_session(id)
                )
            """)

            # ===== INDEXES =====

            cursor.execute("CREATE INDEX IF NOT EXISTS idx_command_pair_entity ON command_pair(entity_type, entity_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_command_singleton_entity ON command_singleton(entity_type, entity_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_comment_guid ON comment(entity_permanent_guid)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_comment_category ON comment(category)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_key_rotation_guid ON key_rotation_history(entity_permanent_guid)")
            cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_cs_permanent_guid ON coordination_server(permanent_guid)")
            cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_router_permanent_guid ON subnet_router(permanent_guid)")
            cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_remote_permanent_guid ON remote(permanent_guid)")
            cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_exit_node_permanent_guid ON exit_node(permanent_guid)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_remote_exit_node ON remote(exit_node_id)")

            logger.info(f"V2 semantic schema initialized at {self.db_path}")

            # ===== EXTRAMURAL CONFIGS (External VPN Management) =====
            # Initialize extramural schema in the same database
            self._init_extramural_schema(cursor)

    def _init_extramural_schema(self, cursor):
        """Initialize extramural config schema tables"""
        # SSH HOST (Shared Resource)
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

        # SPONSOR (External VPN Provider)
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

        # LOCAL PEER (Your Devices)
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

        # EXTRAMURAL CONFIG
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

        # EXTRAMURAL PEER (Sponsor's Servers)
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

        # TRIGGER: Ensure single active peer per config
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

        # Extension to command_pair table
        cursor.execute("""
            SELECT sql FROM sqlite_master
            WHERE type='table' AND name='command_pair'
        """)
        result = cursor.fetchone()

        if result:
            # Check if column exists
            cursor.execute("PRAGMA table_info(command_pair)")
            columns = [row[1] for row in cursor.fetchall()]

            if 'extramural_config_id' not in columns:
                cursor.execute("""
                    ALTER TABLE command_pair
                    ADD COLUMN extramural_config_id INTEGER
                    REFERENCES extramural_config(id) ON DELETE CASCADE
                """)
                logger.info("Added extramural_config_id to command_pair table")

        # Migration: Add allowed_ips to remote table
        cursor.execute("""
            SELECT sql FROM sqlite_master
            WHERE type='table' AND name='remote'
        """)
        result = cursor.fetchone()

        if result:
            cursor.execute("PRAGMA table_info(remote)")
            columns = [row[1] for row in cursor.fetchall()]

            if 'allowed_ips' not in columns:
                cursor.execute("""
                    ALTER TABLE remote
                    ADD COLUMN allowed_ips TEXT
                """)
                logger.info("Added allowed_ips to remote table")

            # Migration: Add exit_node_id to remote table
            if 'exit_node_id' not in columns:
                cursor.execute("""
                    ALTER TABLE remote
                    ADD COLUMN exit_node_id INTEGER
                    REFERENCES exit_node(id) ON DELETE SET NULL
                """)
                logger.info("Added exit_node_id to remote table")

        # EXTRAMURAL STATE TRACKING
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

        # INDEXES FOR PERFORMANCE
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

        logger.info("Extramural schema integrated")

    def get_version(self) -> str:
        """Return database version"""
        return "2.0.0-semantic"


def demonstrate_schema():
    """Show the unified schema"""
    import tempfile

    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
        db_path = Path(f.name)

    try:
        db = WireGuardDBv2(db_path)

        print("=== V2 Unified Semantic Schema ===\n")
        print(f"Version: {db.get_version()}")
        print(f"Location: {db_path}\n")

        with db._connection() as conn:
            cursor = conn.cursor()

            # List all tables
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            tables = [row[0] for row in cursor.fetchall()]

            print(f"Tables: {len(tables)}")
            for table in tables:
                cursor.execute(f"PRAGMA table_info({table})")
                cols = cursor.fetchall()
                print(f"\n{table}:")
                for col in cols:
                    col_id, name, type_, notnull, default, pk = col
                    nullable = "" if notnull else "NULL"
                    pk_marker = "PK" if pk else ""
                    print(f"  {name:25} {type_:15} {nullable:5} {pk_marker}")

        print("\n=== Key Insights ===")
        print("\n1. Semantic understanding = well-named columns")
        print("  - pattern_name (not raw_text)")
        print("  - rationale (not raw_text)")
        print("  - category (not position)")
        print("  - role_type (not raw_text)")
        print("\n2. Triple-purpose public key:")
        print("  - permanent_guid: First key ever seen (immutable, survives rotations)")
        print("  - current_public_key: Active WireGuard key (changes on rotation)")
        print("  - hostname: Defaults to permanent_guid if not provided")
        print("\n3. Comments linked via permanent_guid (survive key rotations)")
        print("\n4. Key rotation history tracks all changes over time")
        print("\nNo layers. No raw blocks. Just attributes populated during import.")

    finally:
        db_path.unlink()


if __name__ == "__main__":
    demonstrate_schema()
