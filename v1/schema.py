"""
V2 Database Schema - Complete AST Model

This schema captures EVERYTHING about a WireGuard configuration in structured form.
No raw blocks needed - we can reconstruct the exact original from this data.

Key principles:
1. Comments are first-class entities with position metadata
2. PostUp/PostDown are parsed into command ASTs
3. Formatting preferences are explicitly captured
4. Unknown fields are preserved for forward compatibility
5. Every element has provenance (where it came from, when, how)
"""

import sqlite3
import logging
from pathlib import Path
from contextlib import contextmanager
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)


class WireGuardDBv2:
    """V2 Database with complete AST model - no raw blocks"""

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
        """Initialize complete AST schema"""
        with self._connection() as conn:
            cursor = conn.cursor()

            # ===== CORE ENTITIES =====

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS coordination_server (
                    id INTEGER PRIMARY KEY,
                    endpoint TEXT NOT NULL,
                    listen_port INTEGER,
                    mtu INTEGER,
                    network_ipv4 TEXT NOT NULL,
                    network_ipv6 TEXT NOT NULL,
                    ipv4_address TEXT NOT NULL,
                    ipv6_address TEXT NOT NULL,
                    private_key TEXT NOT NULL,
                    public_key TEXT NOT NULL,
                    ssh_host TEXT,
                    ssh_user TEXT,
                    ssh_port INTEGER DEFAULT 22,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS subnet_router (
                    id INTEGER PRIMARY KEY,
                    cs_id INTEGER NOT NULL,
                    name TEXT NOT NULL UNIQUE,
                    ipv4_address TEXT NOT NULL,
                    ipv6_address TEXT NOT NULL,
                    private_key TEXT NOT NULL,
                    public_key TEXT NOT NULL,
                    endpoint TEXT,
                    mtu INTEGER,
                    persistent_keepalive INTEGER,
                    preshared_key TEXT,
                    ssh_host TEXT,
                    ssh_user TEXT,
                    ssh_port INTEGER DEFAULT 22,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (cs_id) REFERENCES coordination_server(id) ON DELETE CASCADE
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS peer (
                    id INTEGER PRIMARY KEY,
                    cs_id INTEGER NOT NULL,
                    name TEXT NOT NULL UNIQUE,
                    ipv4_address TEXT NOT NULL,
                    ipv6_address TEXT NOT NULL,
                    private_key TEXT NOT NULL,
                    public_key TEXT NOT NULL,
                    preshared_key TEXT,
                    access_level TEXT NOT NULL,
                    dns_servers TEXT,
                    persistent_keepalive INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (cs_id) REFERENCES coordination_server(id) ON DELETE CASCADE
                )
            """)

            # ===== COMMENTS SYSTEM =====
            # Comments are first-class entities with precise positioning

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS comment (
                    id INTEGER PRIMARY KEY,
                    entity_type TEXT NOT NULL,  -- 'interface', 'peer', 'command', 'file'
                    entity_id INTEGER,  -- NULL for file-level comments
                    position TEXT NOT NULL,  -- 'before', 'after', 'inline', 'above', 'below'
                    line_offset INTEGER,  -- For multi-line entities, which line?
                    text TEXT NOT NULL,
                    indent_level INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # ===== SHELL COMMAND AST =====
            # PostUp/PostDown parsed into structured commands

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS shell_command (
                    id INTEGER PRIMARY KEY,
                    entity_type TEXT NOT NULL,  -- 'cs', 'subnet_router'
                    entity_id INTEGER NOT NULL,
                    command_type TEXT NOT NULL,  -- 'postup', 'postdown'
                    sequence INTEGER NOT NULL,  -- Execution order
                    command_kind TEXT NOT NULL,  -- 'iptables', 'sysctl', 'ip', 'custom'
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Iptables commands decomposed
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS iptables_command (
                    id INTEGER PRIMARY KEY,
                    shell_command_id INTEGER NOT NULL,
                    table_name TEXT NOT NULL,  -- 'filter', 'nat', 'mangle'
                    chain TEXT NOT NULL,  -- 'INPUT', 'FORWARD', 'POSTROUTING', etc.
                    action TEXT NOT NULL,  -- '-A', '-I', '-D'
                    rule_spec TEXT NOT NULL,  -- Parsed rule specification
                    FOREIGN KEY (shell_command_id) REFERENCES shell_command(id) ON DELETE CASCADE
                )
            """)

            # Rule specifications broken down further
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS iptables_rule_component (
                    id INTEGER PRIMARY KEY,
                    iptables_command_id INTEGER NOT NULL,
                    component_order INTEGER NOT NULL,
                    component_type TEXT NOT NULL,  -- 'match', 'target', 'option'
                    flag TEXT NOT NULL,  -- '-s', '-d', '-j', '-o', etc.
                    value TEXT,  -- The value for this flag
                    FOREIGN KEY (iptables_command_id) REFERENCES iptables_command(id) ON DELETE CASCADE
                )
            """)

            # Sysctl commands
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS sysctl_command (
                    id INTEGER PRIMARY KEY,
                    shell_command_id INTEGER NOT NULL,
                    parameter TEXT NOT NULL,  -- e.g., 'net.ipv4.ip_forward'
                    value TEXT NOT NULL,  -- e.g., '1'
                    write_flag BOOLEAN DEFAULT TRUE,  -- -w flag
                    FOREIGN KEY (shell_command_id) REFERENCES shell_command(id) ON DELETE CASCADE
                )
            """)

            # IP route commands
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS ip_command (
                    id INTEGER PRIMARY KEY,
                    shell_command_id INTEGER NOT NULL,
                    subcommand TEXT NOT NULL,  -- 'route', 'addr', 'link'
                    action TEXT NOT NULL,  -- 'add', 'del', 'show'
                    parameters TEXT NOT NULL,  -- JSON of parsed parameters
                    FOREIGN KEY (shell_command_id) REFERENCES shell_command(id) ON DELETE CASCADE
                )
            """)

            # Custom/unparseable shell commands (fallback)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS custom_shell_command (
                    id INTEGER PRIMARY KEY,
                    shell_command_id INTEGER NOT NULL,
                    command_text TEXT NOT NULL,  -- Original text for commands we can't parse
                    parser_notes TEXT,  -- Why couldn't we parse it?
                    FOREIGN KEY (shell_command_id) REFERENCES shell_command(id) ON DELETE CASCADE
                )
            """)

            # ===== FORMATTING PREFERENCES =====
            # Capture user's style preferences explicitly

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS formatting_profile (
                    id INTEGER PRIMARY KEY,
                    name TEXT NOT NULL UNIQUE,
                    description TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS formatting_rule (
                    id INTEGER PRIMARY KEY,
                    profile_id INTEGER NOT NULL,
                    rule_category TEXT NOT NULL,  -- 'spacing', 'indentation', 'ordering'
                    rule_key TEXT NOT NULL,  -- 'blank_lines_between_peers'
                    rule_value TEXT NOT NULL,  -- '2', 'tabs', 'alphabetical'
                    FOREIGN KEY (profile_id) REFERENCES formatting_profile(id) ON DELETE CASCADE
                )
            """)

            # Per-entity formatting overrides
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS entity_formatting (
                    id INTEGER PRIMARY KEY,
                    entity_type TEXT NOT NULL,
                    entity_id INTEGER NOT NULL,
                    format_key TEXT NOT NULL,  -- 'spacing_before', 'spacing_after', 'indent_style'
                    format_value TEXT NOT NULL
                )
            """)

            # ===== UNKNOWN FIELD PRESERVATION =====
            # Handle WireGuard fields we don't know about (yet)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS unknown_field (
                    id INTEGER PRIMARY KEY,
                    entity_type TEXT NOT NULL,  -- 'interface', 'peer'
                    entity_id INTEGER NOT NULL,
                    field_name TEXT NOT NULL,
                    field_value TEXT NOT NULL,
                    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    validation_mode TEXT DEFAULT 'permissive'  -- 'strict', 'permissive', 'ignore'
                )
            """)

            # ===== PEER ORDERING =====
            # Preserve exact peer order from original config

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS cs_peer_order (
                    cs_id INTEGER NOT NULL,
                    entity_type TEXT NOT NULL,  -- 'subnet_router' or 'peer'
                    entity_id INTEGER NOT NULL,
                    display_order INTEGER NOT NULL,
                    FOREIGN KEY (cs_id) REFERENCES coordination_server(id) ON DELETE CASCADE,
                    PRIMARY KEY (cs_id, entity_type, entity_id)
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

            # ===== PROVENANCE & METADATA =====
            # Track where data came from and how it was created

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS import_session (
                    id INTEGER PRIMARY KEY,
                    source_file TEXT NOT NULL,
                    imported_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    parser_version TEXT NOT NULL,
                    checksum TEXT NOT NULL,  -- SHA256 of original file
                    file_size INTEGER NOT NULL
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS entity_provenance (
                    id INTEGER PRIMARY KEY,
                    entity_type TEXT NOT NULL,
                    entity_id INTEGER NOT NULL,
                    import_session_id INTEGER,
                    creation_method TEXT NOT NULL,  -- 'import', 'manual', 'wizard', 'generated'
                    source_line_start INTEGER,  -- Line number in original file
                    source_line_end INTEGER,
                    FOREIGN KEY (import_session_id) REFERENCES import_session(id)
                )
            """)

            # ===== INDEXES FOR PERFORMANCE =====

            cursor.execute("CREATE INDEX IF NOT EXISTS idx_comment_entity ON comment(entity_type, entity_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_shell_cmd_entity ON shell_command(entity_type, entity_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_unknown_field_entity ON unknown_field(entity_type, entity_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_entity_format ON entity_formatting(entity_type, entity_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_provenance ON entity_provenance(entity_type, entity_id)")

            logger.info(f"V2 database schema initialized at {self.db_path}")

    def get_version(self) -> str:
        """Return database version"""
        return "2.0.0-experimental"
