"""SQLite database for WireGuard Friend configuration storage"""

import sqlite3
import logging
from pathlib import Path
from typing import Optional, Dict, List, Tuple
from datetime import datetime
from contextlib import contextmanager

logger = logging.getLogger(__name__)


class WireGuardDB:
    """Database manager for WireGuard Friend"""

    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    @contextmanager
    def _connection(self):
        """Context manager for database connections"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()

    def _init_schema(self):
        """Initialize database schema"""
        with self._connection() as conn:
            cursor = conn.cursor()

            # System configuration
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS system_config (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    description TEXT
                )
            """)

            # Coordination Server
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS coordination_server (
                    id INTEGER PRIMARY KEY,
                    endpoint TEXT NOT NULL,
                    public_key TEXT NOT NULL,
                    private_key TEXT NOT NULL,
                    listen_port INTEGER,
                    mtu INTEGER,
                    ssh_host TEXT,
                    ssh_user TEXT,
                    ssh_port INTEGER DEFAULT 22,
                    network_ipv4 TEXT NOT NULL,
                    network_ipv6 TEXT NOT NULL,
                    ipv4_address TEXT NOT NULL,
                    ipv6_address TEXT NOT NULL,
                    raw_interface_block TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # PostUp/PostDown rules for CS
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS cs_postup_rules (
                    id INTEGER PRIMARY KEY,
                    cs_id INTEGER NOT NULL,
                    rule_text TEXT NOT NULL,
                    rule_order INTEGER NOT NULL,
                    FOREIGN KEY (cs_id) REFERENCES coordination_server(id) ON DELETE CASCADE
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS cs_postdown_rules (
                    id INTEGER PRIMARY KEY,
                    cs_id INTEGER NOT NULL,
                    rule_text TEXT NOT NULL,
                    rule_order INTEGER NOT NULL,
                    FOREIGN KEY (cs_id) REFERENCES coordination_server(id) ON DELETE CASCADE
                )
            """)

            # Subnet Routers
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS subnet_router (
                    id INTEGER PRIMARY KEY,
                    name TEXT NOT NULL UNIQUE,
                    cs_id INTEGER NOT NULL,
                    public_key TEXT NOT NULL,
                    private_key TEXT NOT NULL,
                    ipv4_address TEXT NOT NULL,
                    ipv6_address TEXT NOT NULL,
                    allowed_ips TEXT NOT NULL,
                    mtu INTEGER,
                    has_endpoint BOOLEAN DEFAULT 0,
                    endpoint TEXT,
                    raw_interface_block TEXT NOT NULL,
                    raw_peer_block TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_rotated TIMESTAMP,
                    FOREIGN KEY (cs_id) REFERENCES coordination_server(id) ON DELETE CASCADE
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS sn_postup_rules (
                    id INTEGER PRIMARY KEY,
                    sn_id INTEGER NOT NULL,
                    rule_text TEXT NOT NULL,
                    rule_order INTEGER NOT NULL,
                    FOREIGN KEY (sn_id) REFERENCES subnet_router(id) ON DELETE CASCADE
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS sn_postdown_rules (
                    id INTEGER PRIMARY KEY,
                    sn_id INTEGER NOT NULL,
                    rule_text TEXT NOT NULL,
                    rule_order INTEGER NOT NULL,
                    FOREIGN KEY (sn_id) REFERENCES subnet_router(id) ON DELETE CASCADE
                )
            """)

            # LAN networks advertised by subnet routers
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS sn_lan_networks (
                    id INTEGER PRIMARY KEY,
                    sn_id INTEGER NOT NULL,
                    network_cidr TEXT NOT NULL,
                    description TEXT,
                    FOREIGN KEY (sn_id) REFERENCES subnet_router(id) ON DELETE CASCADE
                )
            """)

            # Peers (clients)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS peer (
                    id INTEGER PRIMARY KEY,
                    name TEXT NOT NULL UNIQUE,
                    cs_id INTEGER NOT NULL,
                    public_key TEXT NOT NULL,
                    private_key TEXT,
                    ipv4_address TEXT NOT NULL,
                    ipv6_address TEXT NOT NULL,
                    access_level TEXT NOT NULL,
                    preshared_key TEXT,
                    persistent_keepalive INTEGER,
                    has_endpoint BOOLEAN DEFAULT 0,
                    endpoint TEXT,
                    raw_interface_block TEXT,
                    raw_peer_block TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_rotated TIMESTAMP,
                    FOREIGN KEY (cs_id) REFERENCES coordination_server(id) ON DELETE CASCADE,
                    CHECK (access_level IN ('full_access', 'vpn_only', 'lan_only', 'custom', 'restricted_ip'))
                )
            """)

            # For existing databases, update the constraint
            # SQLite doesn't support ALTER TABLE for CHECK constraints, so we'll handle this gracefully
            # New peers with restricted_ip will work; old databases are upgraded on first use

            # Custom allowed IPs for 'custom' access level peers
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS peer_custom_allowed_ips (
                    id INTEGER PRIMARY KEY,
                    peer_id INTEGER NOT NULL,
                    allowed_ip TEXT NOT NULL,
                    FOREIGN KEY (peer_id) REFERENCES peer(id) ON DELETE CASCADE
                )
            """)

            # IP restrictions for 'restricted_ip' access level peers
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS peer_ip_restrictions (
                    id INTEGER PRIMARY KEY,
                    peer_id INTEGER NOT NULL,
                    sn_id INTEGER NOT NULL,
                    target_ip TEXT NOT NULL,
                    description TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (peer_id) REFERENCES peer(id) ON DELETE CASCADE,
                    FOREIGN KEY (sn_id) REFERENCES subnet_router(id) ON DELETE CASCADE
                )
            """)

            # Peer-specific firewall rules for subnet routers
            # These are dynamically generated rules tied to specific peers
            # They are separate from the original "sacred" PostUp/PostDown blocks
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS sn_peer_firewall_rules (
                    id INTEGER PRIMARY KEY,
                    sn_id INTEGER NOT NULL,
                    peer_id INTEGER NOT NULL,
                    rule_type TEXT NOT NULL,
                    rule_text TEXT NOT NULL,
                    rule_order INTEGER NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (sn_id) REFERENCES subnet_router(id) ON DELETE CASCADE,
                    FOREIGN KEY (peer_id) REFERENCES peer(id) ON DELETE CASCADE,
                    CHECK (rule_type IN ('postup', 'postdown'))
                )
            """)

            # Track peer order in CS config for perfect reconstruction
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS cs_peer_order (
                    id INTEGER PRIMARY KEY,
                    cs_id INTEGER NOT NULL,
                    peer_public_key TEXT NOT NULL,
                    position INTEGER NOT NULL,
                    is_subnet_router BOOLEAN DEFAULT 0,
                    FOREIGN KEY (cs_id) REFERENCES coordination_server(id) ON DELETE CASCADE
                )
            """)

            logger.info(f"Database initialized at {self.db_path}")

    # ============================================================================
    # Coordination Server operations
    # ============================================================================

    def save_coordination_server(
        self,
        endpoint: str,
        public_key: str,
        private_key: str,
        network_ipv4: str,
        network_ipv6: str,
        ipv4_address: str,
        ipv6_address: str,
        raw_interface_block: str,
        listen_port: Optional[int] = None,
        mtu: Optional[int] = None,
        ssh_host: Optional[str] = None,
        ssh_user: Optional[str] = None,
        ssh_port: int = 22,
    ) -> int:
        """Save coordination server configuration"""
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO coordination_server
                (endpoint, public_key, private_key, listen_port, mtu, ssh_host, ssh_user, ssh_port,
                 network_ipv4, network_ipv6, ipv4_address, ipv6_address, raw_interface_block)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (endpoint, public_key, private_key, listen_port, mtu, ssh_host, ssh_user, ssh_port,
                  network_ipv4, network_ipv6, ipv4_address, ipv6_address, raw_interface_block))

            cs_id = cursor.lastrowid
            logger.info(f"Saved coordination server with ID {cs_id}")
            return cs_id

    def get_coordination_server(self) -> Optional[Dict]:
        """Get coordination server configuration"""
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM coordination_server LIMIT 1")
            row = cursor.fetchone()
            return dict(row) if row else None

    def save_cs_postup_rules(self, cs_id: int, rules: List[str]):
        """Save PostUp rules for coordination server"""
        with self._connection() as conn:
            cursor = conn.cursor()
            for i, rule in enumerate(rules):
                cursor.execute("""
                    INSERT INTO cs_postup_rules (cs_id, rule_text, rule_order)
                    VALUES (?, ?, ?)
                """, (cs_id, rule, i))
            logger.info(f"Saved {len(rules)} PostUp rules for CS {cs_id}")

    def save_cs_postdown_rules(self, cs_id: int, rules: List[str]):
        """Save PostDown rules for coordination server"""
        with self._connection() as conn:
            cursor = conn.cursor()
            for i, rule in enumerate(rules):
                cursor.execute("""
                    INSERT INTO cs_postdown_rules (cs_id, rule_text, rule_order)
                    VALUES (?, ?, ?)
                """, (cs_id, rule, i))
            logger.info(f"Saved {len(rules)} PostDown rules for CS {cs_id}")

    def get_cs_postup_rules(self, cs_id: int) -> List[str]:
        """Get PostUp rules in order"""
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT rule_text FROM cs_postup_rules
                WHERE cs_id = ? ORDER BY rule_order
            """, (cs_id,))
            return [row['rule_text'] for row in cursor.fetchall()]

    def get_cs_postdown_rules(self, cs_id: int) -> List[str]:
        """Get PostDown rules in order"""
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT rule_text FROM cs_postdown_rules
                WHERE cs_id = ? ORDER BY rule_order
            """, (cs_id,))
            return [row['rule_text'] for row in cursor.fetchall()]

    # ============================================================================
    # Subnet Router operations
    # ============================================================================

    def save_subnet_router(
        self,
        name: str,
        cs_id: int,
        public_key: str,
        private_key: str,
        ipv4_address: str,
        ipv6_address: str,
        allowed_ips: str,
        raw_interface_block: str,
        raw_peer_block: str,
        mtu: Optional[int] = None,
        has_endpoint: bool = False,
        endpoint: Optional[str] = None,
    ) -> int:
        """Save subnet router configuration"""
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO subnet_router
                (name, cs_id, public_key, private_key, ipv4_address, ipv6_address,
                 allowed_ips, mtu, has_endpoint, endpoint, raw_interface_block, raw_peer_block)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (name, cs_id, public_key, private_key, ipv4_address, ipv6_address,
                  allowed_ips, mtu, has_endpoint, endpoint, raw_interface_block, raw_peer_block))

            sn_id = cursor.lastrowid
            logger.info(f"Saved subnet router '{name}' with ID {sn_id}")
            return sn_id

    def save_sn_postup_rules(self, sn_id: int, rules: List[str]):
        """Save PostUp rules for subnet router"""
        with self._connection() as conn:
            cursor = conn.cursor()
            for i, rule in enumerate(rules):
                cursor.execute("""
                    INSERT INTO sn_postup_rules (sn_id, rule_text, rule_order)
                    VALUES (?, ?, ?)
                """, (sn_id, rule, i))
            logger.info(f"Saved {len(rules)} PostUp rules for SN {sn_id}")

    def save_sn_postdown_rules(self, sn_id: int, rules: List[str]):
        """Save PostDown rules for subnet router"""
        with self._connection() as conn:
            cursor = conn.cursor()
            for i, rule in enumerate(rules):
                cursor.execute("""
                    INSERT INTO sn_postdown_rules (sn_id, rule_text, rule_order)
                    VALUES (?, ?, ?)
                """, (sn_id, rule, i))
            logger.info(f"Saved {len(rules)} PostDown rules for SN {sn_id}")

    def save_sn_lan_networks(self, sn_id: int, networks: List[str]):
        """Save LAN networks for subnet router"""
        with self._connection() as conn:
            cursor = conn.cursor()
            for network in networks:
                cursor.execute("""
                    INSERT INTO sn_lan_networks (sn_id, network_cidr)
                    VALUES (?, ?)
                """, (sn_id, network))
            logger.info(f"Saved {len(networks)} LAN networks for SN {sn_id}")

    def get_subnet_routers(self, cs_id: int) -> List[Dict]:
        """Get all subnet routers for a coordination server"""
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM subnet_router WHERE cs_id = ?", (cs_id,))
            return [dict(row) for row in cursor.fetchall()]

    def get_sn_lan_networks(self, sn_id: int) -> List[str]:
        """Get LAN networks for a subnet router"""
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT network_cidr FROM sn_lan_networks WHERE sn_id = ?", (sn_id,))
            return [row['network_cidr'] for row in cursor.fetchall()]

    def get_sn_postup_rules(self, sn_id: int) -> List[str]:
        """Get PostUp rules for subnet router in order"""
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT rule_text FROM sn_postup_rules
                WHERE sn_id = ? ORDER BY rule_order
            """, (sn_id,))
            return [row['rule_text'] for row in cursor.fetchall()]

    def get_sn_postdown_rules(self, sn_id: int) -> List[str]:
        """Get PostDown rules for subnet router in order"""
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT rule_text FROM sn_postdown_rules
                WHERE sn_id = ? ORDER BY rule_order
            """, (sn_id,))
            return [row['rule_text'] for row in cursor.fetchall()]

    def save_sn_peer_firewall_rules(self, sn_id: int, peer_id: int, postup_rules: List[str], postdown_rules: List[str]):
        """Save peer-specific firewall rules for subnet router"""
        with self._connection() as conn:
            cursor = conn.cursor()

            # Save PostUp rules
            for i, rule in enumerate(postup_rules):
                cursor.execute("""
                    INSERT INTO sn_peer_firewall_rules (sn_id, peer_id, rule_type, rule_text, rule_order)
                    VALUES (?, ?, 'postup', ?, ?)
                """, (sn_id, peer_id, rule, i))

            # Save PostDown rules
            for i, rule in enumerate(postdown_rules):
                cursor.execute("""
                    INSERT INTO sn_peer_firewall_rules (sn_id, peer_id, rule_type, rule_text, rule_order)
                    VALUES (?, ?, 'postdown', ?, ?)
                """, (sn_id, peer_id, rule, i))

            logger.info(f"Saved {len(postup_rules)} PostUp and {len(postdown_rules)} PostDown firewall rules for peer {peer_id}")

    def get_sn_peer_firewall_rules(self, sn_id: int, rule_type: str) -> List[Tuple[int, str]]:
        """Get peer-specific firewall rules for subnet router

        Returns list of (peer_id, rule_text) tuples in order
        """
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT peer_id, rule_text FROM sn_peer_firewall_rules
                WHERE sn_id = ? AND rule_type = ?
                ORDER BY peer_id, rule_order
            """, (sn_id, rule_type))
            return [(row['peer_id'], row['rule_text']) for row in cursor.fetchall()]

    def delete_peer_firewall_rules(self, peer_id: int):
        """Delete all firewall rules associated with a peer"""
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM sn_peer_firewall_rules WHERE peer_id = ?", (peer_id,))
            logger.info(f"Deleted firewall rules for peer {peer_id}")

    # ============================================================================
    # Peer operations
    # ============================================================================

    def save_peer(
        self,
        name: str,
        cs_id: int,
        public_key: str,
        ipv4_address: str,
        ipv6_address: str,
        access_level: str,
        raw_peer_block: str,
        private_key: Optional[str] = None,
        raw_interface_block: Optional[str] = None,
        preshared_key: Optional[str] = None,
        persistent_keepalive: Optional[int] = None,
        has_endpoint: bool = False,
        endpoint: Optional[str] = None,
    ) -> int:
        """Save peer configuration"""
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO peer
                (name, cs_id, public_key, private_key, ipv4_address, ipv6_address,
                 access_level, preshared_key, persistent_keepalive, has_endpoint, endpoint,
                 raw_interface_block, raw_peer_block)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (name, cs_id, public_key, private_key, ipv4_address, ipv6_address,
                  access_level, preshared_key, persistent_keepalive, has_endpoint, endpoint,
                  raw_interface_block, raw_peer_block))

            peer_id = cursor.lastrowid
            logger.info(f"Saved peer '{name}' with ID {peer_id}")
            return peer_id

    def get_peers(self, cs_id: int) -> List[Dict]:
        """Get all peers for a coordination server"""
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM peer WHERE cs_id = ?", (cs_id,))
            return [dict(row) for row in cursor.fetchall()]

    def get_peer_by_pubkey(self, cs_id: int, public_key: str) -> Optional[Dict]:
        """Get peer by public key"""
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM peer WHERE cs_id = ? AND public_key = ?
            """, (cs_id, public_key))
            row = cursor.fetchone()
            return dict(row) if row else None

    def save_peer_ip_restriction(self, peer_id: int, sn_id: int, target_ip: str, description: Optional[str] = None):
        """Save IP restriction for a peer"""
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO peer_ip_restrictions (peer_id, sn_id, target_ip, description)
                VALUES (?, ?, ?, ?)
            """, (peer_id, sn_id, target_ip, description))
            logger.info(f"Saved IP restriction for peer {peer_id}: {target_ip} on SN {sn_id}")

    def get_peer_ip_restriction(self, peer_id: int) -> Optional[Dict]:
        """Get IP restriction for a peer"""
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM peer_ip_restrictions WHERE peer_id = ?
            """, (peer_id,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def delete_peer_ip_restriction(self, peer_id: int):
        """Delete IP restriction for a peer"""
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM peer_ip_restrictions WHERE peer_id = ?", (peer_id,))
            logger.info(f"Deleted IP restriction for peer {peer_id}")

    # ============================================================================
    # Peer order tracking
    # ============================================================================

    def save_peer_order(self, cs_id: int, public_key: str, position: int, is_subnet_router: bool = False):
        """Save peer position in coordination server config"""
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO cs_peer_order (cs_id, peer_public_key, position, is_subnet_router)
                VALUES (?, ?, ?, ?)
            """, (cs_id, public_key, position, is_subnet_router))

    def get_peer_order(self, cs_id: int) -> List[Dict]:
        """Get peer order for coordination server"""
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM cs_peer_order WHERE cs_id = ? ORDER BY position
            """, (cs_id,))
            return [dict(row) for row in cursor.fetchall()]

    # ============================================================================
    # Configuration reconstruction
    # ============================================================================

    def reconstruct_cs_config(self) -> str:
        """Reconstruct coordination server config from raw blocks"""
        cs = self.get_coordination_server()
        if not cs:
            raise ValueError("No coordination server found in database")

        # Start with raw interface block - OUTPUT AS-IS
        lines = []
        lines.append(cs['raw_interface_block'].rstrip())

        # Get peers in original order
        peer_order = self.get_peer_order(cs['id'])

        for order_entry in peer_order:
            pubkey = order_entry['peer_public_key']

            # Check if this is a subnet router or regular peer
            if order_entry['is_subnet_router']:
                # Find in subnet_router table
                with self._connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute("""
                        SELECT raw_peer_block FROM subnet_router
                        WHERE cs_id = ? AND public_key = ?
                    """, (cs['id'], pubkey))
                    row = cursor.fetchone()
                    if row:
                        lines.append('')
                        lines.append(row['raw_peer_block'].rstrip())
            else:
                # Find in peer table
                peer = self.get_peer_by_pubkey(cs['id'], pubkey)
                if peer:
                    lines.append('')
                    lines.append(peer['raw_peer_block'].rstrip())

        lines.append('')
        return '\n'.join(lines)

    def reconstruct_sn_config(self, sn_id: int) -> str:
        """Reconstruct subnet router config from raw blocks with firewall rules"""
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM subnet_router WHERE id = ?", (sn_id,))
            sn = cursor.fetchone()

            if not sn:
                raise ValueError(f"No subnet router found with ID {sn_id}")

            sn = dict(sn)

        lines = []

        # Start with [Interface] header
        lines.append("[Interface]")

        # Extract PrivateKey and Address from raw_interface_block
        # The raw_interface_block contains the complete Interface section
        # We need to parse it to inject PostUp/PostDown rules
        interface_lines = sn['raw_interface_block'].strip().split('\n')

        # Skip [Interface] line (we already added it) and add the rest
        for line in interface_lines:
            if line.strip() == "[Interface]":
                continue
            # Don't add PostUp/PostDown from original block yet - we'll add them in order below
            if line.strip().startswith("PostUp") or line.strip().startswith("PostDown"):
                continue
            lines.append(line)

        # Add original PostUp rules
        original_postup = self.get_sn_postup_rules(sn_id)
        if original_postup:
            for rule in original_postup:
                lines.append(f"PostUp = {rule}")

        # Add peer-specific PostUp rules with comments
        peer_postup_rules = self.get_sn_peer_firewall_rules(sn_id, 'postup')
        if peer_postup_rules:
            # Group by peer_id
            current_peer_id = None
            for peer_id, rule_text in peer_postup_rules:
                if peer_id != current_peer_id:
                    # Get peer name for comment
                    with self._connection() as conn:
                        cursor = conn.cursor()
                        cursor.execute("SELECT name FROM peer WHERE id = ?", (peer_id,))
                        peer_row = cursor.fetchone()
                        peer_name = peer_row['name'] if peer_row else f"peer-{peer_id}"

                    lines.append(f"# Peer-specific rule for: {peer_name}")
                    current_peer_id = peer_id

                lines.append(f"PostUp = {rule_text}")

        # Add original PostDown rules
        original_postdown = self.get_sn_postdown_rules(sn_id)
        if original_postdown:
            for rule in original_postdown:
                lines.append(f"PostDown = {rule}")

        # Add peer-specific PostDown rules with comments
        peer_postdown_rules = self.get_sn_peer_firewall_rules(sn_id, 'postdown')
        if peer_postdown_rules:
            # Group by peer_id
            current_peer_id = None
            for peer_id, rule_text in peer_postdown_rules:
                if peer_id != current_peer_id:
                    # Get peer name for comment
                    with self._connection() as conn:
                        cursor = conn.cursor()
                        cursor.execute("SELECT name FROM peer WHERE id = ?", (peer_id,))
                        peer_row = cursor.fetchone()
                        peer_name = peer_row['name'] if peer_row else f"peer-{peer_id}"

                    lines.append(f"# Peer-specific rule for: {peer_name}")
                    current_peer_id = peer_id

                lines.append(f"PostDown = {rule_text}")

        # Add the Peer block (connection to coordination server)
        lines.append('')
        lines.append(sn['raw_peer_block'].rstrip())
        lines.append('')

        return '\n'.join(lines)

    def reconstruct_peer_config(self, peer_id: int) -> str:
        """Reconstruct peer client config from raw blocks"""
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM peer WHERE id = ?", (peer_id,))
            peer = cursor.fetchone()

            if not peer:
                raise ValueError(f"No peer found with ID {peer_id}")

            peer = dict(peer)

        if not peer['raw_interface_block']:
            raise ValueError(f"Peer '{peer['name']}' has no client config (no raw_interface_block)")

        # Output raw interface block AS-IS
        lines = []
        lines.append(peer['raw_interface_block'].rstrip())
        lines.append('')

        return '\n'.join(lines)

    # ============================================================================
    # Utility operations
    # ============================================================================

    def clear_all_data(self):
        """Clear all data from database (for testing)"""
        with self._connection() as conn:
            cursor = conn.cursor()
            tables = [
                'cs_peer_order', 'peer_custom_allowed_ips', 'peer_ip_restrictions',
                'sn_peer_firewall_rules', 'peer',
                'sn_lan_networks', 'sn_postdown_rules', 'sn_postup_rules', 'subnet_router',
                'cs_postdown_rules', 'cs_postup_rules', 'coordination_server',
                'system_config'
            ]
            for table in tables:
                cursor.execute(f"DELETE FROM {table}")
            logger.info("Cleared all data from database")
