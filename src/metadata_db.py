"""Metadata SQLite database for WireGuard peer tracking"""

import sqlite3
import logging
from pathlib import Path
from datetime import datetime
from typing import List, Optional, Dict


logger = logging.getLogger(__name__)


class PeerDatabase:
    """SQLite database for WireGuard peer metadata and revocation tracking"""

    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.conn: Optional[sqlite3.Connection] = None
        self._init_database()

    def _init_database(self):
        """Initialize database schema"""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.row_factory = sqlite3.Row

        cursor = self.conn.cursor()

        # Peers table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS peers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                public_key TEXT NOT NULL,
                private_key TEXT,
                ipv4 TEXT NOT NULL,
                ipv6 TEXT NOT NULL,
                peer_type TEXT NOT NULL,
                allowed_ips TEXT,
                comment TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT,
                revoked_at TEXT,
                config_path TEXT,
                qr_code_path TEXT
            )
        ''')

        # Create indexes
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_peers_name ON peers(name)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_peers_public_key ON peers(public_key)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_peers_revoked ON peers(revoked_at)')

        self.conn.commit()
        logger.info(f"Peer database initialized at {self.db_path}")

    def save_peer(self, peer_data: Dict) -> bool:
        """
        Save or update peer configuration

        Args:
            peer_data: Dictionary with peer details

        Returns:
            True if successful
        """
        cursor = self.conn.cursor()

        try:
            cursor.execute('''
                INSERT OR REPLACE INTO peers (
                    name, public_key, private_key, ipv4, ipv6, peer_type,
                    allowed_ips, comment, created_at, updated_at,
                    config_path, qr_code_path
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                peer_data['name'],
                peer_data['public_key'],
                peer_data.get('private_key'),
                peer_data['ipv4'],
                peer_data['ipv6'],
                peer_data['peer_type'],
                peer_data.get('allowed_ips'),
                peer_data.get('comment'),
                peer_data.get('created_at', datetime.now().isoformat()),
                datetime.now().isoformat(),
                peer_data.get('config_path'),
                peer_data.get('qr_code_path'),
            ))

            self.conn.commit()
            logger.info(f"Saved peer: {peer_data['name']}")
            return True

        except Exception as e:
            logger.error(f"Failed to save peer: {e}")
            return False

    def get_peer(self, name: str) -> Optional[Dict]:
        """Get peer by name"""
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM peers WHERE name = ?', (name,))
        row = cursor.fetchone()
        return dict(row) if row else None

    def get_peer_by_public_key(self, public_key: str) -> Optional[Dict]:
        """Get peer by public key"""
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM peers WHERE public_key = ?', (public_key,))
        row = cursor.fetchone()
        return dict(row) if row else None

    def get_all_peers(self, include_revoked: bool = False) -> List[Dict]:
        """
        Get all peers

        Args:
            include_revoked: Include revoked peers in results

        Returns:
            List of peer dictionaries
        """
        cursor = self.conn.cursor()

        if include_revoked:
            cursor.execute('SELECT * FROM peers ORDER BY created_at DESC')
        else:
            cursor.execute('SELECT * FROM peers WHERE revoked_at IS NULL ORDER BY created_at DESC')

        return [dict(row) for row in cursor.fetchall()]

    def get_active_peers(self) -> List[Dict]:
        """Get all active (non-revoked) peers"""
        return self.get_all_peers(include_revoked=False)

    def get_revoked_peers(self) -> List[Dict]:
        """Get all revoked peers"""
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM peers WHERE revoked_at IS NOT NULL ORDER BY revoked_at DESC')
        return [dict(row) for row in cursor.fetchall()]

    def revoke_peer(self, name: str) -> bool:
        """
        Mark peer as revoked

        Args:
            name: Peer name

        Returns:
            True if peer was found and revoked
        """
        cursor = self.conn.cursor()
        now = datetime.now().isoformat()

        cursor.execute('''
            UPDATE peers
            SET revoked_at = ?, updated_at = ?
            WHERE name = ? AND revoked_at IS NULL
        ''', (now, now, name))

        self.conn.commit()
        rows_affected = cursor.rowcount

        if rows_affected > 0:
            logger.info(f"Revoked peer: {name}")
            return True
        else:
            logger.warning(f"Peer not found or already revoked: {name}")
            return False

    def revoke_peer_by_public_key(self, public_key: str) -> bool:
        """
        Mark peer as revoked by public key

        Args:
            public_key: Peer public key

        Returns:
            True if peer was found and revoked
        """
        cursor = self.conn.cursor()
        now = datetime.now().isoformat()

        cursor.execute('''
            UPDATE peers
            SET revoked_at = ?, updated_at = ?
            WHERE public_key = ? AND revoked_at IS NULL
        ''', (now, now, public_key))

        self.conn.commit()
        rows_affected = cursor.rowcount

        if rows_affected > 0:
            logger.info(f"Revoked peer with public key: {public_key[:16]}...")
            return True
        else:
            logger.warning(f"Peer not found or already revoked: {public_key[:16]}...")
            return False

    def get_used_ips(self) -> List[str]:
        """Get list of all used IP addresses (including revoked peers)"""
        cursor = self.conn.cursor()
        cursor.execute('SELECT ipv4, ipv6 FROM peers')
        rows = cursor.fetchall()
        return [row['ipv4'] for row in rows] + [row['ipv6'] for row in rows]

    def get_next_available_ip(self, start_ip: str = "10.66.0.50") -> Optional[str]:
        """
        Find next available IPv4 address

        Args:
            start_ip: Starting IP address

        Returns:
            Next available IP as string, or None if exhausted
        """
        used_ips = self.get_used_ips()

        # Parse start IP
        parts = start_ip.split('.')
        base = '.'.join(parts[:3])
        start_num = int(parts[3])

        # Find next available
        for i in range(start_num, 255):
            candidate = f"{base}.{i}"
            if candidate not in used_ips:
                return candidate

        return None

    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()
            logger.info("Peer database closed")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
