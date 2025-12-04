"""
Exit Node Operations - CRUD and management for exit nodes

Exit nodes are dedicated VPS/servers that provide internet egress for
remote clients. Unlike the coordination server, they don't coordinate
the VPN mesh - they just route internet-bound traffic.

Key design principles:
- Remote-driven: Each remote individually chooses whether to use an exit node
- Default is NO (split tunnel behavior preserved)
- No fallback to CS as exit (explicit design decision)
- exit_only access level requires an exit node
"""

import sys
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent.parent))

from v1.schema_semantic import WireGuardDBv2
from v1.keygen import generate_keypair
from v1.state_tracker import record_state


@dataclass
class ExitNode:
    """Exit node entity"""
    id: int
    cs_id: int
    permanent_guid: str
    current_public_key: str
    hostname: str
    endpoint: str
    listen_port: int
    ipv4_address: str
    ipv6_address: str
    private_key: str
    wan_interface: str
    ssh_host: Optional[str]
    ssh_user: Optional[str]
    ssh_port: int
    created_at: str
    updated_at: str


class ExitNodeOps:
    """Operations for managing exit nodes"""

    def __init__(self, db: WireGuardDBv2):
        self.db = db

    def list_exit_nodes(self) -> List[ExitNode]:
        """List all exit nodes"""
        with self.db._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, cs_id, permanent_guid, current_public_key, hostname,
                       endpoint, listen_port, ipv4_address, ipv6_address,
                       private_key, wan_interface, ssh_host, ssh_user, ssh_port,
                       created_at, updated_at
                FROM exit_node
                ORDER BY hostname
            """)
            rows = cursor.fetchall()

        return [ExitNode(
            id=row[0],
            cs_id=row[1],
            permanent_guid=row[2],
            current_public_key=row[3],
            hostname=row[4],
            endpoint=row[5],
            listen_port=row[6],
            ipv4_address=row[7],
            ipv6_address=row[8],
            private_key=row[9],
            wan_interface=row[10],
            ssh_host=row[11],
            ssh_user=row[12],
            ssh_port=row[13],
            created_at=row[14],
            updated_at=row[15]
        ) for row in rows]

    def get_exit_node(self, exit_node_id: int) -> Optional[ExitNode]:
        """Get a specific exit node by ID"""
        with self.db._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, cs_id, permanent_guid, current_public_key, hostname,
                       endpoint, listen_port, ipv4_address, ipv6_address,
                       private_key, wan_interface, ssh_host, ssh_user, ssh_port,
                       created_at, updated_at
                FROM exit_node WHERE id = ?
            """, (exit_node_id,))
            row = cursor.fetchone()

        if not row:
            return None

        return ExitNode(
            id=row[0],
            cs_id=row[1],
            permanent_guid=row[2],
            current_public_key=row[3],
            hostname=row[4],
            endpoint=row[5],
            listen_port=row[6],
            ipv4_address=row[7],
            ipv6_address=row[8],
            private_key=row[9],
            wan_interface=row[10],
            ssh_host=row[11],
            ssh_user=row[12],
            ssh_port=row[13],
            created_at=row[14],
            updated_at=row[15]
        )

    def get_exit_node_by_hostname(self, hostname: str) -> Optional[ExitNode]:
        """Get exit node by hostname"""
        with self.db._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, cs_id, permanent_guid, current_public_key, hostname,
                       endpoint, listen_port, ipv4_address, ipv6_address,
                       private_key, wan_interface, ssh_host, ssh_user, ssh_port,
                       created_at, updated_at
                FROM exit_node WHERE hostname = ?
            """, (hostname,))
            row = cursor.fetchone()

        if not row:
            return None

        return ExitNode(
            id=row[0],
            cs_id=row[1],
            permanent_guid=row[2],
            current_public_key=row[3],
            hostname=row[4],
            endpoint=row[5],
            listen_port=row[6],
            ipv4_address=row[7],
            ipv6_address=row[8],
            private_key=row[9],
            wan_interface=row[10],
            ssh_host=row[11],
            ssh_user=row[12],
            ssh_port=row[13],
            created_at=row[14],
            updated_at=row[15]
        )

    def add_exit_node(
        self,
        hostname: str,
        endpoint: str,
        ipv4_address: str,
        ipv6_address: str,
        listen_port: int = 51820,
        wan_interface: str = 'eth0',
        ssh_host: str = None,
        ssh_user: str = None,
        ssh_port: int = 22
    ) -> int:
        """
        Add a new exit node.

        Args:
            hostname: Unique name for the exit node (e.g., 'exit-us-west')
            endpoint: Public IP or domain (e.g., 'us-west.example.com')
            ipv4_address: VPN address with CIDR (e.g., '10.66.0.100/32')
            ipv6_address: VPN address with CIDR (e.g., 'fd66::100/128')
            listen_port: WireGuard listen port (default 51820)
            wan_interface: WAN interface for NAT (default 'eth0')
            ssh_host: SSH host for deployment
            ssh_user: SSH user for deployment
            ssh_port: SSH port for deployment

        Returns:
            ID of the newly created exit node
        """
        # Generate keypair
        private_key, public_key = generate_keypair()
        permanent_guid = public_key  # First key = permanent GUID

        with self.db._connection() as conn:
            cursor = conn.cursor()

            # Get coordination server ID
            cursor.execute("SELECT id FROM coordination_server LIMIT 1")
            row = cursor.fetchone()
            if not row:
                raise ValueError("No coordination server found in database")
            cs_id = row[0]

            # Check for duplicate hostname
            cursor.execute("SELECT id FROM exit_node WHERE hostname = ?", (hostname,))
            if cursor.fetchone():
                raise ValueError(f"Exit node with hostname '{hostname}' already exists")

            # Insert exit node
            cursor.execute("""
                INSERT INTO exit_node (
                    cs_id, permanent_guid, current_public_key, hostname,
                    endpoint, listen_port, ipv4_address, ipv6_address,
                    private_key, wan_interface, ssh_host, ssh_user, ssh_port
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                cs_id, permanent_guid, public_key, hostname,
                endpoint, listen_port, ipv4_address, ipv6_address,
                private_key, wan_interface, ssh_host, ssh_user, ssh_port
            ))
            exit_node_id = cursor.lastrowid

        return exit_node_id

    def remove_exit_node(self, exit_node_id: int) -> Tuple[str, int]:
        """
        Remove an exit node.

        Remotes using this exit node will have their exit_node_id set to NULL
        (falling back to split tunnel behavior).

        Args:
            exit_node_id: ID of the exit node to remove

        Returns:
            (hostname, affected_remotes_count) tuple
        """
        with self.db._connection() as conn:
            cursor = conn.cursor()

            # Get exit node details
            cursor.execute("""
                SELECT hostname FROM exit_node WHERE id = ?
            """, (exit_node_id,))
            row = cursor.fetchone()
            if not row:
                raise ValueError(f"Exit node ID {exit_node_id} not found")
            hostname = row[0]

            # Count affected remotes
            cursor.execute("""
                SELECT COUNT(*) FROM remote WHERE exit_node_id = ?
            """, (exit_node_id,))
            affected_count = cursor.fetchone()[0]

            # Clear exit_node_id from remotes (they'll revert to split tunnel)
            cursor.execute("""
                UPDATE remote SET exit_node_id = NULL
                WHERE exit_node_id = ?
            """, (exit_node_id,))

            # Delete the exit node
            cursor.execute("DELETE FROM exit_node WHERE id = ?", (exit_node_id,))

        return hostname, affected_count

    def assign_exit_to_remote(self, remote_id: int, exit_node_id: int) -> bool:
        """
        Assign an exit node to a remote client.

        Args:
            remote_id: ID of the remote to update
            exit_node_id: ID of the exit node to assign

        Returns:
            True if successful
        """
        with self.db._connection() as conn:
            cursor = conn.cursor()

            # Verify remote exists
            cursor.execute("SELECT id FROM remote WHERE id = ?", (remote_id,))
            if not cursor.fetchone():
                raise ValueError(f"Remote ID {remote_id} not found")

            # Verify exit node exists
            cursor.execute("SELECT id FROM exit_node WHERE id = ?", (exit_node_id,))
            if not cursor.fetchone():
                raise ValueError(f"Exit node ID {exit_node_id} not found")

            # Update remote
            cursor.execute("""
                UPDATE remote SET exit_node_id = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            """, (exit_node_id, remote_id))

        return True

    def clear_exit_from_remote(self, remote_id: int) -> bool:
        """
        Remove exit node assignment from a remote (revert to split tunnel).

        Args:
            remote_id: ID of the remote to update

        Returns:
            True if successful
        """
        with self.db._connection() as conn:
            cursor = conn.cursor()

            # Verify remote exists
            cursor.execute("SELECT id, access_level FROM remote WHERE id = ?", (remote_id,))
            row = cursor.fetchone()
            if not row:
                raise ValueError(f"Remote ID {remote_id} not found")

            access_level = row[1]
            if access_level == 'exit_only':
                raise ValueError(
                    f"Cannot clear exit node from exit_only remote. "
                    f"Change access level first or assign a different exit node."
                )

            # Clear exit node assignment
            cursor.execute("""
                UPDATE remote SET exit_node_id = NULL, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            """, (remote_id,))

        return True

    def get_exit_node_for_remote(self, remote_id: int) -> Optional[ExitNode]:
        """Get the exit node assigned to a remote (if any)"""
        with self.db._connection() as conn:
            cursor = conn.cursor()

            cursor.execute("""
                SELECT exit_node_id FROM remote WHERE id = ?
            """, (remote_id,))
            row = cursor.fetchone()

            if not row or row[0] is None:
                return None

            return self.get_exit_node(row[0])

    def list_remotes_using_exit_node(self, exit_node_id: int) -> List[Dict]:
        """
        Get all remotes using a specific exit node.

        Returns list of dicts with remote info.
        """
        with self.db._connection() as conn:
            cursor = conn.cursor()

            cursor.execute("""
                SELECT id, hostname, ipv4_address, access_level
                FROM remote
                WHERE exit_node_id = ?
                ORDER BY hostname
            """, (exit_node_id,))
            rows = cursor.fetchall()

        return [
            {
                'id': row[0],
                'hostname': row[1],
                'ipv4_address': row[2],
                'access_level': row[3]
            }
            for row in rows
        ]

    def get_next_exit_node_ip(self) -> Tuple[str, str]:
        """
        Get next available IP addresses for an exit node.

        Exit nodes use IPs in the 100-119 range (reserving space for 20 exit nodes).

        Returns:
            (ipv4_address, ipv6_address) with CIDR notation
        """
        with self.db._connection() as conn:
            cursor = conn.cursor()

            # Get network info from coordination server
            cursor.execute("""
                SELECT network_ipv4, network_ipv6 FROM coordination_server LIMIT 1
            """)
            row = cursor.fetchone()
            if not row:
                raise ValueError("No coordination server found in database")

            network_ipv4, network_ipv6 = row

            # Extract base IPs
            ipv4_base = network_ipv4.split('/')[0].rsplit('.', 1)[0]
            ipv6_base = network_ipv6.split('/')[0].rstrip(':')

            # Get existing exit node IPs
            existing_ips = set()
            cursor.execute("SELECT ipv4_address FROM exit_node")
            for row in cursor.fetchall():
                ip = row[0].split('/')[0].split('.')[-1]
                existing_ips.add(int(ip))

            # Find next available in 100-119 range
            for i in range(100, 120):
                if i not in existing_ips:
                    ipv4_address = f"{ipv4_base}.{i}/32"
                    ipv6_address = f"{ipv6_base}::{i:x}/128"
                    return ipv4_address, ipv6_address

            raise ValueError("No available IPs in exit node range (100-119)")

    def validate_exit_only_remote(self, remote_id: int) -> bool:
        """
        Validate that an exit_only remote has an exit node assigned.

        Returns True if valid, raises ValueError if invalid.
        """
        with self.db._connection() as conn:
            cursor = conn.cursor()

            cursor.execute("""
                SELECT access_level, exit_node_id FROM remote WHERE id = ?
            """, (remote_id,))
            row = cursor.fetchone()

            if not row:
                raise ValueError(f"Remote ID {remote_id} not found")

            access_level, exit_node_id = row

            if access_level == 'exit_only' and exit_node_id is None:
                raise ValueError(
                    f"exit_only remote must have an exit node assigned"
                )

            return True

    def set_remote_access_level(
        self,
        remote_id: int,
        access_level: str,
        exit_node_id: int = None
    ) -> bool:
        """
        Update a remote's access level, optionally setting exit node.

        Args:
            remote_id: ID of the remote
            access_level: New access level (full_access, vpn_only, lan_only, custom, exit_only)
            exit_node_id: Exit node ID (required for exit_only, optional for others)

        Returns:
            True if successful
        """
        valid_levels = ['full_access', 'vpn_only', 'lan_only', 'custom', 'exit_only']
        if access_level not in valid_levels:
            raise ValueError(f"Invalid access level: {access_level}. Must be one of: {valid_levels}")

        if access_level == 'exit_only' and exit_node_id is None:
            raise ValueError("exit_only access level requires an exit_node_id")

        with self.db._connection() as conn:
            cursor = conn.cursor()

            # Verify remote exists
            cursor.execute("SELECT id FROM remote WHERE id = ?", (remote_id,))
            if not cursor.fetchone():
                raise ValueError(f"Remote ID {remote_id} not found")

            # Verify exit node exists if specified
            if exit_node_id is not None:
                cursor.execute("SELECT id FROM exit_node WHERE id = ?", (exit_node_id,))
                if not cursor.fetchone():
                    raise ValueError(f"Exit node ID {exit_node_id} not found")

            # Update remote
            cursor.execute("""
                UPDATE remote
                SET access_level = ?, exit_node_id = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            """, (access_level, exit_node_id, remote_id))

        return True


def record_add_exit_node(main_db_path: str, db: WireGuardDBv2, hostname: str, public_key: str) -> int:
    """Record state after adding an exit node"""
    return record_state(
        main_db_path,
        db,
        f"Added exit node: {hostname}",
        changes=[{
            'type': 'add',
            'entity_type': 'exit_node',
            'identifier': hostname,
            'new_value': public_key
        }]
    )


def record_remove_exit_node(main_db_path: str, db: WireGuardDBv2, hostname: str, public_key: str, affected_remotes: int) -> int:
    """Record state after removing an exit node"""
    return record_state(
        main_db_path,
        db,
        f"Removed exit node: {hostname} ({affected_remotes} remotes reverted to split tunnel)",
        changes=[{
            'type': 'remove',
            'entity_type': 'exit_node',
            'identifier': hostname,
            'old_value': public_key
        }]
    )


def record_assign_exit_node(main_db_path: str, db: WireGuardDBv2, remote_hostname: str, exit_hostname: str) -> int:
    """Record state after assigning exit node to remote"""
    return record_state(
        main_db_path,
        db,
        f"Assigned exit node {exit_hostname} to remote {remote_hostname}",
        changes=[{
            'type': 'update',
            'entity_type': 'remote',
            'identifier': remote_hostname,
            'field': 'exit_node',
            'new_value': exit_hostname
        }]
    )


def record_clear_exit_node(main_db_path: str, db: WireGuardDBv2, remote_hostname: str, exit_hostname: str) -> int:
    """Record state after clearing exit node from remote"""
    return record_state(
        main_db_path,
        db,
        f"Cleared exit node from remote {remote_hostname} (was {exit_hostname})",
        changes=[{
            'type': 'update',
            'entity_type': 'remote',
            'identifier': remote_hostname,
            'field': 'exit_node',
            'old_value': exit_hostname,
            'new_value': None
        }]
    )
