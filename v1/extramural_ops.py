"""
Extramural Config Operations

Core operations for managing external WireGuard configurations.

Operations:
- SSH Host: CRUD operations for shared SSH resources
- Sponsor: CRUD for external VPN providers
- Local Peer: CRUD for devices receiving extramural configs
- Extramural Config: Import, create, rotate keys, deploy
- Extramural Peer: Manage sponsor server endpoints
"""

import json
import sqlite3
import logging
import uuid
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict, Tuple
from dataclasses import dataclass, asdict
from contextlib import contextmanager

logger = logging.getLogger(__name__)


# ===== DATA MODELS =====

@dataclass
class SSHHost:
    """Shared SSH host configuration"""
    id: Optional[int] = None
    name: str = ""
    ssh_host: str = ""
    ssh_port: int = 22
    ssh_user: Optional[str] = None
    ssh_key_path: Optional[str] = None
    config_directory: str = "/etc/wireguard"
    notes: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


@dataclass
class Sponsor:
    """External VPN provider or service"""
    id: Optional[int] = None
    name: str = ""
    website: Optional[str] = None
    support_url: Optional[str] = None
    notes: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


@dataclass
class LocalPeer:
    """Device receiving extramural configs"""
    id: Optional[int] = None
    permanent_guid: str = ""
    name: str = ""
    ssh_host_id: Optional[int] = None
    notes: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


@dataclass
class ExtramuralConfig:
    """WireGuard config linking local peer to sponsor"""
    id: Optional[int] = None
    local_peer_id: int = 0
    sponsor_id: int = 0
    permanent_guid: str = ""
    interface_name: Optional[str] = None
    local_private_key: str = ""
    local_public_key: str = ""
    assigned_ipv4: Optional[str] = None
    assigned_ipv6: Optional[str] = None
    dns_servers: Optional[str] = None
    listen_port: Optional[int] = None
    mtu: Optional[int] = None
    table_setting: Optional[str] = None
    config_path: Optional[str] = None
    last_deployed_at: Optional[datetime] = None
    pending_remote_update: bool = False
    last_key_rotation_at: Optional[datetime] = None
    notes: Optional[str] = None
    raw_config: Optional[str] = None
    comments: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


@dataclass
class ExtramuralPeer:
    """Sponsor's server endpoint"""
    id: Optional[int] = None
    config_id: int = 0
    name: Optional[str] = None
    public_key: str = ""
    endpoint: Optional[str] = None
    allowed_ips: str = ""
    preshared_key: Optional[str] = None
    persistent_keepalive: Optional[int] = None
    is_active: bool = False
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


# ===== DATABASE OPERATIONS =====

class ExtramuralOps:
    """Core operations for extramural configurations"""

    def __init__(self, db_path: Path):
        self.db_path = db_path

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

    # ===== SSH HOST OPERATIONS =====

    def add_ssh_host(
        self,
        name: str,
        ssh_host: str,
        ssh_port: int = 22,
        ssh_user: Optional[str] = None,
        ssh_key_path: Optional[str] = None,
        config_directory: str = "/etc/wireguard",
        notes: Optional[str] = None
    ) -> int:
        """Add a new SSH host configuration"""
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO ssh_host (name, ssh_host, ssh_port, ssh_user, ssh_key_path, config_directory, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (name, ssh_host, ssh_port, ssh_user, ssh_key_path, config_directory, notes))
            return cursor.lastrowid

    def get_ssh_host(self, host_id: int) -> Optional[SSHHost]:
        """Get SSH host by ID"""
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM ssh_host WHERE id = ?", (host_id,))
            row = cursor.fetchone()
            return SSHHost(**dict(row)) if row else None

    def get_ssh_host_by_name(self, name: str) -> Optional[SSHHost]:
        """Get SSH host by name"""
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM ssh_host WHERE name = ?", (name,))
            row = cursor.fetchone()
            return SSHHost(**dict(row)) if row else None

    def list_ssh_hosts(self) -> List[SSHHost]:
        """List all SSH hosts"""
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM ssh_host ORDER BY name")
            return [SSHHost(**dict(row)) for row in cursor.fetchall()]

    def update_ssh_host(self, host_id: int, **kwargs) -> None:
        """Update SSH host fields"""
        valid_fields = {'name', 'ssh_host', 'ssh_port', 'ssh_user', 'ssh_key_path', 'config_directory', 'notes'}
        updates = {k: v for k, v in kwargs.items() if k in valid_fields}

        if not updates:
            return

        set_clause = ", ".join(f"{k} = ?" for k in updates.keys())
        set_clause += ", updated_at = CURRENT_TIMESTAMP"
        values = list(updates.values()) + [host_id]

        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute(f"UPDATE ssh_host SET {set_clause} WHERE id = ?", values)

    def delete_ssh_host(self, host_id: int) -> None:
        """Delete SSH host (warns if referenced)"""
        with self._connection() as conn:
            cursor = conn.cursor()

            # Check for references
            cursor.execute("SELECT COUNT(*) FROM local_peer WHERE ssh_host_id = ?", (host_id,))
            local_peer_refs = cursor.fetchone()[0]

            if local_peer_refs > 0:
                raise ValueError(f"SSH host is referenced by {local_peer_refs} local peer(s). Remove references first.")

            cursor.execute("DELETE FROM ssh_host WHERE id = ?", (host_id,))

    # ===== SPONSOR OPERATIONS =====

    def add_sponsor(
        self,
        name: str,
        website: Optional[str] = None,
        support_url: Optional[str] = None,
        notes: Optional[str] = None
    ) -> int:
        """Add a new sponsor (external VPN provider)"""
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO sponsor (name, website, support_url, notes)
                VALUES (?, ?, ?, ?)
            """, (name, website, support_url, notes))
            return cursor.lastrowid

    def get_sponsor(self, sponsor_id: int) -> Optional[Sponsor]:
        """Get sponsor by ID"""
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM sponsor WHERE id = ?", (sponsor_id,))
            row = cursor.fetchone()
            return Sponsor(**dict(row)) if row else None

    def get_sponsor_by_name(self, name: str) -> Optional[Sponsor]:
        """Get sponsor by name"""
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM sponsor WHERE name = ?", (name,))
            row = cursor.fetchone()
            return Sponsor(**dict(row)) if row else None

    def list_sponsors(self) -> List[Sponsor]:
        """List all sponsors"""
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM sponsor ORDER BY name")
            return [Sponsor(**dict(row)) for row in cursor.fetchall()]

    def update_sponsor(self, sponsor_id: int, **kwargs) -> None:
        """Update sponsor fields"""
        valid_fields = {'name', 'website', 'support_url', 'notes'}
        updates = {k: v for k, v in kwargs.items() if k in valid_fields}

        if not updates:
            return

        set_clause = ", ".join(f"{k} = ?" for k in updates.keys())
        set_clause += ", updated_at = CURRENT_TIMESTAMP"
        values = list(updates.values()) + [sponsor_id]

        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute(f"UPDATE sponsor SET {set_clause} WHERE id = ?", values)

    def delete_sponsor(self, sponsor_id: int) -> None:
        """Delete sponsor (cascades to configs)"""
        with self._connection() as conn:
            cursor = conn.cursor()

            # Check for configs
            cursor.execute("SELECT COUNT(*) FROM extramural_config WHERE sponsor_id = ?", (sponsor_id,))
            config_count = cursor.fetchone()[0]

            if config_count > 0:
                raise ValueError(f"Sponsor has {config_count} config(s). Delete configs first or use cascade.")

            cursor.execute("DELETE FROM sponsor WHERE id = ?", (sponsor_id,))

    # ===== LOCAL PEER OPERATIONS =====

    def add_local_peer(
        self,
        name: str,
        permanent_guid: Optional[str] = None,
        ssh_host_id: Optional[int] = None,
        notes: Optional[str] = None
    ) -> int:
        """Add a new local peer (your device)"""
        if not permanent_guid:
            permanent_guid = str(uuid.uuid4())

        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO local_peer (permanent_guid, name, ssh_host_id, notes)
                VALUES (?, ?, ?, ?)
            """, (permanent_guid, name, ssh_host_id, notes))
            return cursor.lastrowid

    def get_local_peer(self, peer_id: int) -> Optional[LocalPeer]:
        """Get local peer by ID"""
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM local_peer WHERE id = ?", (peer_id,))
            row = cursor.fetchone()
            return LocalPeer(**dict(row)) if row else None

    def get_local_peer_by_name(self, name: str) -> Optional[LocalPeer]:
        """Get local peer by name"""
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM local_peer WHERE name = ?", (name,))
            row = cursor.fetchone()
            return LocalPeer(**dict(row)) if row else None

    def list_local_peers(self) -> List[LocalPeer]:
        """List all local peers"""
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM local_peer ORDER BY name")
            return [LocalPeer(**dict(row)) for row in cursor.fetchall()]

    def update_local_peer(self, peer_id: int, **kwargs) -> None:
        """Update local peer fields"""
        valid_fields = {'name', 'ssh_host_id', 'notes'}
        updates = {k: v for k, v in kwargs.items() if k in valid_fields}

        if not updates:
            return

        set_clause = ", ".join(f"{k} = ?" for k in updates.keys())
        set_clause += ", updated_at = CURRENT_TIMESTAMP"
        values = list(updates.values()) + [peer_id]

        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute(f"UPDATE local_peer SET {set_clause} WHERE id = ?", values)

    def delete_local_peer(self, peer_id: int) -> None:
        """Delete local peer (cascades to configs)"""
        with self._connection() as conn:
            cursor = conn.cursor()

            # Check for configs
            cursor.execute("SELECT COUNT(*) FROM extramural_config WHERE local_peer_id = ?", (peer_id,))
            config_count = cursor.fetchone()[0]

            if config_count > 0:
                raise ValueError(f"Local peer has {config_count} config(s). Delete configs first or use cascade.")

            cursor.execute("DELETE FROM local_peer WHERE id = ?", (peer_id,))

    # ===== EXTRAMURAL CONFIG OPERATIONS =====

    def add_extramural_config(
        self,
        local_peer_id: int,
        sponsor_id: int,
        local_private_key: str,
        local_public_key: str,
        permanent_guid: Optional[str] = None,
        **kwargs
    ) -> int:
        """Add a new extramural config"""
        if not permanent_guid:
            permanent_guid = local_public_key  # Use public key as permanent identifier

        valid_fields = {
            'interface_name', 'assigned_ipv4', 'assigned_ipv6', 'dns_servers',
            'listen_port', 'mtu', 'table_setting', 'config_path', 'notes',
            'raw_config', 'comments'
        }
        optional = {k: v for k, v in kwargs.items() if k in valid_fields}

        with self._connection() as conn:
            cursor = conn.cursor()

            fields = ['local_peer_id', 'sponsor_id', 'permanent_guid', 'local_private_key', 'local_public_key']
            values = [local_peer_id, sponsor_id, permanent_guid, local_private_key, local_public_key]

            for key, value in optional.items():
                fields.append(key)
                values.append(value)

            placeholders = ", ".join("?" * len(values))
            field_names = ", ".join(fields)

            cursor.execute(f"""
                INSERT INTO extramural_config ({field_names})
                VALUES ({placeholders})
            """, values)
            return cursor.lastrowid

    def get_extramural_config(self, config_id: int) -> Optional[ExtramuralConfig]:
        """Get extramural config by ID"""
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM extramural_config WHERE id = ?", (config_id,))
            row = cursor.fetchone()
            return ExtramuralConfig(**dict(row)) if row else None

    def get_extramural_config_by_peer_sponsor(
        self,
        local_peer_id: int,
        sponsor_id: int
    ) -> Optional[ExtramuralConfig]:
        """Get extramural config by local peer and sponsor"""
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM extramural_config
                WHERE local_peer_id = ? AND sponsor_id = ?
            """, (local_peer_id, sponsor_id))
            row = cursor.fetchone()
            return ExtramuralConfig(**dict(row)) if row else None

    def list_extramural_configs(
        self,
        local_peer_id: Optional[int] = None,
        sponsor_id: Optional[int] = None
    ) -> List[ExtramuralConfig]:
        """List extramural configs, optionally filtered"""
        with self._connection() as conn:
            cursor = conn.cursor()

            if local_peer_id and sponsor_id:
                cursor.execute("""
                    SELECT * FROM extramural_config
                    WHERE local_peer_id = ? AND sponsor_id = ?
                    ORDER BY created_at DESC
                """, (local_peer_id, sponsor_id))
            elif local_peer_id:
                cursor.execute("""
                    SELECT * FROM extramural_config
                    WHERE local_peer_id = ?
                    ORDER BY created_at DESC
                """, (local_peer_id,))
            elif sponsor_id:
                cursor.execute("""
                    SELECT * FROM extramural_config
                    WHERE sponsor_id = ?
                    ORDER BY created_at DESC
                """, (sponsor_id,))
            else:
                cursor.execute("SELECT * FROM extramural_config ORDER BY created_at DESC")

            return [ExtramuralConfig(**dict(row)) for row in cursor.fetchall()]

    def update_extramural_config(self, config_id: int, **kwargs) -> None:
        """Update extramural config fields"""
        valid_fields = {
            'interface_name', 'assigned_ipv4', 'assigned_ipv6', 'dns_servers',
            'listen_port', 'mtu', 'table_setting', 'config_path',
            'pending_remote_update', 'notes'
        }
        updates = {k: v for k, v in kwargs.items() if k in valid_fields}

        if not updates:
            return

        set_clause = ", ".join(f"{k} = ?" for k in updates.keys())
        set_clause += ", updated_at = CURRENT_TIMESTAMP"
        values = list(updates.values()) + [config_id]

        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute(f"UPDATE extramural_config SET {set_clause} WHERE id = ?", values)

    def update_config_from_sponsor(
        self,
        config_id: int,
        local_private_key: Optional[str] = None,
        local_public_key: Optional[str] = None,
        assigned_ipv4: Optional[str] = None,
        assigned_ipv6: Optional[str] = None,
        dns_servers: Optional[str] = None,
        **kwargs
    ) -> None:
        """
        Update config with new details from sponsor.
        This is the common scenario - sponsor sends you a new config file.
        """
        updates = {}

        if local_private_key:
            updates['local_private_key'] = local_private_key
        if local_public_key:
            updates['local_public_key'] = local_public_key
        if assigned_ipv4:
            updates['assigned_ipv4'] = assigned_ipv4
        if assigned_ipv6:
            updates['assigned_ipv6'] = assigned_ipv6
        if dns_servers:
            updates['dns_servers'] = dns_servers

        # Include other valid fields
        valid_fields = {'interface_name', 'listen_port', 'mtu', 'table_setting', 'config_path', 'notes'}
        for key, value in kwargs.items():
            if key in valid_fields and value is not None:
                updates[key] = value

        if not updates:
            return

        # Clear pending_remote_update since this is a sponsor-initiated update
        updates['pending_remote_update'] = 0

        set_clause = ", ".join(f"{k} = ?" for k in updates.keys())
        set_clause += ", updated_at = CURRENT_TIMESTAMP"
        values = list(updates.values()) + [config_id]

        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute(f"UPDATE extramural_config SET {set_clause} WHERE id = ?", values)

    def rotate_local_key(self, config_id: int, new_private_key: str, new_public_key: str) -> None:
        """
        Rotate local keypair for a config (UNUSUAL scenario).
        This sets pending_remote_update=1 because you need to notify the sponsor.
        """
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE extramural_config
                SET local_private_key = ?,
                    local_public_key = ?,
                    pending_remote_update = 1,
                    last_key_rotation_at = CURRENT_TIMESTAMP,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            """, (new_private_key, new_public_key, config_id))

    def clear_pending_update(self, config_id: int) -> None:
        """Clear pending remote update flag"""
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE extramural_config
                SET pending_remote_update = 0,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            """, (config_id,))

    def mark_deployed(self, config_id: int) -> None:
        """Mark config as deployed"""
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE extramural_config
                SET last_deployed_at = CURRENT_TIMESTAMP,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            """, (config_id,))

    def delete_extramural_config(self, config_id: int) -> None:
        """Delete extramural config (cascades to peers)"""
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM extramural_config WHERE id = ?", (config_id,))

    # ===== EXTRAMURAL PEER OPERATIONS =====

    def add_extramural_peer(
        self,
        config_id: int,
        public_key: str,
        allowed_ips: str,
        name: Optional[str] = None,
        endpoint: Optional[str] = None,
        preshared_key: Optional[str] = None,
        persistent_keepalive: Optional[int] = None,
        is_active: bool = False
    ) -> int:
        """Add a sponsor server endpoint"""
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO extramural_peer
                (config_id, name, public_key, endpoint, allowed_ips, preshared_key, persistent_keepalive, is_active)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (config_id, name, public_key, endpoint, allowed_ips, preshared_key, persistent_keepalive, is_active))
            return cursor.lastrowid

    def get_extramural_peer(self, peer_id: int) -> Optional[ExtramuralPeer]:
        """Get extramural peer by ID"""
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM extramural_peer WHERE id = ?", (peer_id,))
            row = cursor.fetchone()
            return ExtramuralPeer(**dict(row)) if row else None

    def list_extramural_peers(self, config_id: int) -> List[ExtramuralPeer]:
        """List all peers for a config"""
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM extramural_peer
                WHERE config_id = ?
                ORDER BY is_active DESC, name
            """, (config_id,))
            return [ExtramuralPeer(**dict(row)) for row in cursor.fetchall()]

    def get_active_peer(self, config_id: int) -> Optional[ExtramuralPeer]:
        """Get the active peer for a config"""
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM extramural_peer
                WHERE config_id = ? AND is_active = 1
                LIMIT 1
            """, (config_id,))
            row = cursor.fetchone()
            return ExtramuralPeer(**dict(row)) if row else None

    def set_active_peer(self, peer_id: int) -> None:
        """Set a peer as active (trigger handles deactivating others)"""
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE extramural_peer
                SET is_active = 1, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            """, (peer_id,))

    def update_extramural_peer(self, peer_id: int, **kwargs) -> None:
        """Update extramural peer fields"""
        valid_fields = {'name', 'public_key', 'endpoint', 'allowed_ips', 'preshared_key', 'persistent_keepalive'}
        updates = {k: v for k, v in kwargs.items() if k in valid_fields}

        if not updates:
            return

        set_clause = ", ".join(f"{k} = ?" for k in updates.keys())
        set_clause += ", updated_at = CURRENT_TIMESTAMP"
        values = list(updates.values()) + [peer_id]

        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute(f"UPDATE extramural_peer SET {set_clause} WHERE id = ?", values)

    def delete_extramural_peer(self, peer_id: int) -> None:
        """Delete extramural peer"""
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM extramural_peer WHERE id = ?", (peer_id,))


# ===== CONVENIENCE FUNCTIONS =====

def generate_wireguard_keypair() -> Tuple[str, str]:
    """Generate a WireGuard keypair using wg command"""
    import subprocess

    try:
        # Generate private key
        private_key = subprocess.check_output(
            ["wg", "genkey"],
            text=True
        ).strip()

        # Derive public key
        public_key = subprocess.check_output(
            ["wg", "pubkey"],
            input=private_key,
            text=True
        ).strip()

        return private_key, public_key

    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Failed to generate WireGuard keypair: {e}")
    except FileNotFoundError:
        raise RuntimeError("WireGuard tools (wg) not found. Please install wireguard-tools.")


if __name__ == "__main__":
    # Demo usage
    import tempfile

    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
        db_path = Path(f.name)

    print(f"Creating demo database at {db_path}\n")

    # Initialize schema
    from v1.extramural_schema import ExtramuralDB
    ExtramuralDB(db_path)

    # Initialize operations
    ops = ExtramuralOps(db_path)

    # Add SSH host
    print("=== Adding SSH Host ===")
    host_id = ops.add_ssh_host(
        name="laptop",
        ssh_host="laptop.local",
        ssh_user="user",
        config_directory="/etc/wireguard"
    )
    print(f"Added SSH host with ID: {host_id}")

    # Add sponsor
    print("\n=== Adding Sponsor ===")
    sponsor_id = ops.add_sponsor(
        name="Mullvad VPN",
        website="https://mullvad.net",
        support_url="https://mullvad.net/help"
    )
    print(f"Added sponsor with ID: {sponsor_id}")

    # Add local peer
    print("\n=== Adding Local Peer ===")
    peer_id = ops.add_local_peer(
        name="my-laptop",
        ssh_host_id=host_id,
        notes="Personal laptop"
    )
    print(f"Added local peer with ID: {peer_id}")

    # Generate keypair
    print("\n=== Generating Keypair ===")
    try:
        private_key, public_key = generate_wireguard_keypair()
        print(f"Private key: {private_key[:20]}...")
        print(f"Public key: {public_key[:20]}...")

        # Add config
        print("\n=== Adding Extramural Config ===")
        config_id = ops.add_extramural_config(
            local_peer_id=peer_id,
            sponsor_id=sponsor_id,
            local_private_key=private_key,
            local_public_key=public_key,
            interface_name="wg-mullvad",
            assigned_ipv4="10.64.1.1/32",
            dns_servers="10.64.0.1"
        )
        print(f"Added config with ID: {config_id}")

        # Add sponsor peer
        print("\n=== Adding Sponsor Peer ===")
        sp_id = ops.add_extramural_peer(
            config_id=config_id,
            name="us-east",
            public_key="SponsorPublicKey123...",
            endpoint="us1.mullvad.net:51820",
            allowed_ips="0.0.0.0/0",
            is_active=True
        )
        print(f"Added sponsor peer with ID: {sp_id}")

        # List everything
        print("\n=== Listing All Entities ===")
        print(f"SSH Hosts: {len(ops.list_ssh_hosts())}")
        print(f"Sponsors: {len(ops.list_sponsors())}")
        print(f"Local Peers: {len(ops.list_local_peers())}")
        print(f"Configs: {len(ops.list_extramural_configs())}")

    except RuntimeError as e:
        print(f"Skipping keypair generation: {e}")

    print(f"\nDemo database available at: {db_path}")
