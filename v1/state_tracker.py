"""
State Tracker - Integration between main DB and SystemStateDB

Provides helper functions to capture network state and record changes.
"""

from pathlib import Path
from typing import List, Dict, Optional

from v1.schema_semantic import WireGuardDBv2
from v1.system_state import SystemStateDB, EntitySnapshot


def get_state_db_path(main_db_path: str) -> Path:
    """Get path to state database (sibling to main DB)"""
    main_path = Path(main_db_path)
    return main_path.parent / 'wireguard_states.db'


def capture_current_topology(db: WireGuardDBv2) -> tuple:
    """
    Capture current network topology from main database.

    Returns:
        (cs_snapshot, router_snapshots, remote_snapshots)
    """
    cs_snapshot = None
    router_snapshots = []
    remote_snapshots = []

    with db._connection() as conn:
        cursor = conn.cursor()

        # Capture coordination server
        cursor.execute("""
            SELECT current_public_key, hostname, ipv4_address, ipv6_address, endpoint
            FROM coordination_server
            LIMIT 1
        """)
        row = cursor.fetchone()
        if row:
            cs_snapshot = EntitySnapshot(
                entity_type='coordination_server',
                public_key=row[0],
                hostname=row[1],
                role_type=None,
                ipv4_address=row[2],
                ipv6_address=row[3],
                allowed_ips=[],
                endpoint=row[4]
            )

        # Capture subnet routers
        cursor.execute("""
            SELECT sr.current_public_key, sr.hostname, sr.ipv4_address, sr.ipv6_address, sr.endpoint, sr.id
            FROM subnet_router sr
            ORDER BY sr.hostname
        """)
        for row in cursor.fetchall():
            pubkey, hostname, ipv4, ipv6, endpoint, router_id = row

            # Get advertised networks for allowed_ips
            cursor.execute("""
                SELECT network_cidr FROM advertised_network
                WHERE subnet_router_id = ?
            """, (router_id,))
            networks = [r[0] for r in cursor.fetchall()]

            # Build allowed_ips: VPN address + advertised networks
            allowed_ips = [ipv4] if ipv4 else []
            allowed_ips.extend(networks)

            router_snapshots.append(EntitySnapshot(
                entity_type='subnet_router',
                public_key=pubkey,
                hostname=hostname,
                role_type='subnet_router',
                ipv4_address=ipv4,
                ipv6_address=ipv6,
                allowed_ips=allowed_ips,
                endpoint=endpoint
            ))

        # Capture remotes
        cursor.execute("""
            SELECT current_public_key, hostname, ipv4_address, ipv6_address, access_level
            FROM remote
            ORDER BY hostname
        """)
        for row in cursor.fetchall():
            pubkey, hostname, ipv4, ipv6, access_level = row

            remote_snapshots.append(EntitySnapshot(
                entity_type='remote',
                public_key=pubkey,
                hostname=hostname,
                role_type=access_level,
                ipv4_address=ipv4,
                ipv6_address=ipv6,
                allowed_ips=[ipv4] if ipv4 else [],
                endpoint=None  # Remotes don't have endpoints (they're clients)
            ))

    return cs_snapshot, router_snapshots, remote_snapshots


def record_state(
    main_db_path: str,
    db: WireGuardDBv2,
    description: str,
    changes: List[Dict] = None
) -> int:
    """
    Record current network state as a new snapshot.

    Args:
        main_db_path: Path to main wireguard.db
        db: Main database connection
        description: Description of what changed (e.g., "Added remote: alice-phone")
        changes: Optional list of granular changes [{'type': 'add', 'entity_type': 'remote', 'identifier': 'alice-phone'}]

    Returns:
        state_id of new state
    """
    state_db_path = get_state_db_path(main_db_path)
    state_db = SystemStateDB(state_db_path)

    # Capture current topology
    cs_snapshot, router_snapshots, remote_snapshots = capture_current_topology(db)

    # Create state
    state_id = state_db.create_state(
        description=description,
        cs=cs_snapshot,
        routers=router_snapshots,
        remotes=remote_snapshots,
        changes=changes
    )

    return state_id


def record_import(main_db_path: str, db: WireGuardDBv2, peer_count: int) -> int:
    """Record initial state after import"""
    return record_state(
        main_db_path,
        db,
        f"Initial import: 1 CS, {peer_count} peers"
    )


def record_add_remote(main_db_path: str, db: WireGuardDBv2, hostname: str, public_key: str) -> int:
    """Record state after adding a remote"""
    return record_state(
        main_db_path,
        db,
        f"Added remote: {hostname}",
        changes=[{
            'type': 'add',
            'entity_type': 'remote',
            'identifier': hostname,
            'new_value': public_key
        }]
    )


def record_add_router(main_db_path: str, db: WireGuardDBv2, hostname: str, public_key: str) -> int:
    """Record state after adding a router"""
    return record_state(
        main_db_path,
        db,
        f"Added router: {hostname}",
        changes=[{
            'type': 'add',
            'entity_type': 'subnet_router',
            'identifier': hostname,
            'new_value': public_key
        }]
    )


def record_remove_peer(
    main_db_path: str,
    db: WireGuardDBv2,
    peer_type: str,
    hostname: str,
    public_key: str
) -> int:
    """Record state after removing a peer"""
    return record_state(
        main_db_path,
        db,
        f"Removed {peer_type}: {hostname}",
        changes=[{
            'type': 'remove',
            'entity_type': peer_type,
            'identifier': hostname,
            'old_value': public_key
        }]
    )


def record_rotate_keys(
    main_db_path: str,
    db: WireGuardDBv2,
    peer_type: str,
    hostname: str,
    old_key: str,
    new_key: str
) -> int:
    """Record state after rotating keys"""
    return record_state(
        main_db_path,
        db,
        f"Rotated key: {hostname}",
        changes=[{
            'type': 'rotate_key',
            'entity_type': peer_type,
            'identifier': hostname,
            'old_value': old_key,
            'new_value': new_key
        }]
    )
