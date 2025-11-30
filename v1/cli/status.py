"""
Network Status View

Shows current state of the WireGuard network.
"""

import sys
import subprocess
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from datetime import datetime, timedelta

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from v1.schema_semantic import WireGuardDBv2
from v1.network_utils import is_local_host
from v1.system_state import SystemStateDB


def show_network_overview(db: WireGuardDBv2):
    """Display network overview"""
    print("\n" + "=" * 70)
    print("WIREGUARD NETWORK STATUS")
    print("=" * 70)

    with db._connection() as conn:
        cursor = conn.cursor()

        # Coordination Server
        cursor.execute("""
            SELECT hostname, endpoint, listen_port, network_ipv4, network_ipv6,
                   ipv4_address, ipv6_address, current_public_key, permanent_guid
            FROM coordination_server
        """)
        row = cursor.fetchone()
        if row:
            hostname, endpoint, port, net4, net6, ip4, ip6, pubkey, guid = row
            print(f"\nCoordination Server:")
            print(f"  Hostname:      {hostname}")
            print(f"  Endpoint:      {endpoint}:{port}")
            print(f"  VPN Network:   {net4}, {net6}")
            print(f"  VPN Address:   {ip4}, {ip6}")
            print(f"  Public Key:    {pubkey[:30]}...")
            print(f"  Permanent ID:  {guid[:30]}...")

        # Subnet Routers
        cursor.execute("""
            SELECT id, hostname, ipv4_address, ipv6_address, endpoint,
                   lan_interface, current_public_key, permanent_guid
            FROM subnet_router
            ORDER BY hostname
        """)
        routers = cursor.fetchall()
        if routers:
            print(f"\nSubnet Routers ({len(routers)}):")
            for router_id, hostname, ip4, ip6, endpoint, lan_if, pubkey, guid in routers:
                print(f"\n  [{router_id}] {hostname}")
                print(f"      VPN Address:   {ip4}, {ip6}")
                print(f"      Endpoint:      {endpoint or 'Dynamic'}")
                print(f"      LAN Interface: {lan_if}")
                print(f"      Public Key:    {pubkey[:30]}...")

                # Advertised networks
                cursor.execute("""
                    SELECT network_cidr
                    FROM advertised_network
                    WHERE subnet_router_id = ?
                """, (router_id,))
                networks = [row[0] for row in cursor.fetchall()]
                if networks:
                    print(f"      Advertises:    {', '.join(networks)}")

        # Remotes
        cursor.execute("""
            SELECT id, hostname, ipv4_address, ipv6_address, access_level,
                   current_public_key, permanent_guid
            FROM remote
            ORDER BY hostname
        """)
        remotes = cursor.fetchall()
        if remotes:
            print(f"\nRemote Clients ({len(remotes)}):")
            for remote_id, hostname, ip4, ip6, access, pubkey, guid in remotes:
                print(f"  [{remote_id:2}] {hostname:25} {ip4:18} {access:15} {pubkey[:20]}...")

    print()


def show_recent_rotations(db: WireGuardDBv2, limit: int = 10):
    """Display recent key rotations"""
    print("=" * 70)
    print("RECENT KEY ROTATIONS")
    print("=" * 70)

    with db._connection() as conn:
        cursor = conn.cursor()

        cursor.execute("""
            SELECT entity_permanent_guid, old_public_key, new_public_key, rotated_at, reason
            FROM key_rotation_history
            ORDER BY rotated_at DESC
            LIMIT ?
        """, (limit,))

        rows = cursor.fetchall()
        if not rows:
            print("\nNo key rotations recorded yet.")
        else:
            for guid, old_key, new_key, rotated_at, reason in rows:
                # Find entity name by GUID
                cursor.execute("""
                    SELECT 'CS', hostname FROM coordination_server WHERE permanent_guid = ?
                    UNION
                    SELECT 'Router', hostname FROM subnet_router WHERE permanent_guid = ?
                    UNION
                    SELECT 'Remote', hostname FROM remote WHERE permanent_guid = ?
                """, (guid, guid, guid))
                entity_row = cursor.fetchone()
                entity_type, hostname = entity_row if entity_row else ('Unknown', 'Unknown')

                print(f"\n  {rotated_at}  [{entity_type}] {hostname}")
                print(f"    Old: {old_key[:30]}...")
                print(f"    New: {new_key[:30]}...")
                print(f"    Reason: {reason}")

    print()


def show_command_patterns(db: WireGuardDBv2):
    """Display configured command patterns"""
    print("=" * 70)
    print("COMMAND PATTERNS")
    print("=" * 70)

    with db._connection() as conn:
        cursor = conn.cursor()

        # Command pairs
        cursor.execute("""
            SELECT entity_type, entity_id, pattern_name, rationale, scope
            FROM command_pair
            ORDER BY entity_type, entity_id, execution_order
        """)
        pairs = cursor.fetchall()

        if pairs:
            print(f"\nCommand Pairs ({len(pairs)}):")
            for entity_type, entity_id, pattern, rationale, scope in pairs:
                print(f"  {entity_type}:{entity_id:2} {pattern:20} {scope:10} {rationale}")

        # Command singletons
        cursor.execute("""
            SELECT entity_type, entity_id, pattern_name, rationale, scope
            FROM command_singleton
            ORDER BY entity_type, entity_id, execution_order
        """)
        singletons = cursor.fetchall()

        if singletons:
            print(f"\nCommand Singletons ({len(singletons)}):")
            for entity_type, entity_id, pattern, rationale, scope in singletons:
                print(f"  {entity_type}:{entity_id:2} {pattern:20} {scope:10} {rationale}")

    print()


def parse_wg_show(output: str) -> Dict[str, Dict[str, str]]:
    """
    Parse output from 'wg show' command.

    Returns:
        Dict mapping public keys to peer status info:
        {
            'pubkey': {
                'endpoint': '1.2.3.4:51820',
                'allowed_ips': '10.0.0.2/32, fd00::2/128',
                'latest_handshake': '1234567890',  # Unix timestamp
                'transfer_rx': '12345',  # bytes
                'transfer_tx': '67890',  # bytes
            }
        }
    """
    peers = {}
    current_peer = None

    for line in output.splitlines():
        line = line.strip()

        if line.startswith('peer:'):
            # New peer section
            pubkey = line.split(':', 1)[1].strip()
            current_peer = pubkey
            peers[pubkey] = {}

        elif current_peer and ':' in line:
            # Peer attribute
            key, value = line.split(':', 1)
            key = key.strip()
            value = value.strip()

            if key == 'endpoint':
                peers[current_peer]['endpoint'] = value
            elif key == 'allowed ips':
                peers[current_peer]['allowed_ips'] = value
            elif key == 'latest handshake':
                # Convert "X seconds ago" to timestamp
                # Format can be: "5 seconds ago", "2 minutes, 30 seconds ago", "never"
                if value == '(none)':
                    peers[current_peer]['latest_handshake'] = None
                else:
                    # For simplicity, store the raw string
                    # In production, parse to get actual timestamp
                    peers[current_peer]['latest_handshake'] = value
            elif key == 'transfer':
                # Format: "12.34 KiB received, 56.78 MiB sent"
                parts = value.split(',')
                if len(parts) >= 2:
                    rx = parts[0].replace('received', '').strip()
                    tx = parts[1].replace('sent', '').strip()
                    peers[current_peer]['transfer_rx'] = rx
                    peers[current_peer]['transfer_tx'] = tx

    return peers


def run_wg_show(cs_endpoint: str, interface: str = 'wg0', user: str = 'root') -> Optional[str]:
    """
    Run 'wg show' on coordination server.

    Args:
        cs_endpoint: Coordination server endpoint (hostname or IP)
        interface: WireGuard interface name
        user: SSH user

    Returns:
        Output from wg show, or None on error
    """
    # Strip port from endpoint if present
    host = cs_endpoint.split(':')[0] if cs_endpoint else None

    if not host:
        print("Error: No coordination server endpoint configured")
        return None

    # Check if target is localhost
    if is_local_host(host):
        # Run locally
        try:
            result = subprocess.run(
                ['sudo', 'wg', 'show', interface],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode != 0:
                print(f"Error running wg show: {result.stderr}")
                return None

            return result.stdout

        except subprocess.TimeoutExpired:
            print("Error: wg show command timed out")
            return None
        except FileNotFoundError:
            print("Error: wg command not found")
            return None
    else:
        # Run via SSH
        try:
            result = subprocess.run(
                ['ssh', f'{user}@{host}', f'wg show {interface}'],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode != 0:
                print(f"Error running wg show via SSH: {result.stderr}")
                return None

            return result.stdout

        except subprocess.TimeoutExpired:
            print("Error: SSH command timed out")
            return None
        except FileNotFoundError:
            print("Error: ssh command not found")
            return None


def show_live_peer_status(db: WireGuardDBv2, interface: str = 'wg0', user: str = 'root'):
    """
    Show live peer connection status by running wg show on coordination server.

    Args:
        db: Database connection
        interface: WireGuard interface name
        user: SSH user for connection
    """
    print("\n" + "=" * 70)
    print("LIVE PEER STATUS")
    print("=" * 70)

    # Get coordination server endpoint
    with db._connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT endpoint, hostname
            FROM coordination_server
            LIMIT 1
        """)
        row = cursor.fetchone()
        if not row:
            print("\nError: No coordination server found in database")
            return

        cs_endpoint, cs_hostname = row

    if not cs_endpoint or cs_endpoint == 'UNKNOWN':
        print(f"\n⚠  Coordination server '{cs_hostname}' has no endpoint configured")
        print("Cannot retrieve live status without endpoint")
        return

    print(f"\nQuerying {cs_hostname} ({cs_endpoint})...")

    # Run wg show
    wg_output = run_wg_show(cs_endpoint, interface=interface, user=user)

    if not wg_output:
        return

    # Parse output
    peer_status = parse_wg_show(wg_output)

    if not peer_status:
        print("\nNo peers connected")
        return

    # Get peer info from database
    with db._connection() as conn:
        cursor = conn.cursor()

        # Build a map of public keys to peer info
        peer_db_info = {}

        # Subnet routers
        cursor.execute("""
            SELECT current_public_key, hostname, ipv4_address, 'router'
            FROM subnet_router
        """)
        for pubkey, hostname, ip, entity_type in cursor.fetchall():
            peer_db_info[pubkey] = {
                'hostname': hostname,
                'ip': ip,
                'type': entity_type
            }

        # Remotes
        cursor.execute("""
            SELECT current_public_key, hostname, ipv4_address, 'remote'
            FROM remote
        """)
        for pubkey, hostname, ip, entity_type in cursor.fetchall():
            peer_db_info[pubkey] = {
                'hostname': hostname,
                'ip': ip,
                'type': entity_type
            }

    # Display peer status
    print(f"\nConnected Peers ({len(peer_status)}):")
    print()
    print(f"{'Hostname':<30} {'Type':<10} {'Endpoint':<22} {'Handshake':<20} {'RX/TX':<30}")
    print("─" * 70)

    for pubkey, status in peer_status.items():
        # Get peer info from database
        db_info = peer_db_info.get(pubkey, {
            'hostname': f'Unknown ({pubkey[:10]}...)',
            'ip': 'Unknown',
            'type': 'unknown'
        })

        hostname = db_info['hostname']
        peer_type = db_info['type']
        endpoint = status.get('endpoint', 'N/A')
        handshake = status.get('latest_handshake', 'Never')
        rx = status.get('transfer_rx', '0 B')
        tx = status.get('transfer_tx', '0 B')

        # Determine online status
        online = '●' if handshake and handshake != '(none)' and 'ago' in handshake else '○'

        print(f"{online} {hostname:<28} {peer_type:<10} {endpoint:<22} {handshake:<20} {rx} ↓ / {tx} ↑")

    print()
    print("Legend: ● = Online (recent handshake)  ○ = Offline/Never connected")
    print()


def show_state_history(db_path: str, limit: int = 20, state_id: int = None):
    """
    Display state history timeline.

    Shows the history of network state snapshots - like git log for your WireGuard network.

    Args:
        db_path: Path to the main database (state DB is derived from it)
        limit: Number of states to show
        state_id: Optional specific state to show in detail
    """
    # State DB is stored alongside the main DB
    state_db_path = Path(db_path).parent / 'wireguard_states.db'

    if not state_db_path.exists():
        print("\n" + "=" * 70)
        print("STATE HISTORY")
        print("=" * 70)
        print("\nNo state history recorded yet.")
        print("\nState snapshots are created when you:")
        print("  • Import configs (initial state)")
        print("  • Add/remove peers")
        print("  • Rotate keys")
        print("\nRun 'wg-friend import' or make changes to start tracking state.")
        print()
        return

    state_db = SystemStateDB(state_db_path)

    if state_id:
        # Show detailed view of a specific state
        state = state_db.get_state(state_id)
        if not state:
            print(f"\nState {state_id} not found.")
            return

        print("\n" + "=" * 70)
        print(f"STATE {state.state_id} - DETAIL VIEW")
        print("=" * 70)
        print(f"\nTimestamp:   {state.created_at.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Description: {state.description}")
        print(f"Entities:    {state.total_entities} total ({state.total_remotes} remotes, {state.total_routers} routers)")

        # Show changes that created this state
        changes = state_db.get_changes(state_id)
        if changes:
            print(f"\nChanges:")
            for change in changes:
                change_type = change['change_type']
                entity = change['entity_identifier']
                old_val = change.get('old_value', '')
                new_val = change.get('new_value', '')

                if change_type == 'add':
                    print(f"  + Added {change['entity_type']}: {entity}")
                elif change_type == 'remove':
                    print(f"  - Removed {change['entity_type']}: {entity}")
                elif change_type == 'rotate_key':
                    print(f"  ↻ Rotated key for {entity}")
                    if old_val:
                        print(f"      Old: {old_val[:30]}...")
                    if new_val:
                        print(f"      New: {new_val[:30]}...")
                elif change_type == 'modify':
                    print(f"  ~ Modified {entity}: {old_val} → {new_val}")

        # Show topology snapshot
        print(f"\nTopology Snapshot:")
        if state.coordination_server:
            cs = state.coordination_server
            print(f"\n  Coordination Server:")
            print(f"    IP: {cs.ipv4_address}, {cs.ipv6_address}")
            print(f"    Key: {cs.public_key[:30]}...")

        if state.subnet_routers:
            print(f"\n  Subnet Routers ({len(state.subnet_routers)}):")
            for router in state.subnet_routers:
                print(f"    • {router.hostname}: {router.ipv4_address}")

        if state.remotes:
            print(f"\n  Remotes ({len(state.remotes)}):")
            for remote in state.remotes:
                print(f"    • {remote.hostname}: {remote.ipv4_address}")

        print()
        return

    # Show timeline
    print("\n" + "=" * 70)
    print("STATE HISTORY TIMELINE")
    print("=" * 70)
    print("\nLike 'git log' for your WireGuard network - each state is a snapshot.")
    print()

    timeline = state_db.get_timeline(limit=limit)

    if not timeline:
        print("No states recorded yet.")
        print()
        return

    # Show newest first (timeline already sorted DESC)
    print(f"{'ID':<4} {'Timestamp':<20} {'Entities':<10} {'Description':<35}")
    print("─" * 70)

    for state in timeline:
        timestamp = state.created_at.strftime('%Y-%m-%d %H:%M')
        entities = f"{state.total_entities} ({state.total_remotes}R)"
        desc = state.description[:35] if len(state.description) <= 35 else state.description[:32] + "..."
        print(f"{state.state_id:<4} {timestamp:<20} {entities:<10} {desc}")

    print()
    print(f"Showing {len(timeline)} most recent states.")
    print("Use 'wg-friend status --history --state <ID>' for details on a specific state.")
    print()


def show_entity_history(db: WireGuardDBv2, db_path: str, entity_name: str):
    """
    Display history for a specific entity (peer).

    Shows when the entity was first seen, key rotations, and current status.

    Args:
        db: Main WireGuard database
        db_path: Path to the main database
        entity_name: Hostname or ID of the entity to look up
    """
    print("\n" + "=" * 70)
    print(f"ENTITY HISTORY: {entity_name}")
    print("=" * 70)

    # First, find the entity in the main DB to get its public key and details
    with db._connection() as conn:
        cursor = conn.cursor()

        # Search across all entity types
        entity_info = None

        # Check coordination server
        cursor.execute("""
            SELECT 'coordination_server' as type, NULL as id, hostname,
                   current_public_key, permanent_guid, ipv4_address
            FROM coordination_server
            WHERE hostname LIKE ?
        """, (f'%{entity_name}%',))
        row = cursor.fetchone()
        if row:
            entity_info = dict(row)

        # Check subnet routers
        if not entity_info:
            cursor.execute("""
                SELECT 'subnet_router' as type, id, hostname,
                       current_public_key, permanent_guid, ipv4_address
                FROM subnet_router
                WHERE hostname LIKE ? OR CAST(id AS TEXT) = ?
            """, (f'%{entity_name}%', entity_name))
            row = cursor.fetchone()
            if row:
                entity_info = dict(row)

        # Check remotes
        if not entity_info:
            cursor.execute("""
                SELECT 'remote' as type, id, hostname,
                       current_public_key, permanent_guid, ipv4_address
                FROM remote
                WHERE hostname LIKE ? OR CAST(id AS TEXT) = ?
            """, (f'%{entity_name}%', entity_name))
            row = cursor.fetchone()
            if row:
                entity_info = dict(row)

        if not entity_info:
            print(f"\nEntity '{entity_name}' not found.")
            print("Try searching by hostname or ID number.")
            print()
            return

        # Display entity info
        print(f"\nEntity Type:   {entity_info['type'].replace('_', ' ').title()}")
        print(f"Hostname:      {entity_info['hostname']}")
        print(f"VPN Address:   {entity_info['ipv4_address']}")
        print(f"Current Key:   {entity_info['current_public_key'][:40]}...")
        print(f"Permanent ID:  {entity_info['permanent_guid'][:40]}...")

        # Get key rotation history for this entity
        cursor.execute("""
            SELECT old_public_key, new_public_key, rotated_at, reason
            FROM key_rotation_history
            WHERE entity_permanent_guid = ?
            ORDER BY rotated_at DESC
        """, (entity_info['permanent_guid'],))

        rotations = cursor.fetchall()

        if rotations:
            print(f"\nKey Rotation History ({len(rotations)} rotations):")
            print("─" * 50)
            for old_key, new_key, rotated_at, reason in rotations:
                print(f"\n  {rotated_at}")
                print(f"    Reason: {reason}")
                print(f"    Old: {old_key[:30]}...")
                print(f"    New: {new_key[:30]}...")
        else:
            print(f"\nNo key rotations recorded for this entity.")

    # Check state database for entity timeline
    state_db_path = Path(db_path).parent / 'wireguard_states.db'

    if state_db_path.exists():
        state_db = SystemStateDB(state_db_path)

        # Check entity history in state DB (by current and historical keys)
        history = state_db.get_entity_history(entity_info['current_public_key'])

        if history:
            print(f"\nState Timeline:")
            print(f"  First seen in: State {history['first_seen_state']}")
            print(f"  Last seen in:  State {history['last_seen_state']}")

            # Get details of first and last states
            first_state = state_db.get_state(history['first_seen_state'])
            last_state = state_db.get_state(history['last_seen_state'])

            if first_state:
                print(f"    First: {first_state.created_at.strftime('%Y-%m-%d %H:%M')} - {first_state.description}")
            if last_state and last_state.state_id != first_state.state_id:
                print(f"    Last:  {last_state.created_at.strftime('%Y-%m-%d %H:%M')} - {last_state.description}")

    print()


def show_status(args) -> int:
    """CLI handler for 'wg-friend status' command"""
    db = WireGuardDBv2(args.db)

    # Show entity history if requested
    entity_name = getattr(args, 'entity', None)
    if entity_name:
        show_entity_history(db, args.db, entity_name)
        return 0

    # Show state history if requested
    if getattr(args, 'history', False):
        state_id = getattr(args, 'state', None)
        show_state_history(args.db, limit=20, state_id=state_id)
        return 0

    # Show live peer status if requested
    if getattr(args, 'live', False):
        interface = getattr(args, 'interface', 'wg0')
        user = getattr(args, 'user', 'root')
        show_live_peer_status(db, interface=interface, user=user)
        return 0

    # Network overview
    show_network_overview(db)

    # Recent rotations (if any)
    if getattr(args, 'full', False):
        show_recent_rotations(db, limit=20)
        show_command_patterns(db)
    else:
        show_recent_rotations(db, limit=5)

    return 0


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('--db', default='wireguard.db')
    parser.add_argument('--full', action='store_true', help='Show full details')

    args = parser.parse_args()
    sys.exit(show_status(args))
