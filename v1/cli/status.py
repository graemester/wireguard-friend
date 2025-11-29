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


def show_status(args) -> int:
    """CLI handler for 'wg-friend status' command"""
    db = WireGuardDBv2(args.db)

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
