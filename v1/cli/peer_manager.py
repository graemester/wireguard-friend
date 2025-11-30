"""
Peer Management - Add, Remove, Modify Peers

Handles interactive peer addition, removal, and modification.
"""

import sys
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from v1.schema_semantic import WireGuardDBv2
from v1.keygen import generate_keypair, generate_preshared_key
from v1.cli.config_generator import generate_remote_config
from v1.state_tracker import record_add_remote, record_add_router, record_remove_peer, record_rotate_keys


def get_next_available_ip(db: WireGuardDBv2, entity_type: str) -> Tuple[str, str]:
    """
    Find next available IP addresses for a new peer.

    Args:
        db: Database connection
        entity_type: 'router' or 'remote'

    Returns:
        (ipv4_address, ipv6_address) with CIDR notation
    """
    with db._connection() as conn:
        cursor = conn.cursor()

        # Get network info from coordination server
        cursor.execute("SELECT network_ipv4, network_ipv6 FROM coordination_server LIMIT 1")
        row = cursor.fetchone()
        if not row:
            raise ValueError("No coordination server found in database")

        network_ipv4, network_ipv6 = row

        # Extract base IPs
        ipv4_base = network_ipv4.split('/')[0].rsplit('.', 1)[0]
        ipv6_base = network_ipv6.split('/')[0].rstrip(':')

        # Get existing IPs
        existing_ips = set()

        # Coordination server
        cursor.execute("SELECT ipv4_address FROM coordination_server")
        for row in cursor.fetchall():
            ip = row[0].split('/')[0].split('.')[-1]
            existing_ips.add(int(ip))

        # Subnet routers
        cursor.execute("SELECT ipv4_address FROM subnet_router")
        for row in cursor.fetchall():
            ip = row[0].split('/')[0].split('.')[-1]
            existing_ips.add(int(ip))

        # Remotes
        cursor.execute("SELECT ipv4_address FROM remote")
        for row in cursor.fetchall():
            ip = row[0].split('/')[0].split('.')[-1]
            existing_ips.add(int(ip))

        # Find next available
        if entity_type == 'router':
            # Routers: 20-29
            start, end = 20, 29
        else:
            # Remotes: 30-254
            start, end = 30, 254

        next_ip = None
        for i in range(start, end + 1):
            if i not in existing_ips:
                next_ip = i
                break

        if next_ip is None:
            raise ValueError(f"No available IPs in range {start}-{end}")

        ipv4_address = f"{ipv4_base}.{next_ip}/32"
        ipv6_address = f"{ipv6_base}::{next_ip:x}/128"

        return ipv4_address, ipv6_address


def prompt(question: str, default: Optional[str] = None) -> str:
    """Prompt user for input"""
    if default:
        response = input(f"{question} [{default}]: ").strip()
        return response if response else default
    else:
        while True:
            response = input(f"{question}: ").strip()
            if response:
                return response
            print("  (required)")


def prompt_yes_no(question: str, default: bool = False) -> bool:
    """Prompt for yes/no"""
    default_str = "Y/n" if default else "y/N"
    response = input(f"{question} [{default_str}]: ").strip().lower()

    if not response:
        return default
    return response in ('y', 'yes')


def add_remote(db: WireGuardDBv2, hostname: Optional[str] = None) -> int:
    """
    Add a new remote client.

    Args:
        db: Database connection
        hostname: Optional hostname (will prompt if not provided)

    Returns:
        remote_id of newly added peer
    """
    print("\n" + "─" * 70)
    print("ADD REMOTE CLIENT")
    print("─" * 70)

    # Get coordination server ID
    with db._connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM coordination_server LIMIT 1")
        row = cursor.fetchone()
        if not row:
            raise ValueError("No coordination server found")
        cs_id = row[0]

    # Prompt for details
    if not hostname:
        hostname = prompt("Hostname (e.g., alice-phone, bob-laptop)")

    device_type = prompt("Device type [mobile/laptop/server]", default="mobile")
    access_level = prompt("Access level [full_access/vpn_only/lan_only/custom]", default="full_access")

    # Auto-assign IPs
    ipv4_address, ipv6_address = get_next_available_ip(db, 'remote')
    print(f"\nAssigned VPN addresses:")
    print(f"  IPv4: {ipv4_address}")
    print(f"  IPv6: {ipv6_address}")

    # Static endpoint (rare for remotes)
    endpoint = None
    if device_type == 'server':
        if prompt_yes_no("Has static endpoint?", default=False):
            endpoint = prompt("Endpoint (IP:port)")

    # Generate keypair
    print("\nGenerating keypair...")
    private_key, public_key = generate_keypair()
    permanent_guid = public_key  # First key = permanent GUID

    # Confirm
    print("\nSummary:")
    print(f"  Hostname: {hostname}")
    print(f"  Device: {device_type}")
    print(f"  Access: {access_level}")
    print(f"  IPv4: {ipv4_address}")
    print(f"  IPv6: {ipv6_address}")
    print(f"  Public Key: {public_key[:30]}...")
    print()

    if not prompt_yes_no("Add this peer?", default=True):
        print("Cancelled.")
        return None

    # Insert into database
    with db._connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO remote (
                cs_id, permanent_guid, current_public_key, hostname,
                ipv4_address, ipv6_address, private_key, access_level,
                endpoint
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            cs_id,
            permanent_guid,
            public_key,
            hostname,
            ipv4_address,
            ipv6_address,
            private_key,
            access_level,
            endpoint
        ))
        remote_id = cursor.lastrowid

    # Record state snapshot
    state_id = record_add_remote(str(db.db_path), db, hostname, public_key)

    print(f"✓ Added remote: {hostname} (ID: {remote_id})")
    print(f"✓ State snapshot recorded (State #{state_id})")
    print()
    print("Next steps:")
    print(f"  1. Regenerate configs: wg-friend generate")
    print(f"  2. Deploy to coordination server: wg-friend deploy")
    print()

    return remote_id


def add_router(db: WireGuardDBv2, hostname: Optional[str] = None) -> int:
    """
    Add a new subnet router (LAN gateway).

    Args:
        db: Database connection
        hostname: Optional hostname (will prompt if not provided)

    Returns:
        router_id of newly added router
    """
    print("\n" + "─" * 70)
    print("ADD SUBNET ROUTER")
    print("─" * 70)

    # Get coordination server ID
    with db._connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM coordination_server LIMIT 1")
        row = cursor.fetchone()
        if not row:
            raise ValueError("No coordination server found")
        cs_id = row[0]

    # Prompt for details
    if not hostname:
        hostname = prompt("Router hostname (e.g., home-gateway, office-router)")

    lan_network = prompt("LAN network to advertise (e.g., 192.168.1.0/24)")
    lan_interface = prompt("LAN interface name", default="eth0")

    # Auto-assign VPN IPs
    ipv4_address, ipv6_address = get_next_available_ip(db, 'router')
    print(f"\nAssigned VPN addresses:")
    print(f"  IPv4: {ipv4_address}")
    print(f"  IPv6: {ipv6_address}")

    # Static endpoint
    endpoint = None
    if prompt_yes_no("Has static endpoint?", default=False):
        endpoint = prompt("Endpoint (IP:port)")

    # Generate keypair
    print("\nGenerating keypair...")
    private_key, public_key = generate_keypair()
    permanent_guid = public_key  # First key = permanent GUID

    # Confirm
    print("\nSummary:")
    print(f"  Hostname: {hostname}")
    print(f"  LAN Network: {lan_network}")
    print(f"  LAN Interface: {lan_interface}")
    print(f"  VPN IPv4: {ipv4_address}")
    print(f"  VPN IPv6: {ipv6_address}")
    print(f"  Endpoint: {endpoint or 'Dynamic'}")
    print(f"  Public Key: {public_key[:30]}...")
    print()

    if not prompt_yes_no("Add this router?", default=True):
        print("Cancelled.")
        return None

    # Insert into database
    with db._connection() as conn:
        cursor = conn.cursor()

        # Insert router
        cursor.execute("""
            INSERT INTO subnet_router (
                cs_id, permanent_guid, current_public_key, hostname,
                ipv4_address, ipv6_address, private_key,
                lan_interface, endpoint
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            cs_id,
            permanent_guid,
            public_key,
            hostname,
            ipv4_address,
            ipv6_address,
            private_key,
            lan_interface,
            endpoint
        ))
        router_id = cursor.lastrowid

        # Insert advertised network
        cursor.execute("""
            INSERT INTO advertised_network (subnet_router_id, network_cidr)
            VALUES (?, ?)
        """, (router_id, lan_network))

    # Record state snapshot
    state_id = record_add_router(str(db.db_path), db, hostname, public_key)

    print(f"✓ Added subnet router: {hostname} (ID: {router_id})")
    print(f"✓ State snapshot recorded (State #{state_id})")
    print()
    print("Next steps:")
    print(f"  1. Regenerate configs: wg-friend generate")
    print(f"  2. Deploy to coordination server: wg-friend deploy")
    print(f"  3. Deploy to router: wg-friend deploy --host {hostname}")
    print()

    return router_id


def list_peers(db: WireGuardDBv2):
    """List all peers in the database"""
    print("\n" + "=" * 70)
    print("PEERS")
    print("=" * 70)

    with db._connection() as conn:
        cursor = conn.cursor()

        # Coordination Server
        cursor.execute("""
            SELECT hostname, ipv4_address, current_public_key
            FROM coordination_server
        """)
        row = cursor.fetchone()
        if row:
            hostname, ipv4, pubkey = row
            print(f"\nCoordination Server:")
            print(f"  {hostname:30} {ipv4:20} {pubkey[:30]}...")

        # Subnet Routers
        cursor.execute("""
            SELECT id, hostname, ipv4_address, current_public_key
            FROM subnet_router
            ORDER BY hostname
        """)
        routers = cursor.fetchall()
        if routers:
            print(f"\nSubnet Routers ({len(routers)}):")
            for router_id, hostname, ipv4, pubkey in routers:
                print(f"  [{router_id:2}] {hostname:30} {ipv4:20} {pubkey[:30]}...")

        # Remotes
        cursor.execute("""
            SELECT id, hostname, ipv4_address, current_public_key, access_level
            FROM remote
            ORDER BY hostname
        """)
        remotes = cursor.fetchall()
        if remotes:
            print(f"\nRemote Clients ({len(remotes)}):")
            for remote_id, hostname, ipv4, pubkey, access in remotes:
                print(f"  [{remote_id:2}] {hostname:30} {ipv4:20} {access:15} {pubkey[:30]}...")

    print()


def remove_peer(db: WireGuardDBv2, peer_type: str, peer_id: int, reason: str = "Manual revocation") -> bool:
    """
    Remove/revoke a peer.

    For now, we actually DELETE the peer. In production, you might want to:
    - Mark as revoked instead of deleting
    - Keep in key_rotation_history
    - Soft delete with revoked_at timestamp

    Args:
        db: Database connection
        peer_type: 'router' or 'remote'
        peer_id: ID of peer to remove
        reason: Reason for removal

    Returns:
        True if removed, False if cancelled
    """
    with db._connection() as conn:
        cursor = conn.cursor()

        # Get peer details
        if peer_type == 'router':
            cursor.execute("""
                SELECT hostname, current_public_key, permanent_guid
                FROM subnet_router WHERE id = ?
            """, (peer_id,))
        elif peer_type == 'remote':
            cursor.execute("""
                SELECT hostname, current_public_key, permanent_guid
                FROM remote WHERE id = ?
            """, (peer_id,))
        else:
            raise ValueError(f"Invalid peer_type: {peer_type}")

        row = cursor.fetchone()
        if not row:
            print(f"Error: {peer_type} ID {peer_id} not found")
            return False

        hostname, current_pubkey, permanent_guid = row

        # Confirm
        print(f"\nRemove {peer_type}: {hostname}")
        print(f"  Public Key: {current_pubkey[:30]}...")
        print(f"  Permanent GUID: {permanent_guid[:30]}...")
        print(f"  Reason: {reason}")
        print()
        print("WARNING:  This will DELETE the peer from the database.")
        print()

        if not prompt_yes_no("Are you sure?", default=False):
            print("Cancelled.")
            return False

        # Log removal in key_rotation_history (as a record of deletion)
        cursor.execute("""
            INSERT INTO key_rotation_history (
                entity_permanent_guid, old_public_key, new_public_key,
                rotated_at, reason
            ) VALUES (?, ?, ?, ?, ?)
        """, (
            permanent_guid,
            current_pubkey,
            'REVOKED',
            datetime.utcnow().isoformat(),
            f"Removed: {reason}"
        ))

        # Delete peer
        if peer_type == 'router':
            # Delete advertised networks first (foreign key constraint)
            cursor.execute("DELETE FROM advertised_network WHERE subnet_router_id = ?", (peer_id,))
            cursor.execute("DELETE FROM subnet_router WHERE id = ?", (peer_id,))
        else:
            cursor.execute("DELETE FROM remote WHERE id = ?", (peer_id,))

    # Record state snapshot (after removal)
    state_id = record_remove_peer(str(db.db_path), db, peer_type, hostname, current_pubkey)

    print(f"✓ Removed {peer_type}: {hostname}")
    print(f"✓ State snapshot recorded (State #{state_id})")
    print()
    print("Next steps:")
    print(f"  1. Regenerate configs: wg-friend generate")
    print(f"  2. Deploy to coordination server: wg-friend deploy")
    print()

    return True


def rotate_keys(db: WireGuardDBv2, peer_type: str, peer_id: int, reason: str = "Scheduled rotation") -> bool:
    """
    Rotate keys for a peer while maintaining permanent_guid.

    Args:
        db: Database connection
        peer_type: 'router', 'remote', or 'cs'
        peer_id: ID of peer (ignored for cs)
        reason: Reason for rotation

    Returns:
        True if rotated, False if cancelled
    """
    with db._connection() as conn:
        cursor = conn.cursor()

        # Get current key and GUID
        if peer_type == 'cs':
            cursor.execute("""
                SELECT hostname, current_public_key, permanent_guid, private_key
                FROM coordination_server LIMIT 1
            """)
        elif peer_type == 'router':
            cursor.execute("""
                SELECT hostname, current_public_key, permanent_guid, private_key
                FROM subnet_router WHERE id = ?
            """, (peer_id,))
        elif peer_type == 'remote':
            cursor.execute("""
                SELECT hostname, current_public_key, permanent_guid, private_key
                FROM remote WHERE id = ?
            """, (peer_id,))
        else:
            raise ValueError(f"Invalid peer_type: {peer_type}")

        row = cursor.fetchone()
        if not row:
            print(f"Error: {peer_type} not found")
            return False

        hostname, old_pubkey, permanent_guid, old_privkey = row

        print(f"\nRotate keys for: {hostname}")
        print(f"  Current Public Key: {old_pubkey[:30]}...")
        print(f"  Permanent GUID: {permanent_guid[:30]}... (unchanged)")
        print(f"  Reason: {reason}")
        print()

        if not prompt_yes_no("Generate new keypair?", default=True):
            print("Cancelled.")
            return False

        # Generate new keypair
        new_privkey, new_pubkey = generate_keypair()

        print(f"\nNew Public Key: {new_pubkey[:30]}...")
        print()

        if not prompt_yes_no("Apply rotation?", default=True):
            print("Cancelled.")
            return False

        # Log rotation
        cursor.execute("""
            INSERT INTO key_rotation_history (
                entity_permanent_guid, old_public_key, new_public_key,
                rotated_at, reason
            ) VALUES (?, ?, ?, ?, ?)
        """, (
            permanent_guid,
            old_pubkey,
            new_pubkey,
            datetime.utcnow().isoformat(),
            reason
        ))

        # Update peer
        if peer_type == 'cs':
            cursor.execute("""
                UPDATE coordination_server
                SET current_public_key = ?, private_key = ?
            """, (new_pubkey, new_privkey))
        elif peer_type == 'router':
            cursor.execute("""
                UPDATE subnet_router
                SET current_public_key = ?, private_key = ?
                WHERE id = ?
            """, (new_pubkey, new_privkey, peer_id))
        else:
            cursor.execute("""
                UPDATE remote
                SET current_public_key = ?, private_key = ?
                WHERE id = ?
            """, (new_pubkey, new_privkey, peer_id))

    # Record state snapshot
    state_id = record_rotate_keys(str(db.db_path), db, peer_type, hostname, old_pubkey, new_pubkey)

    print(f"✓ Rotated keys for: {hostname}")
    print(f"  Old: {old_pubkey[:30]}...")
    print(f"  New: {new_pubkey[:30]}...")
    print(f"  GUID: {permanent_guid[:30]}... (unchanged)")
    print(f"✓ State snapshot recorded (State #{state_id})")
    print()
    print("Next steps:")
    print(f"  1. Regenerate configs: wg-friend generate")
    print(f"  2. Deploy new configs: wg-friend deploy")
    print()

    return True


def add_preshared_key(db: WireGuardDBv2, peer_type: str, peer_id: int) -> bool:
    """
    Add or update preshared key for a peer.

    Args:
        db: Database connection
        peer_type: 'router' or 'remote'
        peer_id: ID of peer

    Returns:
        True if successful, False if cancelled
    """
    with db._connection() as conn:
        cursor = conn.cursor()

        # Get peer details
        if peer_type == 'router':
            cursor.execute("""
                SELECT hostname, preshared_key
                FROM subnet_router WHERE id = ?
            """, (peer_id,))
        elif peer_type == 'remote':
            cursor.execute("""
                SELECT hostname, preshared_key
                FROM remote WHERE id = ?
            """, (peer_id,))
        else:
            raise ValueError(f"Invalid peer_type: {peer_type}")

        row = cursor.fetchone()
        if not row:
            print(f"Error: {peer_type} ID {peer_id} not found")
            return False

        hostname, current_psk = row

        # Determine action
        action = "Update" if current_psk else "Add"
        print(f"\n{action} preshared key for: {hostname}")

        if current_psk:
            print("  WARNING:  This peer already has a preshared key.")
            print("  Continuing will replace it with a new one.")

        print()
        print("This will:")
        print("  1. Generate new preshared key")
        print("  2. Update peer in database")
        print()
        print("Benefits:")
        print("  • Post-quantum resistance")
        print("  • Additional layer of security")
        print()

        if not prompt_yes_no(f"{action} preshared key?", default=True):
            print("Cancelled.")
            return False

        # Generate preshared key
        preshared_key = generate_preshared_key()
        print(f"✓ Generated preshared key: {preshared_key[:20]}...")

        # Update peer
        if peer_type == 'router':
            cursor.execute("""
                UPDATE subnet_router
                SET preshared_key = ?
                WHERE id = ?
            """, (preshared_key, peer_id))
        else:
            cursor.execute("""
                UPDATE remote
                SET preshared_key = ?
                WHERE id = ?
            """, (preshared_key, peer_id))

    print(f"✓ Preshared key {action.lower()}d")
    print()
    print("Next steps:")
    print("  1. Regenerate configs: wg-friend generate")
    print("  2. Deploy to coordination server: wg-friend deploy")
    print(f"  3. Deploy to {hostname}: wg-friend deploy --host {hostname}")
    print()

    return True


def generate_qr(db: WireGuardDBv2, remote_id: int, output_dir: Path = Path('generated')) -> bool:
    """
    Generate QR code for a specific remote peer.

    Args:
        db: Database connection
        remote_id: ID of remote peer
        output_dir: Output directory for QR code image

    Returns:
        True if successful, False on error
    """
    with db._connection() as conn:
        cursor = conn.cursor()

        # Get peer details
        cursor.execute("""
            SELECT hostname
            FROM remote WHERE id = ?
        """, (remote_id,))
        row = cursor.fetchone()
        if not row:
            print(f"Error: Remote peer ID {remote_id} not found")
            return False

        hostname = row[0]

    print(f"\nGenerating QR code for: {hostname}")

    # Generate config
    remote_config = generate_remote_config(db, remote_id)

    # Ensure output directory exists
    output_dir.mkdir(exist_ok=True, parents=True)

    # Generate QR code
    try:
        import qrcode

        qr = qrcode.QRCode()
        qr.add_data(remote_config)
        qr.make()

        qr_file = output_dir / f"{hostname}.png"
        img = qr.make_image(fill_color="black", back_color="white")
        img.save(qr_file)

        print(f"✓ QR code saved: {qr_file}")
        print()
        print("You can:")
        print(f"  1. Send this QR code to the user")
        print(f"  2. They can scan it with WireGuard mobile app")
        print(f"  3. The connection will be configured automatically")
        print()

        return True

    except ImportError:
        print("Error: qrcode module not installed")
        print("Install with: pip install qrcode[pil]")
        return False
    except Exception as e:
        print(f"Error generating QR code: {e}")
        return False


def run_generate_qr(args) -> int:
    """CLI handler for 'wg-friend qr' command"""
    db = WireGuardDBv2(args.db)

    # List remote peers only (routers and CS don't need QR codes)
    with db._connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, hostname, ipv4_address, current_public_key
            FROM remote
            ORDER BY hostname
        """)
        remotes = cursor.fetchall()

    if not remotes:
        print("\nNo remote peers found in database.")
        print("Add a peer first with: wg-friend add peer")
        return 1

    print("\n" + "=" * 70)
    print("REMOTE PEERS")
    print("=" * 70)
    for remote_id, hostname, ipv4, pubkey in remotes:
        print(f"  [{remote_id:2}] {hostname:30} {ipv4:20}")
    print()

    print("─" * 70)
    print("GENERATE QR CODE")
    print("─" * 70)

    try:
        remote_id = int(prompt("Remote peer ID"))
    except ValueError:
        print("Error: Invalid ID")
        return 1

    output_dir = Path(getattr(args, 'output', 'generated'))
    success = generate_qr(db, remote_id, output_dir)
    return 0 if success else 1


def run_preshared_key(args) -> int:
    """CLI handler for 'wg-friend psk' command"""
    db = WireGuardDBv2(args.db)

    # List peers first
    list_peers(db)

    print("\n" + "─" * 70)
    print("ADD/UPDATE PRESHARED KEY")
    print("─" * 70)

    peer_type = prompt("Peer type [router/remote]")
    if peer_type not in ('router', 'remote'):
        print(f"Error: Invalid type '{peer_type}'")
        return 1

    peer_id = int(prompt("Peer ID"))

    success = add_preshared_key(db, peer_type, peer_id)
    return 0 if success else 1


def run_add_peer(args) -> int:
    """CLI handler for 'wg-friend add' command"""
    db = WireGuardDBv2(args.db)

    if args.type == 'peer' or args.type == 'remote':
        add_remote(db, hostname=getattr(args, 'hostname', None))
    elif args.type == 'router':
        add_router(db, hostname=getattr(args, 'hostname', None))
    else:
        print(f"Error: Unknown type '{args.type}'")
        print("Usage: wg-friend add [peer|router]")
        return 1

    return 0


def run_remove_peer(args) -> int:
    """CLI handler for 'wg-friend remove' command"""
    db = WireGuardDBv2(args.db)

    # List peers first
    list_peers(db)

    # Prompt for type and ID
    peer_type = prompt("Peer type [router/remote]")
    if peer_type not in ('router', 'remote'):
        print(f"Error: Invalid type '{peer_type}'")
        return 1

    peer_id = int(prompt("Peer ID"))
    reason = prompt("Reason for removal", default="Manual revocation")

    success = remove_peer(db, peer_type, peer_id, reason)
    return 0 if success else 1


def run_rotate_keys(args) -> int:
    """CLI handler for 'wg-friend rotate' command"""
    db = WireGuardDBv2(args.db)

    # If peer specified as argument
    if hasattr(args, 'peer') and args.peer:
        # Parse peer spec: "router:1", "remote:3", "cs"
        if args.peer == 'cs':
            peer_type = 'cs'
            peer_id = None
        elif ':' in args.peer:
            peer_type, peer_id = args.peer.split(':', 1)
            peer_id = int(peer_id)
        else:
            print("Error: Invalid peer spec. Use 'cs', 'router:ID', or 'remote:ID'")
            return 1
    else:
        # Interactive selection
        list_peers(db)
        peer_type = prompt("Peer type [cs/router/remote]")
        if peer_type not in ('cs', 'router', 'remote'):
            print(f"Error: Invalid type '{peer_type}'")
            return 1

        peer_id = None
        if peer_type != 'cs':
            peer_id = int(prompt("Peer ID"))

    reason = getattr(args, 'reason', None) or prompt("Reason for rotation", default="Scheduled rotation")

    success = rotate_keys(db, peer_type, peer_id, reason)
    return 0 if success else 1


def add_peer(args):
    """Legacy function name - redirects to run_add_peer"""
    return run_add_peer(args)


def revoke_peer(args):
    """Legacy function name - redirects to run_remove_peer"""
    return run_remove_peer(args)


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('--db', default='wireguard.db')
    subparsers = parser.add_subparsers(dest='command')

    # Add
    add_parser = subparsers.add_parser('add')
    add_parser.add_argument('type', choices=['peer', 'remote', 'router'])
    add_parser.add_argument('--hostname')

    # Remove
    remove_parser = subparsers.add_parser('remove')

    # Rotate
    rotate_parser = subparsers.add_parser('rotate')
    rotate_parser.add_argument('peer', nargs='?')
    rotate_parser.add_argument('--reason')

    # List
    list_parser = subparsers.add_parser('list')

    args = parser.parse_args()

    if args.command == 'add':
        sys.exit(run_add_peer(args))
    elif args.command == 'remove':
        sys.exit(run_remove_peer(args))
    elif args.command == 'rotate':
        sys.exit(run_rotate_keys(args))
    elif args.command == 'list':
        db = WireGuardDBv2(args.db)
        list_peers(db)
        sys.exit(0)
    else:
        parser.print_help()
        sys.exit(1)
