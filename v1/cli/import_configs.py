"""
Import Existing WireGuard Configs into Database

Parses existing configs and stores in database with permanent_guid.
"""

import sys
from pathlib import Path
from typing import List, Dict, Optional

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from v1.entity_parser import EntityParser
from v1.patterns import PatternRecognizer
from v1.comments import CommentCategorizer, CommentCategory
from v1.schema_semantic import WireGuardDBv2
from v1.keygen import derive_public_key
from v1.state_tracker import record_import


def parse_interface_section(entity, categorizer):
    """Parse [Interface] section and extract fields"""
    interface_data = {
        'addresses': [],
        'private_key': None,
        'listen_port': None,
        'mtu': None,
        'dns': [],
        'postup': [],
        'postdown': [],
        'comments': []
    }

    for line in entity.lines:
        stripped = line.strip()

        if not stripped or stripped.startswith('['):
            continue

        # Comments
        if stripped.startswith('#'):
            text = stripped[1:].strip()
            comment = categorizer.categorize(text, 'interface')
            interface_data['comments'].append(comment)
            continue

        # Fields
        if '=' in stripped:
            field_part = stripped.split('#')[0].strip()
            parts = field_part.split('=', 1)
            if len(parts) != 2:
                continue

            key = parts[0].strip()
            value = parts[1].strip()

            if key.lower() == 'address':
                addrs = [a.strip() for a in value.split(',')]
                interface_data['addresses'].extend(addrs)
            elif key.lower() == 'privatekey':
                interface_data['private_key'] = value
            elif key.lower() == 'listenport':
                interface_data['listen_port'] = int(value)
            elif key.lower() == 'mtu':
                interface_data['mtu'] = int(value)
            elif key.lower() == 'dns':
                dns = [d.strip() for d in value.split(',')]
                interface_data['dns'].extend(dns)
            elif key.lower() == 'postup':
                if ';' in value:
                    interface_data['postup'].extend([c.strip() for c in value.split(';')])
                else:
                    interface_data['postup'].append(value)
            elif key.lower() == 'postdown':
                if ';' in value:
                    interface_data['postdown'].extend([c.strip() for c in value.split(';')])
                else:
                    interface_data['postdown'].append(value)

    return interface_data


def parse_peer_section(entity, categorizer):
    """Parse [Peer] section"""
    peer_data = {
        'public_key': None,
        'preshared_key': None,
        'allowed_ips': [],
        'endpoint': None,
        'persistent_keepalive': None,
        'hostname': None,
        'role_type': None,
        'comments': []
    }

    comments_before_pubkey = []

    for line in entity.lines:
        stripped = line.strip()

        if not stripped:
            continue

        # Comments before PublicKey
        if stripped.startswith('#'):
            text = stripped[1:].strip()
            if peer_data['public_key'] is None:
                comments_before_pubkey.append(text)
            continue

        # Fields
        if '=' in stripped:
            field_part = stripped.split('#')[0].strip()
            parts = field_part.split('=', 1)
            if len(parts) != 2:
                continue

            key = parts[0].strip()
            value = parts[1].strip()

            if key.lower() == 'publickey':
                peer_data['public_key'] = value

                # Categorize comments
                for text in comments_before_pubkey:
                    comment = categorizer.categorize(text, 'peer')
                    peer_data['comments'].append(comment)

                    if comment.category == CommentCategory.HOSTNAME:
                        peer_data['hostname'] = comment.text
                    elif comment.category == CommentCategory.ROLE:
                        peer_data['role_type'] = comment.role_type

            elif key.lower() == 'presharedkey':
                peer_data['preshared_key'] = value
            elif key.lower() == 'allowedips':
                ips = [ip.strip() for ip in value.split(',')]
                peer_data['allowed_ips'].extend(ips)
            elif key.lower() == 'endpoint':
                peer_data['endpoint'] = value
            elif key.lower() == 'persistentkeepalive':
                peer_data['persistent_keepalive'] = int(value)

    return peer_data


def import_coordination_server(config_path: Path, db: WireGuardDBv2, hostname: str = None):
    """Import coordination server config"""
    parser = EntityParser()
    entities = parser.parse_file(config_path)

    valid, msg = parser.validate_structure(entities)
    if not valid:
        raise ValueError(f"Invalid config structure: {msg}")

    categorizer = CommentCategorizer()
    pattern_recognizer = PatternRecognizer()

    # Parse [Interface]
    interface = parse_interface_section(entities[0], categorizer)

    # Derive public key from private key
    if not interface['private_key']:
        raise ValueError("No PrivateKey found in [Interface]")

    public_key = derive_public_key(interface['private_key'])
    permanent_guid = public_key  # First key = permanent GUID

    print(f"\nCoordination Server:")
    print(f"  permanent_guid: {permanent_guid[:30]}...")
    print(f"  Addresses: {interface['addresses']}")

    # Recognize patterns
    pairs, singletons, unrecognized = pattern_recognizer.recognize_pairs(
        interface['postup'],
        interface['postdown']
    )

    print(f"  Patterns: {len(pairs)} pairs, {len(singletons)} singletons")

    # Extract endpoint and network from addresses
    endpoint = None  # Will need to prompt or detect
    listen_port = interface.get('listen_port', 51820)

    # Parse addresses (first IPv4, first IPv6)
    ipv4_addr = None
    ipv6_addr = None
    for addr in interface['addresses']:
        if ':' in addr:
            ipv6_addr = addr
        else:
            ipv4_addr = addr

    # Extract network from address
    if ipv4_addr:
        parts = ipv4_addr.split('/')
        network_ipv4 = parts[0].rsplit('.', 1)[0] + '.0/' + parts[1] if len(parts) == 2 else ipv4_addr
    else:
        network_ipv4 = "10.66.0.0/24"

    if ipv6_addr:
        network_ipv6 = ipv6_addr.rsplit(':', 1)[0] + ':/64'
    else:
        network_ipv6 = "fd66::/64"

    # Use provided hostname or default
    if not hostname:
        hostname = 'coordination-server'

    # Insert into database
    with db._connection() as conn:
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO coordination_server (
                permanent_guid, current_public_key, hostname,
                endpoint, listen_port, mtu,
                network_ipv4, network_ipv6,
                ipv4_address, ipv6_address,
                private_key
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            permanent_guid,
            public_key,
            hostname,
            endpoint or 'UNKNOWN',  # TODO: prompt
            listen_port,
            interface.get('mtu'),
            network_ipv4,
            network_ipv6,
            ipv4_addr or '10.66.0.1/24',
            ipv6_addr or 'fd66::1/64',
            interface['private_key']
        ))

        cs_id = cursor.lastrowid

        # Store command pairs
        for i, pair in enumerate(pairs):
            import json
            cursor.execute("""
                INSERT INTO command_pair (
                    entity_type, entity_id,
                    pattern_name, rationale, scope,
                    up_commands, down_commands,
                    execution_order
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                'coordination_server', cs_id,
                pair.pattern_name,
                pair.rationale,
                pair.scope.value,
                json.dumps(pair.up_commands if isinstance(pair.up_commands, list) else [pair.up_commands]),
                json.dumps(pair.down_commands if isinstance(pair.down_commands, list) else [pair.down_commands]),
                i
            ))

        # Store command singletons
        for i, singleton in enumerate(singletons):
            cursor.execute("""
                INSERT INTO command_singleton (
                    entity_type, entity_id,
                    pattern_name, rationale, scope,
                    up_commands,
                    execution_order
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                'coordination_server', cs_id,
                singleton.pattern_name,
                singleton.rationale,
                singleton.scope.value,
                json.dumps(singleton.up_commands if isinstance(singleton.up_commands, list) else [singleton.up_commands]),
                i
            ))

    # Parse [Peer] sections
    peer_entities = entities[1:]
    peers = []

    for entity in peer_entities:
        peer = parse_peer_section(entity, categorizer)
        if peer['public_key']:
            peers.append(peer)

    print(f"  Found {len(peers)} peers in config")

    return cs_id, peers


def import_subnet_router(config_path: Path, db: WireGuardDBv2, hostname: str = None, cs_pubkey: str = None):
    """
    Import subnet router config.

    Args:
        config_path: Path to subnet router .conf file
        db: Database connection
        hostname: Friendly name for this router
        cs_pubkey: Expected CS public key (to validate peer section)

    Returns:
        router_id
    """
    parser = EntityParser()
    entities = parser.parse_file(config_path)

    valid, msg = parser.validate_structure(entities)
    if not valid:
        raise ValueError(f"Invalid config structure: {msg}")

    categorizer = CommentCategorizer()
    pattern_recognizer = PatternRecognizer()

    # Parse [Interface]
    interface = parse_interface_section(entities[0], categorizer)

    if not interface['private_key']:
        raise ValueError("No PrivateKey found in [Interface]")

    public_key = derive_public_key(interface['private_key'])
    permanent_guid = public_key

    # Parse addresses
    ipv4_addr = None
    ipv6_addr = None
    for addr in interface['addresses']:
        if ':' in addr:
            ipv6_addr = addr
        else:
            ipv4_addr = addr

    if not hostname:
        hostname = config_path.stem

    print(f"\nSubnet Router: {hostname}")
    print(f"  permanent_guid: {permanent_guid[:30]}...")
    print(f"  Addresses: {interface['addresses']}")

    # Get CS ID
    with db._connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM coordination_server LIMIT 1")
        row = cursor.fetchone()
        if not row:
            raise ValueError("No coordination server found - import CS first")
        cs_id = row[0]

    # Parse [Peer] section to get endpoint
    peer_data = None
    if len(entities) > 1:
        peer_data = parse_peer_section(entities[1], categorizer)

    endpoint = peer_data.get('endpoint') if peer_data else None

    # Try to infer LAN network from AllowedIPs or PostUp/PostDown
    lan_networks = []
    if peer_data:
        for ip in peer_data.get('allowed_ips', []):
            # Skip VPN networks and default routes
            if ip.startswith('10.') or ip.startswith('fd') or ip in ('0.0.0.0/0', '::/0'):
                continue
            if ip.startswith('192.168.') or ip.startswith('172.'):
                lan_networks.append(ip)

    # Recognize patterns
    pairs, singletons, unrecognized = pattern_recognizer.recognize_pairs(
        interface['postup'],
        interface['postdown']
    )

    # Insert into database
    with db._connection() as conn:
        cursor = conn.cursor()

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
            ipv4_addr or '10.66.0.20/32',
            ipv6_addr,
            interface['private_key'],
            'eth0',  # Default - user can update later
            endpoint
        ))
        router_id = cursor.lastrowid

        # Update CS endpoint if we found it and CS has UNKNOWN
        if endpoint:
            # Parse endpoint (host:port format)
            if ':' in endpoint:
                cs_endpoint = endpoint.rsplit(':', 1)[0]
            else:
                cs_endpoint = endpoint

            cursor.execute("""
                UPDATE coordination_server
                SET endpoint = ?
                WHERE id = ? AND (endpoint IS NULL OR endpoint = 'UNKNOWN')
            """, (cs_endpoint, cs_id))

            if cursor.rowcount > 0:
                print(f"  ✓ Updated CS endpoint: {cs_endpoint}")

        # Insert advertised networks
        for network in lan_networks:
            cursor.execute("""
                INSERT INTO advertised_network (subnet_router_id, network_cidr)
                VALUES (?, ?)
            """, (router_id, network))

        # Store command pairs
        import json
        for i, pair in enumerate(pairs):
            cursor.execute("""
                INSERT INTO command_pair (
                    entity_type, entity_id,
                    pattern_name, rationale, scope,
                    up_commands, down_commands,
                    execution_order
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                'subnet_router', router_id,
                pair.pattern_name,
                pair.rationale,
                pair.scope.value,
                json.dumps(pair.up_commands if isinstance(pair.up_commands, list) else [pair.up_commands]),
                json.dumps(pair.down_commands if isinstance(pair.down_commands, list) else [pair.down_commands]),
                i
            ))

    print(f"  ✓ Imported subnet router (ID: {router_id})")
    if lan_networks:
        print(f"  ✓ LAN networks: {', '.join(lan_networks)}")

    return router_id


def import_remote(config_path: Path, db: WireGuardDBv2, hostname: str = None, cs_pubkey: str = None):
    """
    Import remote client config.

    Args:
        config_path: Path to client .conf file
        db: Database connection
        hostname: Friendly name for this remote
        cs_pubkey: Expected CS public key (to validate peer section)

    Returns:
        remote_id
    """
    parser = EntityParser()
    entities = parser.parse_file(config_path)

    valid, msg = parser.validate_structure(entities)
    if not valid:
        raise ValueError(f"Invalid config structure: {msg}")

    categorizer = CommentCategorizer()

    # Parse [Interface]
    interface = parse_interface_section(entities[0], categorizer)

    if not interface['private_key']:
        raise ValueError("No PrivateKey found in [Interface]")

    public_key = derive_public_key(interface['private_key'])
    permanent_guid = public_key

    # Parse addresses
    ipv4_addr = None
    ipv6_addr = None
    for addr in interface['addresses']:
        if ':' in addr:
            ipv6_addr = addr
        else:
            ipv4_addr = addr

    if not hostname:
        hostname = config_path.stem

    print(f"\nRemote Client: {hostname}")
    print(f"  permanent_guid: {permanent_guid[:30]}...")
    print(f"  Addresses: {interface['addresses']}")

    # Get CS ID
    with db._connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM coordination_server LIMIT 1")
        row = cursor.fetchone()
        if not row:
            raise ValueError("No coordination server found - import CS first")
        cs_id = row[0]

    # Parse [Peer] section to get endpoint
    peer_data = None
    if len(entities) > 1:
        peer_data = parse_peer_section(entities[1], categorizer)

    endpoint = peer_data.get('endpoint') if peer_data else None
    allowed_ips_list = peer_data.get('allowed_ips', []) if peer_data else []
    allowed_ips = ', '.join(allowed_ips_list) if allowed_ips_list else None

    # Store the AllowedIPs exactly as imported
    if allowed_ips:
        print(f"  AllowedIPs: {allowed_ips}")

    # Infer access level from AllowedIPs for display purposes
    access_level = 'custom'  # Default to custom since we store actual IPs
    if allowed_ips_list:
        if '0.0.0.0/0' in allowed_ips_list or '::/0' in allowed_ips_list:
            access_level = 'full_access'
        elif any('192.168' in ip or '10.' in ip for ip in allowed_ips_list):
            access_level = 'lan_only'
        else:
            access_level = 'vpn_only'

    print(f"  Inferred access level: {access_level}")

    # Insert into database
    with db._connection() as conn:
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO remote (
                cs_id, permanent_guid, current_public_key, hostname,
                ipv4_address, ipv6_address, private_key,
                access_level, allowed_ips
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            cs_id,
            permanent_guid,
            public_key,
            hostname,
            ipv4_addr or '10.66.0.30/32',
            ipv6_addr or '',
            interface['private_key'],
            access_level,
            allowed_ips
        ))
        remote_id = cursor.lastrowid

        # Update CS endpoint if we found it and CS has UNKNOWN
        if endpoint:
            # Parse endpoint (host:port format)
            if ':' in endpoint:
                cs_endpoint = endpoint.rsplit(':', 1)[0]
            else:
                cs_endpoint = endpoint

            cursor.execute("""
                UPDATE coordination_server
                SET endpoint = ?
                WHERE id = ? AND (endpoint IS NULL OR endpoint = 'UNKNOWN')
            """, (cs_endpoint, cs_id))

            if cursor.rowcount > 0:
                print(f"  ✓ Updated CS endpoint: {cs_endpoint}")

    print(f"  ✓ Imported remote client (ID: {remote_id})")
    print(f"  ✓ Access level: {access_level}")

    return remote_id


def run_import(args) -> int:
    """Import existing configs into database"""
    print("=" * 70)
    print("IMPORT CONFIGS")
    print("=" * 70)
    print()

    # Check if database exists
    db_path = Path(args.db)
    if db_path.exists():
        print(f"WARNING:  Database already exists: {db_path}")
        response = input("Overwrite? (y/N): ").strip().lower()
        if response not in ('y', 'yes'):
            print("Cancelled.")
            return 1
        db_path.unlink()

    # Validate inputs
    if not args.cs:
        print("Error: --cs (coordination server config) required")
        return 1

    cs_path = Path(args.cs)
    if not cs_path.exists():
        print(f"Error: File not found: {cs_path}")
        return 1

    # Create database
    print(f"Creating database: {db_path}")
    db = WireGuardDBv2(db_path)

    try:
        # Get hostname from args if provided (from entity review)
        cs_hostname = getattr(args, 'cs_name', None)

        # Import coordination server
        cs_id, cs_peers = import_coordination_server(cs_path, db, hostname=cs_hostname)

        # Track import counts
        snr_count = 0
        remote_count = 0

        # Check if we have confirmed entities from entity review
        confirmed_entities = getattr(args, 'entities', None)

        if confirmed_entities:
            # Import all confirmed entities (CS was already done above)
            for entity in confirmed_entities:
                if entity.config_type == 'coordination_server':
                    continue  # Already imported

                elif entity.config_type == 'subnet_router':
                    try:
                        router_id = import_subnet_router(
                            entity.path, db, hostname=entity.friendly_name
                        )
                        snr_count += 1
                    except Exception as e:
                        print(f"\n  Error importing subnet router {entity.path.name}: {e}")

                elif entity.config_type == 'client':
                    try:
                        remote_id = import_remote(
                            entity.path, db, hostname=entity.friendly_name
                        )
                        remote_count += 1
                    except Exception as e:
                        print(f"\n  Error importing remote {entity.path.name}: {e}")

        else:
            # Legacy mode: use args.snr and args.remote if provided
            if args.snr:
                for snr_path in args.snr:
                    snr_file = Path(snr_path)
                    if snr_file.exists():
                        try:
                            router_id = import_subnet_router(snr_file, db)
                            snr_count += 1
                        except Exception as e:
                            print(f"\n  Error importing subnet router {snr_file.name}: {e}")
                    else:
                        print(f"\n  Warning: File not found: {snr_path}")

            if args.remote:
                for remote_path in args.remote:
                    remote_file = Path(remote_path)
                    if remote_file.exists():
                        try:
                            remote_id = import_remote(remote_file, db)
                            remote_count += 1
                        except Exception as e:
                            print(f"\n  Error importing remote {remote_file.name}: {e}")
                    else:
                        print(f"\n  Warning: File not found: {remote_path}")

        # Record initial state snapshot
        state_id = record_import(str(db_path), db, len(cs_peers))

        print()
        print("=" * 70)
        print("Import done")
        print("=" * 70)
        print(f"✓ Database created: {db_path}")
        print(f"✓ Coordination server imported")
        print(f"✓ Found {len(cs_peers)} peers in CS config")
        if snr_count > 0:
            print(f"✓ Imported {snr_count} subnet router(s)")
        if remote_count > 0:
            print(f"✓ Imported {remote_count} remote client(s)")
        print(f"✓ State snapshot recorded (State #{state_id})")
        print()

        # Offer to enter maintenance mode
        response = input("Enter maintenance mode? [Y/n]: ").strip().lower()
        if response in ('', 'y', 'yes'):
            from v1.cli.tui import run_tui
            return run_tui(str(db_path))
        else:
            print()
            print("Next steps:")
            print(f"  1. Review database: sqlite3 {db_path}")
            print(f"  2. Add missing entities: wg-friend add peer/router")
            print(f"  3. Generate configs: wg-friend generate")
            print()

        return 0

    except Exception as e:
        print(f"\nError during import: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--db', default='wireguard.db')
    parser.add_argument('--cs', required=True)
    parser.add_argument('--snr', action='append')
    parser.add_argument('--remote', action='append')
    args = parser.parse_args()
    sys.exit(run_import(args))
