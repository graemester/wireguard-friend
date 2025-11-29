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


def import_coordination_server(config_path: Path, db: WireGuardDBv2):
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
            'coordination-server',
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


def run_import(args) -> int:
    """Import existing configs into v2 database"""
    print("=" * 70)
    print("IMPORT CONFIGS TO V2")
    print("=" * 70)
    print()

    # Check if database exists
    db_path = Path(args.db)
    if db_path.exists():
        print(f"⚠  Database already exists: {db_path}")
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
        # Import coordination server
        cs_id, cs_peers = import_coordination_server(cs_path, db)

        # TODO: Import subnet routers
        if args.snr:
            print("\n⚠  Subnet router import not yet implemented")
            print("   Use 'wg-friend add router' to add routers manually")

        # TODO: Import remotes
        if args.remote:
            print("\n⚠  Remote import not yet implemented")
            print("   Use 'wg-friend add peer' to add peers manually")

        print()
        print("=" * 70)
        print("IMPORT COMPLETE")
        print("=" * 70)
        print(f"✓ Database created: {db_path}")
        print(f"✓ Coordination server imported")
        print(f"✓ Found {len(cs_peers)} peers (stored as references)")
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
