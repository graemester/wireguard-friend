"""
Config Generator - Database → WireGuard Configs

Generates configs from v2 database using template patterns from v1.
"""

import sys
import json
from pathlib import Path
from typing import List, Dict, Optional

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from v1.schema_semantic import WireGuardDBv2


def generate_cs_config(db: WireGuardDBv2) -> str:
    """Generate coordination server config"""
    with db._connection() as conn:
        cursor = conn.cursor()

        # Get CS data
        cursor.execute("SELECT * FROM coordination_server WHERE id = 1")
        cs = dict(cursor.fetchone())

        # Get all subnet routers
        cursor.execute("""
            SELECT sr.*, GROUP_CONCAT(an.network_cidr) as advertised_networks
            FROM subnet_router sr
            LEFT JOIN advertised_network an ON sr.id = an.subnet_router_id
            GROUP BY sr.id
        """)
        routers = [dict(row) for row in cursor.fetchall()]

        # Get all remotes
        cursor.execute("SELECT * FROM remote")
        remotes = [dict(row) for row in cursor.fetchall()]

        # Get command pairs
        cursor.execute("""
            SELECT * FROM command_pair
            WHERE entity_type = 'coordination_server'
            ORDER BY execution_order
        """)
        command_pairs = [dict(row) for row in cursor.fetchall()]

        # Get command singletons
        cursor.execute("""
            SELECT * FROM command_singleton
            WHERE entity_type = 'coordination_server'
            ORDER BY execution_order
        """)
        command_singletons = [dict(row) for row in cursor.fetchall()]

    # Build config
    lines = []

    # [Interface]
    lines.append("[Interface]")
    lines.append(f"Address = {cs['ipv4_address']}, {cs['ipv6_address']}")
    lines.append(f"PrivateKey = {cs['private_key']}")
    lines.append(f"ListenPort = {cs['listen_port']}")

    if cs.get('mtu'):
        lines.append(f"MTU = {cs['mtu']}")

    # Commands
    if command_pairs or command_singletons:
        lines.append("")

        # PostUp (singletons first, then pairs)
        for singleton in command_singletons:
            cmds = json.loads(singleton['up_commands'])
            for cmd in cmds:
                lines.append(f"PostUp = {cmd}")

        for pair in command_pairs:
            cmds = json.loads(pair['up_commands'])
            for cmd in cmds:
                lines.append(f"PostUp = {cmd}")

        # PostDown (pairs only)
        for pair in command_pairs:
            cmds = json.loads(pair['down_commands'])
            for cmd in cmds:
                lines.append(f"PostDown = {cmd}")

    # Peers - Subnet Routers
    for router in routers:
        lines.append("")
        lines.append("[Peer]")
        lines.append(f"# {router['hostname']}")

        # Role comment if initiates only
        if router.get('endpoint') is None:
            lines.append("# no endpoint == behind CGNAT == initiates connection")

        lines.append(f"PublicKey = {router['current_public_key']}")

        # AllowedIPs = router IP + advertised networks
        allowed_ips = [router['ipv4_address'], router['ipv6_address']]
        if router['advertised_networks']:
            allowed_ips.extend(router['advertised_networks'].split(','))
        lines.append(f"AllowedIPs = {', '.join(allowed_ips)}")

        if router.get('endpoint'):
            lines.append(f"Endpoint = {router['endpoint']}")

        if router.get('persistent_keepalive'):
            lines.append(f"PersistentKeepalive = {router['persistent_keepalive']}")

    # Peers - Remotes
    for remote in remotes:
        lines.append("")
        lines.append("[Peer]")
        lines.append(f"# {remote['hostname']}")

        # Role comment for dynamic endpoints
        if remote.get('endpoint') is None:
            lines.append("# Endpoint will be dynamic (mobile device)")

        lines.append(f"PublicKey = {remote['current_public_key']}")

        # AllowedIPs
        allowed_ips = [remote['ipv4_address'], remote['ipv6_address']]
        lines.append(f"AllowedIPs = {', '.join(allowed_ips)}")

        if remote.get('endpoint'):
            lines.append(f"Endpoint = {remote['endpoint']}")

        if remote.get('persistent_keepalive'):
            lines.append(f"PersistentKeepalive = {remote['persistent_keepalive']}")

    return '\n'.join(lines) + '\n'


def generate_router_config(db: WireGuardDBv2, router_id: int) -> str:
    """Generate subnet router config"""
    with db._connection() as conn:
        cursor = conn.cursor()

        # Get CS
        cursor.execute("SELECT * FROM coordination_server WHERE id = 1")
        cs = dict(cursor.fetchone())

        # Get this router
        cursor.execute("SELECT * FROM subnet_router WHERE id = ?", (router_id,))
        router = dict(cursor.fetchone())

        # Get advertised networks
        cursor.execute("""
            SELECT network_cidr FROM advertised_network
            WHERE subnet_router_id = ?
        """, (router_id,))
        advertised_networks = [row['network_cidr'] for row in cursor.fetchall()]

        # Get command pairs for this router
        cursor.execute("""
            SELECT * FROM command_pair
            WHERE entity_type = 'subnet_router' AND entity_id = ?
            ORDER BY execution_order
        """, (router_id,))
        command_pairs = [dict(row) for row in cursor.fetchall()]

    lines = []

    # [Interface]
    lines.append("[Interface]")
    lines.append(f"Address = {router['ipv4_address']}, {router['ipv6_address']}")
    lines.append(f"PrivateKey = {router['private_key']}")

    if router.get('mtu'):
        lines.append(f"MTU = {router['mtu']}")

    # Commands
    if command_pairs:
        lines.append("")

        # PostUp
        for pair in command_pairs:
            cmds = json.loads(pair['up_commands'])
            for cmd in cmds:
                lines.append(f"PostUp = {cmd}")

        # PostDown
        for pair in command_pairs:
            cmds = json.loads(pair['down_commands'])
            for cmd in cmds:
                lines.append(f"PostDown = {cmd}")

    # [Peer] - CS
    lines.append("")
    lines.append("[Peer]")
    lines.append(f"# coordination-server")
    lines.append(f"PublicKey = {cs['current_public_key']}")
    lines.append(f"Endpoint = {cs['endpoint']}:{cs['listen_port']}")

    # AllowedIPs = VPN network (so router can reach all VPN clients)
    lines.append(f"AllowedIPs = {cs['network_ipv4']}, {cs['network_ipv6']}")
    lines.append(f"PersistentKeepalive = 25")

    return '\n'.join(lines) + '\n'


def generate_remote_config(db: WireGuardDBv2, remote_id: int) -> str:
    """Generate remote client config"""
    with db._connection() as conn:
        cursor = conn.cursor()

        # Get CS
        cursor.execute("SELECT * FROM coordination_server WHERE id = 1")
        cs = dict(cursor.fetchone())

        # Get this remote
        cursor.execute("SELECT * FROM remote WHERE id = ?", (remote_id,))
        remote = dict(cursor.fetchone())

        # Get all advertised networks (for AllowedIPs)
        cursor.execute("""
            SELECT DISTINCT network_cidr FROM advertised_network
        """)
        advertised_networks = [row['network_cidr'] for row in cursor.fetchall()]

    lines = []

    # [Interface]
    lines.append("[Interface]")
    lines.append(f"Address = {remote['ipv4_address']}, {remote['ipv6_address']}")
    lines.append(f"PrivateKey = {remote['private_key']}")

    if remote.get('dns_servers'):
        lines.append(f"DNS = {remote['dns_servers']}")

    lines.append("MTU = 1280")

    # [Peer] - CS
    lines.append("")
    lines.append("[Peer]")
    lines.append(f"# coordination-server")
    lines.append(f"PublicKey = {cs['current_public_key']}")
    lines.append(f"Endpoint = {cs['endpoint']}:{cs['listen_port']}")

    # AllowedIPs based on access level
    access = remote.get('access_level', 'full_access')
    if access == 'full_access':
        # VPN network + all advertised LANs
        allowed_ips = [cs['network_ipv4'], cs['network_ipv6']] + advertised_networks
    elif access == 'vpn_only':
        # Just VPN network
        allowed_ips = [cs['network_ipv4'], cs['network_ipv6']]
    elif access == 'lan_only':
        # Just advertised LANs
        allowed_ips = advertised_networks
    else:
        # Custom - stored in database
        allowed_ips = [cs['network_ipv4']]  # Default fallback

    lines.append(f"AllowedIPs = {', '.join(allowed_ips)}")
    lines.append(f"PersistentKeepalive = 25")

    return '\n'.join(lines) + '\n'


def generate_configs(args) -> int:
    """Generate all configs from database"""
    db_path = Path(args.db)

    if not db_path.exists():
        print(f"Error: Database not found: {db_path}")
        print("Run 'wg-friend init' first")
        return 1

    output_dir = Path(args.output)
    output_dir.mkdir(exist_ok=True, parents=True)

    db = WireGuardDBv2(db_path)

    print(f"Generating configs from {db_path}...")
    print()

    # Generate CS config
    print("Coordination Server:")
    cs_config = generate_cs_config(db)
    cs_file = output_dir / "coordination.conf"
    cs_file.write_text(cs_config)
    cs_file.chmod(0o600)
    print(f"  ✓ {cs_file}")

    # Generate router configs
    with db._connection() as conn:
        cursor = conn.cursor()

        cursor.execute("SELECT id, hostname FROM subnet_router")
        routers = cursor.fetchall()

        if routers:
            print("\nSubnet Routers:")
            for router_id, hostname in routers:
                router_config = generate_router_config(db, router_id)
                router_file = output_dir / f"{hostname}.conf"
                router_file.write_text(router_config)
                router_file.chmod(0o600)
                print(f"  ✓ {router_file}")

        cursor.execute("SELECT id, hostname FROM remote")
        remotes = cursor.fetchall()

        if remotes:
            print("\nRemote Clients:")
            for remote_id, hostname in remotes:
                remote_config = generate_remote_config(db, remote_id)
                remote_file = output_dir / f"{hostname}.conf"
                remote_file.write_text(remote_config)
                remote_file.chmod(0o600)
                print(f"  ✓ {remote_file}")

                # Generate QR code if requested
                if args.qr:
                    try:
                        import qrcode
                        qr = qrcode.QRCode()
                        qr.add_data(remote_config)
                        qr.make()

                        qr_file = output_dir / f"{hostname}.png"
                        img = qr.make_image(fill_color="black", back_color="white")
                        img.save(qr_file)
                        print(f"    QR: {qr_file}")
                    except ImportError:
                        if args.qr:
                            print("    (qrcode module not installed - pip install qrcode)")

    print()
    print(f"✓ Generated configs in {output_dir}")
    print()

    return 0


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--db', default='wireguard.db')
    parser.add_argument('--output', default='generated')
    parser.add_argument('--qr', action='store_true')
    args = parser.parse_args()
    sys.exit(generate_configs(args))
