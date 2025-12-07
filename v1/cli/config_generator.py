"""
Config Generator - Database -> WireGuard Configs

Generates configs from v2 database using template patterns from v1.

Supports:
- Coordination server configs
- Subnet router configs
- Remote client configs (with optional exit node routing)
- Exit node configs (internet egress servers)
"""

import sys
import json
from pathlib import Path
from typing import List, Dict, Optional

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from v1.schema_semantic import WireGuardDBv2
from v1.encryption import decrypt_value


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

        # Get all exit nodes
        cursor.execute("SELECT * FROM exit_node")
        exit_nodes = [dict(row) for row in cursor.fetchall()]

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
    lines.append(f"PrivateKey = {decrypt_value(cs['private_key'])}")
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

        # PresharedKey (if configured)
        if remote.get('preshared_key'):
            lines.append(f"PresharedKey = {decrypt_value(remote['preshared_key'])}")

        # AllowedIPs
        allowed_ips = [remote['ipv4_address'], remote['ipv6_address']]
        lines.append(f"AllowedIPs = {', '.join(allowed_ips)}")

        if remote.get('endpoint'):
            lines.append(f"Endpoint = {remote['endpoint']}")

        if remote.get('persistent_keepalive'):
            lines.append(f"PersistentKeepalive = {remote['persistent_keepalive']}")

    # Peers - Exit Nodes
    for exit_node in exit_nodes:
        lines.append("")
        lines.append("[Peer]")
        lines.append(f"# exit-node: {exit_node['hostname']}")
        lines.append(f"PublicKey = {exit_node['current_public_key']}")

        # AllowedIPs = just the exit node's VPN address
        allowed_ips = [exit_node['ipv4_address'], exit_node['ipv6_address']]
        lines.append(f"AllowedIPs = {', '.join(allowed_ips)}")

        lines.append(f"Endpoint = {exit_node['endpoint']}:{exit_node['listen_port']}")
        lines.append("PersistentKeepalive = 25")

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
    lines.append(f"PrivateKey = {decrypt_value(router['private_key'])}")

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
    """
    Generate remote client config.

    If the remote has an exit node assigned:
    - For exit_only: Only the exit node peer (no CS)
    - For other access levels: CS peer for VPN traffic + exit node peer for internet

    If no exit node assigned: Standard split tunnel (only CS peer, no default route)
    """
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

        # Get exit node if assigned
        exit_node = None
        if remote.get('exit_node_id'):
            cursor.execute("""
                SELECT * FROM exit_node WHERE id = ?
            """, (remote['exit_node_id'],))
            exit_row = cursor.fetchone()
            if exit_row:
                exit_node = dict(exit_row)

    lines = []
    access_level = remote.get('access_level', 'full_access')
    is_exit_only = access_level == 'exit_only'

    # [Interface]
    lines.append("[Interface]")
    lines.append(f"Address = {remote['ipv4_address']}, {remote['ipv6_address']}")
    lines.append(f"PrivateKey = {decrypt_value(remote['private_key'])}")

    if remote.get('dns_servers'):
        lines.append(f"DNS = {remote['dns_servers']}")
    elif exit_node:
        # Use public DNS when routing through exit node
        lines.append("DNS = 1.1.1.1, 8.8.8.8")

    lines.append("MTU = 1280")

    # [Peer] - CS (skip for exit_only)
    if not is_exit_only:
        lines.append("")
        lines.append("[Peer]")
        lines.append(f"# coordination-server")
        lines.append(f"PublicKey = {cs['current_public_key']}")

        # PresharedKey (symmetric - same key on both sides)
        if remote.get('preshared_key'):
            lines.append(f"PresharedKey = {decrypt_value(remote['preshared_key'])}")

        lines.append(f"Endpoint = {cs['endpoint']}:{cs['listen_port']}")

        # AllowedIPs for CS - VPN traffic only (not default route if using exit)
        stored_allowed_ips = remote.get('allowed_ips')
        if stored_allowed_ips and not exit_node:
            # Use exactly what was imported (only if not using exit)
            lines.append(f"AllowedIPs = {stored_allowed_ips}")
        else:
            # Compute from access_level
            if access_level == 'full_access':
                allowed_ips = [cs['network_ipv4'], cs['network_ipv6']] + advertised_networks
            elif access_level == 'vpn_only':
                allowed_ips = [cs['network_ipv4'], cs['network_ipv6']]
            elif access_level == 'lan_only':
                allowed_ips = advertised_networks if advertised_networks else [cs['network_ipv4'], cs['network_ipv6']]
            else:
                allowed_ips = [cs['network_ipv4'], cs['network_ipv6']]

            lines.append(f"AllowedIPs = {', '.join(allowed_ips)}")
        lines.append(f"PersistentKeepalive = 25")

    # [Peer] - Exit Node (if assigned)
    if exit_node:
        lines.append("")
        lines.append("[Peer]")
        lines.append(f"# exit-node: {exit_node['hostname']}")
        lines.append(f"PublicKey = {exit_node['current_public_key']}")
        lines.append(f"Endpoint = {exit_node['endpoint']}:{exit_node['listen_port']}")

        # Exit node gets default route (all internet traffic)
        lines.append("AllowedIPs = 0.0.0.0/0, ::/0")
        lines.append("PersistentKeepalive = 25")

    return '\n'.join(lines) + '\n'


def generate_exit_node_config(db: WireGuardDBv2, exit_node_id: int) -> str:
    """
    Generate exit node config.

    Exit node config includes:
    - Interface with NAT/masquerading for internet egress
    - Peer entries for all remotes using this exit node
    """
    with db._connection() as conn:
        cursor = conn.cursor()

        # Get this exit node
        cursor.execute("SELECT * FROM exit_node WHERE id = ?", (exit_node_id,))
        exit_node = dict(cursor.fetchone())

        # Get all remotes using this exit node
        cursor.execute("""
            SELECT id, hostname, ipv4_address, ipv6_address, current_public_key, preshared_key
            FROM remote
            WHERE exit_node_id = ?
            ORDER BY hostname
        """, (exit_node_id,))
        remotes = [dict(row) for row in cursor.fetchall()]

    lines = []

    # [Interface]
    lines.append("[Interface]")
    lines.append(f"Address = {exit_node['ipv4_address']}, {exit_node['ipv6_address']}")
    lines.append(f"PrivateKey = {decrypt_value(exit_node['private_key'])}")
    lines.append(f"ListenPort = {exit_node['listen_port']}")

    # PostUp/PostDown for NAT and IP forwarding
    wan = exit_node.get('wan_interface', 'eth0')
    lines.append("")
    lines.append("# Enable IP forwarding and NAT for internet egress")
    lines.append(f"PostUp = sysctl -w net.ipv4.ip_forward=1")
    lines.append(f"PostUp = sysctl -w net.ipv6.conf.all.forwarding=1")
    lines.append(f"PostUp = iptables -A FORWARD -i %i -j ACCEPT")
    lines.append(f"PostUp = iptables -t nat -A POSTROUTING -o {wan} -j MASQUERADE")
    lines.append(f"PostUp = ip6tables -A FORWARD -i %i -j ACCEPT")
    lines.append(f"PostUp = ip6tables -t nat -A POSTROUTING -o {wan} -j MASQUERADE")
    lines.append(f"PostDown = iptables -D FORWARD -i %i -j ACCEPT")
    lines.append(f"PostDown = iptables -t nat -D POSTROUTING -o {wan} -j MASQUERADE")
    lines.append(f"PostDown = ip6tables -D FORWARD -i %i -j ACCEPT")
    lines.append(f"PostDown = ip6tables -t nat -D POSTROUTING -o {wan} -j MASQUERADE")

    # [Peer] entries for each remote using this exit
    for remote in remotes:
        lines.append("")
        lines.append("[Peer]")
        lines.append(f"# {remote['hostname']}")
        lines.append(f"PublicKey = {remote['current_public_key']}")

        if remote.get('preshared_key'):
            lines.append(f"PresharedKey = {decrypt_value(remote['preshared_key'])}")

        # AllowedIPs = just this remote's VPN addresses
        lines.append(f"AllowedIPs = {remote['ipv4_address']}, {remote['ipv6_address']}")

    return '\n'.join(lines) + '\n'


def generate_configs(args) -> int:
    """Generate all configs from database"""
    db_path = Path(args.db)
    dry_run = getattr(args, 'dry_run', False)

    if not db_path.exists():
        print(f"\n✗ Database not found: {db_path}")
        print(f"\n💡 Run 'wg-friend init' to create a new network")
        print(f"   or 'wg-friend import' to import existing configs")
        return 1

    output_dir = Path(args.output)

    if dry_run:
        print(f"[DRY RUN] Would generate configs from {db_path}")
        print(f"[DRY RUN] Output directory: {output_dir}")
        print()
    else:
        output_dir.mkdir(exist_ok=True, parents=True)
        print(f"Generating configs from {db_path}...")
        print()

    db = WireGuardDBv2(db_path)

    # Generate CS config
    print("Coordination Server:")
    cs_config = generate_cs_config(db)
    cs_file = output_dir / "coordination.conf"
    if dry_run:
        print(f"  [DRY RUN] Would write: {cs_file}")
    else:
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
                if dry_run:
                    print(f"  [DRY RUN] Would write: {router_file}")
                else:
                    router_file.write_text(router_config)
                    router_file.chmod(0o600)
                    print(f"  ✓ {router_file}")

        # Get remotes with private keys (skip provisional peers)
        cursor.execute("""
            SELECT id, hostname, private_key FROM remote
            WHERE private_key IS NOT NULL
        """)
        remotes = cursor.fetchall()

        # Also get provisional peers for informational display
        cursor.execute("""
            SELECT id, hostname FROM remote
            WHERE private_key IS NULL
        """)
        provisional_remotes = cursor.fetchall()

        if remotes:
            print("\nRemote Clients:")
            for remote_id, hostname, _ in remotes:
                remote_config = generate_remote_config(db, remote_id)
                remote_file = output_dir / f"{hostname}.conf"
                if dry_run:
                    print(f"  [DRY RUN] Would write: {remote_file}")
                    if args.qr:
                        print(f"  [DRY RUN] Would write: {output_dir / f'{hostname}.png'}")
                else:
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

        # Show provisional peers (in CS config but no local config generated)
        if provisional_remotes:
            print("\nProvisional Remotes (in CS config, no private key):")
            for remote_id, hostname in provisional_remotes:
                print(f"  ! {hostname} - rotate keys to generate config")

        # Generate exit node configs
        cursor.execute("SELECT id, hostname FROM exit_node")
        exit_nodes = cursor.fetchall()

        if exit_nodes:
            print("\nExit Nodes:")
            for exit_id, hostname in exit_nodes:
                exit_config = generate_exit_node_config(db, exit_id)
                exit_file = output_dir / f"{hostname}.conf"
                if dry_run:
                    print(f"  [DRY RUN] Would write: {exit_file}")
                else:
                    exit_file.write_text(exit_config)
                    exit_file.chmod(0o600)
                    # Count remotes using this exit
                    cursor.execute("""
                        SELECT COUNT(*) FROM remote WHERE exit_node_id = ?
                    """, (exit_id,))
                    remote_count = cursor.fetchone()[0]
                    print(f"  ✓ {exit_file} ({remote_count} clients)")

    print()
    if dry_run:
        print(f"[DRY RUN] No files were written")
    else:
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
