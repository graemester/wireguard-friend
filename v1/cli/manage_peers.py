"""
Manage Peers - Entity-centered peer management interface

Provides drill-down capability to view and manage any peer in the network.
"""

import sys
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Any
from datetime import datetime
from dataclasses import dataclass

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from v1.schema_semantic import WireGuardDBv2

# Rich imports
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.tree import Tree
    from rich.text import Text
    from rich import box
    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False
    console = None


def clear_screen():
    """Clear screen and move cursor to home"""
    if RICH_AVAILABLE:
        console.clear()
    print("\033[H", end="", flush=True)


@dataclass
class PeerInfo:
    """Unified peer information structure"""
    peer_type: str  # 'cs', 'router', 'remote', 'exit_node'
    peer_id: int
    hostname: str
    ipv4_address: str
    ipv6_address: str
    public_key: str
    # Type-specific fields stored in extras
    extras: Dict[str, Any]


def get_all_peers(db: WireGuardDBv2) -> List[PeerInfo]:
    """Fetch all peers from database with unified structure"""
    peers = []

    with db._connection() as conn:
        cursor = conn.cursor()

        # Coordination Server
        cursor.execute("""
            SELECT hostname, ipv4_address, ipv6_address, current_public_key,
                   endpoint, listen_port, mtu, network_ipv4, network_ipv6,
                   ssh_host, ssh_user, ssh_port, private_key,
                   created_at, updated_at
            FROM coordination_server WHERE id = 1
        """)
        row = cursor.fetchone()
        if row:
            peers.append(PeerInfo(
                peer_type='cs',
                peer_id=1,
                hostname=row['hostname'] or 'coordination-server',
                ipv4_address=row['ipv4_address'],
                ipv6_address=row['ipv6_address'] or '',
                public_key=row['current_public_key'],
                extras={
                    'endpoint': row['endpoint'],
                    'listen_port': row['listen_port'],
                    'mtu': row['mtu'],
                    'network_ipv4': row['network_ipv4'],
                    'network_ipv6': row['network_ipv6'],
                    'ssh_host': row['ssh_host'],
                    'ssh_user': row['ssh_user'],
                    'ssh_port': row['ssh_port'],
                    'private_key': row['private_key'],
                    'created_at': row['created_at'],
                    'updated_at': row['updated_at'],
                }
            ))

        # Subnet Routers
        cursor.execute("""
            SELECT id, hostname, ipv4_address, ipv6_address, current_public_key,
                   endpoint, mtu, persistent_keepalive, lan_interface,
                   ssh_host, ssh_user, ssh_port, private_key, preshared_key,
                   created_at, updated_at
            FROM subnet_router ORDER BY hostname
        """)
        for row in cursor.fetchall():
            # Get advertised networks
            cursor.execute("""
                SELECT network_cidr, description
                FROM advertised_network
                WHERE subnet_router_id = ?
            """, (row['id'],))
            networks = [(r['network_cidr'], r['description']) for r in cursor.fetchall()]

            peers.append(PeerInfo(
                peer_type='router',
                peer_id=row['id'],
                hostname=row['hostname'] or f"router-{row['id']}",
                ipv4_address=row['ipv4_address'],
                ipv6_address=row['ipv6_address'] or '',
                public_key=row['current_public_key'],
                extras={
                    'endpoint': row['endpoint'],
                    'mtu': row['mtu'],
                    'persistent_keepalive': row['persistent_keepalive'],
                    'lan_interface': row['lan_interface'],
                    'ssh_host': row['ssh_host'],
                    'ssh_user': row['ssh_user'],
                    'ssh_port': row['ssh_port'],
                    'private_key': row['private_key'],
                    'preshared_key': row['preshared_key'],
                    'advertised_networks': networks,
                    'created_at': row['created_at'],
                    'updated_at': row['updated_at'],
                }
            ))

        # Remote Clients
        cursor.execute("""
            SELECT id, hostname, ipv4_address, ipv6_address, current_public_key,
                   dns_servers, persistent_keepalive, access_level, allowed_ips,
                   private_key, preshared_key, created_at, updated_at,
                   permanent_guid, exit_node_id
            FROM remote ORDER BY hostname
        """)
        for row in cursor.fetchall():
            # Fetch comments for this peer
            cursor.execute("""
                SELECT category, text FROM comment
                WHERE entity_permanent_guid = ? AND entity_type = 'remote'
                ORDER BY display_order
            """, (row['permanent_guid'],))
            comments = [(r['category'], r['text']) for r in cursor.fetchall()]

            # Get exit node info if assigned
            exit_node_info = None
            if row.get('exit_node_id'):
                cursor.execute("""
                    SELECT hostname, endpoint FROM exit_node WHERE id = ?
                """, (row['exit_node_id'],))
                exit_row = cursor.fetchone()
                if exit_row:
                    exit_node_info = {
                        'hostname': exit_row['hostname'],
                        'endpoint': exit_row['endpoint']
                    }

            peers.append(PeerInfo(
                peer_type='remote',
                peer_id=row['id'],
                hostname=row['hostname'] or f"remote-{row['id']}",
                ipv4_address=row['ipv4_address'],
                ipv6_address=row['ipv6_address'] or '',
                public_key=row['current_public_key'],
                extras={
                    'dns_servers': row['dns_servers'],
                    'persistent_keepalive': row['persistent_keepalive'],
                    'access_level': row['access_level'],
                    'allowed_ips': row['allowed_ips'],
                    'private_key': row['private_key'],
                    'preshared_key': row['preshared_key'],
                    'created_at': row['created_at'],
                    'updated_at': row['updated_at'],
                    'is_provisional': row['private_key'] is None,
                    'comments': comments,
                    'exit_node_id': row.get('exit_node_id'),
                    'exit_node_info': exit_node_info,
                }
            ))

        # Exit Nodes
        cursor.execute("""
            SELECT id, hostname, ipv4_address, ipv6_address, current_public_key,
                   endpoint, listen_port, wan_interface,
                   ssh_host, ssh_user, ssh_port, private_key,
                   created_at, updated_at, permanent_guid
            FROM exit_node ORDER BY hostname
        """)
        for row in cursor.fetchall():
            # Count remotes using this exit node
            cursor.execute("""
                SELECT COUNT(*) as cnt FROM remote WHERE exit_node_id = ?
            """, (row['id'],))
            remote_count = cursor.fetchone()['cnt']

            peers.append(PeerInfo(
                peer_type='exit_node',
                peer_id=row['id'],
                hostname=row['hostname'] or f"exit-{row['id']}",
                ipv4_address=row['ipv4_address'],
                ipv6_address=row['ipv6_address'] or '',
                public_key=row['current_public_key'],
                extras={
                    'endpoint': row['endpoint'],
                    'listen_port': row['listen_port'],
                    'wan_interface': row['wan_interface'],
                    'ssh_host': row['ssh_host'],
                    'ssh_user': row['ssh_user'],
                    'ssh_port': row['ssh_port'],
                    'private_key': row['private_key'],
                    'created_at': row['created_at'],
                    'updated_at': row['updated_at'],
                    'remote_count': remote_count,
                }
            ))

    return peers


def render_peer_list(peers: List[PeerInfo], filter_text: str = "") -> str:
    """Render the peer list with optional filtering"""
    # Filter peers
    if filter_text:
        filter_lower = filter_text.lower()
        filtered = [p for p in peers if filter_lower in p.hostname.lower()]
    else:
        filtered = peers

    # Group by type
    cs_peers = [p for p in filtered if p.peer_type == 'cs']
    routers = [p for p in filtered if p.peer_type == 'router']
    remotes = [p for p in filtered if p.peer_type == 'remote']
    exit_nodes = [p for p in filtered if p.peer_type == 'exit_node']

    # Build display with sequential numbering
    lines = []
    peer_map = {}  # number -> peer
    num = 1

    if cs_peers:
        lines.append("")
        lines.append("[COORDINATION SERVER]")
        lines.append("")
        for p in cs_peers:
            peer_map[num] = p
            lines.append(f"  [{num:2}] {p.hostname}")
            lines.append(f"       IP: {p.ipv4_address:20}  Key: {p.public_key[:24]}...")
            num += 1

    if routers:
        lines.append("")
        lines.append(f"[SUBNET ROUTERS] ({len(routers)})")
        lines.append("")
        for i, p in enumerate(routers):
            peer_map[num] = p
            is_last = (i == len(routers) - 1)
            connector = " L" if is_last else " |"
            lines.append(f"  [{num:2}] {p.hostname}")
            nets = p.extras.get('advertised_networks', [])
            net_str = ', '.join(n[0] for n in nets[:2]) if nets else 'none'
            lines.append(f"       IP: {p.ipv4_address:20}  Nets: {net_str}")
            num += 1

    if remotes:
        lines.append("")
        # Count provisional
        provisional_count = sum(1 for r in remotes if r.extras.get('is_provisional'))
        if provisional_count > 0:
            lines.append(f"[REMOTE CLIENTS] ({len(remotes) - provisional_count} full, {provisional_count} provisional)")
        else:
            lines.append(f"[REMOTE CLIENTS] ({len(remotes)})")
        lines.append("")
        for i, p in enumerate(remotes):
            peer_map[num] = p
            access = p.extras.get('access_level', 'unknown')
            status = " [provisional]" if p.extras.get('is_provisional') else ""
            exit_info = ""
            if p.extras.get('exit_node_info'):
                exit_info = f" -> {p.extras['exit_node_info']['hostname']}"
            lines.append(f"  [{num:2}] {p.hostname}{status}{exit_info}")
            lines.append(f"       IP: {p.ipv4_address:20}  Access: {access}")
            num += 1

    if exit_nodes:
        lines.append("")
        lines.append(f"[EXIT NODES] ({len(exit_nodes)})")
        lines.append("")
        for i, p in enumerate(exit_nodes):
            peer_map[num] = p
            remote_count = p.extras.get('remote_count', 0)
            client_str = f"{remote_count} clients" if remote_count != 1 else "1 client"
            lines.append(f"  [{num:2}] {p.hostname}")
            lines.append(f"       Endpoint: {p.extras.get('endpoint', 'unknown')}:{p.extras.get('listen_port', 51820)}  ({client_str})")
            num += 1

    if not filtered:
        lines.append("")
        lines.append("  No peers found matching filter.")

    return "\n".join(lines), peer_map


def show_peer_list(db: WireGuardDBv2) -> Optional[PeerInfo]:
    """
    Display peer list and let user select one.

    Returns:
        Selected PeerInfo or None if user cancelled
    """
    peers = get_all_peers(db)
    filter_text = ""

    while True:
        clear_screen()
        # Render list
        list_content, peer_map = render_peer_list(peers, filter_text)
        total = len(peers)
        shown = len(peer_map)

        # Display
        if RICH_AVAILABLE:
            title = f"MANAGE PEERS [{shown} of {total}]" if filter_text else f"MANAGE PEERS [{total} peers]"
            console.print()
            console.print(Panel(
                list_content,
                title=f"[bold]{title}[/bold]",
                title_align="left",
                subtitle="[dim]Enter number to view | Type to filter | \\[B]ack[/dim]",
                border_style="cyan",
                padding=(0, 2)
            ))
        else:
            print("\n" + "=" * 70)
            print(f"MANAGE PEERS [{shown} peers]")
            print("=" * 70)
            print(list_content)
            print("\n" + "-" * 70)
            print("Enter peer number | Type to filter | 'b' back")

        # Get input
        if filter_text:
            prompt = f"Filter [{filter_text}]: "
        else:
            prompt = "Select: "

        choice = input(prompt).strip()

        # Handle input
        if choice.lower() in ('b', 'back', 'q', 'quit', ''):
            return None

        # Try as number
        try:
            num = int(choice)
            if num in peer_map:
                return peer_map[num]
            else:
                print(f"  Invalid number. Enter 1-{len(peer_map)}.")
        except ValueError:
            # Treat as filter text
            filter_text = choice


def format_value(value: Any, mask: bool = False) -> str:
    """Format a value for display"""
    if value is None:
        return "(not set)"
    if mask:
        return "*" * 32 + " (hidden)"
    if isinstance(value, list):
        if not value:
            return "(none)"
        return "\n".join(f"    - {v}" for v in value)
    return str(value)


def show_peer_detail(db: WireGuardDBv2, peer: PeerInfo) -> Optional[str]:
    """
    Display full peer details and action menu.

    Returns:
        Action to perform ('rotate', 'remove', 'generate', etc.) or None
    """
    clear_screen()
    type_labels = {
        'cs': 'Coordination Server',
        'router': 'Subnet Router',
        'remote': 'Remote Client',
        'exit_node': 'Exit Node'
    }
    type_label = type_labels.get(peer.peer_type, peer.peer_type)

    # Build detail sections
    sections = []

    # General section
    general = []
    general.append(f"  Type:           {type_label}")
    general.append(f"  Hostname:       {peer.hostname}")
    if peer.peer_type != 'cs':
        general.append(f"  ID:             {peer.peer_id}")
    if peer.extras.get('is_provisional'):
        general.append(f"  Status:         [PROVISIONAL] - no private key")
    if peer.extras.get('endpoint'):
        general.append(f"  Endpoint:       {peer.extras['endpoint']}")
    if peer.extras.get('listen_port'):
        general.append(f"  Listen Port:    {peer.extras['listen_port']}")
    if peer.extras.get('mtu'):
        general.append(f"  MTU:            {peer.extras['mtu']}")
    if peer.extras.get('persistent_keepalive'):
        general.append(f"  Keepalive:      {peer.extras['persistent_keepalive']}s")
    if peer.extras.get('access_level'):
        general.append(f"  Access Level:   {peer.extras['access_level']}")
    if peer.extras.get('wan_interface'):
        general.append(f"  WAN Interface:  {peer.extras['wan_interface']}")
    if peer.extras.get('remote_count') is not None:
        general.append(f"  Clients Using:  {peer.extras['remote_count']}")
    # Exit node info for remotes
    if peer.extras.get('exit_node_info'):
        exit_info = peer.extras['exit_node_info']
        general.append(f"  Exit Node:      {exit_info['hostname']} ({exit_info['endpoint']})")
    elif peer.peer_type == 'remote':
        general.append(f"  Exit Node:      (none - split tunnel)")
    sections.append(("GENERAL", "\n".join(general)))

    # Network section
    network = []
    network.append(f"  IPv4 Address:   {peer.ipv4_address}")
    if peer.ipv6_address:
        network.append(f"  IPv6 Address:   {peer.ipv6_address}")
    if peer.extras.get('network_ipv4'):
        network.append(f"  Network IPv4:   {peer.extras['network_ipv4']}")
    if peer.extras.get('network_ipv6'):
        network.append(f"  Network IPv6:   {peer.extras['network_ipv6']}")
    if peer.extras.get('dns_servers'):
        network.append(f"  DNS Servers:    {peer.extras['dns_servers']}")
    if peer.extras.get('lan_interface'):
        network.append(f"  LAN Interface:  {peer.extras['lan_interface']}")

    # Advertised networks for routers
    nets = peer.extras.get('advertised_networks', [])
    if nets:
        network.append(f"  Advertised Networks:")
        for cidr, desc in nets:
            if desc:
                network.append(f"    - {cidr} ({desc})")
            else:
                network.append(f"    - {cidr}")

    # Allowed IPs for remotes
    if peer.extras.get('allowed_ips'):
        network.append(f"  Allowed IPs:    {peer.extras['allowed_ips']}")

    sections.append(("NETWORK", "\n".join(network)))

    # Cryptography section
    crypto = []
    crypto.append(f"  Public Key:     {peer.public_key}")
    if peer.extras.get('is_provisional'):
        crypto.append(f"  Private Key:    (not available - rotate keys to generate)")
    else:
        crypto.append(f"  Private Key:    {'*' * 32} (hidden)")
    if peer.extras.get('preshared_key'):
        crypto.append(f"  Preshared Key:  {'*' * 32} (hidden)")
    sections.append(("CRYPTOGRAPHY", "\n".join(crypto)))

    # SSH section (if applicable)
    if peer.extras.get('ssh_host') or peer.peer_type in ('cs', 'router', 'exit_node'):
        ssh = []
        ssh.append(f"  SSH Host:       {peer.extras.get('ssh_host') or '(not set)'}")
        ssh.append(f"  SSH User:       {peer.extras.get('ssh_user') or 'root'}")
        ssh.append(f"  SSH Port:       {peer.extras.get('ssh_port') or 22}")
        sections.append(("SSH ACCESS", "\n".join(ssh)))

    # Metadata section
    meta = []
    meta.append(f"  Created:        {peer.extras.get('created_at') or '(unknown)'}")
    meta.append(f"  Updated:        {peer.extras.get('updated_at') or '(unknown)'}")
    sections.append(("METADATA", "\n".join(meta)))

    # Comments section (if any)
    comments = peer.extras.get('comments', [])
    if comments:
        comment_lines = []
        for category, text in comments:
            comment_lines.append(f"  [{category}] {text}")
        sections.append(("COMMENTS", "\n".join(comment_lines)))

    # Build actions based on type
    if peer.peer_type == 'cs':
        actions = [
            ("1", "Edit Hostname"),
            ("2", "Rotate Keys"),
            ("3", "View Key History"),
            ("4", "Generate Config"),
            ("5", "Deploy Config"),
        ]
    elif peer.peer_type == 'router':
        actions = [
            ("1", "Edit Hostname"),
            ("2", "Rotate Keys"),
            ("3", "View Key History"),
            ("4", "Generate Config"),
            ("5", "Deploy Config"),
            ("6", "Remove Peer"),
        ]
    elif peer.peer_type == 'exit_node':
        actions = [
            ("1", "Edit Hostname"),
            ("2", "Rotate Keys"),
            ("3", "View Key History"),
            ("4", "Edit Endpoint"),
            ("5", "Edit WAN Interface"),
            ("6", "Generate Config"),
            ("7", "Deploy Config"),
            ("8", "Remove Exit Node"),
        ]
    else:  # remote
        # Check if exit node is assigned
        has_exit = peer.extras.get('exit_node_id') is not None
        if has_exit:
            actions = [
                ("1", "Edit Hostname"),
                ("2", "Rotate Keys"),
                ("3", "View Key History"),
                ("4", "Change Access Level"),
                ("5", "Clear Exit Node"),
                ("6", "Generate Config"),
                ("7", "Generate QR Code"),
                ("8", "Remove Peer"),
            ]
        else:
            actions = [
                ("1", "Edit Hostname"),
                ("2", "Rotate Keys"),
                ("3", "View Key History"),
                ("4", "Change Access Level"),
                ("5", "Assign Exit Node"),
                ("6", "Generate Config"),
                ("7", "Generate QR Code"),
                ("8", "Remove Peer"),
            ]

    # Display
    breadcrumb = f"[Peers] > [{type_label}] > {peer.hostname}"

    if RICH_AVAILABLE:
        console.print()
        console.print(Panel(
            f"[dim]{breadcrumb}[/dim]",
            title="[bold]PEER DETAILS[/bold]",
            title_align="left",
            border_style="cyan",
            padding=(0, 2)
        ))

        for section_name, section_content in sections:
            console.print(Panel(
                section_content,
                title=f"[bold]{section_name}[/bold]",
                title_align="left",
                border_style="dim",
                padding=(0, 1)
            ))

        # Actions - escape brackets for Rich markup using backslash
        action_lines = []
        for key, label in actions:
            action_lines.append(f"  \\[{key}] {label}")
        action_lines.append("")
        action_lines.append("  \\[B]ack to Peer List    \\[M]ain Menu")

        console.print(Panel(
            "\n".join(action_lines),
            title="[bold]ACTIONS[/bold]",
            title_align="left",
            border_style="yellow",
            padding=(0, 1)
        ))
    else:
        print("\n" + "=" * 70)
        print("PEER DETAILS")
        print("=" * 70)
        print(breadcrumb)
        print("-" * 70)

        for section_name, section_content in sections:
            print(f"\n{section_name}")
            print("-" * 40)
            print(section_content)

        print("\n" + "=" * 70)
        print("ACTIONS")
        print("-" * 70)
        for key, label in actions:
            print(f"  [{key}] {label}")
        print()
        print("  [B]ack to Peer List    [M]ain Menu")

    # Get choice
    choice = input("\nAction: ").strip().lower()

    if choice in ('', 'b', 'back'):
        return 'back'
    if choice in ('m', 'q', 'quit', 'menu'):
        return 'quit'

    # Map action
    action_map = {a[0]: a[1] for a in actions}
    if choice in action_map:
        return action_map[choice]

    return None


def execute_peer_action(db: WireGuardDBv2, peer: PeerInfo, action: str, db_path: str) -> bool:
    """
    Execute an action on a peer.

    Returns:
        True if should stay in detail view, False to go back to list
    """
    from v1.cli.peer_manager import rotate_keys, remove_peer
    from v1.cli.config_generator import generate_cs_config, generate_router_config, generate_remote_config
    from v1.cli.status import show_entity_history

    print(f"\n{'=' * 70}")
    print(f"ACTION: {action.upper()}")
    print(f"{'=' * 70}")
    print(f"Peer: {peer.hostname} ({peer.peer_type})")
    print()

    if action == "Edit Hostname":
        print(f"Current hostname: {peer.hostname}")
        new_hostname = input("New hostname: ").strip()

        if not new_hostname:
            print("Cancelled - no hostname entered.")
            input("\nPress Enter to continue...")
            return True

        # Validate hostname (simple pattern)
        import re
        if not re.fullmatch(r'[a-zA-Z0-9][-a-zA-Z0-9]{0,28}[a-zA-Z0-9]', new_hostname) and len(new_hostname) > 1:
            if len(new_hostname) == 1 and new_hostname.isalnum():
                pass  # Single character is okay
            else:
                print(f"\n[WARNING] '{new_hostname}' contains unusual characters.")
                confirm = input("Use anyway? [y/N]: ").strip().lower()
                if confirm != 'y':
                    print("Cancelled.")
                    input("\nPress Enter to continue...")
                    return True

        # Update database
        with db._connection() as conn:
            cursor = conn.cursor()
            if peer.peer_type == 'cs':
                cursor.execute("""
                    UPDATE coordination_server SET hostname = ?, updated_at = ?
                    WHERE id = ?
                """, (new_hostname, datetime.utcnow().isoformat(), peer.peer_id))
            elif peer.peer_type == 'router':
                cursor.execute("""
                    UPDATE subnet_router SET hostname = ?, updated_at = ?
                    WHERE id = ?
                """, (new_hostname, datetime.utcnow().isoformat(), peer.peer_id))
            elif peer.peer_type == 'exit_node':
                cursor.execute("""
                    UPDATE exit_node SET hostname = ?, updated_at = ?
                    WHERE id = ?
                """, (new_hostname, datetime.utcnow().isoformat(), peer.peer_id))
            else:
                cursor.execute("""
                    UPDATE remote SET hostname = ?, updated_at = ?
                    WHERE id = ?
                """, (new_hostname, datetime.utcnow().isoformat(), peer.peer_id))

        print(f"\n[OK] Hostname changed: {peer.hostname} -> {new_hostname}")
        input("\nPress Enter to continue...")
        return True

    elif action == "Rotate Keys":
        reason = input("Reason for rotation [Scheduled rotation]: ").strip()
        if not reason:
            reason = "Scheduled rotation"

        peer_type = peer.peer_type
        peer_id = peer.peer_id if peer.peer_type != 'cs' else None

        success = rotate_keys(db, peer_type, peer_id, reason)
        if success:
            print("\n[OK] Keys rotated successfully.")
            print("     Run 'Generate Config' to create updated configs.")
        input("\nPress Enter to continue...")
        return True

    elif action == "View Key History":
        show_entity_history(db, db_path, peer.hostname)
        input("\nPress Enter to continue...")
        return True

    elif action == "Generate Config":
        from pathlib import Path
        from v1.cli.config_generator import generate_exit_node_config

        # Check for provisional peer
        if peer.peer_type == 'remote' and peer.extras.get('is_provisional'):
            print(f"\n[ERROR] {peer.hostname} is a provisional peer.")
            print("        Rotate keys first to generate a private key.")
            print("        Then you can generate a config.")
            input("\nPress Enter to continue...")
            return True

        output_dir = Path('generated')
        output_dir.mkdir(exist_ok=True)

        if peer.peer_type == 'cs':
            config = generate_cs_config(db)
            filename = "coordination.conf"
        elif peer.peer_type == 'router':
            config = generate_router_config(db, peer.peer_id)
            filename = f"{peer.hostname}.conf"
        elif peer.peer_type == 'exit_node':
            config = generate_exit_node_config(db, peer.peer_id)
            filename = f"{peer.hostname}.conf"
        else:
            config = generate_remote_config(db, peer.peer_id)
            filename = f"{peer.hostname}.conf"

        output_path = output_dir / filename
        output_path.write_text(config)
        output_path.chmod(0o600)

        print(f"\n[OK] Config saved to: {output_path}")

        # Offer to view
        view = input("\nView config? [y/N]: ").strip().lower()
        if view == 'y':
            print("\n" + "-" * 70)
            print(config)
            print("-" * 70)

        input("\nPress Enter to continue...")
        return True

    elif action == "Generate QR Code":
        # Check for provisional peer
        if peer.extras.get('is_provisional'):
            print(f"\n[ERROR] {peer.hostname} is a provisional peer.")
            print("        Rotate keys first to generate a private key.")
            print("        Then you can generate a QR code.")
            input("\nPress Enter to continue...")
            return True

        try:
            import qrcode
            from pathlib import Path

            config = generate_remote_config(db, peer.peer_id)

            output_dir = Path('generated')
            output_dir.mkdir(exist_ok=True)

            qr = qrcode.QRCode()
            qr.add_data(config)
            qr.make()

            qr_file = output_dir / f"{peer.hostname}.png"
            img = qr.make_image(fill_color="black", back_color="white")
            img.save(qr_file)

            print(f"\n[OK] QR code saved to: {qr_file}")

            # Also save config
            conf_file = output_dir / f"{peer.hostname}.conf"
            conf_file.write_text(config)
            conf_file.chmod(0o600)
            print(f"[OK] Config saved to: {conf_file}")

        except ImportError:
            print("\n[ERROR] qrcode module not installed.")
            print("        pip install qrcode[pil]")

        input("\nPress Enter to continue...")
        return True

    elif action == "Deploy Config":
        from v1.cli.deploy import deploy_to_host
        from pathlib import Path

        output_dir = Path('generated')

        if peer.peer_type == 'cs':
            config_file = output_dir / "coordination.conf"
        else:
            config_file = output_dir / f"{peer.hostname}.conf"

        if not config_file.exists():
            print(f"\n[ERROR] Config not found: {config_file}")
            print("        Run 'Generate Config' first.")
            input("\nPress Enter to continue...")
            return True

        endpoint = peer.extras.get('endpoint') or peer.extras.get('ssh_host')
        if not endpoint or endpoint == 'UNKNOWN':
            print("\n[ERROR] No endpoint/SSH host configured for this peer.")
            input("\nPress Enter to continue...")
            return True

        user = peer.extras.get('ssh_user') or 'root'

        print(f"Deploying to: {endpoint}")
        print(f"Config: {config_file}")
        print(f"User: {user}")

        confirm = input("\nProceed? [y/N]: ").strip().lower()
        if confirm != 'y':
            print("Cancelled.")
            input("\nPress Enter to continue...")
            return True

        success = deploy_to_host(
            hostname=peer.hostname,
            config_file=config_file,
            endpoint=endpoint,
            user=user,
            restart=False,
            dry_run=False
        )

        if success:
            restart = input("\nRestart WireGuard? [y/N]: ").strip().lower()
            if restart == 'y':
                from v1.cli.deploy import restart_wireguard
                restart_wireguard(endpoint, user=user)

        input("\nPress Enter to continue...")
        return True

    elif action == "Change Access Level":
        print("Current access level:", peer.extras.get('access_level'))
        print()
        print("Available levels:")
        print("  1. full_access - All traffic through VPN")
        print("  2. vpn_only    - VPN network only")
        print("  3. lan_only    - LAN access only")
        print("  4. custom      - Custom AllowedIPs")
        print()

        choice = input("New level [1-4]: ").strip()
        levels = {'1': 'full_access', '2': 'vpn_only', '3': 'lan_only', '4': 'custom'}

        if choice in levels:
            new_level = levels[choice]
            with db._connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE remote SET access_level = ?, updated_at = ?
                    WHERE id = ?
                """, (new_level, datetime.utcnow().isoformat(), peer.peer_id))
                conn.commit()
            print(f"\n[OK] Access level changed to: {new_level}")
            print("     Regenerate config to apply changes.")
        else:
            print("Invalid choice.")

        input("\nPress Enter to continue...")
        return True

    elif action == "Remove Peer":
        if peer.peer_type == 'cs':
            print("[ERROR] Cannot remove coordination server.")
            input("\nPress Enter to continue...")
            return True

        reason = input("Reason for removal [Manual revocation]: ").strip()
        if not reason:
            reason = "Manual revocation"

        success = remove_peer(db, peer.peer_type, peer.peer_id, reason)
        if success:
            print("\n[OK] Peer removed.")
            return False  # Go back to list

        input("\nPress Enter to continue...")
        return True

    elif action == "Edit Endpoint":
        # Exit node only
        print(f"Current endpoint: {peer.extras.get('endpoint', '(not set)')}")
        new_endpoint = input("New endpoint: ").strip()

        if not new_endpoint:
            print("Cancelled - no endpoint entered.")
            input("\nPress Enter to continue...")
            return True

        with db._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE exit_node SET endpoint = ?, updated_at = ?
                WHERE id = ?
            """, (new_endpoint, datetime.utcnow().isoformat(), peer.peer_id))

        print(f"\n[OK] Endpoint changed to: {new_endpoint}")
        input("\nPress Enter to continue...")
        return True

    elif action == "Edit WAN Interface":
        # Exit node only
        print(f"Current WAN interface: {peer.extras.get('wan_interface', 'eth0')}")
        new_wan = input("New WAN interface: ").strip()

        if not new_wan:
            print("Cancelled - no interface entered.")
            input("\nPress Enter to continue...")
            return True

        with db._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE exit_node SET wan_interface = ?, updated_at = ?
                WHERE id = ?
            """, (new_wan, datetime.utcnow().isoformat(), peer.peer_id))

        print(f"\n[OK] WAN interface changed to: {new_wan}")
        print("     Regenerate config to apply changes.")
        input("\nPress Enter to continue...")
        return True

    elif action == "Remove Exit Node":
        from v1.exit_node_ops import ExitNodeOps

        ops = ExitNodeOps(db)
        remotes_using = ops.list_remotes_using_exit_node(peer.peer_id)

        if remotes_using:
            print(f"\n[WARNING] {len(remotes_using)} remote(s) use this exit node:")
            for r in remotes_using[:5]:
                print(f"  - {r['hostname']}")
            if len(remotes_using) > 5:
                print(f"  ... and {len(remotes_using) - 5} more")
            print("\nThese remotes will revert to split tunnel (no default route).")

        confirm = input(f"\nRemove exit node '{peer.hostname}'? [y/N]: ").strip().lower()
        if confirm != 'y':
            print("Cancelled.")
            input("\nPress Enter to continue...")
            return True

        hostname, affected = ops.remove_exit_node(peer.peer_id)
        print(f"\n[OK] Exit node '{hostname}' removed.")
        if affected > 0:
            print(f"     {affected} remote(s) reverted to split tunnel.")
        return False  # Go back to list

    elif action == "Assign Exit Node":
        from v1.exit_node_ops import ExitNodeOps

        ops = ExitNodeOps(db)
        exit_nodes = ops.list_exit_nodes()

        if not exit_nodes:
            print("\n[ERROR] No exit nodes configured.")
            print("        Add an exit node first via the Exit Nodes menu.")
            input("\nPress Enter to continue...")
            return True

        print("\nAvailable Exit Nodes:")
        for en in exit_nodes:
            print(f"  [{en.id:2}] {en.hostname} ({en.endpoint})")

        try:
            exit_id = int(input("\nExit Node ID: ").strip())
        except ValueError:
            print("Invalid ID.")
            input("\nPress Enter to continue...")
            return True

        exit_node = ops.get_exit_node(exit_id)
        if not exit_node:
            print("Exit node not found.")
            input("\nPress Enter to continue...")
            return True

        ops.assign_exit_to_remote(peer.peer_id, exit_id)
        print(f"\n[OK] Assigned exit node '{exit_node.hostname}' to {peer.hostname}")
        print("     Remote will now route internet traffic through this exit node.")
        print("     Regenerate config to apply changes.")
        input("\nPress Enter to continue...")
        return True

    elif action == "Clear Exit Node":
        from v1.exit_node_ops import ExitNodeOps

        ops = ExitNodeOps(db)

        # Check if exit_only
        if peer.extras.get('access_level') == 'exit_only':
            print("\n[ERROR] Cannot clear exit node from exit_only remote.")
            print("        Change access level first, or assign a different exit node.")
            input("\nPress Enter to continue...")
            return True

        exit_info = peer.extras.get('exit_node_info')
        if exit_info:
            print(f"Current exit node: {exit_info['hostname']}")

        confirm = input("Clear exit node assignment? [y/N]: ").strip().lower()
        if confirm != 'y':
            print("Cancelled.")
            input("\nPress Enter to continue...")
            return True

        ops.clear_exit_from_remote(peer.peer_id)
        print(f"\n[OK] Cleared exit node from {peer.hostname}")
        print("     Remote will now use split tunnel (no default route).")
        print("     Regenerate config to apply changes.")
        input("\nPress Enter to continue...")
        return True

    return True


def manage_peers_menu(db: WireGuardDBv2, db_path: str):
    """Main entry point for Manage Peers interface"""
    while True:
        # Show peer list and get selection
        peer = show_peer_list(db)

        if peer is None:
            # User cancelled
            return

        # Show detail view and get action
        while True:
            action = show_peer_detail(db, peer)

            if action == 'back':
                break  # Back to list

            if action == 'quit':
                return  # Exit to main menu

            if action:
                # Execute action
                stay_in_detail = execute_peer_action(db, peer, action, db_path)
                if not stay_in_detail:
                    break  # Peer was removed, go back to list

                # Refresh peer data
                peers = get_all_peers(db)
                updated_peer = None
                for p in peers:
                    if p.peer_type == peer.peer_type and p.peer_id == peer.peer_id:
                        updated_peer = p
                        break

                if updated_peer:
                    peer = updated_peer
                else:
                    break  # Peer no longer exists
