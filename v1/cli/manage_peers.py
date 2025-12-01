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
    peer_type: str  # 'cs', 'router', 'remote'
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
                   private_key, preshared_key, created_at, updated_at
            FROM remote ORDER BY hostname
        """)
        for row in cursor.fetchall():
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
        lines.append(f"[REMOTE CLIENTS] ({len(remotes)})")
        lines.append("")
        for i, p in enumerate(remotes):
            peer_map[num] = p
            access = p.extras.get('access_level', 'unknown')
            lines.append(f"  [{num:2}] {p.hostname}")
            lines.append(f"       IP: {p.ipv4_address:20}  Access: {access}")
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
        'remote': 'Remote Client'
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
    crypto.append(f"  Private Key:    {'*' * 32} (hidden)")
    if peer.extras.get('preshared_key'):
        crypto.append(f"  Preshared Key:  {'*' * 32} (hidden)")
    sections.append(("CRYPTOGRAPHY", "\n".join(crypto)))

    # SSH section (if applicable)
    if peer.extras.get('ssh_host') or peer.peer_type in ('cs', 'router'):
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

    # Build actions based on type
    if peer.peer_type == 'cs':
        actions = [
            ("1", "Rotate Keys"),
            ("2", "View Key History"),
            ("3", "Generate Config"),
            ("4", "Deploy Config"),
        ]
    elif peer.peer_type == 'router':
        actions = [
            ("1", "Rotate Keys"),
            ("2", "View Key History"),
            ("3", "Generate Config"),
            ("4", "Deploy Config"),
            ("5", "Remove Peer"),
        ]
    else:  # remote
        actions = [
            ("1", "Rotate Keys"),
            ("2", "View Key History"),
            ("3", "Change Access Level"),
            ("4", "Generate Config"),
            ("5", "Generate QR Code"),
            ("6", "Remove Peer"),
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

    if action == "Rotate Keys":
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
        output_dir = Path('generated')
        output_dir.mkdir(exist_ok=True)

        if peer.peer_type == 'cs':
            config = generate_cs_config(db)
            filename = "coordination.conf"
        elif peer.peer_type == 'router':
            config = generate_router_config(db, peer.peer_id)
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
