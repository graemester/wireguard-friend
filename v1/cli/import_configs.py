"""
Import Existing WireGuard Configs into Database

Parses existing configs and stores in database with permanent_guid.
"""

import sys
from pathlib import Path
from typing import List, Dict, Optional

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

# Rich imports for enhanced UI
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.prompt import Confirm
    from rich import box
    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False
    console = None
    Confirm = None

from v1.entity_parser import EntityParser
from v1.patterns import PatternRecognizer
from v1.comments import CommentCategorizer, CommentCategory
from v1.schema_semantic import WireGuardDBv2
from v1.keygen import derive_public_key
from v1.state_tracker import record_import
from v1.cli.validation import run_validation_checks


def rprint(msg: str = "", style: str = None):
    """Print with Rich if available, else plain print"""
    if RICH_AVAILABLE:
        if style:
            console.print(f"[{style}]{msg}[/{style}]")
        else:
            console.print(msg)
    else:
        # Strip Rich markup for plain output
        import re
        plain = re.sub(r'\[/?[^\]]+\]', '', msg)
        print(plain)


def separate_allowed_ips(allowed_ips: List[str]) -> tuple:
    """
    Separate AllowedIPs into VPN IPs and advertised networks.

    VPN IPs are /32 (IPv4) or /128 (IPv6) - the peer's address on the VPN.
    Advertised networks are larger CIDRs that the peer routes (LANs).

    Returns:
        (vpn_ips, advertised_networks) - two lists
    """
    vpn_ips = []
    advertised = []

    for ip in allowed_ips:
        ip = ip.strip()
        if not ip:
            continue

        # Check prefix length
        if '/' in ip:
            prefix = ip.split('/')[-1]
            try:
                prefix_len = int(prefix)
                # /32 for IPv4, /128 for IPv6 = VPN IP
                if prefix_len == 32 or prefix_len == 128:
                    vpn_ips.append(ip)
                else:
                    advertised.append(ip)
            except ValueError:
                advertised.append(ip)  # Malformed, treat as network
        else:
            # No prefix, treat as VPN IP
            vpn_ips.append(ip)

    return vpn_ips, advertised


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

    rprint()
    rprint("[bold cyan]Coordination Server[/bold cyan]")
    rprint(f"  GUID: [dim]{permanent_guid[:30]}...[/dim]")
    rprint(f"  Addresses: [green]{', '.join(interface['addresses'])}[/green]")

    # Recognize patterns
    pairs, singletons, unrecognized = pattern_recognizer.recognize_pairs(
        interface['postup'],
        interface['postdown']
    )

    if pairs or singletons:
        rprint(f"  Patterns: [yellow]{len(pairs)} pairs, {len(singletons)} singletons[/yellow]")

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

    # Parse [Peer] sections and extract advertised networks
    peer_entities = entities[1:]
    peers = []

    rprint()
    rprint(f"  [bold]Analyzing {len(peer_entities)} peers from CS config:[/bold]")

    for entity in peer_entities:
        peer = parse_peer_section(entity, categorizer)
        if peer['public_key']:
            # Separate VPN IPs from advertised networks
            vpn_ips, advertised = separate_allowed_ips(peer['allowed_ips'])
            peer['vpn_ips'] = vpn_ips
            peer['advertised_networks'] = advertised

            peer_name = peer.get('hostname', peer['public_key'][:20] + '...')

            if advertised:
                # This peer is likely a subnet router
                peer['inferred_type'] = 'subnet_router'
                rprint(f"    [cyan]{peer_name}[/cyan] [dim](subnet router)[/dim]")
                rprint(f"      VPN: [green]{', '.join(vpn_ips)}[/green]")
                rprint(f"      LANs: [yellow]{', '.join(advertised)}[/yellow]")
            else:
                # No LANs = likely a remote client
                peer['inferred_type'] = 'remote'
                rprint(f"    [cyan]{peer_name}[/cyan] [dim](remote)[/dim]")
                rprint(f"      VPN: [green]{', '.join(vpn_ips)}[/green]")

            peers.append(peer)

    # Collect all advertised LANs
    all_lans = []
    for peer in peers:
        all_lans.extend(peer.get('advertised_networks', []))

    # Environment summary with Rich Table
    rprint()
    if RICH_AVAILABLE:
        env_table = Table(title="Environment Model", box=box.ROUNDED, show_header=False)
        env_table.add_column("Property", style="bold")
        env_table.add_column("Value", style="green")

        env_table.add_row("VPN Network (IPv4)", network_ipv4)
        env_table.add_row("VPN Network (IPv6)", network_ipv6)
        if all_lans:
            env_table.add_row("Advertised LANs", ', '.join(set(all_lans)))
        else:
            env_table.add_row("Advertised LANs", "(none)")

        console.print(env_table)
    else:
        rprint("  [bold]Environment summary:[/bold]")
        rprint(f"    VPN Network: {network_ipv4}, {network_ipv6}")
        if all_lans:
            rprint(f"    Advertised LANs: {', '.join(set(all_lans))}")
        else:
            rprint(f"    Advertised LANs: (none)")

    return cs_id, peers, network_ipv4, network_ipv6


def import_subnet_router(config_path: Path, db: WireGuardDBv2, hostname: str = None,
                         cs_pubkey: str = None, cs_peers: List[Dict] = None):
    """
    Import subnet router config.

    Args:
        config_path: Path to subnet router .conf file
        db: Database connection
        hostname: Friendly name for this router
        cs_pubkey: Expected CS public key (to validate peer section)
        cs_peers: Peer data from CS config (includes advertised networks)

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

    rprint()
    rprint(f"[bold magenta]Subnet Router:[/bold magenta] [cyan]{hostname}[/cyan]")
    rprint(f"  GUID: [dim]{permanent_guid[:30]}...[/dim]")
    rprint(f"  Addresses: [green]{', '.join(interface['addresses'])}[/green]")

    # Get CS ID
    with db._connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM coordination_server LIMIT 1")
        row = cursor.fetchone()
        if not row:
            raise ValueError("No coordination server found - import CS first")
        cs_id = row[0]

    # Parse [Peer] section to get CS endpoint
    peer_data = None
    if len(entities) > 1:
        peer_data = parse_peer_section(entities[1], categorizer)

    endpoint = peer_data.get('endpoint') if peer_data else None

    # Get advertised networks from CS peer entry (matched by public key)
    # The CS's [Peer] section for this router contains the LANs it advertises
    lan_networks = []
    if cs_peers:
        for cs_peer in cs_peers:
            if cs_peer['public_key'] == public_key:
                lan_networks = cs_peer.get('advertised_networks', [])
                if lan_networks:
                    rprint(f"  Advertised LANs: [yellow]{', '.join(lan_networks)}[/yellow]")
                break
        else:
            rprint(f"  [yellow]Warning:[/yellow] Router not found in CS peers (pubkey mismatch)")
    else:
        # Fallback: try to infer from PostUp/PostDown (legacy mode)
        pass

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
                rprint(f"  [green]✓[/green] Updated CS endpoint: [cyan]{cs_endpoint}[/cyan]")

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

    rprint(f"  [green]✓[/green] Imported subnet router (ID: {router_id})")
    if lan_networks:
        rprint(f"  [green]✓[/green] LAN networks: [yellow]{', '.join(lan_networks)}[/yellow]")

    return router_id


def create_provisional_remote(db: WireGuardDBv2, cs_peer: Dict, cs_id: int) -> int:
    """
    Create a provisional remote from CS peer data.

    Provisional remotes are peers that exist in the CS config but for which
    we don't have the private key. They use private_key=NULL.

    Args:
        db: Database connection
        cs_peer: Peer data from CS config (public_key, vpn_ips, hostname, comments)
        cs_id: Coordination server ID

    Returns:
        remote_id
    """
    public_key = cs_peer['public_key']
    permanent_guid = public_key  # First key = permanent GUID

    # Get VPN IPs
    vpn_ips = cs_peer.get('vpn_ips', [])
    ipv4_addr = None
    ipv6_addr = None
    for ip in vpn_ips:
        if ':' in ip:
            ipv6_addr = ip
        else:
            ipv4_addr = ip

    # Use hostname from CS peer comments, or default to VPN IP
    hostname = cs_peer.get('hostname')
    if not hostname:
        # Default to VPN IP (without CIDR suffix)
        if ipv4_addr:
            hostname = ipv4_addr.split('/')[0]
        else:
            hostname = public_key[:12] + '...'

    # Extract additional fields from CS peer
    preshared_key = cs_peer.get('preshared_key')
    persistent_keepalive = cs_peer.get('persistent_keepalive')

    rprint()
    rprint(f"[bold yellow]Provisional Remote:[/bold yellow] [cyan]{hostname}[/cyan]")
    rprint(f"  GUID: [dim]{permanent_guid[:30]}...[/dim]")
    if ipv4_addr:
        rprint(f"  VPN IP: [green]{ipv4_addr}[/green]")
    if preshared_key:
        rprint(f"  [dim]Has preshared key[/dim]")
    rprint(f"  [dim](no private key - will be generated on key rotation)[/dim]")

    # Insert into database with NULL private_key
    with db._connection() as conn:
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO remote (
                cs_id, permanent_guid, current_public_key, hostname,
                ipv4_address, ipv6_address, private_key, preshared_key,
                persistent_keepalive, access_level
            ) VALUES (?, ?, ?, ?, ?, ?, NULL, ?, ?, ?)
        """, (
            cs_id,
            permanent_guid,
            public_key,
            hostname,
            ipv4_addr or '',
            ipv6_addr or '',
            preshared_key,
            persistent_keepalive,
            'unknown'  # Access level unknown for provisional peers
        ))
        remote_id = cursor.lastrowid

        # Store comments from CS peer
        for comment in cs_peer.get('comments', []):
            cursor.execute("""
                INSERT INTO comment (
                    entity_permanent_guid, entity_type,
                    category, text, display_order
                ) VALUES (?, ?, ?, ?, ?)
            """, (
                permanent_guid,
                'remote',
                comment.category.value if hasattr(comment.category, 'value') else str(comment.category),
                comment.text,
                comment.display_order
            ))

    rprint(f"  [yellow]![/yellow] Created provisional remote (ID: {remote_id})")

    return remote_id


def import_remote(config_path: Path, db: WireGuardDBv2, hostname: str = None,
                  cs_pubkey: str = None, known_networks: set = None):
    """
    Import remote client config.

    Args:
        config_path: Path to client .conf file
        db: Database connection
        hostname: Friendly name for this remote
        cs_pubkey: Expected CS public key (to validate peer section)
        known_networks: Set of valid network CIDRs (VPN + advertised LANs)

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

    rprint()
    rprint(f"[bold blue]Remote Client:[/bold blue] [cyan]{hostname}[/cyan]")
    rprint(f"  GUID: [dim]{permanent_guid[:30]}...[/dim]")
    rprint(f"  Addresses: [green]{', '.join(interface['addresses'])}[/green]")

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

    # Validate AllowedIPs against known networks
    if known_networks and allowed_ips_list:
        validated = []
        unknown = []

        for ip in allowed_ips_list:
            ip = ip.strip()
            # Full tunnel routes are always valid
            if ip in ('0.0.0.0/0', '::/0'):
                validated.append(ip)
            elif ip in known_networks:
                validated.append(ip)
            else:
                unknown.append(ip)

        if validated:
            rprint(f"  AllowedIPs: [green]{', '.join(validated)}[/green] [dim](validated)[/dim]")
        if unknown:
            rprint(f"  [yellow]Warning:[/yellow] Unknown networks in AllowedIPs: {', '.join(unknown)}")
            rprint(f"           These don't match VPN or advertised LANs")
            # Still include them but flag as potentially problematic
            validated.extend(unknown)

        allowed_ips = ', '.join(validated)
    else:
        allowed_ips = ', '.join(allowed_ips_list) if allowed_ips_list else None
        if allowed_ips:
            rprint(f"  AllowedIPs: [green]{allowed_ips}[/green]")

    # Infer access level from AllowedIPs
    access_level = 'custom'
    if allowed_ips_list:
        if '0.0.0.0/0' in allowed_ips_list or '::/0' in allowed_ips_list:
            access_level = 'full_access'
        elif any('192.168' in ip or '172.' in ip for ip in allowed_ips_list):
            access_level = 'lan_only'
        else:
            access_level = 'vpn_only'

    rprint(f"  Access level: [magenta]{access_level}[/magenta]")

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
                rprint(f"  [green]✓[/green] Updated CS endpoint: [cyan]{cs_endpoint}[/cyan]")

    rprint(f"  [green]✓[/green] Imported remote client (ID: {remote_id})")

    return remote_id


def import_exit_node(config_path: Path, db: WireGuardDBv2, hostname: str = None):
    """
    Import exit node config.

    Exit nodes are servers that provide internet egress for VPN clients.
    They have NAT/masquerade rules but peers only have VPN IPs (no LANs).

    Args:
        config_path: Path to exit node .conf file
        db: Database connection
        hostname: Friendly name for this exit node

    Returns:
        exit_node_id
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

    listen_port = interface.get('listen_port', 51820)

    rprint()
    rprint(f"[bold magenta]Exit Node:[/bold magenta] [cyan]{hostname}[/cyan]")
    rprint(f"  GUID: [dim]{permanent_guid[:30]}...[/dim]")
    rprint(f"  Addresses: [green]{', '.join(interface['addresses'])}[/green]")
    if listen_port:
        rprint(f"  Listen Port: [yellow]{listen_port}[/yellow]")

    # Detect WAN interface from PostUp rules
    wan_interface = 'eth0'  # Default
    for rule in interface.get('postup', []):
        if 'MASQUERADE' in rule and '-o ' in rule:
            # Extract interface name from "-o <iface>"
            import re
            match = re.search(r'-o\s+(\S+)', rule)
            if match:
                wan_interface = match.group(1)
                break

    rprint(f"  WAN Interface: [yellow]{wan_interface}[/yellow]")

    # Recognize patterns
    pairs, singletons, unrecognized = pattern_recognizer.recognize_pairs(
        interface['postup'],
        interface['postdown']
    )

    if pairs or singletons:
        rprint(f"  Patterns: [yellow]{len(pairs)} pairs, {len(singletons)} singletons[/yellow]")

    # Get CS ID
    with db._connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM coordination_server LIMIT 1")
        row = cursor.fetchone()
        if not row:
            raise ValueError("No coordination server found - import CS first")
        cs_id = row[0]

    # Need endpoint - prompt user or get from args
    rprint(f"  [yellow]Note:[/yellow] Exit node requires a public endpoint")
    endpoint = input(f"  Enter endpoint (IP/domain) for {hostname}: ").strip()
    if not endpoint:
        endpoint = hostname  # Use hostname as fallback

    # Insert into database
    with db._connection() as conn:
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO exit_node (
                cs_id, permanent_guid, current_public_key, hostname,
                endpoint, listen_port, ipv4_address, ipv6_address,
                private_key, wan_interface
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            cs_id,
            permanent_guid,
            public_key,
            hostname,
            endpoint,
            listen_port,
            ipv4_addr or '10.66.0.100/32',
            ipv6_addr or '',
            interface['private_key'],
            wan_interface
        ))
        exit_node_id = cursor.lastrowid

        # Add to peer order (unified sequence across all peer types)
        cursor.execute("""
            SELECT COALESCE(MAX(display_order), 0) + 1
            FROM cs_peer_order WHERE cs_id = ?
        """, (cs_id,))
        next_order = cursor.fetchone()[0]

        cursor.execute("""
            INSERT INTO cs_peer_order (cs_id, entity_type, entity_id, display_order)
            VALUES (?, 'exit_node', ?, ?)
        """, (cs_id, exit_node_id, next_order))

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
                'exit_node', exit_node_id,
                pair.pattern_name,
                pair.rationale,
                pair.scope.value,
                json.dumps(pair.up_commands if isinstance(pair.up_commands, list) else [pair.up_commands]),
                json.dumps(pair.down_commands if isinstance(pair.down_commands, list) else [pair.down_commands]),
                i
            ))

    rprint(f"  [green]✓[/green] Imported exit node (ID: {exit_node_id})")

    return exit_node_id


def run_import(args) -> int:
    """Import existing configs into database"""
    if RICH_AVAILABLE:
        console.print()
        console.print(Panel.fit(
            "[bold cyan]Phase 2: Import WireGuard Configs[/bold cyan]\n\n"
            "Parse configs and build environment model",
            border_style="cyan"
        ))
        console.print()
    else:
        print("=" * 70)
        print("PHASE 2: IMPORT CONFIGS")
        print("=" * 70)
        print()

    # Check if database exists
    db_path = Path(args.db)
    if db_path.exists():
        rprint(f"[yellow]WARNING:[/yellow] Database already exists: {db_path}")
        if RICH_AVAILABLE:
            if not Confirm.ask("Overwrite?", default=False):
                rprint("[dim]Cancelled.[/dim]")
                return 1
        else:
            response = input("Overwrite? (y/N): ").strip().lower()
            if response not in ('y', 'yes'):
                rprint("Cancelled.")
                return 1
        db_path.unlink()

    # Validate inputs
    if not args.cs:
        rprint("[red]Error:[/red] --cs (coordination server config) required")
        return 1

    cs_path = Path(args.cs)
    if not cs_path.exists():
        rprint(f"[red]Error:[/red] File not found: {cs_path}")
        return 1

    # Create database
    rprint(f"Creating database: [cyan]{db_path}[/cyan]")
    db = WireGuardDBv2(db_path)

    try:
        # Get hostname from args if provided (from entity review)
        cs_hostname = getattr(args, 'cs_name', None)

        # Import coordination server - returns CS peers with advertised networks
        cs_id, cs_peers, vpn_ipv4, vpn_ipv6 = import_coordination_server(cs_path, db, hostname=cs_hostname)

        # Build environment knowledge from CS peers
        # Map public_key -> advertised networks (for SNR matching)
        # Collect all known networks for remote validation
        peer_networks = {}  # pubkey -> advertised LANs
        all_advertised_lans = set()

        for peer in cs_peers:
            pubkey = peer['public_key']
            advertised = peer.get('advertised_networks', [])
            peer_networks[pubkey] = advertised
            all_advertised_lans.update(advertised)

        # Known valid networks for remote AllowedIPs validation
        known_networks = {vpn_ipv4, vpn_ipv6}
        known_networks.update(all_advertised_lans)

        # Track import counts
        snr_count = 0
        remote_count = 0
        exit_count = 0

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
                            entity.path, db, hostname=entity.friendly_name,
                            cs_peers=cs_peers
                        )
                        snr_count += 1
                    except Exception as e:
                        rprint(f"\n  [red]Error:[/red] importing subnet router {entity.path.name}: {e}")

                elif entity.config_type == 'exit_node':
                    try:
                        exit_id = import_exit_node(
                            entity.path, db, hostname=entity.friendly_name
                        )
                        exit_count += 1
                    except Exception as e:
                        rprint(f"\n  [red]Error:[/red] importing exit node {entity.path.name}: {e}")

                elif entity.config_type == 'client':
                    try:
                        remote_id = import_remote(
                            entity.path, db, hostname=entity.friendly_name,
                            known_networks=known_networks
                        )
                        remote_count += 1
                    except Exception as e:
                        rprint(f"\n  [red]Error:[/red] importing remote {entity.path.name}: {e}")

        else:
            # Legacy mode: use args.snr and args.remote if provided
            if args.snr:
                for snr_path in args.snr:
                    snr_file = Path(snr_path)
                    if snr_file.exists():
                        try:
                            router_id = import_subnet_router(snr_file, db, cs_peers=cs_peers)
                            snr_count += 1
                        except Exception as e:
                            rprint(f"\n  [red]Error:[/red] importing subnet router {snr_file.name}: {e}")
                    else:
                        rprint(f"\n  [yellow]Warning:[/yellow] File not found: {snr_path}")

            if args.remote:
                for remote_path in args.remote:
                    remote_file = Path(remote_path)
                    if remote_file.exists():
                        try:
                            remote_id = import_remote(remote_file, db, known_networks=known_networks)
                            remote_count += 1
                        except Exception as e:
                            rprint(f"\n  [red]Error:[/red] importing remote {remote_file.name}: {e}")
                    else:
                        rprint(f"\n  [yellow]Warning:[/yellow] File not found: {remote_path}")

        # Create provisional remotes for CS peers that weren't matched
        # These are peers in the CS config for which we don't have configs
        provisional_count = 0

        with db._connection() as conn:
            cursor = conn.cursor()

            # Get all public keys already in database (SNRs + remotes)
            cursor.execute("SELECT current_public_key FROM subnet_router")
            imported_keys = {row[0] for row in cursor.fetchall()}
            cursor.execute("SELECT current_public_key FROM remote")
            imported_keys.update(row[0] for row in cursor.fetchall())

        # Find CS peers not yet imported (excluding subnet routers by advertised networks)
        for cs_peer in cs_peers:
            pubkey = cs_peer['public_key']
            if pubkey in imported_keys:
                continue  # Already imported

            # Skip if this is a subnet router (has advertised networks)
            if cs_peer.get('advertised_networks'):
                continue

            # This is an unmatched remote - create provisional entry
            try:
                remote_id = create_provisional_remote(db, cs_peer, cs_id)
                provisional_count += 1
            except Exception as e:
                peer_name = cs_peer.get('hostname', pubkey[:20] + '...')
                rprint(f"\n  [red]Error:[/red] creating provisional remote {peer_name}: {e}")

        # Record initial state snapshot
        state_id = record_import(str(db_path), db, len(cs_peers))

        # Run validation checks (Phase 5)
        passed, failed, warnings = run_validation_checks(db, ping_endpoint=True)

        # Success summary
        if RICH_AVAILABLE:
            console.print()
            summary_lines = [
                f"[green]✓[/green] Database created: [cyan]{db_path}[/cyan]",
                f"[green]✓[/green] Coordination server imported",
                f"[green]✓[/green] Found {len(cs_peers)} peers in CS config",
            ]
            if snr_count > 0:
                summary_lines.append(f"[green]✓[/green] Imported {snr_count} subnet router(s)")
            if exit_count > 0:
                summary_lines.append(f"[green]✓[/green] Imported {exit_count} exit node(s)")
            if remote_count > 0:
                summary_lines.append(f"[green]✓[/green] Imported {remote_count} remote client(s)")
            if provisional_count > 0:
                summary_lines.append(f"[yellow]![/yellow] Created {provisional_count} provisional remote(s)")
            summary_lines.append(f"[green]✓[/green] State snapshot recorded (State #{state_id})")

            # Add validation summary
            if failed == 0:
                summary_lines.append(f"[green]✓[/green] Validation: {passed} checks passed")
            else:
                summary_lines.append(f"[yellow]![/yellow] Validation: {passed} passed, {failed} failed")

            console.print(Panel(
                "\n".join(summary_lines),
                title="[bold green]Import Complete[/bold green]",
                border_style="green"
            ))
            console.print()
        else:
            print()
            print("=" * 70)
            print("Import done")
            print("=" * 70)
            print(f"✓ Database created: {db_path}")
            print(f"✓ Coordination server imported")
            print(f"✓ Found {len(cs_peers)} peers in CS config")
            if snr_count > 0:
                print(f"  Imported {snr_count} subnet router(s)")
            if exit_count > 0:
                print(f"  Imported {exit_count} exit node(s)")
            if remote_count > 0:
                print(f"  Imported {remote_count} remote client(s)")
            if provisional_count > 0:
                print(f"! Created {provisional_count} provisional remote(s)")
            print(f"✓ State snapshot recorded (State #{state_id})")
            print(f"✓ Validation: {passed} passed, {failed} failed")
            print()

        # Offer to enter maintenance mode
        if RICH_AVAILABLE:
            enter_tui = Confirm.ask("Enter maintenance mode?", default=True)
        else:
            response = input("Enter maintenance mode? [Y/n]: ").strip().lower()
            enter_tui = response in ('', 'y', 'yes')

        if enter_tui:
            from v1.cli.tui import run_tui
            return run_tui(str(db_path))
        else:
            rprint()
            rprint("[bold]Next steps:[/bold]")
            rprint(f"  1. Review database: [cyan]sqlite3 {db_path}[/cyan]")
            rprint(f"  2. Add missing entities: [cyan]wg-friend add peer/router[/cyan]")
            rprint(f"  3. Generate configs: [cyan]wg-friend generate[/cyan]")
            rprint()

        return 0

    except Exception as e:
        rprint(f"\n[red]Error during import:[/red] {e}")
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
