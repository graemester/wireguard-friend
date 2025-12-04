"""
First-Run Wizard for WireGuard Friend

Interactive setup for new users with no existing configs.
"""

import sys
from pathlib import Path
from typing import List, Dict, Optional

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from v1.schema_semantic import WireGuardDBv2
from v1.keygen import generate_keypair


def print_header():
    """Print welcome header"""
    print("=" * 70)
    print("  WireGuard Friend - First Run Setup")
    print("=" * 70)
    print()
    print("Let's set up your WireGuard VPN network!")
    print()


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


def prompt_int(question: str, default: int, min_val: int = 0, max_val: int = 100) -> int:
    """Prompt for integer"""
    while True:
        response = input(f"{question} [{default}]: ").strip()
        if not response:
            return default
        try:
            value = int(response)
            if min_val <= value <= max_val:
                return value
            print(f"  (must be between {min_val} and {max_val})")
        except ValueError:
            print("  (must be a number)")


def setup_coordination_server() -> Dict:
    """Set up coordination server (VPS hub)"""
    print("\n" + "─" * 70)
    print("COORDINATION SERVER (VPS Hub)")
    print("─" * 70)
    print("This is your central VPN server that all peers connect to.")
    print()

    endpoint = prompt("Public IP or hostname (e.g., vps.example.com)")
    listen_port = prompt_int("Listen port", default=51820, min_val=1, max_val=65535)

    ipv4_network = prompt("VPN IPv4 network", default="10.66.0.0/24")
    ipv6_network = prompt("VPN IPv6 network", default="fd66::/64")

    # Extract IP address from network
    ipv4_address = ipv4_network.split('/')[0][:-1] + '1' + '/' + ipv4_network.split('/')[1]
    ipv6_address = ipv6_network.split('/')[0] + '1' + '/' + ipv6_network.split('/')[1]

    print("\nGenerating keypair...")
    private_key, public_key = generate_keypair()

    return {
        'endpoint': endpoint,
        'listen_port': listen_port,
        'network_ipv4': ipv4_network,
        'network_ipv6': ipv6_network,
        'ipv4_address': ipv4_address,
        'ipv6_address': ipv6_address,
        'private_key': private_key,
        'public_key': public_key,
        'permanent_guid': public_key,  # First key = permanent GUID
    }


def setup_subnet_router(cs_config: Dict, router_num: int) -> Optional[Dict]:
    """Set up a subnet router (LAN gateway)"""
    print("\n" + "─" * 70)
    print(f"SUBNET ROUTER #{router_num} (LAN Gateway)")
    print("─" * 70)
    print("Connects your home/office LAN to the VPN.")
    print()

    hostname = prompt(f"Router hostname (e.g., home-gateway)")
    lan_network = prompt("LAN network to advertise (e.g., 192.168.1.0/24)")
    lan_interface = prompt("LAN interface name", default="eth0")

    # Auto-assign VPN IP
    base_ip = cs_config['network_ipv4'].split('/')[0].rsplit('.', 1)[0]
    router_ip = f"{base_ip}.{20 + router_num}/32"

    ipv6_base = cs_config['network_ipv6'].split('/')[0].rstrip(':')
    router_ipv6 = f"{ipv6_base}::{20 + router_num:x}/128"

    print(f"\nAssigned VPN addresses:")
    print(f"  IPv4: {router_ip}")
    print(f"  IPv6: {router_ipv6}")

    has_static_endpoint = prompt_yes_no("Does this router have a static IP/hostname?", default=False)
    endpoint = None
    if has_static_endpoint:
        endpoint = prompt("Router endpoint (IP:port)")

    print("\nGenerating keypair...")
    private_key, public_key = generate_keypair()

    return {
        'hostname': hostname,
        'ipv4_address': router_ip,
        'ipv6_address': router_ipv6,
        'lan_network': lan_network,
        'lan_interface': lan_interface,
        'endpoint': endpoint,
        'private_key': private_key,
        'public_key': public_key,
        'permanent_guid': public_key,
    }


def setup_remote(cs_config: Dict, remote_num: int) -> Dict:
    """Set up a remote client"""
    print(f"\nRemote #{remote_num}")

    hostname = prompt(f"  Name (e.g., alice-phone, bob-laptop)")

    device_type = prompt("  Device type [mobile/laptop/server]", default="mobile")

    # Auto-assign VPN IP
    base_ip = cs_config['network_ipv4'].split('/')[0].rsplit('.', 1)[0]
    remote_ip = f"{base_ip}.{30 + remote_num}/32"

    ipv6_base = cs_config['network_ipv6'].split('/')[0].rstrip(':')
    remote_ipv6 = f"{ipv6_base}::{30 + remote_num:x}/128"

    has_static_endpoint = device_type == 'server'
    endpoint = None
    if has_static_endpoint:
        if prompt_yes_no("  Has static endpoint?", default=False):
            endpoint = prompt("  Endpoint (IP:port)")

    print("\n  Generating keypair...")
    private_key, public_key = generate_keypair()

    return {
        'hostname': hostname,
        'device_type': device_type,
        'ipv4_address': remote_ip,
        'ipv6_address': remote_ipv6,
        'endpoint': endpoint,
        'private_key': private_key,
        'public_key': public_key,
        'permanent_guid': public_key,
        'access_level': 'full_access',  # Default
    }


def setup_exit_node(cs_config: Dict, exit_num: int) -> Dict:
    """Set up an exit node (internet egress server)"""
    print("\n" + "-" * 70)
    print(f"EXIT NODE #{exit_num + 1} (Internet Egress Server)")
    print("-" * 70)
    print("Exit nodes route internet traffic for remotes that want to")
    print("hide their IP or appear in a different geographic location.")
    print()

    hostname = prompt(f"Hostname (e.g., 'exit-us-west', 'exit-eu-central')")
    endpoint = prompt("Public IP/domain (e.g., 'us-west.example.com')")

    listen_port = prompt_int("Listen port", default=51820, min_val=1, max_val=65535)
    wan_interface = prompt("WAN interface for NAT", default="eth0")

    # Auto-assign VPN IP in 100-119 range
    base_ip = cs_config['network_ipv4'].split('/')[0].rsplit('.', 1)[0]
    exit_ip = f"{base_ip}.{100 + exit_num}/32"

    ipv6_base = cs_config['network_ipv6'].split('/')[0].rstrip(':')
    exit_ipv6 = f"{ipv6_base}::{100 + exit_num:x}/128"

    print(f"\nAssigned VPN addresses:")
    print(f"  IPv4: {exit_ip}")
    print(f"  IPv6: {exit_ipv6}")

    # SSH deployment info
    ssh_host = None
    ssh_user = None
    ssh_port = 22
    if prompt_yes_no("Configure SSH for deployment?", default=False):
        ssh_host = prompt("SSH host")
        ssh_user = prompt("SSH user", default="root")
        ssh_port = prompt_int("SSH port", default=22, min_val=1, max_val=65535)

    print("\nGenerating keypair...")
    private_key, public_key = generate_keypair()

    return {
        'hostname': hostname,
        'endpoint': endpoint,
        'listen_port': listen_port,
        'wan_interface': wan_interface,
        'ipv4_address': exit_ip,
        'ipv6_address': exit_ipv6,
        'ssh_host': ssh_host,
        'ssh_user': ssh_user,
        'ssh_port': ssh_port,
        'private_key': private_key,
        'public_key': public_key,
        'permanent_guid': public_key,
    }


def run_init_wizard(db_path: str) -> int:
    """Run the interactive first-run wizard"""
    print_header()

    # Check if database already exists
    db_file = Path(db_path)
    if db_file.exists():
        print(f"WARNING:  Database already exists: {db_path}")
        if not prompt_yes_no("Overwrite?", default=False):
            print("Cancelled.")
            return 1
        db_file.unlink()

    # 1. Coordination Server
    cs_config = setup_coordination_server()

    # 2. Subnet Routers
    routers = []
    if prompt_yes_no("\nDo you have a home/office network to connect?", default=True):
        num_routers = prompt_int("How many subnet routers?", default=1, max_val=10)
        for i in range(num_routers):
            router = setup_subnet_router(cs_config, i)
            routers.append(router)

    # 3. Exit Nodes (optional)
    exit_nodes = []
    print("\n" + "-" * 70)
    print("EXIT NODES (Optional)")
    print("-" * 70)
    print("Exit nodes route internet traffic through a dedicated server")
    print("for privacy or geo-location purposes.")
    if prompt_yes_no("\nDo you want to add exit nodes?", default=False):
        num_exits = prompt_int("How many exit nodes?", default=1, max_val=20)
        for i in range(num_exits):
            exit_node = setup_exit_node(cs_config, i)
            exit_nodes.append(exit_node)

    # 4. Remote Clients
    print("\n" + "-" * 70)
    print("REMOTE CLIENTS (Phones, Laptops, etc.)")
    print("-" * 70)
    num_remotes = prompt_int("How many initial clients?", default=3, max_val=50)

    remotes = []
    for i in range(num_remotes):
        remote = setup_remote(cs_config, i)
        remotes.append(remote)

    # Summary
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"Coordination Server: {cs_config['endpoint']}")
    print(f"  VPN Network: {cs_config['network_ipv4']}, {cs_config['network_ipv6']}")
    print(f"  Listen Port: {cs_config['listen_port']}")
    print(f"\nSubnet Routers: {len(routers)}")
    for router in routers:
        print(f"  - {router['hostname']}: {router['lan_network']}")
    if exit_nodes:
        print(f"\nExit Nodes: {len(exit_nodes)}")
        for exit_node in exit_nodes:
            print(f"  - {exit_node['hostname']}: {exit_node['endpoint']}")
    print(f"\nRemote Clients: {len(remotes)}")
    for remote in remotes:
        print(f"  - {remote['hostname']} ({remote['device_type']})")
    print()

    if not prompt_yes_no("Proceed with setup?", default=True):
        print("Cancelled.")
        return 1

    # Create database and store
    print("\nCreating database...")
    db = WireGuardDBv2(db_file)

    with db._connection() as conn:
        cursor = conn.cursor()

        # Insert coordination server
        cursor.execute("""
            INSERT INTO coordination_server (
                permanent_guid, current_public_key, hostname,
                endpoint, listen_port, network_ipv4, network_ipv6,
                ipv4_address, ipv6_address, private_key
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            cs_config['permanent_guid'],
            cs_config['public_key'],
            'coordination-server',
            cs_config['endpoint'],
            cs_config['listen_port'],
            cs_config['network_ipv4'],
            cs_config['network_ipv6'],
            cs_config['ipv4_address'],
            cs_config['ipv6_address'],
            cs_config['private_key']
        ))
        cs_id = cursor.lastrowid

        # Insert subnet routers
        for router in routers:
            cursor.execute("""
                INSERT INTO subnet_router (
                    cs_id, permanent_guid, current_public_key, hostname,
                    ipv4_address, ipv6_address, endpoint,
                    private_key, lan_interface
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                cs_id,
                router['permanent_guid'],
                router['public_key'],
                router['hostname'],
                router['ipv4_address'],
                router['ipv6_address'],
                router['endpoint'],
                router['private_key'],
                router['lan_interface']
            ))
            router_id = cursor.lastrowid

            # Add advertised network
            cursor.execute("""
                INSERT INTO advertised_network (subnet_router_id, network_cidr)
                VALUES (?, ?)
            """, (router_id, router['lan_network']))

        # Insert exit nodes
        for exit_node in exit_nodes:
            cursor.execute("""
                INSERT INTO exit_node (
                    cs_id, permanent_guid, current_public_key, hostname,
                    endpoint, listen_port, ipv4_address, ipv6_address,
                    private_key, wan_interface, ssh_host, ssh_user, ssh_port
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                cs_id,
                exit_node['permanent_guid'],
                exit_node['public_key'],
                exit_node['hostname'],
                exit_node['endpoint'],
                exit_node['listen_port'],
                exit_node['ipv4_address'],
                exit_node['ipv6_address'],
                exit_node['private_key'],
                exit_node['wan_interface'],
                exit_node.get('ssh_host'),
                exit_node.get('ssh_user'),
                exit_node.get('ssh_port', 22)
            ))

        # Insert remotes
        for remote in remotes:
            cursor.execute("""
                INSERT INTO remote (
                    cs_id, permanent_guid, current_public_key, hostname,
                    ipv4_address, ipv6_address, private_key, access_level
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                cs_id,
                remote['permanent_guid'],
                remote['public_key'],
                remote['hostname'],
                remote['ipv4_address'],
                remote['ipv6_address'],
                remote['private_key'],
                remote['access_level']
            ))

    total_entities = 1 + len(routers) + len(exit_nodes) + len(remotes)
    print(f"  Database created: {db_path}")
    print(f"  Stored {total_entities} entities")
    print()
    print("Next steps:")
    print(f"  1. Generate configs:  wg-friend generate --qr")
    print(f"  2. View configs:      ls generated/")
    print(f"  3. Deploy to servers: wg-friend deploy")
    print()

    return 0


if __name__ == '__main__':
    sys.exit(run_init_wizard('wireguard.db'))
