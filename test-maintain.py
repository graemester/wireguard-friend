#!/usr/bin/env python3
"""Test maintenance mode by listing all entities"""

from pathlib import Path
from src.database import WireGuardDB
from rich.console import Console
from rich.table import Table
from rich import box

console = Console()

db = WireGuardDB(Path("wg-friend.db"))

# Coordination Server
cs = db.get_coordination_server()
if cs:
    console.print("\n[bold cyan]Coordination Server:[/bold cyan]")
    console.print(f"  Endpoint: {cs['endpoint']}")
    console.print(f"  Network: {cs['network_ipv4']}, {cs['network_ipv6']}")
    console.print(f"  SSH: {cs['ssh_user']}@{cs['ssh_host']}:{cs['ssh_port']}")

# Subnet Routers
if cs:
    sn_list = db.get_subnet_routers(cs['id'])
    if sn_list:
        console.print(f"\n[bold cyan]Subnet Routers ({len(sn_list)}):[/bold cyan]")
        table = Table(show_header=True, box=box.SIMPLE)
        table.add_column("Name", style="cyan")
        table.add_column("IPv4", style="yellow")
        table.add_column("IPv6", style="yellow")
        table.add_column("LANs", style="green")

        for sn in sn_list:
            lans = db.get_sn_lan_networks(sn['id'])
            lan_str = ", ".join(lans) if lans else "None"
            table.add_row(sn['name'], sn['ipv4_address'], sn['ipv6_address'], lan_str)

        console.print(table)

# Peers
if cs:
    peers = db.get_peers(cs['id'])
    if peers:
        console.print(f"\n[bold cyan]Peers ({len(peers)}):[/bold cyan]")
        table = Table(show_header=True, box=box.SIMPLE)
        table.add_column("Name", style="cyan")
        table.add_column("IPv4", style="yellow")
        table.add_column("IPv6", style="yellow")
        table.add_column("Access", style="green")
        table.add_column("Client Config", style="magenta")

        for peer in peers:
            has_config = "Yes" if peer['raw_interface_block'] else "No"
            table.add_row(
                peer['name'],
                peer['ipv4_address'],
                peer['ipv6_address'],
                peer['access_level'],
                has_config
            )

        console.print(table)

# Test reconstruction
console.print("\n[bold cyan]Testing Config Reconstruction:[/bold cyan]")
config = db.reconstruct_cs_config()
peer_count = config.count('[Peer]')
console.print(f"  Coordination server config has {peer_count} peers")
console.print(f"  Config length: {len(config)} bytes")
