#!/usr/bin/env python3
"""
Test script for restricted IP access feature
"""

from pathlib import Path
from src.database import WireGuardDB
from src.keygen import generate_keypair
from rich.console import Console

console = Console()

db = WireGuardDB(Path("wg-friend.db"))

# Get coordination server
cs = db.get_coordination_server()
if not cs:
    console.print("[red]No coordination server found. Run import first.[/red]")
    exit(1)

console.print(f"[cyan]Working with CS: {cs['endpoint']}[/cyan]")

# Get subnet routers
subnet_routers = db.get_subnet_routers(cs['id'])
if not subnet_routers:
    console.print("[red]No subnet routers found. Need at least one for restricted IP.[/red]")
    exit(1)

sn = subnet_routers[0]
console.print(f"[cyan]Using subnet router: {sn['name']}[/cyan]")

# Find next available IP
existing_peers = db.get_peers(cs['id'])
used_ipv4 = set()
used_ipv6 = set()

# CS IPs
used_ipv4.add(cs['ipv4_address'])
used_ipv6.add(cs['ipv6_address'])

# Peer IPs
for p in existing_peers:
    if p['ipv4_address'] and p['ipv4_address'] != '0.0.0.0':
        used_ipv4.add(p['ipv4_address'])
    if p['ipv6_address'] and p['ipv6_address'] != '::':
        used_ipv6.add(p['ipv6_address'])

# SN IPs
for sn_item in subnet_routers:
    used_ipv4.add(sn_item['ipv4_address'])
    used_ipv6.add(sn_item['ipv6_address'])

# Find next available
ipv4_base = ".".join(cs['ipv4_address'].split('.')[:-1])
ipv6_base = cs['ipv6_address'].rsplit(':', 1)[0]

next_ipv4 = None
for i in range(2, 255):
    candidate = f"{ipv4_base}.{i}"
    if candidate not in used_ipv4:
        next_ipv4 = candidate
        break

next_ipv6 = None
for i in range(2, 65535):
    candidate = f"{ipv6_base}:{i:x}"
    if candidate not in used_ipv6:
        next_ipv6 = candidate
        break

console.print(f"[green]Next available: {next_ipv4}, {next_ipv6}[/green]")

# Create restricted peer
name = "test-restricted"
target_ip = "192.168.10.50"

# Generate keypair
private_key, public_key = generate_keypair()

console.print(f"\n[cyan]Creating restricted IP peer '{name}'...[/cyan]")
console.print(f"  Target IP: {target_ip}")
console.print(f"  Subnet Router: {sn['name']}")

# Build peer entry for CS
peer_block = f"[Peer]\n"
peer_block += f"# {name}\n"
peer_block += f"PublicKey = {public_key}\n"
peer_block += f"AllowedIPs = {next_ipv4}/32, {next_ipv6}/128\n"

# Build client config - only allow target IP
client_config = f"[Interface]\n"
client_config += f"PrivateKey = {private_key}\n"
client_config += f"Address = {next_ipv4}/24, {next_ipv6}/64\n"
client_config += f"DNS = {cs['ipv4_address']}\n"
if cs['mtu']:
    client_config += f"MTU = {cs['mtu']}\n"
client_config += f"\n[Peer]\n"
client_config += f"PublicKey = {cs['public_key']}\n"
client_config += f"Endpoint = {cs['endpoint']}\n"
client_config += f"AllowedIPs = {cs['network_ipv4']}, {cs['network_ipv6']}, {target_ip}/32\n"
client_config += f"PersistentKeepalive = 25\n"

# Save peer to database
peer_id = db.save_peer(
    name=name,
    cs_id=cs['id'],
    public_key=public_key,
    ipv4_address=next_ipv4,
    ipv6_address=next_ipv6,
    access_level='restricted_ip',
    raw_peer_block=peer_block,
    private_key=private_key,
    raw_interface_block=client_config,
    persistent_keepalive=25
)

# Add to peer order
peer_order = db.get_peer_order(cs['id'])
next_position = len(peer_order) + 1
db.save_peer_order(cs['id'], public_key, next_position, is_subnet_router=False)

console.print(f"[green]✓ Peer created with ID {peer_id}[/green]")

# Save IP restriction
db.save_peer_ip_restriction(
    peer_id=peer_id,
    sn_id=sn['id'],
    target_ip=target_ip,
    description=f"Test restricted access to {target_ip}"
)

console.print(f"[green]✓ IP restriction saved[/green]")

# Generate and save firewall rules
postup_rules = [
    f"iptables -I FORWARD -s {next_ipv4}/32 -d {target_ip}/32 -j ACCEPT",
    f"iptables -I FORWARD -s {next_ipv4}/32 -j DROP"
]

postdown_rules = [
    f"iptables -D FORWARD -s {next_ipv4}/32 -d {target_ip}/32 -j ACCEPT",
    f"iptables -D FORWARD -s {next_ipv4}/32 -j DROP"
]

db.save_sn_peer_firewall_rules(
    sn_id=sn['id'],
    peer_id=peer_id,
    postup_rules=postup_rules,
    postdown_rules=postdown_rules
)

console.print(f"[green]✓ Firewall rules saved[/green]")

# Reconstruct and display subnet router config
console.print(f"\n[bold cyan]Subnet Router Config ({sn['name']}):[/bold cyan]")
sn_config = db.reconstruct_sn_config(sn['id'])

# Count peer-specific rules
peer_rule_count = sn_config.count("# Peer-specific rule for:")

console.print("[dim]" + "="*60 + "[/dim]")
console.print(sn_config)
console.print("[dim]" + "="*60 + "[/dim]")

console.print(f"\n[bold]Summary:[/bold]")
console.print(f"  • Peer: {name}")
console.print(f"  • Access: restricted_ip")
console.print(f"  • Target IP: {target_ip}")
console.print(f"  • Subnet Router: {sn['name']}")
console.print(f"  • Firewall rules: {len(postup_rules)} PostUp, {len(postdown_rules)} PostDown")
console.print(f"  • Peer-specific rule sections: {peer_rule_count}")

# Show client config
console.print(f"\n[bold cyan]Client Config:[/bold cyan]")
console.print("[dim]" + "="*60 + "[/dim]")
console.print(client_config)
console.print("[dim]" + "="*60 + "[/dim]")

# Save configs to output
output_dir = Path("output")
output_dir.mkdir(exist_ok=True)

client_file = output_dir / f"{name}.conf"
with open(client_file, 'w') as f:
    f.write(client_config)
client_file.chmod(0o600)

sn_file = output_dir / f"{sn['name']}-updated.conf"
with open(sn_file, 'w') as f:
    f.write(sn_config)
sn_file.chmod(0o600)

console.print(f"\n[green]✓ Configs saved to output/[/green]")
console.print(f"  • Client: {client_file}")
console.print(f"  • Subnet Router: {sn_file}")

console.print(f"\n[bold]Test complete![/bold]")
console.print(f"[yellow]To delete this test peer, use: ./wg-friend-maintain.py and select option [3] Manage Peers[/yellow]")
