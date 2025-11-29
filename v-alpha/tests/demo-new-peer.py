#!/usr/bin/env python3
"""
Demonstrate creating a new peer programmatically
"""

from pathlib import Path
from src.database import WireGuardDB
from src.keygen import generate_keypair
from rich.console import Console

console = Console()

db = WireGuardDB(Path("wg-friend.db"))

# Get coordination server
cs = db.get_coordination_server()
console.print(f"[cyan]Working with CS: {cs['endpoint']}[/cyan]")

# Find next available IP
existing_peers = db.get_peers(cs['id'])
existing_sn = db.get_subnet_routers(cs['id'])

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
for sn in existing_sn:
    used_ipv4.add(sn['ipv4_address'])
    used_ipv6.add(sn['ipv6_address'])

console.print(f"\n[yellow]Currently used IPs: {len(used_ipv4)} IPv4, {len(used_ipv6)} IPv6[/yellow]")

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

# Create new peer "demo-device"
name = "demo-device"
private_key, public_key = generate_keypair()

console.print(f"\n[cyan]Creating peer '{name}'...[/cyan]")
console.print(f"  Public Key: {public_key[:20]}...")

# Build peer entry for CS
peer_block = f"[Peer]\n"
peer_block += f"# {name}\n"
peer_block += f"PublicKey = {public_key}\n"
peer_block += f"AllowedIPs = {next_ipv4}/32, {next_ipv6}/128\n"

# Build client config
client_config = f"[Interface]\n"
client_config += f"PrivateKey = {private_key}\n"
client_config += f"Address = {next_ipv4}/24, {next_ipv6}/64\n"
client_config += f"DNS = {cs['ipv4_address']}\n"
if cs['mtu']:
    client_config += f"MTU = {cs['mtu']}\n"
client_config += f"\n[Peer]\n"
client_config += f"PublicKey = {cs['public_key']}\n"
client_config += f"Endpoint = {cs['endpoint']}\n"

# Full access - get all networks
all_networks = [cs['network_ipv4'], cs['network_ipv6']]
for sn in existing_sn:
    lans = db.get_sn_lan_networks(sn['id'])
    all_networks.extend(lans)

allowed_ips = ", ".join(all_networks)
client_config += f"AllowedIPs = {allowed_ips}\n"
client_config += f"PersistentKeepalive = 25\n"

# Save to database
peer_id = db.save_peer(
    name=name,
    cs_id=cs['id'],
    public_key=public_key,
    ipv4_address=next_ipv4,
    ipv6_address=next_ipv6,
    access_level='full_access',
    raw_peer_block=peer_block,
    private_key=private_key,
    raw_interface_block=client_config,
    persistent_keepalive=25
)

# Add to peer order
peer_order = db.get_peer_order(cs['id'])
next_position = len(peer_order) + 1
db.save_peer_order(cs['id'], public_key, next_position, is_subnet_router=False)

console.print(f"[green]✓ Peer '{name}' created with ID {peer_id}[/green]")

# Save configs
output_dir = Path("output")
output_dir.mkdir(exist_ok=True)

# Save client config
client_file = output_dir / f"{name}.conf"
with open(client_file, 'w') as f:
    f.write(client_config)
client_file.chmod(0o600)
console.print(f"[green]✓ Client config saved to {client_file}[/green]")

# Regenerate CS config
cs_config = db.reconstruct_cs_config()
cs_file = output_dir / "coordination-updated.conf"
with open(cs_file, 'w') as f:
    f.write(cs_config)
cs_file.chmod(0o600)

peer_count = cs_config.count('[Peer]')
console.print(f"[green]✓ Updated CS config saved to {cs_file} ({peer_count} peers)[/green]")

console.print("\n[bold]Summary:[/bold]")
console.print(f"  • Created peer: {name}")
console.print(f"  • Assigned IPs: {next_ipv4}, {next_ipv6}")
console.print(f"  • Access level: full_access")
console.print(f"  • Total peers in CS: {peer_count}")
console.print(f"\n[bold]Next steps:[/bold]")
console.print(f"  1. Deploy {cs_file} to coordination server")
console.print(f"  2. Restart WireGuard on coordination server")
console.print(f"  3. Import {client_file} on client device")
