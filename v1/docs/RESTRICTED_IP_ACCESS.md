# Restricted IP Access Feature

## Overview

WireGuard Friend now supports **restricted IP access**, allowing you to create peers that can only access ONE specific IP address on your LAN. This is enforced through firewall rules on the subnet router.

## How It Works

### Client Side (WireGuard AllowedIPs)
The client config includes:
- VPN network (for connectivity to coordination server)
- The target IP only (e.g., `192.168.10.50/32`)

This tells WireGuard to **route** traffic to that IP through the VPN.

### Server Side (Subnet Router Firewall)
The subnet router enforces the restriction with iptables rules:
```bash
# Allow ONLY traffic to the target IP
iptables -I FORWARD -s <peer-vpn-ip>/32 -d <target-ip>/32 -j ACCEPT

# Drop ALL other traffic from this peer
iptables -I FORWARD -s <peer-vpn-ip>/32 -j DROP
```

## Architecture

### Database Schema

**peer table** - Updated constraint:
```sql
CHECK (access_level IN ('full_access', 'vpn_only', 'lan_only', 'custom', 'restricted_ip'))
```

**peer_ip_restrictions** - New table:
```sql
CREATE TABLE peer_ip_restrictions (
    id INTEGER PRIMARY KEY,
    peer_id INTEGER NOT NULL,
    sn_id INTEGER NOT NULL,
    target_ip TEXT NOT NULL,
    description TEXT,
    FOREIGN KEY (peer_id) REFERENCES peer(id) ON DELETE CASCADE,
    FOREIGN KEY (sn_id) REFERENCES subnet_router(id) ON DELETE CASCADE
)
```

**sn_peer_firewall_rules** - New table:
```sql
CREATE TABLE sn_peer_firewall_rules (
    id INTEGER PRIMARY KEY,
    sn_id INTEGER NOT NULL,
    peer_id INTEGER NOT NULL,
    rule_type TEXT NOT NULL,  -- 'postup' or 'postdown'
    rule_text TEXT NOT NULL,
    rule_order INTEGER NOT NULL,
    FOREIGN KEY (sn_id) REFERENCES subnet_router(id) ON DELETE CASCADE,
    FOREIGN KEY (peer_id) REFERENCES peer(id) ON DELETE CASCADE
)
```

### Separation from Sacred Blocks

**Key Design Principle:** Peer-specific firewall rules are stored separately from the original "sacred" PostUp/PostDown blocks.

When reconstructing subnet router configs:
1. **Original Interface settings** - Preserved from raw_interface_block
2. **Original PostUp rules** - From sn_postup_rules table (sacred)
3. **Peer-specific PostUp rules** - From sn_peer_firewall_rules (labeled with comments)
4. **Original PostDown rules** - From sn_postdown_rules table (sacred)
5. **Peer-specific PostDown rules** - From sn_peer_firewall_rules (labeled with comments)
6. **Peer block** - Connection to coordination server

Example output:
```ini
[Interface]
Address = 10.66.0.20/24
PrivateKey = ...
ListenPort = 51820

# Original sacred PostUp rules
PostUp = sysctl -w net.ipv4.ip_forward=1
PostUp = iptables -A FORWARD -i wg0 -o enp1s0 -j ACCEPT
...

# Peer-specific rule for: test-restricted
PostUp = iptables -I FORWARD -s 10.66.0.2/32 -d 192.168.10.50/32 -j ACCEPT
PostUp = iptables -I FORWARD -s 10.66.0.2/32 -j DROP

# Original sacred PostDown rules
PostDown = iptables -D FORWARD -i wg0 -o enp1s0 -j ACCEPT
...

# Peer-specific rule for: test-restricted
PostDown = iptables -D FORWARD -s 10.66.0.2/32 -d 192.168.10.50/32 -j ACCEPT
PostDown = iptables -D FORWARD -s 10.66.0.2/32 -j DROP

[Peer]
PublicKey = ...
AllowedIPs = ...
```

## Usage

### Creating a Restricted IP Peer

#### Interactive Mode
```bash
./wg-friend-maintain.py
# Select [4] Create New Peer
# Enter peer name
# Select [4] Restricted IP access level
# Select subnet router
# Enter target IP (e.g., 192.168.10.50)
```

The script will:
1. Create the peer in the database
2. Save IP restriction details
3. Generate firewall rules (PostUp/PostDown)
4. Save firewall rules to database
5. Show next steps (deploy CS config and subnet router config)

#### Programmatic
```python
from pathlib import Path
from src.database import WireGuardDB
from src.keygen import generate_keypair

db = WireGuardDB(Path("wg-friend.db"))
cs = db.get_coordination_server()
sn = db.get_subnet_routers(cs['id'])[0]

# Create peer
private_key, public_key = generate_keypair()
peer_id = db.save_peer(
    name="restricted-client",
    cs_id=cs['id'],
    public_key=public_key,
    private_key=private_key,
    ipv4_address="10.66.0.100",
    ipv6_address="fd66:6666::100",
    access_level='restricted_ip',
    raw_peer_block=peer_block,
    raw_interface_block=client_config,
    persistent_keepalive=25
)

# Save restriction
db.save_peer_ip_restriction(
    peer_id=peer_id,
    sn_id=sn['id'],
    target_ip="192.168.10.50"
)

# Generate and save firewall rules
postup_rules = [
    f"iptables -I FORWARD -s 10.66.0.100/32 -d 192.168.10.50/32 -j ACCEPT",
    f"iptables -I FORWARD -s 10.66.0.100/32 -j DROP"
]
postdown_rules = [
    f"iptables -D FORWARD -s 10.66.0.100/32 -d 192.168.10.50/32 -j ACCEPT",
    f"iptables -D FORWARD -s 10.66.0.100/32 -j DROP"
]

db.save_sn_peer_firewall_rules(
    sn_id=sn['id'],
    peer_id=peer_id,
    postup_rules=postup_rules,
    postdown_rules=postdown_rules
)

# Reconstruct subnet router config (includes new rules)
sn_config = db.reconstruct_sn_config(sn['id'])
```

### Deleting a Restricted IP Peer

```bash
./wg-friend-maintain.py
# Select [3] Manage Peers
# Select the restricted peer
# Select [5] Delete Peer
```

The script will:
1. Detect IP restriction and affected subnet router
2. Delete IP restriction from database (CASCADE)
3. Delete firewall rules from database (CASCADE)
4. Delete peer from database
5. Show next steps (deploy CS config and affected subnet router config)

**The firewall rules are automatically removed when the peer is deleted** thanks to `ON DELETE CASCADE` foreign keys.

## Migration

Existing databases need migration to support `restricted_ip`:

```bash
python3 migrate-restricted-ip.py
```

This creates a new peer table with the updated CHECK constraint and copies all data.

## Testing

Run the test script to create a restricted IP peer:

```bash
python3 test-restricted-ip.py
```

This will:
1. Create a peer with restricted_ip access level
2. Save IP restriction for 192.168.10.50
3. Generate and save firewall rules
4. Export subnet router config showing peer-specific rules with labels
5. Save configs to output/ directory

## Security Considerations

### Firewall Rule Order
- Rules use `-I FORWARD` (INSERT) to place them at the **top** of the chain
- ACCEPT rule comes **before** DROP rule
- This ensures the specific IP is allowed first, then everything else is blocked

### Client Config
- Client's AllowedIPs includes VPN network + target IP only
- Client **cannot route** to other IPs even if firewall allows it
- Defense in depth: both routing and firewall enforcement

### Deletion Safety
- Foreign key constraints ensure rules are deleted with peer
- No orphaned rules left in database
- Subnet router config must be re-deployed to update iptables

## Comparison with Other Access Levels

| Access Level | VPN Access | LAN Access | Firewall Rules |
|--------------|------------|------------|----------------|
| `full_access` | Yes | All LANs | None (default ACCEPT) |
| `vpn_only` | Yes | None | None (no routing) |
| `lan_only` | Yes | All LANs | None (default ACCEPT) |
| `restricted_ip` | Yes | **One IP only** | **Enforced by iptables** |

## Files Modified

### Database
- `src/database.py` - Added tables, methods, updated reconstruction

### Maintenance Script
- `wg-friend-maintain.py` - Updated peer creation and deletion

### New Files
- `migrate-restricted-ip.py` - Database migration script
- `test-restricted-ip.py` - Test script for restricted IP feature
- `RESTRICTED_IP_ACCESS.md` - This documentation

## Future Enhancements

Potential improvements:
- Support for multiple restricted IPs per peer
- Port-based restrictions (e.g., only SSH, only HTTPS)
- Time-based access restrictions
- Logging of blocked connection attempts
- Web UI for managing restrictions
