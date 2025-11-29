# Restricted IP Access

Granular network access control for WireGuard peers.

---

## Current Status

**v1.0.0:** Access levels available:
- `full_access` - VPN network + all advertised LANs
- `vpn_only` - VPN network only (peer-to-peer)
- `lan_only` - VPN network + specific LANs
- `custom` - User-defined allowed IPs

**Future:** Port-based and per-IP restrictions planned for later releases.

---

## Access Levels

### full_access

Peer can access:
- VPN network (e.g., 10.20.0.0/24)
- All advertised LAN networks (e.g., 192.168.1.0/24)

Use case: Administrators, trusted devices

### vpn_only

Peer can access:
- VPN network only
- Can reach other peers via coordination server
- Cannot access advertised LANs

Use case: Contractors, temporary access

### lan_only

Peer can access:
- VPN network
- Specific LAN networks (selected during peer creation)

Use case: Remote workers accessing specific office LANs

### custom

Peer gets user-defined allowed IPs.

Specify during peer creation:
```bash
wg-friend add peer
# Select "custom" access level
# Enter allowed IPs: 10.20.0.0/24, 192.168.1.50/32
```

Use case: Special scenarios requiring precise control

---

## How Access Levels Work

### Client Side (AllowedIPs)

Client config includes routes based on access level:

**full_access:**
```ini
[Peer]
AllowedIPs = 10.20.0.0/24, 192.168.1.0/24, 192.168.2.0/24
```

**vpn_only:**
```ini
[Peer]
AllowedIPs = 10.20.0.0/24
```

**lan_only** (selected LANs):
```ini
[Peer]
AllowedIPs = 10.20.0.0/24, 192.168.1.0/24
```

### Server Side

Subnet routers handle forwarding based on their firewall rules (PostUp/PostDown).

---

## Setting Access Level

During peer creation:
```bash
wg-friend add peer

# Prompts:
Hostname: alice-laptop
Device type: laptop
Access level: (full_access/vpn_only/lan_only/custom)
> full_access
```

Stored in database:
```sql
SELECT hostname, access_level FROM remote;
```

---

## Changing Access Level

Not currently supported via CLI.

Manual database update (use with caution):
```sql
sqlite3 wireguard.db
UPDATE remote SET access_level = 'vpn_only' WHERE hostname = 'alice-laptop';
.quit
```

Then regenerate configs:
```bash
wg-friend generate
wg-friend deploy
```

---

## Future: Port-Based Restrictions

Planned for future release:

Allow peer to access specific IP:port combinations:
- 192.168.1.50:22 (SSH only)
- 192.168.1.51:443 (HTTPS only)
- 192.168.1.52:3389 (RDP only)

Implementation would use iptables rules on subnet router:
```bash
# Allow only SSH to specific host
iptables -A FORWARD -s <peer-vpn-ip> -d 192.168.1.50 -p tcp --dport 22 -j ACCEPT
iptables -A FORWARD -s <peer-vpn-ip> -j DROP
```

---

## Future: Per-Peer Firewall Rules

Planned for future release:

Database schema addition:
```sql
CREATE TABLE peer_firewall_rules (
    id INTEGER PRIMARY KEY,
    peer_id INTEGER NOT NULL,
    rule_type TEXT NOT NULL,  -- 'allow' or 'deny'
    protocol TEXT,             -- 'tcp', 'udp', 'icmp', or NULL for all
    destination_ip TEXT,
    destination_port INTEGER,
    FOREIGN KEY (peer_id) REFERENCES remote(id) ON DELETE CASCADE
);
```

This would generate subnet router PostUp/PostDown rules specific to each peer.

---

## Security Considerations

Access levels are enforced by:
1. **Client routing** (AllowedIPs tells client what to route through VPN)
2. **Server forwarding** (subnet router decides what to forward)

Client can modify their config to try routing other traffic through VPN, but subnet router will not forward it unless explicitly configured.

Additional security:
- Use `vpn_only` for untrusted devices
- Use `lan_only` to limit blast radius
- Monitor with `wg-friend status --live`
- Rotate keys regularly

---

## Database Schema

Current implementation:

**remote table:**
```sql
CREATE TABLE remote (
    id INTEGER PRIMARY KEY,
    hostname TEXT NOT NULL,
    permanent_guid TEXT NOT NULL UNIQUE,
    current_public_key TEXT NOT NULL,
    private_key TEXT NOT NULL,
    ipv4_address TEXT,
    ipv6_address TEXT,
    access_level TEXT NOT NULL,  -- 'full_access', 'vpn_only', 'lan_only', 'custom'
    custom_allowed_ips TEXT,     -- JSON array for 'custom' access_level
    device_type TEXT,
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

---

## Examples

### Create vpn_only peer:
```bash
wg-friend add peer
# hostname: contractor-laptop
# type: laptop
# access_level: vpn_only
```

### Create custom access peer:
```bash
wg-friend add peer
# hostname: limited-device
# type: desktop
# access_level: custom
# allowed_ips: 10.20.0.0/24, 192.168.1.100/32
```

### View peer access levels:
```bash
sqlite3 wireguard.db "SELECT hostname, access_level FROM remote;"
```

---

See [COMMAND_REFERENCE.md](../COMMAND_REFERENCE.md) for peer management commands.
