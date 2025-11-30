# Exit Node Design for WireGuard Friend

## Overview

This document describes a proposed extension to WireGuard Friend that allows remotes to optionally route their internet traffic through a dedicated exit node. This is distinct from the coordination server and enables use cases like:

- Exiting internet traffic in a specific geography
- Offloading data ingress/egress from the coordination server
- Separating VPN coordination from internet egress concerns

## Current Behavior

Today, WireGuard Friend operates in **split tunnel** mode:

- VPN traffic (to the coordination server network, subnet routers, and other peers) routes through WireGuard
- Internet traffic exits directly from each device's local network
- The coordination server routes peer-to-peer traffic but does not act as an internet gateway

```
[Remote] ──WG──> [CS] ──WG──> [Other Peers / Subnet Routers]
    │
    └──────────> [Internet] (direct, local exit)
```

## Proposed Design

### Core Principle: Remote-Driven

The exit node feature is **remote-driven**, meaning:

1. Each remote individually chooses whether to use an exit node
2. The default answer is **No** (preserving split tunnel behavior)
3. Exit nodes only matter for remotes that opt in
4. No exit nodes are required unless at least one remote wants one

### Traffic Flow with Exit Node

When a remote opts to use an exit node:

```
[Remote] ──WG──> [Exit Node] ──> [Internet]
    │
    └──WG──> [CS] ──WG──> [Other Peers / Subnet Routers]
```

The remote maintains two WireGuard relationships:
- **CS connection**: For VPN traffic to the coordination server network
- **Exit connection**: For internet-bound traffic (0.0.0.0/0, ::/0)

### No Automatic Fallback to CS

If a remote is configured to use an exit node but none exist:

- **DO NOT** fall back to using CS as exit
- **DO** fall back to device's local internet (split tunnel)
- This keeps CS responsibilities clear and prevents unexpected load

## User Experience

### Adding a Remote

When adding a remote peer, the wizard asks:

```
Hostname: alice-laptop
Access level [full/vpn/lan]: full

Route internet through exit node? [y/N]: _
```

**If No (default):** Move on quickly. Remote uses split tunnel.

**If Yes:**
- If 0 exit nodes exist: "No exit nodes configured. Add one now? [y/N]"
- If 1+ exit nodes exist: List them and let user choose

```
Available exit nodes:
  1. exit-us-west (us-west.example.com:51820)
  2. exit-eu-central (eu.example.com:51820)

Select exit node [1-2]: _
```

### Adding an Exit Node

Exit nodes can be added:
- During the "Add remote" flow (when first remote wants exit)
- Via dedicated command: `wg-friend add exit-node`

```
=== ADD EXIT NODE ===

Hostname: exit-us-west
Public endpoint (IP or domain): us-west.example.com
Listen port [51820]: 51820
```

The exit node gets:
- Its own keypair
- A VPN IP address from the network range
- Peer relationships with remotes that choose it

### Scope: Remotes Only

The exit node question is **only asked for remotes**, not for:
- Coordination servers (they coordinate, not exit)
- Subnet routers (they advertise LANs, not internet)

A subnet router could theoretically enforce exit for its entire subnet, but this creates exception-management complexity. The simpler model: configure per-remote, and if you want a subnet to use an exit, configure each device on that subnet individually.

## Data Model

### New Table: `exit_node`

```sql
CREATE TABLE exit_node (
    id INTEGER PRIMARY KEY,
    permanent_guid TEXT UNIQUE NOT NULL,  -- First public key
    current_public_key TEXT NOT NULL,
    private_key TEXT NOT NULL,
    hostname TEXT NOT NULL,
    endpoint TEXT NOT NULL,               -- Public IP/domain:port
    listen_port INTEGER DEFAULT 51820,
    ipv4_address TEXT,                    -- VPN address (e.g., 10.66.0.X/32)
    ipv6_address TEXT,                    -- VPN address (e.g., fd66::X/128)
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

### Modified Table: `remote`

Add nullable foreign key:

```sql
ALTER TABLE remote ADD COLUMN exit_node_id INTEGER REFERENCES exit_node(id);
```

- `NULL`: Remote uses split tunnel (no exit node)
- Non-null: Remote routes internet through specified exit node

### Relationship Summary

```
exit_node 1 ──< many remote (those that opt in)
```

Multiple remotes can share one exit node. One remote can only use one exit node at a time.

## Config Generation

### Remote Config (with exit node)

When generating a remote's config, if `exit_node_id` is set:

```ini
[Interface]
PrivateKey = <remote-private-key>
Address = 10.66.0.5/32, fd66::5/128
DNS = 1.1.1.1

# Coordination Server - VPN traffic only
[Peer]
PublicKey = <cs-public-key>
Endpoint = cs.example.com:51820
AllowedIPs = 10.66.0.0/24, fd66::/64  # VPN network only
PersistentKeepalive = 25

# Exit Node - Internet traffic
[Peer]
PublicKey = <exit-public-key>
Endpoint = us-west.example.com:51820
AllowedIPs = 0.0.0.0/0, ::/0          # Default route
PersistentKeepalive = 25
```

Key insight: The remote has **two peers** - CS for VPN traffic, exit for internet.

### Remote Config (without exit node - unchanged)

```ini
[Interface]
PrivateKey = <remote-private-key>
Address = 10.66.0.5/32, fd66::5/128
DNS = 1.1.1.1

[Peer]
PublicKey = <cs-public-key>
Endpoint = cs.example.com:51820
AllowedIPs = 10.66.0.0/24, fd66::/64  # VPN network only
PersistentKeepalive = 25
```

No default route peer = split tunnel behavior preserved.

### Exit Node Config

The exit node needs:
1. Interface setup
2. Peer entries for each remote that uses it
3. IP forwarding and NAT rules

```ini
[Interface]
PrivateKey = <exit-private-key>
Address = 10.66.0.100/32
ListenPort = 51820
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

# Remote: alice-laptop
[Peer]
PublicKey = <alice-laptop-public-key>
AllowedIPs = 10.66.0.5/32, fd66::5/128

# Remote: bob-phone
[Peer]
PublicKey = <bob-phone-public-key>
AllowedIPs = 10.66.0.6/32, fd66::6/128
```

### Coordination Server Config (unchanged conceptually)

The CS doesn't need to know about exit nodes. It continues to:
- Have peer entries for all remotes
- Route VPN traffic between peers
- Not handle internet-bound traffic

## Operations

### Adding Exit Node

1. Generate keypair
2. Assign VPN IP from network range
3. Store in `exit_node` table
4. Generate and deploy exit node config
5. Record state snapshot

### Assigning Exit Node to Remote

1. Update `remote.exit_node_id`
2. Regenerate remote config (adds exit peer)
3. Regenerate exit node config (adds remote peer)
4. Deploy both configs
5. Record state snapshot

### Removing Exit Node

1. Find all remotes using this exit node
2. Set their `exit_node_id` to NULL (fall back to split tunnel)
3. Regenerate affected remote configs
4. Delete exit node record
5. Record state snapshot

### Key Rotation on Exit Node

1. Generate new keypair
2. Update `current_public_key` (permanent_guid unchanged)
3. Regenerate exit node config
4. Regenerate configs for all remotes using this exit
5. Deploy all affected configs
6. Record state snapshot with rotation change

## State Tracking

Exit node operations integrate with `SystemStateDB`:

```python
def record_add_exit_node(main_db_path, db, hostname, public_key) -> int:
    return record_state(
        main_db_path, db,
        f"Added exit node: {hostname}",
        changes=[{
            'type': 'add',
            'entity_type': 'exit_node',
            'identifier': hostname,
            'new_value': public_key
        }]
    )
```

`capture_current_topology()` extended to include exit node snapshots.

## CLI Integration

### New Commands

```bash
# Add exit node
wg-friend add exit-node

# List exit nodes
wg-friend status --exits

# Assign exit to existing remote
wg-friend exit assign <remote> <exit-node>

# Remove exit assignment from remote
wg-friend exit clear <remote>
```

### TUI Integration

New menu option under "Add Peer" flow or dedicated "Manage Exit Nodes" submenu:

```
WIREGUARD FRIEND - MAIN MENU
  1. Network Status
  2. List All Peers
  3. Add Peer
  4. Remove Peer
  5. Rotate Keys
  6. History
  7. Manage Exit Nodes    <-- NEW
  8. Generate Configs
  9. Deploy Configs
```

## New Scenario: Exit-Only Clients

### The Use Case

With exit nodes, a new scenario emerges: a **stationary device on a LAN** that wants to use WireGuard purely to route internet traffic through an exit node. This device:

- Is already on a trusted network (home LAN)
- Doesn't need VPN access to the coordination server
- Doesn't need to reach other VPN peers or subnet routers
- Just wants: Device → Exit Node → Internet

Examples:
- Smart TV that should appear to be in another country
- Gaming console routing through low-latency exit
- Workstation that needs to exit in a specific jurisdiction

### How This Differs from Traditional Remotes

| Aspect | Traditional Remote | Exit-Only Client |
|--------|-------------------|------------------|
| Location | Mobile/outside network | Stationary on LAN |
| Needs CS access | Yes | No |
| Needs peer access | Usually | No |
| Primary purpose | VPN connectivity | Internet egress |
| Peers in config | CS + maybe exit | Exit only |

### Proposed Handling: Extend Remote Access Levels

Rather than creating a new entity type, extend the `remote` concept with a new access level:

```
access_level options:
- full:      CS + subnet routers + other peers + optional exit
- vpn:       CS + VPN network only + optional exit
- lan:       CS + specific subnets + optional exit
- exit_only: Exit node only (no CS, no VPN)       <-- NEW
```

A remote with `access_level='exit_only'`:
- Has no peer entry for CS
- Only peer is the exit node
- Gets a VPN IP (for exit node to identify it)
- Minimal config

### Exit-Only Client Config

```ini
[Interface]
PrivateKey = <client-private-key>
Address = 10.66.0.50/32
DNS = 1.1.1.1

# Exit Node - all traffic
[Peer]
PublicKey = <exit-public-key>
Endpoint = us-west.example.com:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
```

That's it. No CS peer. Traffic either goes to exit or nowhere.

### Add Remote Flow for Exit-Only

```
Hostname: living-room-tv
Access level [full/vpn/lan/exit_only]: exit_only

Since this is exit-only, it will ONLY connect to an exit node.
No VPN access to coordination server or other peers.

Available exit nodes:
  1. exit-us-west (us-west.example.com:51820)

Select exit node [1]: 1

✓ Exit-only client added: living-room-tv
  Uses exit: exit-us-west
```

### Implications

1. **IP Allocation**: Exit-only clients still get VPN IPs from main range (exit node needs to identify them via AllowedIPs)

2. **Exit Node Required**: For `exit_only` access level, an exit node MUST be selected (unlike other levels where it's optional)

3. **No Fallback**: If the exit node is unreachable, the device has no connectivity (expected behavior - it's the whole point)

4. **Upgradeable**: An exit-only client can later be upgraded to `full` access by changing access_level and regenerating config

5. **CS Doesn't Know**: The coordination server has no peer entry for exit-only clients. They're invisible to the VPN mesh.

### Data Model Impact

No schema changes needed beyond what's already planned:
- `remote.access_level` already exists, just add 'exit_only' as valid value
- `remote.exit_node_id` is required (not nullable) when `access_level='exit_only'`

### Validation Rules

```python
def validate_remote(remote):
    if remote.access_level == 'exit_only':
        if remote.exit_node_id is None:
            raise ValueError("exit_only clients must have an exit node assigned")
    # exit_node_id can be NULL for other access levels (split tunnel)
```

## Constraints and Non-Goals

### Supported Scenario

- **Dedicated exit node with public IP**: The only supported configuration
- Exit node is a separate VPS/server you control
- It has a public IP address and can accept incoming WireGuard connections

### Not Supported

- Using CS as fallback exit (explicit design decision)
- Exit through subnet router (too complex, use per-device config)
- Multiple exit nodes per remote (one at a time)
- Exit node chains (exit -> exit)
- Automatic exit selection based on latency/geography

### Keeping It Simple

The design prioritizes simplicity:

1. **Binary choice per remote**: Exit or no exit (split tunnel)
2. **Explicit selection**: User picks which exit node
3. **No magic**: System does exactly what's configured
4. **Graceful degradation**: No exit = split tunnel, not error

## Migration Path

For existing deployments:

1. No schema migration needed initially (exit_node_id defaults to NULL)
2. All existing remotes continue with split tunnel behavior
3. Exit nodes can be added incrementally
4. Remotes can be updated one at a time to use exit

## Security Considerations

- Exit node sees decrypted internet traffic from remotes using it
- Exit node operator must be trusted
- Exit node should have proper firewall rules
- Consider: should exit node also peer with CS? (For accessing VPN resources while using exit)

## Open Questions

1. **Exit + VPN access**: If a remote uses an exit node, can it still reach other VPN peers?
   - Answer: Yes, via the CS peer entry with VPN-only AllowedIPs

2. **Preshared keys**: Should remote-exit relationships support PSK?
   - Probably yes, for consistency with other peer relationships

3. **Exit node in state tracking**: New entity type in snapshots?
   - Yes, parallel to `router_snapshots` and `remote_snapshots`

4. **DNS handling**: Where should DNS queries go?
   - If using exit: through exit (add DNS= pointing to exit or public resolver)
   - If split tunnel: local DNS or specified in interface

## Implementation Order

1. **Phase 1: Data Model**
   - Add `exit_node` table
   - Add `exit_node_id` to remote table
   - Update schema version

2. **Phase 2: Core Logic**
   - Exit node CRUD operations
   - Config generation with exit peers
   - State tracking integration

3. **Phase 3: CLI/TUI**
   - Add exit node command
   - Modify add-remote flow
   - Exit management menus

4. **Phase 4: Deploy**
   - Exit node deployment support
   - Multi-config deployment coordination
