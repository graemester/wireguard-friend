# WireGuard Friend - Architecture

## Design Overview

WireGuard Friend stores configurations in SQLite with a dual storage model: original text blocks for reconstruction and structured fields for querying.

## Core Architecture

### Dual Storage Model

```
┌─────────────────────────────────────┐
│ WireGuard Config File               │
└─────────────────────────────────────┘
            ↓
    ┌───── Parser ─────┐
    ↓                   ↓
┌─────────────┐   ┌──────────────┐
│ Text Blocks │   │ Structured   │
│ (original)  │   │ Data         │
│             │   │ (queryable)  │
│ Purpose:    │   │ Purpose:     │
│ • Config    │   │ • Queries    │
│   output    │   │ • IP alloc   │
└─────────────┘   └──────────────┘
```

#### Text Blocks

**Storage**:
- `raw_interface_block`: Text from `[Interface]` section
- `raw_peer_block`: Text from each `[Peer]` section

**Characteristics**:
- Preserved as imported
- Includes comments, formatting
- PostUp/PostDown stored as complete text

#### Structured Data

**Storage**:
- `ipv4_address`: "10.66.0.1"
- `ipv6_address`: "fd66:6666::1"
- `network_ipv4`: "10.66.0.0/24"
- `public_key`: "Yk+VD886XMnyu2..."
- `access_level`: "full_access"

**Use Cases**:
- Find next available IP address
- Query peers by access level
- Filter by network membership
- Track key rotation dates

### Design Rules

#### 1. PostUp/PostDown Are Monolithic

**Don't** parse PostUp/PostDown rules. Store as text.

```python
# GOOD - Store as-is
postup_rules = [
    "iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE",
]

# BAD - Don't parse into components
```

**Rationale**: iptables rules are complex, context-dependent, and fragile.

#### 2. Peer Order Preserved

Original peer order is maintained.

```sql
CREATE TABLE cs_peer_order (
    cs_id INTEGER,
    peer_public_key TEXT,
    position INTEGER,
    is_subnet_router BOOLEAN
);
```

## Database Schema

### Entity Relationships

```
coordination_server (1)
    ├─→ cs_postup_rules (many)
    ├─→ cs_postdown_rules (many)
    ├─→ cs_peer_order (many)
    ├─→ subnet_router (many)
    │       ├─→ sn_postup_rules (many)
    │       ├─→ sn_postdown_rules (many)
    │       └─→ sn_lan_networks (many)
    └─→ peer (many)
```

### Key Tables

#### `coordination_server`

Stores the VPS hub configuration.

**Text blocks**:
- `raw_interface_block` - [Interface] section

**Structured data**:
- `endpoint` - your.vpshost.com:51820
- `network_ipv4/ipv6` - Network ranges
- `ipv4/ipv6_address` - CS addresses
- `public_key`, `private_key` - CS keys
- `ssh_host/user/port` - Deployment config

#### `subnet_router`

Stores LAN gateway configurations.

**Text blocks**:
- `raw_interface_block` - Subnet router's [Interface]
- `raw_peer_block` - Entry in CS config

**Structured data**:
- `name` - Friendly name (e.g., "home-router")
- `ipv4/ipv6_address` - Router addresses
- `allowed_ips` - Networks advertised to CS
- `has_endpoint` - Behind CGNAT?

**Related tables**:
- `sn_lan_networks` - LANs advertised (192.168.10.0/24)
- `sn_postup_rules` - Router's PostUp rules
- `sn_postdown_rules` - Router's PostDown rules

#### `peer`

Stores client device configurations.

**Text blocks**:
- `raw_interface_block` - Client's [Interface] (if available)
- `raw_peer_block` - Entry in CS config

**Structured data**:
- `name` - Friendly name (e.g., "iphone16pro")
- `ipv4/ipv6_address` - Peer addresses
- `access_level` - What peer can access
- `public_key`, `private_key` - Peer keys
- `last_rotated` - Key rotation timestamp

#### `cs_peer_order`

Preserves original peer order from CS config.

**Fields**:
- `position` - Original position (1, 2, 3...)
- `peer_public_key` - Reference to peer
- `is_subnet_router` - Type flag

### Storage Patterns

#### Storing Rules

PostUp/PostDown rules stored in separate tables:

```sql
CREATE TABLE cs_postup_rules (
    cs_id INTEGER,
    rule_text TEXT,
    rule_order INTEGER
);
```

#### Storing Comments

Multi-line comments stored as single string with newlines:

```python
comment = "home-router\nno endpoint == behind CGNAT"
```

## Import Workflow

### Phase 1: Parse & Classify

```python
def parse_file(path):
    # Extract text blocks
    interface_block = extract_interface_block(content)
    peer_blocks = extract_peer_blocks(content)

    # Parse structured data from blocks
    network = parse_network_from_raw(interface_block)
    peers_data = [parse_peer_from_raw(pb) for pb in peer_blocks]

    return RawConfig(
        raw_interface=interface_block,
        raw_peers=peer_blocks,
        network=network,
        peers=peers_data
    )
```

### Phase 2: CS Confirmation

Save coordination server and all peers from CS config.

### Phase 3: Subnet Router Confirmation

Match subnet router configs to CS peers by public key.

### Phase 4: Peer Review

Match client configs to CS peers, add access levels.

### Phase 5: Save & Verify

Save configs to output directory.

## Key Rotation

### Atomic Update

When rotating keys, update both configs:

```python
def rotate_peer_keys(peer_id):
    # Generate new keypair
    private_key, public_key = generate_keypair()

    # Update peer's client config
    new_interface = replace_in_text(old_interface,
                                     "PrivateKey = <old>",
                                     f"PrivateKey = {private_key}")

    # Update CS peer entry
    new_peer_block = replace_in_text(old_peer_block,
                                      "PublicKey = <old>",
                                      f"PublicKey = {public_key}")

    # Atomic update
    db.transaction():
        db.update(peer_id, ...)
```

## Access Levels

Access levels control `AllowedIPs` in client config:

- **full_access**: All networks (VPN + all LANs)
- **vpn_only**: VPN networks only
- **lan_only**: VPN + subnet router LANs
- **restricted_ip**: Specific IPs with optional port restrictions

## Performance

### Database Indexes

```sql
CREATE INDEX idx_peer_pubkey ON peer(public_key);
CREATE INDEX idx_peer_cs ON peer(cs_id);
CREATE INDEX idx_peer_order ON cs_peer_order(cs_id, position);
```

### Typical Performance

Typical network (50 peers):
- Parse: <100ms
- Database operations: <50ms
- Config generation: <10ms

## Design Rationale

### Why SQLite?

- Single file database
- No server required
- Transactions (atomicity)
- SQL queries (flexibility)
- Portable (backup = copy file)

### Why Dual Storage?

- Text blocks preserve original formatting and comments
- Structured data enables queries and IP allocation
- Each serves its purpose without compromise
