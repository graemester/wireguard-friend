# WireGuard Friend - Architecture

## Design Philosophy

**Perfect Fidelity Above All Else**

WireGuard Friend is built on one core principle: **reconstructed configs must be byte-for-byte identical to originals**. This drives every architectural decision.

### Why Perfect Fidelity Matters

1. **Trust**: Users can verify output matches input exactly
2. **Safety**: No unintended modifications to working configs
3. **Debugging**: Eliminates "what did the tool change?" questions
4. **Preservation**: Maintains all quirks, comments, formatting

## Core Architecture

### Dual Storage Model

WireGuard Friend stores each configuration in **two complementary forms**:

```
┌─────────────────────────────────────┐
│ WireGuard Config File               │
└─────────────────────────────────────┘
            ↓
    ┌───── Parser ─────┐
    ↓                   ↓
┌─────────────┐   ┌──────────────┐
│ Raw Blocks  │   │ Structured   │
│ (exact text)│   │ Data         │
│             │   │ (queryable)  │
│ Purpose:    │   │ Purpose:     │
│ • Recon-    │   │ • Queries    │
│   struction │   │ • IP alloc   │
│ • Fidelity  │   │ • Logic      │
└─────────────┘   └──────────────┘
       ↓
┌─────────────────────────────────────┐
│ Reconstructed Config                │
│ (byte-for-byte identical)           │
└─────────────────────────────────────┘
```

#### Raw Blocks

**Purpose**: Perfect reconstruction

**Storage**:
- `raw_interface_block`: Exact text from `[Interface]` section
- `raw_peer_block`: Exact text from each `[Peer]` section

**Characteristics**:
- Never parsed beyond extraction
- Preserved byte-for-byte
- Includes all comments, whitespace, formatting
- PostUp/PostDown stored as complete text

**Example**:
```sql
raw_interface_block = "[Interface]\n
Address = 10.66.0.1/24\n
Address = fd66:6666::1/64\n
ListenPort = 51820\n
MTU = 1280\n
PrivateKey = MO/coICCT9/GZRJMnUhhwBzx6ud3WguyPqlt8F6tr2c=\n
\n
# Update PostUp/PostDown to handle both IPv4 and IPv6\n
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT..."
```

#### Structured Data

**Purpose**: Queries and business logic

**Storage**:
- `ipv4_address`: "10.66.0.1"
- `ipv6_address`: "fd66:6666::1"
- `network_ipv4`: "10.66.0.0/24"
- `public_key`: "Yk+VD886XMnyu2..."
- `access_level`: "full_access"

**Characteristics**:
- Extracted from raw blocks
- Used for queries, IP allocation, filtering
- Never used for reconstruction
- Can be regenerated from raw blocks

**Use Cases**:
- Find next available IP address
- Query peers by access level
- Filter by network membership
- Track key rotation dates

### Sacred Rules

#### 1. PostUp/PostDown Are Monolithic

**Never** parse PostUp/PostDown rules. Store as exact text.

```python
# GOOD - Store as-is
postup_rules = [
    "iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE",
    "ip6tables -A FORWARD -i wg0 -j ACCEPT; ip6tables -t nat -A POSTROUTING -o eth0 -j MASQUERADE"
]

# BAD - Don't parse into components
# postup = {
#     'table': 'nat',
#     'chain': 'POSTROUTING',
#     'action': 'MASQUERADE'
# }
```

**Rationale**: iptables rules are complex, context-dependent, and fragile. Any parsing risks breaking working configurations.

#### 2. Reconstruction Uses Raw Blocks Only

```python
def reconstruct_cs_config():
    cs = get_coordination_server()
    
    # Output raw interface block AS-IS
    lines = [cs.raw_interface_block]
    
    # Output raw peer blocks AS-IS
    for peer in get_peers_in_order():
        lines.append(peer.raw_peer_block)
    
    return '\n'.join(lines)
```

**Never** build configs from structured data. Always use raw blocks.

#### 3. Peer Order Preserved

Original peer order must be maintained exactly.

```sql
CREATE TABLE cs_peer_order (
    cs_id INTEGER,
    peer_public_key TEXT,
    position INTEGER,  -- Original position
    is_subnet_router BOOLEAN
);
```

**Rationale**: Order may matter for routing, debugging, or user preferences.

#### 4. Multi-line Comments Preserved

```
[Peer]
# icculus
# no endpoint == behind CGNAT == initiates connection
PublicKey = ...
```

Stored as:
```python
comment_lines = ["icculus", "no endpoint == behind CGNAT == initiates connection"]
```

Reconstructed as:
```python
for line in comment_lines:
    output(f"# {line}")
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

**Raw blocks**:
- `raw_interface_block` - Entire [Interface] section

**Structured data**:
- `endpoint` - wireguard.graeme.host:51820
- `network_ipv4/ipv6` - Network ranges
- `ipv4/ipv6_address` - CS addresses
- `public_key`, `private_key` - CS keys
- `ssh_host/user/port` - Deployment config

#### `subnet_router`

Stores LAN gateway configurations.

**Raw blocks**:
- `raw_interface_block` - Subnet router's [Interface]
- `raw_peer_block` - Entry in CS config

**Structured data**:
- `name` - Friendly name (e.g., "icculus")
- `ipv4/ipv6_address` - Router addresses
- `allowed_ips` - Networks advertised to CS
- `has_endpoint` - Behind CGNAT?

**Related tables**:
- `sn_lan_networks` - LANs advertised (192.168.12.0/24)
- `sn_postup_rules` - Router's PostUp rules
- `sn_postdown_rules` - Router's PostDown rules

#### `peer`

Stores client device configurations.

**Raw blocks**:
- `raw_interface_block` - Client's [Interface] (if we have it)
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

**Purpose**: Ensures reconstructed config has identical peer order.

### Storage Patterns

#### Storing Rules

PostUp/PostDown rules stored in separate tables:

```sql
CREATE TABLE cs_postup_rules (
    cs_id INTEGER,
    rule_text TEXT,      -- Complete rule as-is
    rule_order INTEGER   -- Preserve order
);
```

Example:
```
rule_order=1: "iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE"
rule_order=2: "ip6tables -A FORWARD -i wg0 -j ACCEPT; ip6tables -t nat -A POSTROUTING -o eth0 -j MASQUERADE"
rule_order=3: "iptables -I INPUT -i wg0 -p tcp --dport 5432 -j ACCEPT"
```

#### Storing Comments

Multi-line comments stored as single string with newlines:

```python
# Original:
# # icculus
# # no endpoint == behind CGNAT == initiates connection

# Stored as:
comment = "icculus\nno endpoint == behind CGNAT == initiates connection"

# Reconstructed:
for line in comment.split('\n'):
    output(f"# {line}")
```

#### Subnet Router Positioning

Subnet routers always appear first in peer list:

```sql
-- Subnet routers: position 1, 2, 3...
-- Regular peers: position 4, 5, 6...

SELECT * FROM cs_peer_order 
WHERE cs_id = 1 
ORDER BY is_subnet_router DESC, position ASC;
```

## Import Workflow

### Phase 1: Parse & Classify

```python
def parse_file(path):
    with open(path) as f:
        content = f.read()
    
    # Extract raw blocks
    interface_block = extract_interface_block(content)  # Exact text
    peer_blocks = extract_peer_blocks(content)          # List of exact text
    
    # Parse structured data FROM raw blocks
    network = parse_network_from_raw(interface_block)
    peers_data = [parse_peer_from_raw(pb) for pb in peer_blocks]
    
    return RawConfig(
        raw_interface=interface_block,  # For reconstruction
        raw_peers=peer_blocks,          # For reconstruction
        network=network,                # For logic
        peers=peers_data               # For logic
    )
```

**Key principle**: Raw blocks extracted first, structured data derived from them.

### Phase 2: CS Confirmation

```python
def save_cs(parsed):
    # Save raw interface block
    cs_id = db.save_coordination_server(
        raw_interface_block=parsed.raw_interface,  # Exact text
        network_ipv4=parsed.network.ipv4,          # For queries
        ...
    )
    
    # Save ALL peers from CS (even without client configs)
    for pos, peer_block in enumerate(parsed.raw_peers):
        peer_id = db.save_peer(
            raw_peer_block=peer_block,      # Exact text
            raw_interface_block=None,       # Don't have client config yet
            ipv4=extract_ipv4(peer_block),  # For queries
            ...
        )
        db.save_peer_order(cs_id, peer.public_key, pos+1)
```

**Key principle**: Save ALL peers from CS immediately, even if we don't have their client configs.

### Phase 3: SN Confirmation

```python
def match_subnet_router(sn_config, cs_peers):
    # Derive public key from SN's private key
    sn_pubkey = derive_public_key(sn_config.private_key)
    
    # Find matching peer in CS
    for peer in cs_peers:
        if peer.public_key == sn_pubkey:
            # Delete peer record
            db.delete_peer(peer.id)
            
            # Save as subnet_router instead
            db.save_subnet_router(
                raw_interface_block=sn_config.raw_interface,
                raw_peer_block=peer.raw_peer_block,  # From CS
                ...
            )
            
            # Update peer_order
            db.update_peer_order(cs_id, sn_pubkey, is_subnet_router=True)
```

**Key principle**: Move peer → subnet_router, preserve both raw blocks.

### Phase 4: Peer Review

```python
def match_client(client_config, cs_peers):
    # Derive public key from client's private key
    client_pubkey = derive_public_key(client_config.private_key)
    
    # Find matching peer in CS
    for peer in cs_peers:
        if peer.public_key == client_pubkey:
            # UPDATE existing peer record
            db.update_peer(
                peer.id,
                raw_interface_block=client_config.raw_interface,  # Add client config
                private_key=client_config.private_key,
                access_level=selected_access_level
            )
```

**Key principle**: Update existing peer, don't create new one.

### Phase 5: Verification

```python
def verify():
    # Reconstruct from raw blocks
    reconstructed = db.reconstruct_cs_config()
    
    # Compare with original
    with open('import/coordination.conf') as f:
        original = f.read()
    
    if reconstructed == original:
        print("✓ Perfect match")
    else:
        print("✗ Configs differ")
        show_diff(original, reconstructed)
```

**Key principle**: Byte-for-byte comparison, not functional equivalence.

## Reconstruction Algorithm

```python
def reconstruct_cs_config(cs_id):
    cs = get_coordination_server(cs_id)
    
    # Start with raw interface block - OUTPUT AS-IS
    lines = [cs.raw_interface_block.rstrip()]
    
    # Get peers in original order
    peer_order = get_peer_order(cs_id)  # Ordered by position
    
    for order_entry in peer_order:
        pubkey = order_entry.peer_public_key
        
        if order_entry.is_subnet_router:
            # Find in subnet_router table
            sn = get_subnet_router_by_pubkey(cs_id, pubkey)
            if sn:
                lines.append('')
                lines.append(sn.raw_peer_block.rstrip())
        else:
            # Find in peer table
            peer = get_peer_by_pubkey(cs_id, pubkey)
            if peer:
                lines.append('')
                lines.append(peer.raw_peer_block.rstrip())
    
    lines.append('')
    return '\n'.join(lines)
```

**Key points**:
1. Raw blocks output AS-IS
2. No parsing, no rebuilding
3. Original order preserved
4. Blank lines added between sections
5. Final newline added

## Key Rotation

### Atomic Update

When rotating keys, update both configs atomically:

```python
def rotate_peer_keys(peer_id):
    # Generate new keypair
    private_key, public_key = generate_keypair()
    
    # Update peer's client config (raw_interface_block)
    old_interface = peer.raw_interface_block
    new_interface = replace_in_text(old_interface, 
                                     "PrivateKey = <old>",
                                     f"PrivateKey = {private_key}")
    
    # Update CS peer entry (raw_peer_block)
    old_peer_block = peer.raw_peer_block
    new_peer_block = replace_in_text(old_peer_block,
                                      "PublicKey = <old>",
                                      f"PublicKey = {public_key}")
    
    # Atomic update
    db.transaction():
        db.update(peer_id,
                  private_key=private_key,
                  public_key=public_key,
                  raw_interface_block=new_interface,
                  raw_peer_block=new_peer_block,
                  last_rotated=now())
```

**Key principle**: Update raw blocks by text replacement, not regeneration.

## Access Levels

### Implementation

Access levels control `AllowedIPs` in client config:

```python
def build_allowed_ips(peer, access_level):
    if access_level == 'full_access':
        # Return exactly what's in CS peer entry
        return extract_allowed_ips(peer.raw_peer_block)
    
    elif access_level == 'vpn_only':
        # VPN networks only
        return f"{cs.network_ipv4}, {cs.network_ipv6}"
    
    elif access_level == 'lan_only':
        # VPN + all subnet router LANs
        lans = get_all_sn_lan_networks(cs_id)
        return f"{cs.network_ipv4}, {cs.network_ipv6}, {', '.join(lans)}"
```

**Key principle**: Access level stored separately, applied when building client config.

## Error Handling

### Import Failures

If import fails mid-way:
- Database changes in transaction
- Rollback on error
- User can re-run import

### Reconstruction Mismatches

If reconstruction ≠ original:
- Display diff
- Save both to output/
- Continue anyway (user decides)

### Key Rotation Conflicts

If keys rotated but not deployed:
- Timestamp tracks last rotation
- Warn user of pending deployment
- Don't allow double rotation

## Performance

### Database Indexes

```sql
CREATE INDEX idx_peer_pubkey ON peer(public_key);
CREATE INDEX idx_peer_cs ON peer(cs_id);
CREATE INDEX idx_peer_order ON cs_peer_order(cs_id, position);
```

### Query Optimization

- Use raw blocks for reconstruction (no joins needed)
- Use structured data for queries (indexed)
- Separate tables for 1:many relationships (rules, LANs)

### Reconstruction Speed

Typical network (50 peers):
- Parse: <100ms
- Database operations: <50ms
- Reconstruction: <10ms

**Total**: <200ms for complete workflow

## Testing Strategy

### Fidelity Testing

```bash
# Import → Reconstruct → Compare
./wg-friend-onboard-v2.py --import-dir test/fixtures/
diff test/fixtures/coordination.conf output/coordination.conf

# Must be byte-for-byte identical
test $? -eq 0
```

### Stress Testing

```python
# Large network
generate_cs_config(peers=1000)
import_and_reconstruct()
verify_fidelity()

# Complex rules  
generate_postup_rules(count=50, complexity='high')
import_and_reconstruct()
verify_fidelity()
```

### Regression Testing

```python
# Known edge cases
test_multiline_comments()
test_missing_mtu()
test_duplicate_address_lines()
test_peer_order_preservation()
test_postup_postdown_order()
```

## Future Enhancements

### Planned

- Custom access levels (specific IPs)
- Peer groups (label/organize)
- Config templates
- Bulk operations
- Audit log

### Will NOT Implement

- Parsing PostUp/PostDown (violates sacred rule)
- Config generation from scratch (violates fidelity)
- YAML/JSON export (loses raw blocks)
- Git integration (not needed with SQLite)

## Design Rationale

### Why SQLite?

- Single file database
- No server required
- Transactions (atomicity)
- SQL queries (flexibility)
- Portable (backup = copy file)

### Why Not YAML/JSON?

- Can't preserve exact formatting
- Loses comments
- Changes whitespace
- Not queryable without loading

### Why Raw Blocks?

- Only way to guarantee fidelity
- Preserves all original information
- Simple to verify (byte comparison)
- Immune to parsing bugs

### Why Structured Data Too?

- Enables queries (find available IPs)
- Supports business logic (access levels)
- Faster than parsing raw blocks
- Can be regenerated if needed

---

**The architecture prioritizes fidelity over convenience, simplicity over features, and trust over cleverness.**
