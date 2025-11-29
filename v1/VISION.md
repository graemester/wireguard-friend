# Unified Semantic Model

## Database Schema

**10 tables:**

### Core Entities
```sql
coordination_server (id, endpoint, addresses, keys, ssh_info, ...)
subnet_router (id, name, addresses, keys, lan_interface, ...)
remote (id, name, addresses, keys, access_level, ...)  -- not "peer"
advertised_network (id, subnet_router_id, network_cidr, ...)
```

### Commands (semantic attributes)
```sql
command_pair (
    id, entity_type, entity_id,
    pattern_name,     -- Populated by pattern recognizer
    rationale,        -- Populated by pattern recognizer
    scope,            -- Populated by pattern recognizer
    up_commands,      -- JSON array
    down_commands,    -- JSON array
    variables,        -- Extracted variables
    execution_order
)

command_singleton (
    id, entity_type, entity_id,
    pattern_name, rationale, scope,
    up_commands, variables,
    execution_order
)
```

### Comments (semantic categories)
```sql
comment (
    id, entity_type, entity_id,
    category,         -- Populated by comment categorizer
    text,
    role_type,        -- For role comments
    applies_to_pattern,  -- For rationale comments
    display_order
)
```

### Metadata
```sql
cs_peer_order (cs_id, entity_type, entity_id, display_order)
import_session (id, source_file, checksum, imported_at, ...)
entity_provenance (id, entity_type, entity_id, import_session_id, ...)
```

---

## Import Flow

```
1. Read config file
   ↓
2. Extract PostUp/PostDown commands
   ↓
3. Pattern recognizer identifies pairs
   → Populates: pattern_name, rationale, scope, variables
   ↓
4. Extract comments
   ↓
5. Comment categorizer identifies categories
   → Populates: category, role_type, display_order
   ↓
6. Store in database
   → All semantic attributes populated
   → No raw blocks stored
```

**The "semantic" part happens during import, not in a separate layer.**

---

## Pattern Library (from your configs)

**Recognized patterns:**

1. `nat_masquerade_ipv4` - NAT for VPN subnet (IPv4)
2. `nat_masquerade_ipv6` - NAT for VPN subnet (IPv6)
3. `bidirectional_forwarding_ipv4` - Forwarding + NAT for LAN
4. `bidirectional_forwarding_ipv6` - Forwarding for LAN (IPv6)
5. `mss_clamping_ipv4` - Fix MTU/fragmentation (IPv4)
6. `mss_clamping_ipv6` - Fix MTU/fragmentation (IPv6)
7. `allow_service_port` - Allow specific service over WireGuard
8. `enable_ip_forwarding` - Enable kernel forwarding (singleton)

**Extensible:** Add new patterns as you encounter them.

**Test result:** 100% recognition on your coordination.conf and wg0.conf ✓

---

## Comment Categories (from your configs)

**Detected patterns:**

**Hostname:**
- Simple alphanumeric identifiers
- Examples: `icculus`, `mba15m2`, `iphone16pro`

**Role:**
- `initiates_only` - "no endpoint == behind CGNAT == initiates connection"
- `dynamic_endpoint` - "Endpoint will be dynamic (mobile device)"

**Rationale:**
- `enable_forwarding` - "Enable IP forwarding"
- `mss_clamping` - "MSS clamping to fix fragmentation issues"

**Custom:**
- First person indicators ("I rotate", "I added")
- Temporal context ("Sundays", "when")
- Personal notes ("brother was trying to spoof")

**Test result:** All categories detected correctly ✓

---

## Nomenclature

**Clear entity names (avoid WireGuard [Peer] confusion):**

- `coordination_server` - The hub (VPS)
- `subnet_router` - Advertises LAN networks
- `remote` - Client device (not "peer")

Each entity:
- Has [Interface] section in its config
- Appears as [Peer] in other configs

---

## What Makes This "Semantic"?

**It's just good database design:**

| Instead of... | We have... |
|---------------|------------|
| `raw_text = "iptables ..."` | `pattern_name = "nat_masquerade_ipv4"` |
| `raw_text = "iptables ..."` | `rationale = "NAT for VPN subnet"` |
| `comment_position = "inline"` | `category = "hostname"` |
| `comment_text = "no endpoint..."` | `role_type = "initiates_only"` |

**Semantic = meaningful column names + pattern recognition during import.**

---

## No Layers

```
┌─────────────────────────────────────┐
│         Import Process              │
│  (pattern recognition happens here) │
└─────────────────────────────────────┘
                 ↓
┌─────────────────────────────────────┐
│          Database                   │
│  (semantic attributes stored)       │
│                                     │
│  command_pair:                      │
│    pattern_name = "nat..."          │
│    rationale = "NAT for..."         │
│                                     │
│  comment:                           │
│    category = "hostname"            │
│    role_type = "initiates_only"     │
└─────────────────────────────────────┘
                 ↓
┌─────────────────────────────────────┐
│         Export Process              │
│  (uses semantic attributes)         │
└─────────────────────────────────────┘
```

**One database. Well-named columns. That's it.**

---

## Implementation Status

**Working:**
- ✓ Pattern recognizer (100% success on your configs)
- ✓ Comment categorizer (all categories detected)
- ✓ Unified schema (10 tables, semantic attributes)

**TODO:**
- Import integration (wire pattern recognizer into parser)
- Database persistence (insert methods)
- Export integration (generate configs from semantic attributes)
- Round-trip test (import → DB → export → verify)

---

## Key Insight

> "I don't understand why semantic isn't reduced to technical at the level of the database. They're just relationships."

**You were right.**

Semantic understanding isn't a layer.
It's just:
- Good attribute names
- Pattern recognition during import
- Well-designed relationships

At the database level, it's all just tables, columns, and foreign keys.

---

**V2 = One unified model with semantic attributes.**

No raw blocks. No layers. Just relationships.
