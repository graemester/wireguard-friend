# WireGuard Friend - Architecture

Internal design and implementation documentation.

For usage instructions, see [quick-start.md](../quick-start.md).

---

## Design Overview

WireGuard Friend stores WireGuard configurations in a SQLite database with a semantic schema. The database tracks entities (coordination server, subnet routers, client peers) with permanent identities that survive key rotation.

### Application Flow

```
wg-friend
    │
    ├─→ Has database? ─→ Maintenance Mode (TUI)
    │
    ├─→ Configs found? ─→ Import Mode
    │
    └─→ Clean slate? ─→ Init Wizard
```

The main entry point detects the current state and routes appropriately.

## Design Philosophy

**Semantic Storage with Permanent Identity**

WireGuard Friend parses configurations into semantic data (addresses, keys, endpoints, routes) and stores them in a queryable database. Each entity receives a permanent GUID (its first public key) that never changes, even during key rotation.

## Core Architecture

### Permanent GUID System

Every entity has two key identifiers:

```
┌──────────────────────────────────────┐
│ Entity (CS, Router, or Remote)       │
├──────────────────────────────────────┤
│ permanent_guid:     ABC123...        │  ← Never changes
│ current_public_key: XYZ789...        │  ← Can be rotated
└──────────────────────────────────────┘
```

**permanent_guid**: First public key seen, immutable identifier
**current_public_key**: Current public key, can rotate

This allows:
- Key rotation without losing identity
- Comments linked to permanent_guid survive rotation
- Audit trail of all key changes
- Hostname defaults to permanent_guid prefix

### Database Schema

**Core tables:**
- `coordination_server` - VPS hub configuration
- `subnet_router` - LAN gateway configurations
- `remote` - Client device configurations
- `key_rotation_history` - Audit trail of key changes
- `comment` - Entity comments linked via permanent_guid
- `command_pair` - PostUp/PostDown pattern storage

**Key relationships:**
```
coordination_server (1) ←→ (N) subnet_router
coordination_server (1) ←→ (N) remote
entity (1) ←→ (N) comment [via permanent_guid]
entity (1) ←→ (N) key_rotation_history
```

### Import Flow

```
Existing WireGuard Config
    ↓
Parser extracts:
  - Interface settings
  - Peer configurations
  - PostUp/PostDown commands
    ↓
Derive public keys from private keys
Assign permanent_guid (first public key)
Recognize patterns (NAT, MSS clamping, etc.)
    ↓
Store in SQLite database
```

### Generation Flow

```
SQLite Database
    ↓
Read entity data:
  - Coordination server settings
  - Subnet router configs
  - Remote client configs
    ↓
Apply templates:
  - [Interface] section
  - [Peer] sections (one per peer)
  - PostUp/PostDown commands
    ↓
Generate WireGuard .conf files
Optionally generate QR codes
```

### Key Rotation Flow

```
User selects peer to rotate
    ↓
Show current_public_key
Show permanent_guid (unchanged)
    ↓
Generate new keypair
    ↓
Update current_public_key in database
Log rotation in key_rotation_history
permanent_guid stays the same
    ↓
Regenerate configs
Deploy via SSH
```

## Configuration Storage

### Coordination Server

Stored in `coordination_server` table:
- Interface settings (private key, addresses, listen port)
- Network configuration
- SSH deployment settings

### Subnet Routers

Stored in `subnet_router` table:
- Interface settings (private key, addresses)
- Advertised networks (LANs to route)
- Endpoint (how CS reaches it)
- PostUp/PostDown patterns

### Remote Clients

Stored in `remote` table:
- Interface settings (private key, addresses)
- Access level (full_access, vpn_only, lan_only, custom)
- Device metadata (hostname, type, notes)
- Allowed networks based on access level

## PostUp/PostDown Patterns

Common patterns recognized during import:

**NAT forwarding:**
```bash
PostUp = iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
```

**MSS clamping:**
```bash
PostUp = iptables -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
```

**IP forwarding:**
```bash
PostUp = sysctl -w net.ipv4.ip_forward=1
```

Patterns stored in `command_pair` table for reuse during generation.

## Access Levels

Determines which networks a remote client can access:

- **full_access**: VPN network + all advertised LANs
- **vpn_only**: VPN network only (peer-to-peer via CS)
- **lan_only**: VPN network + specific LANs
- **custom**: User-defined allowed IPs

## SSH Deployment

Deployment process:
1. Generate all configs from database
2. For each target (CS, routers):
   - Check if localhost (skip SSH)
   - SSH to target
   - Backup existing config (timestamped)
   - Upload new config
   - Set permissions (600)
   - Optionally restart WireGuard

## Interactive TUI

Maintenance mode provides menu-driven interface:
- View network status
- List all peers
- Add peer (interactive)
- Remove peer (interactive)
- Rotate keys (interactive)
- View rotation history

## Files and Structure

```
v1/
├── wg-friend              # Main CLI entry point
├── cli/                   # CLI modules
│   ├── init_wizard.py     # First-run setup
│   ├── import_configs.py  # Import existing configs
│   ├── peer_manager.py    # Add/remove peers
│   ├── config_generator.py # Generate configs
│   ├── deploy.py          # SSH deployment
│   ├── status.py          # Network status
│   ├── tui.py             # Interactive TUI
│   └── ssh_setup.py       # SSH key setup wizard
├── schema_semantic.py     # Database schema
├── parser.py              # Config parser
├── generator.py           # Config generator
├── keygen.py              # Key generation utilities
└── network_utils.py       # Network utilities
```

## Database Location

Default: `wireguard.db` in current directory

Override with `--db` flag:
```bash
wg-friend --db /path/to/database.db <command>
```

## Testing

Unit tests verify:
- permanent_guid assignment
- Key derivation from private keys
- Config parsing and generation
- Database operations

Integration tests verify:
- End-to-end import workflow
- Config roundtrip (import → generate → import)
- Key rotation preserves identity
- SSH deployment

---

See [quick-start.md](../quick-start.md) for usage examples.
