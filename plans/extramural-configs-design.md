# Extramural Configs Design for WireGuard Friend

## Overview

This document describes a new feature for managing **extramural WireGuard configurations** — configs for external VPN services (commercial VPNs, employer VPNs, etc.) where you control only the local end of the tunnel.

The term "extramural" means "outside the walls" — these configs exist completely outside your mesh network (the "intramural" side managed by coordination servers, subnet routers, and remotes).

## The Problem

Users often have WireGuard configurations from external sources:

- Commercial VPN providers (Mullvad, ProtonVPN, FastestVPN, etc.)
- Employer-provided VPN access
- Friend's or family's network access
- Other services that provide WireGuard configs

Currently, wireguard-friend only manages configs where it controls both ends of the tunnel. There's no way to:

- Store and organize external configs
- Deploy them to devices via SSH
- Rotate local keys (and track that the remote needs updating)
- Track deployment status
- Manage multiple external VPNs across multiple devices

## Core Principles

### 1. Complete Separation from Mesh

Extramural configs have **no relationship** to the intramural mesh:

- They don't appear in mesh topology views
- They don't participate in mesh config generation
- They don't share IP address allocation
- They are managed through a completely separate menu

### 2. Shared SSH Infrastructure

The **only** point of contact between extramural and intramural is SSH configuration:

- SSH host configurations are first-class, durable entities
- Both mesh entities and extramural local peers can reference the same SSH host
- SSH configs survive deletion of entities that reference them
- When adding a new entity, if a matching SSH config exists, offer to reuse it

### 3. You Control Only the Local End

For extramural configs:

- **You control**: Your private key, your interface configuration
- **Sponsor controls**: Their public key, their endpoint, your assigned IP, AllowedIPs

This means:

- You CAN rotate your local keys (then manually notify sponsor)
- You CANNOT rotate sponsor's keys
- You CAN deploy configs to your devices
- You CANNOT deploy to sponsor's infrastructure

## Data Model

### Entity Hierarchy

```
Sponsor (Vendor)
└── Local Peer (Device)
    └── Extramural Config
        └── Extramural Peer(s) (Sponsor's servers)
```

Primary navigation is **Sponsor → Local Peer → Config**, with a pivot view available to browse **Local Peer → Configs**.

### SSH Host (Shared Resource)

SSH configurations are independent, durable entities that can be referenced by both mesh and extramural systems.

```sql
CREATE TABLE ssh_host (
    id INTEGER PRIMARY KEY,

    -- Identity
    name TEXT NOT NULL UNIQUE,              -- "catapult", "xeon", "vpn-server"

    -- Connection details
    ssh_host TEXT NOT NULL,                 -- IP or hostname: 192.168.1.50, catapult.local
    ssh_port INTEGER DEFAULT 22,
    ssh_user TEXT,                          -- root, admin, etc.
    ssh_key_path TEXT,                      -- ~/.ssh/id_ed25519 (optional)

    -- Deployment target
    config_directory TEXT DEFAULT '/etc/wireguard',

    -- Metadata
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

**Lifecycle rules:**

- SSH hosts are NEVER automatically deleted when referencing entities are deleted
- When adding a mesh remote or extramural local_peer, if a name-matching SSH host exists, prompt to use it
- SSH hosts can only be explicitly deleted via dedicated management
- Warn on explicit delete if any entities still reference the SSH host

### Sponsor (Vendor)

Represents an external VPN provider or service.

```sql
CREATE TABLE sponsor (
    id INTEGER PRIMARY KEY,

    -- Identity
    name TEXT NOT NULL UNIQUE,              -- "FastestVPN", "Mullvad", "Work VPN"

    -- Optional details
    website TEXT,                           -- https://mullvad.net
    support_url TEXT,                       -- Where to update keys, manage account
    notes TEXT,                             -- Free-form notes

    -- Metadata
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### Local Peer

Represents a device you control that can receive extramural configs.

```sql
CREATE TABLE local_peer (
    id INTEGER PRIMARY KEY,

    -- Identity (GUID survives renames)
    permanent_guid TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL UNIQUE,              -- "catapult", "xeon", "phone"

    -- SSH deployment (optional - phone won't have SSH)
    ssh_host_id INTEGER REFERENCES ssh_host(id) ON DELETE SET NULL,

    -- Metadata
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

**Design notes:**

- `ssh_host_id` is nullable (phones and tablets don't have SSH)
- `ssh_host_id` uses SET NULL on delete (don't cascade-delete local_peer if SSH host is removed)
- `permanent_guid` survives renames for audit trail consistency

### Extramural Config

The actual WireGuard configuration, linking a local peer to a sponsor.

```sql
CREATE TABLE extramural_config (
    id INTEGER PRIMARY KEY,

    -- Relationships
    local_peer_id INTEGER NOT NULL REFERENCES local_peer(id) ON DELETE CASCADE,
    sponsor_id INTEGER NOT NULL REFERENCES sponsor(id) ON DELETE CASCADE,

    -- Identity (first local public key, survives local key rotations)
    permanent_guid TEXT NOT NULL UNIQUE,

    -- Interface naming
    interface_name TEXT,                    -- "wg-mullvad", "wg-work" (for wg-quick)

    -- Local Interface (what YOU control)
    local_private_key TEXT NOT NULL,
    local_public_key TEXT NOT NULL,         -- Derived from private key

    -- Assigned by sponsor (you don't control these)
    assigned_ipv4 TEXT,                     -- 10.66.44.5/32
    assigned_ipv6 TEXT,                     -- fd00::5/128

    -- Optional interface settings
    dns_servers TEXT,                       -- Comma-separated: 1.1.1.1, 8.8.8.8
    listen_port INTEGER,                    -- Usually NULL for clients
    mtu INTEGER,
    table_setting TEXT,                     -- Routing table (rare)

    -- Deployment tracking
    config_path TEXT,                       -- /etc/wireguard/wg-mullvad.conf
    last_deployed_at TIMESTAMP,             -- NULL = never deployed

    -- Key rotation state
    pending_remote_update BOOLEAN DEFAULT 0, -- Local key changed, sponsor needs new pubkey
    last_key_rotation_at TIMESTAMP,

    -- Metadata
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    UNIQUE(local_peer_id, sponsor_id)       -- One config per device per sponsor
);
```

**Design notes:**

- `permanent_guid` is the first `local_public_key` ever generated, used for audit trail
- `pending_remote_update` tracks when you've rotated local keys but haven't yet updated the sponsor
- `last_deployed_at` is set on creation if user confirms config is already deployed

### Extramural Peer

The remote peer(s) in an extramural config. Some sponsors provide multiple server options.

```sql
CREATE TABLE extramural_peer (
    id INTEGER PRIMARY KEY,
    config_id INTEGER NOT NULL REFERENCES extramural_config(id) ON DELETE CASCADE,

    -- Peer identity (sponsor's server)
    name TEXT,                              -- "US-West", "Frankfurt", "Exit-1"

    -- Connection details (controlled by sponsor)
    public_key TEXT NOT NULL,               -- Sponsor's public key
    endpoint TEXT,                          -- server.mullvad.net:51820

    -- Routing (controlled by sponsor's instructions)
    allowed_ips TEXT NOT NULL,              -- Usually "0.0.0.0/0, ::/0"

    -- Optional settings
    preshared_key TEXT,                     -- If sponsor provides one
    persistent_keepalive INTEGER,           -- Usually 25 for NAT traversal

    -- Active peer selection
    is_active BOOLEAN DEFAULT 0,            -- Which peer is used in generated config

    -- Metadata
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Ensure exactly one active peer per config
CREATE TRIGGER ensure_single_active_peer
AFTER UPDATE OF is_active ON extramural_peer
WHEN NEW.is_active = 1
BEGIN
    UPDATE extramural_peer
    SET is_active = 0
    WHERE config_id = NEW.config_id
    AND id != NEW.id;
END;
```

**Design notes:**

- Multiple peers per config supports providers with multiple server endpoints
- `is_active` determines which peer appears in the generated config
- Trigger ensures only one peer is active at a time

### PostUp/PostDown for Extramural

Reuse the existing `command_pair` table with extended entity support:

```sql
-- Add extramural support to command_pair
ALTER TABLE command_pair ADD COLUMN extramural_config_id INTEGER
    REFERENCES extramural_config(id) ON DELETE CASCADE;

-- Update entity_type to include 'extramural_config'
-- Existing values: 'coordination_server', 'subnet_router'
-- New value: 'extramural_config'
```

Common use cases for extramural PostUp/PostDown:

- **Kill switch**: Block traffic if VPN drops
- **DNS leak protection**: Force DNS through tunnel
- **Split tunneling**: Route only certain traffic through VPN

## Mesh Schema Modifications

To enable SSH host sharing, modify existing mesh entities:

```sql
-- Coordination server already has ssh_* fields, add optional reference
ALTER TABLE coordination_server ADD COLUMN ssh_host_id INTEGER
    REFERENCES ssh_host(id) ON DELETE SET NULL;

-- Subnet router already has ssh_* fields, add optional reference
ALTER TABLE subnet_router ADD COLUMN ssh_host_id INTEGER
    REFERENCES ssh_host(id) ON DELETE SET NULL;

-- Remote doesn't currently have SSH, but could in future
-- (typically remotes are phones/laptops that don't need SSH deployment)
```

**Migration strategy:**

1. Create `ssh_host` table
2. For existing CS and SNR with ssh_* fields populated, create ssh_host entries
3. Link via new ssh_host_id column
4. Keep legacy ssh_* columns for backwards compatibility during transition

## Operations

### Import Existing Config

Parse an existing .conf file from a sponsor.

**Flow:**

1. User provides path to .conf file
2. Parse [Interface] section:
   - Extract PrivateKey → `local_private_key`
   - Derive PublicKey → `local_public_key`, `permanent_guid`
   - Extract Address → `assigned_ipv4`, `assigned_ipv6`
   - Extract DNS → `dns_servers`
   - Extract ListenPort, MTU, Table if present
3. Parse [Peer] section(s):
   - Extract PublicKey, Endpoint, AllowedIPs, PresharedKey, PersistentKeepalive
   - Create `extramural_peer` entries
4. Select or create sponsor
5. Select or create local peer
6. Ask: "Is this config already deployed on [device]?"
   - If yes: `last_deployed_at = now()`
   - If no: `last_deployed_at = NULL`
7. Save to database

**Parser integration:**

Reuse existing `WireGuardParser` from `v1/parser.py` — it already handles:

- [Interface] and [Peer] section parsing
- All standard fields
- Comments (which we can optionally preserve as notes)
- Unknown fields (which we preserve)

### Create New Config

For cases where user generates their own keypair and will provide pubkey to sponsor.

**Flow:**

1. Select or create sponsor
2. Select or create local peer
3. Generate keypair (`wg genkey | wg pubkey`)
4. Display public key prominently:
   ```
   Your public key (give this to sponsor):

     abc123xyz...

   ```
5. User enters details from sponsor:
   - Assigned IP (required)
   - DNS servers (optional)
   - Sponsor's public key (required)
   - Sponsor's endpoint (required)
   - AllowedIPs (default: 0.0.0.0/0, ::/0)
   - Preshared key (if provided)
6. Ask: "Is this config already deployed?"
7. Save to database

### Rotate Local Key

Replace your keypair (then manually update sponsor).

**Flow:**

1. Generate new keypair
2. Update `local_private_key`, `local_public_key`
3. Set `pending_remote_update = true`
4. Set `last_key_rotation_at = now()`
5. Display prominently:
   ```
   ⚠ LOCAL KEY ROTATED

   Your new public key:

     xyz789abc...

   You must update this at your sponsor's portal/support.
   Until you do, this config will not connect.

   Press Enter when you've updated the sponsor...
   ```
6. After user confirms: `pending_remote_update = false`
7. Optionally deploy updated config

**Note:** `permanent_guid` does NOT change on local key rotation — it's the original pubkey for audit purposes.

### Deploy Config

Generate .conf file and push to device via SSH.

**Flow:**

1. Generate config content from database
2. Connect via SSH (using linked `ssh_host`)
3. Write to `config_path` (default: `/etc/wireguard/{interface_name}.conf`)
4. Update `last_deployed_at = now()`
5. Optionally restart interface: `wg-quick down {interface}; wg-quick up {interface}`

**Config generation:**

```ini
# Generated by WireGuard Friend
# Sponsor: {sponsor.name}
# Config: {local_peer.name}/{sponsor.name}
# Generated: {timestamp}

[Interface]
PrivateKey = {local_private_key}
Address = {assigned_ipv4}, {assigned_ipv6}
DNS = {dns_servers}
# MTU, ListenPort, Table if set

# PostUp/PostDown if configured

[Peer]
# {active_peer.name}
PublicKey = {active_peer.public_key}
Endpoint = {active_peer.endpoint}
AllowedIPs = {active_peer.allowed_ips}
PresharedKey = {active_peer.preshared_key}  # if set
PersistentKeepalive = {active_peer.persistent_keepalive}  # if set
```

### Switch Active Peer

Change which sponsor server endpoint is used.

**Flow:**

1. List available peers for config
2. User selects new active peer
3. Update `is_active` flags (trigger handles exclusivity)
4. Regenerate config
5. Optionally deploy

### Update Peer Details

When sponsor changes their endpoint or rotates their key.

**Flow:**

1. User provides new endpoint or public key
2. Update `extramural_peer` record
3. Regenerate config
4. Optionally deploy

## TUI Structure

### Main Menu Addition

```
WIREGUARD FRIEND - MAIN MENU

  1. Network Status
  2. List All Peers
  3. Add Peer
  4. Remove Peer
  5. Rotate Keys
  6. History
  7. Extramural                    ← NEW
  8. Generate Configs
  9. Deploy Configs

  q. Quit
```

### Extramural Main Menu

```
EXTRAMURAL

Manage external WireGuard configs (commercial VPNs, etc.)

  1. View by Sponsor              ← Primary hierarchy
  2. View by Local Peer           ← Pivot view

  S. Manage Sponsors
  P. Manage Local Peers
  H. Manage SSH Hosts             ← Shared resource management

  B. Back

Choice:
```

### View by Sponsor (Primary)

```
EXTRAMURAL - BY SPONSOR

  1. FastestVPN     (3 local peers)
  2. Mullvad        (2 local peers)
  3. Work VPN       (1 local peer)

  A. Add Sponsor
  B. Back

Choice: 1

───────────────────────────────────────────────────────────────────────

FASTESTVPN
https://fastestvpn.com

Local Peers:
  1. catapult    [US-West]       deployed 2024-11-28 14:32
  2. xeon        [Frankfurt]     deployed 2024-11-15 09:17
  3. phone       [US-East]       never deployed

  A. Add Config for Existing Peer
  N. Add Config for New Peer
  I. Import Config File
  E. Edit Sponsor Details
  R. Remove Sponsor
  B. Back

Choice: 1

───────────────────────────────────────────────────────────────────────

FASTESTVPN → CATAPULT

Interface: wg-fastestvpn
Your Public Key: abc123xyz789...
Assigned IP: 10.66.44.5/32
Last Deployed: 2024-11-28 14:32

Available Peers:
  ● US-West       us-west.fastestvpn.com:51820    (active)
  ○ US-East       us-east.fastestvpn.com:51820
  ○ Frankfurt     frankfurt.fastestvpn.com:51820

  1. Switch Active Peer
  2. Rotate Local Key
  3. Deploy
  4. View Full Config
  5. Edit Config
  6. Remove Config
  B. Back

Choice:
```

### View by Local Peer (Pivot)

```
EXTRAMURAL - BY LOCAL PEER

  1. catapult     (3 sponsors)    root@catapult.local
  2. xeon         (2 sponsors)    admin@192.168.1.50
  3. phone        (1 sponsor)     [no SSH]

  A. Add Local Peer
  B. Back

Choice: 1

───────────────────────────────────────────────────────────────────────

CATAPULT
SSH: root@catapult.local:22
Config Directory: /etc/wireguard

Configs:
  1. FastestVPN   [US-West]       deployed 2024-11-28 14:32
  2. Mullvad      [Frankfurt]     deployed 2024-11-15 09:17
  3. Work VPN     [HQ]            never deployed

  A. Add Config
  I. Import Config File
  D. Deploy All Configs
  E. Edit Local Peer
  R. Remove Local Peer
  B. Back

Choice:
```

### Manage Sponsors

```
MANAGE SPONSORS

  1. FastestVPN     https://fastestvpn.com
  2. Mullvad        https://mullvad.net
  3. Work VPN       (no website)

  A. Add Sponsor
  B. Back

Choice: 1

───────────────────────────────────────────────────────────────────────

EDIT SPONSOR: FASTESTVPN

Current values:
  Name: FastestVPN
  Website: https://fastestvpn.com
  Support URL: https://support.fastestvpn.com
  Notes: (none)

  1. Edit Name
  2. Edit Website
  3. Edit Support URL
  4. Edit Notes
  R. Remove Sponsor (will delete all configs!)
  B. Back

Choice:
```

### Manage Local Peers

```
MANAGE LOCAL PEERS

  1. catapult     SSH: root@catapult.local
  2. xeon         SSH: admin@192.168.1.50
  3. phone        [no SSH]

  A. Add Local Peer
  B. Back

Choice: 1

───────────────────────────────────────────────────────────────────────

EDIT LOCAL PEER: CATAPULT

Current values:
  Name: catapult
  SSH Host: catapult.local (root@catapult.local:22)
  Notes: Main workstation

  1. Edit Name
  2. Change SSH Host Link
  3. Edit Notes
  R. Remove Local Peer (will delete all configs!)
  B. Back

Choice:
```

### Manage SSH Hosts

```
SSH HOSTS

These are shared between mesh and extramural configs.

  1. catapult         root@catapult.local:22        /etc/wireguard
  2. xeon             admin@192.168.1.50:22         /etc/wireguard
  3. vpn-server       root@vpn.example.com:22       /etc/wireguard

  A. Add SSH Host
  B. Back

Choice: 1

───────────────────────────────────────────────────────────────────────

EDIT SSH HOST: CATAPULT

Current values:
  Name: catapult
  Host: catapult.local
  Port: 22
  User: root
  Key Path: ~/.ssh/id_ed25519
  Config Directory: /etc/wireguard

Used by:
  • Extramural: catapult (local peer)
  • Mesh: (none)

  1. Edit Host
  2. Edit Port
  3. Edit User
  4. Edit Key Path
  5. Edit Config Directory
  T. Test Connection
  R. Remove SSH Host
  B. Back

Choice:
```

### Pending Remote Update Warning

When a config has `pending_remote_update = true`, show warning in all views:

```
FASTESTVPN → CATAPULT

⚠ PENDING REMOTE UPDATE
Your local key was rotated. Update your public key at sponsor.
New public key: xyz789abc...

Interface: wg-fastestvpn
...
```

## What's NOT Supported (Explicit)

For extramural configs, you CANNOT:

| Operation | Why Not |
|-----------|---------|
| Rotate sponsor's keys | You don't control their infrastructure |
| Add/remove peers on sponsor side | You don't control their infrastructure |
| Change your assigned IP | Sponsor assigns this |
| Enforce access levels | Sponsor's AllowedIPs determines what you can reach |
| Deploy to sponsor's servers | You don't have access |
| View sponsor's interface status | You don't have access |
| Include in mesh topology views | Completely separate system |
| Automatic key sync with sponsor | Would require API integration |

## CLI Commands

In addition to TUI, provide CLI commands:

```bash
# List all extramural configs
wf extramural list

# List by sponsor
wf extramural list --sponsor mullvad

# List by local peer
wf extramural list --peer catapult

# Import config
wf extramural import /path/to/config.conf --sponsor "FastestVPN" --peer catapult

# Create new config (interactive)
wf extramural create --sponsor "FastestVPN" --peer catapult

# Rotate local key
wf extramural rotate-key catapult/fastestvpn

# Deploy config
wf extramural deploy catapult/fastestvpn

# Deploy all configs for a peer
wf extramural deploy catapult --all

# Switch active peer
wf extramural switch-peer catapult/fastestvpn us-east

# Show config details
wf extramural show catapult/fastestvpn

# Generate config file to stdout
wf extramural generate catapult/fastestvpn

# Manage sponsors
wf extramural sponsor add "New VPN"
wf extramural sponsor list
wf extramural sponsor remove "Old VPN"

# Manage local peers
wf extramural peer add catapult --ssh-host catapult
wf extramural peer list
wf extramural peer remove catapult

# Manage SSH hosts (shared)
wf ssh-host add catapult --host catapult.local --user root
wf ssh-host list
wf ssh-host test catapult
wf ssh-host remove catapult
```

## State Tracking

### Separate from Mesh State

Extramural configs are tracked separately from mesh state:

```sql
CREATE TABLE extramural_state_snapshot (
    id INTEGER PRIMARY KEY,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    description TEXT,
    snapshot_data TEXT NOT NULL  -- JSON: all configs at this point
);

CREATE TABLE extramural_state_change (
    id INTEGER PRIMARY KEY,
    snapshot_id INTEGER NOT NULL REFERENCES extramural_state_snapshot(id),
    change_type TEXT NOT NULL,   -- 'config_added', 'config_removed', 'key_rotated', 'deployed'
    entity_type TEXT NOT NULL,   -- 'sponsor', 'local_peer', 'config', 'peer'
    entity_id INTEGER,
    entity_name TEXT,
    old_value TEXT,
    new_value TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### Tracked Events

- Sponsor added/removed/edited
- Local peer added/removed/edited
- Config imported/created/removed
- Local key rotated
- Pending remote update cleared
- Config deployed
- Active peer switched
- Extramural peer added/removed/updated

## Security Considerations

### Private Key Storage

Extramural configs store private keys in the database, same as mesh configs:

- Database should be protected with appropriate file permissions
- Consider encryption at rest for production deployments
- Backup strategy should account for sensitive key material

### Imported Configs

When importing configs:

- Warn if config contains unusual fields
- Validate key formats
- Check for obviously malformed endpoints

### SSH Deployment

- Support key-based authentication (preferred)
- Never store SSH passwords
- Verify host keys on first connection
- Log all deployment operations

## Migration Path

For existing users:

1. **Schema migration**: Add new tables (no changes to existing data)
2. **SSH host extraction**: Offer to create ssh_host entries from existing CS/SNR ssh_* fields
3. **Gradual adoption**: Users can start using extramural without affecting mesh

## Implementation Order

### Phase 1: Data Model

1. Create `ssh_host` table
2. Create `sponsor` table
3. Create `local_peer` table
4. Create `extramural_config` table
5. Create `extramural_peer` table
6. Add extramural support to `command_pair`
7. Add `ssh_host_id` to mesh entities (optional FK)

### Phase 2: Core Operations

1. Import existing config (parser integration)
2. Create new config (with keypair generation)
3. Generate config file from database
4. Local key rotation
5. SSH deployment

### Phase 3: TUI Integration

1. Add "Extramural" to main menu
2. Implement "View by Sponsor" flow
3. Implement "View by Local Peer" flow
4. Implement sponsor management
5. Implement local peer management
6. Implement SSH host management
7. Implement config detail views
8. Implement all config operations

### Phase 4: CLI Commands

1. `wf extramural list`
2. `wf extramural import`
3. `wf extramural create`
4. `wf extramural deploy`
5. `wf extramural rotate-key`
6. `wf extramural switch-peer`
7. `wf ssh-host` commands

### Phase 5: Polish

1. State tracking integration
2. Pending remote update warnings
3. Deployment status display
4. Error handling and validation
5. Documentation

## Relationship to Exit Node Feature

This feature is **independent** of the exit node feature (see `exit-node-design.md`):

| Aspect | Exit Nodes (Intramural) | Extramural Configs |
|--------|------------------------|-------------------|
| Control | You control both ends | You control local end only |
| Relationship to mesh | Part of mesh topology | Completely separate |
| Key rotation | Full rotation both ends | Local only |
| Deployment | Deploy to your exit server | Deploy to your device |
| Use case | Self-hosted exit for mesh remotes | External VPN service |

Both features can coexist:

- `wg0` → Mesh connection to your CS
- `wg-exit` → On-mesh exit node (future)
- `wg-mullvad` → Extramural commercial VPN

A device might use the mesh for accessing home resources and an extramural config for general internet privacy — completely independent tunnels.

## Open Questions

### Resolved

1. **Q: How to organize configs?**
   A: Sponsor → Local Peer → Config hierarchy, with pivot view by Local Peer

2. **Q: How to handle SSH sharing?**
   A: SSH hosts are independent, durable entities; both mesh and extramural reference them

3. **Q: How to track deployment status?**
   A: Simple `last_deployed_at` timestamp, set on creation if user confirms already deployed

4. **Q: Live status checking?**
   A: Not supported — just deployment timestamps

### Future Considerations

1. **API integration with sponsors**: Some providers have APIs for key updates. Could automate `pending_remote_update` resolution. Low priority.

2. **Config sync across devices**: If same sponsor config on multiple devices, could sync peer selections. Low priority.

3. **Backup/export**: Export all extramural configs for backup purposes. Medium priority.

4. **Import from provider account**: Some providers let you download all configs at once. Could batch import. Low priority.
