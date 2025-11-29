# WireGuard Friend - Command Reference

Reference for `wg-friend` commands.

## Quick Reference

```bash
# Setup
wg-friend init                    # First-run wizard (new setup)
wg-friend import --cs <file>      # Import existing configs

# Generate Configs
wg-friend generate                # Generate all configs
wg-friend generate --qr           # Generate with QR codes

# Peer Management
wg-friend add peer                # Add remote client (interactive)
wg-friend add router              # Add subnet router (interactive)
wg-friend remove                  # Remove peer (interactive)
wg-friend list                    # List all peers

# Key Rotation
wg-friend rotate                  # Rotate keys (interactive)
wg-friend rotate cs               # Rotate coordination server keys
wg-friend rotate router:1         # Rotate router #1 keys
wg-friend rotate remote:5         # Rotate remote #5 keys

# Deployment
wg-friend deploy                  # Deploy to all hosts (interactive confirm)
wg-friend deploy --host <name>    # Deploy to specific host
wg-friend deploy --restart        # Deploy and restart WireGuard
wg-friend deploy --dry-run        # Show what would be done

# Status & Monitoring
wg-friend status                  # Show network status
wg-friend status --full           # Show full details with patterns

# Interactive Mode
wg-friend maintain                # Launch interactive TUI
```

## Detailed Commands

### `wg-friend init` - First-Run Wizard

Interactive setup for new WireGuard networks.

**Usage:**
```bash
wg-friend init
wg-friend init --db custom.db
```

**What it does:**
- Prompts for coordination server details (endpoint, port, network ranges)
- Creates subnet routers (optional)
- Creates initial remote clients
- Generates keypairs for all entities
- Assigns permanent_guid to each entity
- Creates SQLite database with all configuration

**Example:**
```bash
./v1/wg-friend init

# Answers:
#   Endpoint: vps.example.com
#   Port: 51820
#   VPN Network: 10.66.0.0/24, fd66::/64
#   Add subnet router: yes
#     - home-gateway, 192.168.1.0/24
#   Add 3 remotes:
#     - alice-phone (mobile)
#     - bob-laptop (laptop)
#     - charlie-ipad (mobile)
```

**Output:**
- `wireguard.db` - Database with all entities
- Ready for `wg-friend generate`

---

### `wg-friend import` - Import Existing Configs

Import existing WireGuard configs into v1 database.

**Usage:**
```bash
wg-friend import --cs <file>
wg-friend import --cs coordination.conf --db imported.db
```

**What it does:**
- Parses coordination server config using bracket delimiter rule
- Derives public keys from private keys
- Recognizes PostUp/PostDown patterns (NAT, MSS clamping, etc.)
- Assigns permanent_guid (first public key seen)
- Stores semantic data in database
- Finds all peers in config

**Example:**
```bash
./v1/wg-friend import --cs /etc/wireguard/wg0.conf
```

**Output:**
- `wireguard.db` - Database with imported coordination server
- Coordination server patterns recognized and stored
- Ready for `wg-friend add` to add peers

---

### `wg-friend generate` - Generate Configs

Generate WireGuard configs from database.

**Usage:**
```bash
wg-friend generate
wg-friend generate --qr
wg-friend generate --output custom-dir
wg-friend generate --db custom.db --output generated --qr
```

**Options:**
- `--db <file>` - Database file (default: wireguard.db)
- `--output <dir>` - Output directory (default: generated/)
- `--qr` - Generate QR codes for mobile devices

**What it does:**
- Reads all entities from database
- Generates coordination server config
- Generates subnet router configs
- Generates remote client configs
- Applies PostUp/PostDown patterns
- Creates QR codes for mobile devices (if --qr)

**Example:**
```bash
./v1/wg-friend generate --qr
```

**Output:**
```
generated/
  coordination.conf           # VPS config
  home-gateway.conf           # Router config
  alice-phone.conf            # Client config
  alice-phone.png             # QR code
  bob-laptop.conf
  charlie-ipad.conf
  charlie-ipad.png
```

---

### `wg-friend add` - Add Peers

Add new peers to the network.

**Usage:**
```bash
wg-friend add peer            # Add remote client (interactive)
wg-friend add router          # Add subnet router (interactive)
wg-friend add peer --hostname alice-desktop
```

**Interactive Prompts:**

**For remote clients:**
- Hostname (e.g., alice-phone)
- Device type (mobile/laptop/server)
- Access level (full_access/vpn_only/lan_only)
- Static endpoint (optional, for servers)

**For subnet routers:**
- Hostname (e.g., office-gateway)
- LAN network to advertise (e.g., 10.0.0.0/24)
- LAN interface (default: eth0)
- Static endpoint (optional)

**What it does:**
- Auto-assigns next available VPN IP
- Generates new keypair
- Assigns permanent_guid (public key)
- Stores in database
- Shows next steps (generate, deploy)

**Example:**
```bash
./v1/wg-friend add peer

# Prompts:
#   Hostname: alice-desktop
#   Device type: laptop
#   Access level: full_access
#
# Output:
#   Assigned VPN addresses:
#     IPv4: 10.66.0.35/32
#     IPv6: fd66::23/128
#   ✓ Added remote: alice-desktop (ID: 8)
```

---

### `wg-friend remove` - Remove Peers

Remove/revoke peers from the network.

**Usage:**
```bash
wg-friend remove              # Interactive peer selection
```

**What it does:**
- Lists all current peers
- Prompts for peer type (router/remote)
- Prompts for peer ID
- Prompts for reason (audit trail)
- Confirms deletion
- Logs removal in key_rotation_history
- Deletes peer from database

**Example:**
```bash
./v1/wg-friend remove

# Shows peer list, then:
#   Peer type: remote
#   Peer ID: 8
#   Reason: Device lost
#   Are you sure? yes
#
# Output:
#   ✓ Removed remote: alice-desktop
#   Next steps:
#     1. Regenerate configs: wg-friend generate
#     2. Deploy: wg-friend deploy
```

---

### `wg-friend list` - List Peers

Show all peers in the network.

**Usage:**
```bash
wg-friend list
wg-friend list --db custom.db
```

**Output:**
```
======================================================================
PEERS
======================================================================

Coordination Server:
  coordination-server            10.66.0.1/24         XYZ123...

Subnet Routers (1):
  [ 1] home-gateway               10.66.0.20/32        ABC456...

Remote Clients (3):
  [ 1] alice-phone                10.66.0.30/32        full_access     DEF789...
  [ 2] bob-laptop                 10.66.0.31/32        full_access     GHI012...
  [ 3] charlie-ipad               10.66.0.32/32        full_access     JKL345...
```

---

### `wg-friend rotate` - Rotate Keys

Rotate cryptographic keys while maintaining permanent_guid.

**Usage:**
```bash
wg-friend rotate                        # Interactive
wg-friend rotate cs                     # Coordination server
wg-friend rotate router:1               # Router #1
wg-friend rotate remote:3               # Remote #3
wg-friend rotate cs --reason "Scheduled monthly rotation"
```

**What it does:**
- Shows current public key and permanent_guid
- Generates new keypair
- Updates current_public_key (permanent_guid stays same!)
- Logs rotation in key_rotation_history
- Shows next steps (generate, deploy)

**Example:**
```bash
./v1/wg-friend rotate remote:5

# Shows:
#   Rotate keys for: alice-phone
#     Current Public Key: ABC123...
#     Permanent GUID: ABC123... (unchanged)
#     Reason: Scheduled rotation
#
#   Generate new keypair? yes
#   New Public Key: XYZ789...
#   Apply rotation? yes
#
# Output:
#   ✓ Rotated keys for: alice-phone
#     Old: ABC123...
#     New: XYZ789...
#     GUID: ABC123... (unchanged)
```

**Key Points:**
- permanent_guid NEVER changes (immutable identity)
- current_public_key changes to new key
- Comments stay linked via permanent_guid
- All rotation logged with timestamp and reason

---

### `wg-friend deploy` - SSH Deployment

Deploy configs to remote servers via SSH.

**Usage:**
```bash
wg-friend deploy                        # Deploy to all hosts
wg-friend deploy --host home-gateway    # Deploy to specific host
wg-friend deploy --restart              # Restart WireGuard after deploy
wg-friend deploy --dry-run              # Show what would be done
wg-friend deploy --user admin           # Use different SSH user
```

**Options:**
- `--host <name>` - Deploy to specific host
- `--restart` - Restart WireGuard after deployment
- `--dry-run` - Show what would be done (no changes)
- `--user <name>` - SSH user (default: root)
- `--output <dir>` - Config directory (default: generated/)

**What it does:**
- Reads deployment targets from database (endpoints configured)
- For each target:
  1. Backup existing config (timestamped)
  2. SCP new config to /etc/wireguard/wg0.conf
  3. Optionally restart WireGuard (wg-quick down/up)
- Shows deployment summary

**Example:**
```bash
./v1/wg-friend deploy --restart

# Output:
#   Found 2 deployable host(s):
#     - coordination-server → vps.example.com
#     - home-gateway → 192.168.1.1
#
#   Proceed? yes
#
#   ──────────────────────────────────────────────
#   Deploy: coordination-server (vps.example.com)
#   ──────────────────────────────────────────────
#     Backing up to /etc/wireguard/wg0.conf.backup.20250129_143022
#     ✓ Config deployed
#     ✓ WireGuard restarted
#     ✓ Deploy complete
#
#   ... (repeat for home-gateway) ...
#
#   DEPLOYMENT SUMMARY
#     Total:   2
#     Success: 2
#     Failed:  0
```

**SSH Requirements:**
- SSH key authentication configured
- Root access or sudo permissions
- WireGuard installed on target hosts

---

### `wg-friend status` - Network Status

Show current network status and configuration.

**Usage:**
```bash
wg-friend status                # Basic status
wg-friend status --full         # Full details with patterns
```

**Output:**
```
======================================================================
WIREGUARD NETWORK STATUS
======================================================================

Coordination Server:
  Hostname:      coordination-server
  Endpoint:      vps.example.com:51820
  VPN Network:   10.66.0.0/24, fd66::/64
  VPN Address:   10.66.0.1/24, fd66::1/64
  Public Key:    ABC123...
  Permanent ID:  ABC123...

Subnet Routers (1):
  [1] home-gateway
      VPN Address:   10.66.0.20/32, fd66::14/128
      Endpoint:      Dynamic
      LAN Interface: eth0
      Advertises:    192.168.1.0/24

Remote Clients (3):
  [ 1] alice-phone           10.66.0.30/32      full_access     DEF789...
  [ 2] bob-laptop            10.66.0.31/32      full_access     GHI012...
  [ 3] charlie-ipad          10.66.0.32/32      full_access     JKL345...

======================================================================
RECENT KEY ROTATIONS
======================================================================

  2025-01-29T14:30:22  [Remote] alice-phone
    Old: ABC123...
    New: XYZ789...
    Reason: Scheduled monthly rotation
```

---

### `wg-friend maintain` - Interactive TUI

Launch interactive text-based UI for managing the network.

**Usage:**
```bash
wg-friend maintain
wg-friend maintain --db custom.db
```

**Features:**
- Network status overview
- List all peers
- Add peers (interactive)
- Remove peers (interactive)
- Rotate keys (interactive)
- View rotation history
- Menu-driven navigation

**Menu Options:**
1. Network Status
2. List All Peers
3. Add Peer
4. Remove Peer
5. Rotate Keys
6. Recent Key Rotations
7. Generate Configs (shows command to run)
8. Deploy Configs (shows command to run)
q. Quit

**Example:**
```bash
./v1/wg-friend maintain

# Interactive menu appears:
#   ======================================================================
#   WIREGUARD FRIEND - MAIN MENU
#   ======================================================================
#     1. Network Status
#     2. List All Peers
#     3. Add Peer
#     4. Remove Peer
#     5. Rotate Keys
#     6. Recent Key Rotations
#     7. Generate Configs (requires running separate command)
#     8. Deploy Configs (requires running separate command)
#     q. Quit
#
#   Choice: _
```

---

## Workflow Examples

### New Network Setup

```bash
# 1. Create network
./v1/wg-friend init

# 2. Generate configs
./v1/wg-friend generate --qr

# 3. Deploy to servers
./v1/wg-friend deploy --restart

# 4. Done! Network is live
```

### Import Existing Network

```bash
# 1. Import coordination server
./v1/wg-friend import --cs /etc/wireguard/wg0.conf

# 2. Add existing peers manually
./v1/wg-friend add peer    # repeat for each peer

# 3. Generate updated configs
./v1/wg-friend generate --qr

# 4. Deploy
./v1/wg-friend deploy --restart
```

### Add New User

```bash
# 1. Add peer
./v1/wg-friend add peer
# Enter: alice-desktop, laptop, full_access

# 2. Regenerate configs
./v1/wg-friend generate --qr

# 3. Deploy to coordination server
./v1/wg-friend deploy --host coordination-server --restart

# 4. Give alice-desktop.conf (or QR code) to user
```

### Monthly Key Rotation

```bash
# 1. View current status
./v1/wg-friend status

# 2. Rotate coordination server keys
./v1/wg-friend rotate cs --reason "Monthly rotation"

# 3. Rotate all peer keys
./v1/wg-friend rotate router:1 --reason "Monthly rotation"
./v1/wg-friend rotate remote:1 --reason "Monthly rotation"
# ... repeat for all peers ...

# 4. Regenerate all configs
./v1/wg-friend generate --qr

# 5. Deploy everywhere
./v1/wg-friend deploy --restart

# 6. Verify rotation history
./v1/wg-friend status --full
```

### Interactive Management

```bash
# Launch TUI
./v1/wg-friend maintain

# Navigate menus:
#   - View status
#   - Add/remove peers
#   - Rotate keys
#   - Exit when done

# Then generate and deploy:
./v1/wg-friend generate --qr
./v1/wg-friend deploy --restart
```

---

## Database Location

Default: `wireguard.db` in current directory

Override with `--db <path>` on any command:
```bash
wg-friend --db /path/to/custom.db <command>
```

---

## Generated Configs Location

Default: `generated/` in current directory

Override with `--output <path>` on generate command:
```bash
wg-friend generate --output /path/to/configs
wg-friend deploy --output /path/to/configs
```

---

## Exit Codes

- `0` - Success
- `1` - Error (invalid arguments, missing files, operation failed)

---

## Tips

1. **Always generate after changes:**
   ```bash
   wg-friend add peer && wg-friend generate
   ```

2. **Use dry-run for safety:**
   ```bash
   wg-friend deploy --dry-run
   ```

3. **Backup database before major changes:**
   ```bash
   cp wireguard.db wireguard.db.backup
   ```

4. **View status regularly:**
   ```bash
   wg-friend status
   ```

5. **Use interactive mode for exploration:**
   ```bash
   wg-friend maintain
   ```
