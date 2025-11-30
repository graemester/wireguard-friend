# WireGuard Friend - Quick Start

## First Run (New Setup)

```bash
# Run wg-friend - it detects what to do
./v1/wg-friend

# If no database or configs found, it launches the wizard
# Questions about your network:
#  - VPS endpoint
#  - VPN network ranges
#  - Subnet routers (optional)
#  - Initial clients

# Creates: wireguard.db

# Or explicitly run init:
./v1/wg-friend init
```

## Smart Routing

WireGuard Friend routes based on what it finds:

- **Database exists** → Launches interactive TUI (maintenance mode)
- **Configs found, no database** → Suggests import command
- **Clean slate** → Runs init wizard

```bash
# First time - runs wizard
./v1/wg-friend

# After setup - launches TUI
./v1/wg-friend
```

## Generate Configs

```bash
# Generate configs from database
./v1/wg-friend generate --qr

# Output: generated/
#   coordination.conf
#   home-gateway.conf  (if you have subnet routers)
#   alice-phone.conf
#   alice-phone.png    (QR code)
#   bob-laptop.conf
#   etc.
```

## Features

**First-run wizard** (`wg-friend init`)
- Interactive setup
- Auto IP allocation
- Keypair generation
- permanent_guid assignment
- Database creation

**Config generation** (`wg-friend generate`)
- Reads from database
- Generates coordination server config
- Generates subnet router configs
- Generates remote client configs
- QR codes for mobile devices
- Uses WireGuard config templates

**Import existing configs** (`wg-friend import`)
- Parse existing WireGuard configs
- Extract semantic data
- Recognize PostUp/PostDown patterns
- Assign permanent_guid from derived public keys
- Store in database

**Peer management** (`wg-friend add/remove`)
- Add remote clients (auto IP assignment)
- Add subnet routers (auto IP assignment)
- Remove peers (with audit trail)
- List peers

**Key rotation** (`wg-friend rotate`)
- Rotate keys for any peer (CS, router, remote)
- Maintains permanent_guid (immutable)
- Logs rotation history with reason
- Interactive or command-line usage

**SSH deployment** (`wg-friend deploy`)
- Deploy to hosts
- Config backup before deploy
- Optional WireGuard restart
- Dry-run mode
- SSH key authentication

**Network status** (`wg-friend status`)
- View coordination server details
- List routers and remotes
- Show recent key rotations
- Display command patterns

**Interactive TUI** (`wg-friend maintain`)
- Menu-driven interface
- Network status view
- Add/remove peers interactively
- Rotate keys interactively
- View rotation history

**permanent_guid system**
- First public key = immutable GUID
- Comments linked via GUID
- Key rotation preserves identity
- Hostname defaults to GUID

## Example Workflow

```bash
# 1. First run setup
./v1/wg-friend init
# Answer:
#   - Endpoint: vps.example.com
#   - Subnet router: yes (home-gateway, 192.168.1.0/24)
#   - Clients: 3 (alice-phone, bob-laptop, charlie-ipad)

# 2. Generate configs
./v1/wg-friend generate --qr

# 3. Deploy
scp generated/coordination.conf root@vps:/etc/wireguard/wg0.conf
scp generated/home-gateway.conf root@gateway:/etc/wireguard/wg0.conf

# 4. Start WireGuard
ssh root@vps 'wg-quick up wg0'
ssh root@gateway 'wg-quick up wg0'

# 5. Mobile devices
# Scan QR codes: generated/alice-phone.png
```

## Database Schema

See `v1/schema_semantic.py` for schema.

**Tables:**
- `coordination_server` - VPS hub
- `subnet_router` - LAN gateways
- `remote` - Client devices
- `command_pair` - PostUp/PostDown patterns
- `comment` - Semantic comments
- `key_rotation_history` - Key change tracking

**permanent_guid:**
- Every entity has `permanent_guid` (immutable)
- Every entity has `current_public_key` (can rotate)
- Comments link via `permanent_guid` (survive rotations)

## Testing

**Unit tests:**
```bash
cd v1
python3 test_permanent_guid.py
python3 test_key_validation.py
```

**Integration tests:**
```bash
cd v1/integration-tests
make test
```

## Usage Examples

**First-time users** - `wg-friend init` → configs → deploy
**Existing configs** - `wg-friend import` → manage
**Simple networks** - 1 CS + optional SNR + clients
**Complex networks** - Multiple routers, many clients
**SSH deployment** - Automated deployment with backup
**Peer management** - Add/remove/rotate peers
**Key rotation** - On-demand with audit trail
**Interactive mode** - TUI for management

## Try It

```bash
cd /home/ged/wireguard-friend

# Create test setup
./v1/wg-friend init --db test.db

# Generate configs
./v1/wg-friend generate --db test.db --output test-generated --qr

# Check output
ls test-generated/
```
