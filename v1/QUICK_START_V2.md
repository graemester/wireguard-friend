# WireGuard Friend v2 - Quick Start

## First Run (New Setup)

```bash
# Just run wg-friend - it auto-detects what to do!
./v2/wg-friend

# If no database or configs found, it automatically launches the wizard
# Answer questions about your network:
#  - VPS endpoint
#  - VPN network ranges
#  - Subnet routers (optional)
#  - Initial clients

# This creates: wireguard.db

# Or explicitly run init:
./v2/wg-friend init
```

## Smart Routing - Just Run `wg-friend`!

**No arguments needed!** WireGuard Friend v2 intelligently routes based on what it finds:

- **Database exists** → Launches interactive TUI (maintenance mode)
- **Configs found, no database** → Suggests import command
- **Clean slate** → Runs init wizard

```bash
# First time - runs wizard
./v2/wg-friend

# After setup - launches TUI
./v2/wg-friend

# It just works!
```

## Generate Configs

```bash
# Generate all configs from database
./v2/wg-friend generate --qr

# Output: generated/
#   coordination.conf
#   home-gateway.conf  (if you have subnet routers)
#   alice-phone.conf
#   alice-phone.png    (QR code)
#   bob-laptop.conf
#   etc.
```

## What's Working - FULL FEATURE PARITY!

✅ **First-run wizard** (`wg-friend init`)
- Interactive setup
- Auto IP allocation
- Keypair generation
- permanent_guid assignment
- Database creation

✅ **Config generation** (`wg-friend generate`)
- Reads from v2 database
- Generates coordination server config
- Generates subnet router configs
- Generates remote client configs
- QR codes for mobile devices
- Perfect fidelity (uses v1's proven templates)

✅ **Import existing configs** (`wg-friend import`)
- Parse existing WireGuard configs
- Extract semantic data
- Recognize PostUp/PostDown patterns
- Assign permanent_guid from derived public keys
- Store in v2 database

✅ **Peer management** (`wg-friend add/remove`)
- Add remote clients (auto IP assignment)
- Add subnet routers (auto IP assignment)
- Remove peers (with audit trail)
- List all peers

✅ **Key rotation** (`wg-friend rotate`)
- Rotate keys for any peer (CS, router, remote)
- Maintains permanent_guid (immutable)
- Logs rotation history with reason
- Interactive or command-line usage

✅ **SSH deployment** (`wg-friend deploy`)
- Deploy to all hosts or specific host
- Automatic config backup before deploy
- Optional WireGuard restart
- Dry-run mode
- SSH key authentication

✅ **Network status** (`wg-friend status`)
- View coordination server details
- List all routers and remotes
- Show recent key rotations
- Display command patterns

✅ **Interactive TUI** (`wg-friend maintain`)
- Menu-driven interface
- Network status view
- Add/remove peers interactively
- Rotate keys interactively
- View rotation history

✅ **permanent_guid system**
- First public key = immutable GUID
- Comments linked via GUID
- Key rotation preserves identity
- Hostname defaults to GUID

## Example Workflow

```bash
# 1. First run setup
./v2/wg-friend init
# Answer:
#   - Endpoint: vps.example.com
#   - Subnet router: yes (home-gateway, 192.168.1.0/24)
#   - Clients: 3 (alice-phone, bob-laptop, charlie-ipad)

# 2. Generate configs
./v2/wg-friend generate --qr

# 3. Deploy (manual for now)
scp generated/coordination.conf root@vps:/etc/wireguard/wg0.conf
scp generated/home-gateway.conf root@gateway:/etc/wireguard/wg0.conf

# 4. Start WireGuard
ssh root@vps 'wg-quick up wg0'
ssh root@gateway 'wg-quick up wg0'

# 5. Mobile devices
# Scan QR codes: generated/alice-phone.png
```

## Key Differences from v1

**v2 Improvements:**
- ✅ permanent_guid system (no more comment mismatches!)
- ✅ Simpler first run (wizard vs manual config files)
- ✅ Semantic database (no raw blocks needed)
- ✅ Key derivation + validation
- ✅ Clean architecture (bracket delimiter → semantic → database)

**Migration:**
- v1 → v2 migration not needed
- v2 is clean break (better architecture)
- Use `wg-friend init` for fresh start
- Can recreate network in minutes

## Database Schema

See `v2/schema_semantic.py` for full schema.

**Key tables:**
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
cd v2
python3 test_permanent_guid.py
python3 test_key_validation.py
```

**Integration tests:**
```bash
cd v2/integration-tests
make test
```

## v2 is Ready For

✅ **First-time users** - `wg-friend init` → configs → deploy
✅ **Existing users** - `wg-friend import` → manage
✅ **Simple networks** - 1 CS + optional SNR + clients
✅ **Complex networks** - Multiple routers, many clients
✅ **Testing** - Integration tests prove it works
✅ **Real deployment** - Full SSH automation with backup
✅ **Peer management** - Add/remove/rotate peers
✅ **Key rotation** - Scheduled or on-demand with audit trail
✅ **Interactive mode** - TUI for easy management

## v2 Has Feature Parity with v1!

All major v1 features are now implemented in v2:
- ✅ First-run setup (improved with wizard)
- ✅ Config generation (same templates as v1)
- ✅ Import existing configs (v1 → v2 compatible)
- ✅ Peer management (add/remove)
- ✅ Key rotation (with permanent_guid!)
- ✅ SSH deployment (with automatic backup)
- ✅ Network status view
- ✅ Interactive TUI mode

**Plus v2 improvements:**
- permanent_guid system (no more comment mismatches!)
- Semantic database (cleaner architecture)
- Key validation (derived from private keys)
- Rotation history (full audit trail)
- Auto IP allocation (no manual tracking)

## Try It Now

```bash
cd /home/ged/wireguard-friend

# Create test setup
./v2/wg-friend init --db test.db

# Generate configs
./v2/wg-friend generate --db test.db --output test-generated --qr

# Check output
ls test-generated/
```

**It works!** 🎉
