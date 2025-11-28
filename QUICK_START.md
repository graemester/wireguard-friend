# WireGuard Friend - Quick Start Guide

## Overview

WireGuard Friend is a management system for WireGuard VPN networks. It imports existing configs or helps you create new ones, stores everything in SQLite, and provides tools for peer management, key rotation, and deployment.

## Quick Start

### 1. Choose Your Setup Path

**Option A: Import Existing Configs** (if you already have WireGuard running)

```bash
# Gather your existing configs into import/ directory
mkdir -p import
scp user@your-vps:/etc/wireguard/wg0.conf import/coordination.conf
scp user@your-router:/etc/wireguard/wg0.conf import/router.conf
cp ~/your-client-configs/*.conf import/  # Optional

# Run onboarding (detects and imports everything)
./wg-friend-onboard.py --import-dir import/
```

**Option B: Create from Scratch** (new WireGuard setup)

```bash
# Just run onboarding with empty import/ directory
mkdir -p import
./wg-friend-onboard.py --import-dir import/
# → Wizard mode activates automatically when no configs found
```

The wizard will guide you through:
1. **Coordination Server** - Public VPS endpoint, VPN networks
2. **Subnet Routers** - Optional LAN gateways with PostUp/PostDown rules
3. **Initial Peers** - Client devices with access levels

Both routes will:
- ✅ Parse and classify configs (CS, subnet routers, clients)
- ✅ Derive public keys from private keys
- ✅ Match clients to CS peers
- ✅ Save everything to SQLite database

### 2. View Your Network

Use maintenance mode to view your network:

```bash
./wg-friend-maintain.py
# Select [5] List All Entities
```

Or query the database directly:
```bash
sqlite3 wg-friend.db "SELECT name, ipv4_address, access_level FROM peer;"
```

### 3. Maintenance Mode

Run interactive maintenance:

```bash
./wg-friend-maintain.py
```

Menu options:
- **[1] Manage Coordination Server** - View, export, deploy
- **[2] Manage Subnet Routers** - View config, rotate keys, deploy
- **[3] Manage Peers** - View config, generate QR, rotate keys
- **[4] Create New Peer** - Auto-assign IPs, generate keys
- **[5] List All Entities** - Overview of network
- **[6] Deploy Configs** - Push to servers (local or remote)
- **[7] SSH Setup** - Interactive key generation and installation

## SSH Setup (One-Time)

Before deploying configs to remote servers, set up SSH authentication:

```bash
./wg-friend-maintain.py
# Select [7] SSH Setup (Key Generation & Installation)
```

The wizard will:
1. **Generate SSH key** (if needed) - Creates `~/.ssh/wg-friend-TIMESTAMP`
2. **Install to coordination server** - Prompts for password once
3. **Install to subnet routers** - Prompts for each router
4. **Test authentication** - Verifies keys work

**Note:** SSH setup is **not needed** if you're running the script on the target server itself (it will use local sudo instead).

### Key Reuse
The wizard is smart about keys:
- Tests all existing `wg-friend-*` keys before creating new ones
- Reuses working keys (no password prompt needed)
- Only creates new keys when necessary
- One key can work for multiple servers

## Common Operations

### Create a New Peer

```bash
./wg-friend-maintain.py
# Select [4] Create New Peer
```

This will:
1. Find next available IP addresses
2. Generate new keypair
3. Build client config with proper access level
4. Add peer to coordination server
5. Save configs to `output/`

### Rotate Peer Keys

```bash
./wg-friend-maintain.py
# Select [3] Manage Peers
# Select peer
# Select [3] Rotate Keys
```

This will:
1. Generate new keypair
2. Update peer's client config
3. Update coordination server peer entry
4. Mark as rotated with timestamp

### Generate QR Code for Mobile

```bash
./wg-friend-maintain.py
# Select [3] Manage Peers
# Select peer (e.g., iphone16pro)
# Select [2] Generate QR Code
```

Saves QR code to `output/{peer-name}-qr.png`

### Deploy Configuration to Servers

The script automatically detects whether you're deploying **locally** or **remotely**:

#### Deploy Coordination Server
```bash
./wg-friend-maintain.py
# Select [1] Manage Coordination Server
# Select [3] Deploy to Server
```

#### Deploy Subnet Router
```bash
./wg-friend-maintain.py
# Select [2] Manage Subnet Routers
# Select router
# Select [4] Deploy to Server
```

**Local Deployment** (running ON the target server):
- Detects localhost automatically
- Uses `sudo` for operations (no SSH needed)
- Prompts for sudo password if needed
- Faster and works in restricted environments

**Remote Deployment** (deploying to another server):
- Uses SSH key-based authentication
- Requires one-time SSH setup (option 7)
- Connects securely to remote host
- Works from any machine

Both deployment methods:
1. Backup existing config with timestamp
2. Install new config to `/etc/wireguard/wg0.conf`
3. Set proper permissions (`600` - owner read/write only)
4. Optionally restart WireGuard service
5. Verify WireGuard is running

#### Deployment Scenarios

| Where You Run | CS Deploy | Subnet Router Deploy |
|---------------|-----------|----------------------|
| On your laptop | SSH to VPS | SSH to router |
| On the VPS (CS) | **Local (sudo)** | SSH to router |
| On subnet router | SSH to VPS | **Local (sudo)** |

## Access Levels

When creating or updating peers, choose access level:

- **full_access**: All networks (VPN + all LAN subnets)
  - `AllowedIPs = 10.20.0.0/24, fd20::/64, 192.168.10.0/24`

- **vpn_only**: Just the VPN network
  - `AllowedIPs = 10.20.0.0/24, fd20::/64`

- **lan_only**: VPN + specific LAN subnets
  - `AllowedIPs = 10.20.0.0/24, fd20::/64, 192.168.10.0/24`

- **restricted_ip**: Access to specific IPs/ports only

## Database Queries

Query the database directly:

```bash
# List all peers
sqlite3 wg-friend.db "SELECT name, ipv4_address, access_level FROM peer;"

# Find peers needing client configs
sqlite3 wg-friend.db "SELECT name, ipv4_address FROM peer WHERE raw_interface_block IS NULL;"

# List subnet routers and their LANs
sqlite3 wg-friend.db "
  SELECT sn.name, lan.network_cidr
  FROM subnet_router sn
  JOIN sn_lan_networks lan ON sn.id = lan.sn_id;
"
```

## File Structure

```
wireguard-friend/
├── wg-friend-onboard.py        # Import existing configs or create new
├── wg-friend-maintain.py       # Maintenance mode
├── wg-friend.db                # SQLite database
├── src/
│   ├── database.py             # Database operations
│   ├── keygen.py               # Key generation
│   ├── ssh_client.py           # SSH deployment
│   └── qr_generator.py         # QR code generation
├── import/                     # Place configs here for import
└── output/                     # Generated configs
```

## Key Features

- **Key Rotation**: Update both peer and CS configs atomically
- **Auto IP Allocation**: Finds next available IP addresses
- **QR Code Generation**: For easy mobile device setup
- **Smart Deployment**: Automatic local/remote detection
- **SSH Wizard**: Interactive key setup with testing
- **Proper Permissions**: All sensitive files secured (600)
- **Access Levels**: Control what peers can access
- **Restricted IP Access**: Limit peers to specific IPs and ports

## Next Steps

1. **Import your configs**: `./wg-friend-onboard.py --import-dir import/`
2. **Explore maintenance**: `./wg-friend-maintain.py`
3. **Create new peer**: Follow interactive prompts
4. **Deploy to server**: Use SSH deployment feature

## Troubleshooting

### "No coordination server found"
- Run import first: `./wg-friend-onboard.py --import-dir import/`

### "Failed to derive public key"
- Install WireGuard tools: `sudo apt install wireguard-tools`

### Database locked
- Only one process can access database at a time
- Close other instances of the scripts

### SSH deployment fails
- Run SSH setup wizard: `./wg-friend-maintain.py` → option 7
- Verify SSH access manually: `ssh user@host`
- Check SSH key exists: `ls ~/.ssh/wg-friend-*`
- Test key authentication from wizard

### Local deployment requires sudo
- The script needs sudo to modify `/etc/wireguard/`
- You'll be prompted for your password
- Ensure your user has sudo privileges

## Safety Features

- **File Permissions**: All configs saved with 600 (owner read/write only)
- **SSH Keys**: Private keys 600, public keys 644
- **Timestamped Backups**: Before every deployment
- **Confirmation Prompts**: For key rotation and deployment
- **Secure Storage**: Private keys stored securely in database
- **Smart Detection**: Automatically uses local or remote deployment
- **Key Testing**: Tests authentication before declaring success
