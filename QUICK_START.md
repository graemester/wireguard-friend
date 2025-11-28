# WireGuard Friend - Quick Start Guide

## Overview

WireGuard Friend is a complete management system for WireGuard VPN networks with **perfect configuration fidelity**. It imports existing configs, stores them in SQLite with raw block preservation, and provides powerful maintenance capabilities.

## Architecture

### Raw Block Storage + Structured Data
- **Raw Blocks**: Exact text from config files preserved byte-for-byte
- **Structured Data**: Queryable fields extracted for logic (IPs, keys, access levels)
- **Perfect Reconstruction**: Generated configs are **identical** to originals

### Database Schema
- **coordination_server**: VPS hub configuration
- **subnet_router**: Internal LAN gateways
- **peer**: Client devices
- **Raw blocks preserved** for Interface sections and Peer entries
- **PostUp/PostDown rules** stored as sacred monolithic blocks

## Quick Start

### 1. Import Existing Configurations

Place your WireGuard configs in the `import/` directory:
- `coordination.conf` - Your coordination server config
- `wg0.conf` - Subnet router config (optional)
- `*.conf` - Client configs (optional)

Run the import:

```bash
./wg-friend-onboard.py --import-dir import/ --yes
```

This will:
- ✅ Parse and classify configs (CS, subnet routers, clients)
- ✅ Extract raw blocks + structured data
- ✅ Derive public keys from private keys
- ✅ Match clients to CS peers
- ✅ Save everything to SQLite database
- ✅ Reconstruct and verify configs (byte-for-byte match)

### 2. View Your Network

List all entities:

```bash
python3 test-maintain.py
```

Output:
```
Coordination Server:
  Endpoint: wireguard.graeme.host:51820
  Network: 10.66.0.0/24, fd66:6666::/64
  SSH: ged@wireguard.graeme.host:22

Subnet Routers (1):
  Name      IPv4         IPv6            LANs
  icculus   10.66.0.20   fd66:6666::20   192.168.10.0/24

Peers (10):
  Name            IPv4          IPv6           Access        Client Config
  iphone16pro     10.66.0.9     fd66:6666::9   full_access   Yes
  mba15m2         10.66.0.10    fd66:6666::10  full_access   No
  ...
```

### 3. Maintenance Mode

Run interactive maintenance:

```bash
./wg-friend-maintain.py
```

Menu options:
- **[1] Manage Coordination Server** - View, export, deploy
- **[2] Manage Subnet Routers** - View config, rotate keys
- **[3] Manage Peers** - View config, generate QR, rotate keys
- **[4] Create New Peer** - Auto-assign IPs, generate keys
- **[5] List All Entities** - Overview of network
- **[6] Deploy Configs** - Push to servers via SSH

## Common Operations

### Create a New Peer

```bash
python3 demo-new-peer.py
```

This demonstrates:
1. Finding next available IP addresses
2. Generating new keypair
3. Building client config with proper access level
4. Adding peer to coordination server
5. Saving configs to `output/`

Result:
```
✓ Peer 'demo-device' created with ID 12
✓ Client config saved to output/demo-device.conf
✓ Updated CS config saved to output/coordination-updated.conf (12 peers)
```

### Rotate Peer Keys

Interactive mode:
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

### Deploy Configuration to Server

```bash
./wg-friend-maintain.py
# Select [1] Manage Coordination Server
# Select [3] Deploy to Server
```

This will:
1. Backup existing config on server
2. Upload new config via SSH
3. Set proper permissions (600)
4. Optionally restart WireGuard service

## Access Levels

When creating or updating peers, choose access level:

- **full_access**: All networks (VPN + all LAN subnets)
  - `AllowedIPs = 10.20.0.0/24, fd20::/64, 192.168.10.0/24`

- **vpn_only**: Just the VPN network
  - `AllowedIPs = 10.20.0.0/24, fd20::/64`

- **lan_only**: VPN + specific LAN subnets
  - `AllowedIPs = 10.20.0.0/24, fd20::/64, 192.168.10.0/24`

- **custom**: Specific IPs (parking lot for future)

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

# Check peer order
sqlite3 wg-friend.db "
  SELECT position, peer_public_key, is_subnet_router
  FROM cs_peer_order
  ORDER BY position;
"
```

## File Structure

```
wireguard-friend/
├── wg-friend-onboard.py     # Import existing configs
├── wg-friend-maintain.py       # Maintenance mode
├── wg-friend.db                # SQLite database
├── src/
│   ├── database.py             # Database operations
│   ├── raw_parser.py           # Raw block extraction
│   ├── keygen.py               # Key generation
│   ├── ssh_client.py           # SSH deployment
│   └── qr_generator.py         # QR code generation
├── import/                     # Place configs here for import
│   ├── coordination.conf
│   ├── wg0.conf
│   └── *.conf
└── output/                     # Generated configs
    ├── coordination.conf
    ├── demo-device.conf
    └── *.conf
```

## Key Features

✅ **Perfect Fidelity**: Reconstructed configs are byte-for-byte identical to originals
✅ **Raw Block Storage**: Exact text preserved, never parsed or modified
✅ **PostUp/PostDown Sacred**: Rules stored as monolithic blocks
✅ **Multi-line Comments**: Preserved perfectly
✅ **Peer Order**: Original sequence maintained
✅ **Key Rotation**: Update both peer and CS configs atomically
✅ **Auto IP Allocation**: Finds next available IP addresses
✅ **QR Code Generation**: For easy mobile device setup
✅ **SSH Deployment**: Push configs directly to servers
✅ **Access Levels**: Control what peers can access

## Verification

Import preserves ALL peers:

```bash
# Original coordination.conf had 11 peers
wc -c import/coordination.conf
# 2358 import/coordination.conf

# Reconstructed config is IDENTICAL
wc -c output/coordination.conf
# 2358 output/coordination.conf

# Byte-for-byte match
diff import/coordination.conf output/coordination.conf
# (no output = perfect match)
```

## Next Steps

1. **Import your configs**: `./wg-friend-onboard.py --import-dir import/ --yes`
2. **Verify reconstruction**: `diff import/coordination.conf output/coordination.conf`
3. **Explore maintenance**: `./wg-friend-maintain.py`
4. **Create new peer**: Follow interactive prompts
5. **Deploy to server**: Use SSH deployment feature

## Troubleshooting

### "No coordination server found"
- Run import first: `./wg-friend-onboard.py --import-dir import/`

### "Failed to derive public key"
- Install WireGuard tools: `sudo apt install wireguard-tools`

### Database locked
- Only one process can access database at a time
- Close other instances of the scripts

### SSH deployment fails
- Verify SSH access: `ssh user@host`
- Ensure sudo permissions for WireGuard commands
- Check firewall rules

## Safety Features

- Configs saved with 600 permissions (owner read/write only)
- Database backup before destructive operations
- Confirmation prompts for key rotation and deployment
- Original configs preserved in raw blocks
- Private keys stored securely, masked in display only

---

**Built with perfect configuration fidelity in mind.**
