# WireGuard Friend

**Complete WireGuard VPN management with perfect configuration fidelity.**

WireGuard Friend imports your existing WireGuard configurations, stores them in SQLite with raw block preservation, and provides powerful maintenance capabilities—all while ensuring generated configs are **byte-for-byte identical** to your originals.

## Why WireGuard Friend?

- 🎯 **Perfect Fidelity**: Reconstructed configs match originals exactly
- 🔒 **Raw Block Storage**: Original text preserved, never parsed or modified  
- 🛡️ **Sacred PostUp/PostDown**: Rules stored as monolithic blocks
- 📊 **SQLite Database**: Queryable structured data + raw blocks
- 🔑 **Key Rotation**: Atomic updates to both peer and coordinator
- 📱 **QR Code Generation**: Easy mobile device setup
- 🚀 **SSH Deployment**: Push configs directly to servers
- 🎚️ **Access Levels**: Control what each peer can access

## Quick Start

```bash
# 1. Import existing configurations
./wg-friend-onboard-v2.py --import-dir import/ --yes

# 2. Verify perfect reconstruction
diff import/coordination.conf output/coordination.conf
# (no output = byte-for-byte match)

# 3. View your network
python3 test-maintain.py

# 4. Interactive maintenance
./wg-friend-maintain.py
```

See **[QUICK_START.md](QUICK_START.md)** for detailed walkthrough.

## Architecture

### Raw Block Storage + Structured Data

WireGuard Friend stores configurations in **two complementary forms**:

1. **Raw Blocks** (exact text from files) - For perfect reconstruction
2. **Structured Data** (extracted fields) - For queries and logic

```
Config File → Parser → ┌─ Raw Block (byte-for-byte preservation)
                       └─ Structured Data (IPs, keys, networks)
                       
Database → Reconstructor → Config File (identical to original)
```

### Key Design Decisions

- **PostUp/PostDown**: Never parsed, stored as exact text
- **Multi-line comments**: Preserved with original formatting
- **Peer order**: Maintained from original config
- **Private keys**: Stored securely, masked in display only
- **No YAML, No Git**: Just SQLite + raw blocks

See **[ARCHITECTURE.md](ARCHITECTURE.md)** for detailed design.

## Features

### Import System (`wg-friend-onboard-v2.py`)

5-phase workflow:
1. **Parse & Classify** - Auto-detect CS/SN/clients
2. **CS Confirmation** - Review network, rules, SSH
3. **SN Confirmation** - Match routers, identify LANs
4. **Peer Review** - Match clients, set access levels
5. **Verification** - Reconstruct and verify byte-for-byte

Result: All configs preserved in database + verified output files

### Maintenance System (`wg-friend-maintain.py`)

Interactive menu:
- Manage Coordination Server (view, export, deploy)
- Manage Subnet Routers (configs, key rotation)
- Manage Peers (QR codes, key rotation, configs)
- Create New Peer (auto IP allocation)
- Deploy Configs (SSH with backup)

### Access Levels

| Level | AllowedIPs |
|-------|------------|
| **full_access** | VPN + all LANs |
| **vpn_only** | Just VPN network |
| **lan_only** | VPN + specific LANs |
| **custom** | User-defined (future) |

## Command Reference

### Import

```bash
./wg-friend-onboard-v2.py [OPTIONS]

  --import-dir PATH     Config directory (default: import/)
  --db PATH            Database path (default: wg-friend.db)  
  --clear-db           Clear database before import
  -y, --yes            Auto-confirm prompts
```

### Maintenance

```bash
./wg-friend-maintain.py [OPTIONS]

  --db PATH            Database path (default: wg-friend.db)
```

### Database Queries

```bash
# List all peers
sqlite3 wg-friend.db "SELECT name, ipv4_address, access_level FROM peer;"

# Find peers without client configs
sqlite3 wg-friend.db "SELECT name FROM peer WHERE raw_interface_block IS NULL;"

# Subnet routers with LANs
sqlite3 wg-friend.db "
  SELECT sn.name, lan.network_cidr  
  FROM subnet_router sn
  JOIN sn_lan_networks lan ON sn.id = lan.sn_id;
"

# Check peer order
sqlite3 wg-friend.db "SELECT position, peer_public_key FROM cs_peer_order ORDER BY position;"

# Recently rotated keys
sqlite3 wg-friend.db "SELECT name, last_rotated FROM peer WHERE last_rotated IS NOT NULL ORDER BY last_rotated DESC;"
```

## Examples

### Create New Mobile Client

```bash
./wg-friend-maintain.py
# [4] Create New Peer
# Name: alice-iphone
# Access: [1] Full access  
# Generate QR: Yes

# Result:
# - output/alice-iphone.conf
# - output/alice-iphone-qr.png
# - Updated CS config ready to deploy
```

### Rotate Compromised Key

```bash
./wg-friend-maintain.py
# [3] Manage Peers → Select peer → [3] Rotate Keys

# Then deploy:
# - New client config to device
# - Updated CS config to server
```

### Deploy to Server

```bash
./wg-friend-maintain.py
# [1] Manage Coordination Server → [3] Deploy to Server

# This will:
# - Backup existing config
# - Upload new config
# - Set permissions (600)
# - Restart WireGuard (optional)
```

## Project Structure

```
wireguard-friend/
├── README.md                    # This file
├── QUICK_START.md               # Detailed walkthrough
├── ARCHITECTURE.md              # Design decisions
├── wg-friend-onboard-v2.py     # Import script
├── wg-friend-maintain.py       # Maintenance script
├── wg-friend.db                # SQLite database
├── src/
│   ├── database.py             # DB operations (442 lines)
│   ├── raw_parser.py           # Raw block extraction (358 lines)
│   ├── keygen.py               # Key generation
│   ├── ssh_client.py           # SSH deployment
│   └── qr_generator.py         # QR code generation
├── import/                     # Place configs here for import
└── output/                     # Generated configs
```

## Testing

Verify perfect fidelity:

```bash
# Import configs
./wg-friend-onboard-v2.py --clear-db --import-dir import/ --yes

# Verify byte-for-byte match
diff import/coordination.conf output/coordination.conf
# (no output = success)

# Check database
python3 test-maintain.py

# Create test peer
python3 demo-new-peer.py
```

## Troubleshooting

**"Failed to derive public key"**
```bash
sudo apt install wireguard-tools
which wg
```

**"Database locked"**
```bash
pkill -f wg-friend
rm wg-friend.db-journal
```

**SSH deployment fails**
```bash
# Test access
ssh user@host
# Check sudo perms
ssh user@host sudo -l
```

See **[QUICK_START.md](QUICK_START.md)** troubleshooting section for more.

## Security

- Configs saved with 600 permissions
- Private keys stored in database (protect wg-friend.db)
- Keys masked in terminal display
- No keys transmitted except via SSH deployment
- Backup existing configs before deployment

## Development

```bash
# Test import
./wg-friend-onboard-v2.py --clear-db --import-dir import/ --yes

# Run queries
python3 test-maintain.py

# Test peer creation  
python3 demo-new-peer.py

# Verify reconstruction
diff import/coordination.conf output/coordination.conf
```

## Documentation

- **[QUICK_START.md](QUICK_START.md)** - Complete walkthrough with examples
- **[ARCHITECTURE.md](ARCHITECTURE.md)** - Design decisions and rationale
- **Code docstrings** - Module and function documentation

## Requirements

- Python 3.8+
- WireGuard tools (`wg`, `wg-quick`)
- SQLite 3
- SSH access to servers (for deployment)

```bash
# Install dependencies
pip install -r requirements.txt

# Verify WireGuard
which wg wg-quick
```

## Credits

Built with:
- **SQLite** - Database storage
- **Rich** - Terminal UI
- **WireGuard** - VPN protocol

**Designed with perfect configuration fidelity in mind.**

No YAML. No Git. Just SQLite + Raw Blocks. 🎯
