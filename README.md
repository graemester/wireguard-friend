# WireGuard Friend

**Configuration management system for WireGuard VPN networks with perfect fidelity.**

WireGuard Friend helps you build, manage, and maintain hub-and-spoke WireGuard VPN topologies. Import existing configs or build from scratch, manage peers and subnet routers, rotate keys, and deploy—all while ensuring perfect byte-for-byte configuration fidelity.

## What It Does

WireGuard Friend manages this network architecture:

```
                    ┌─────────────────────┐
                    │  Coordination Server │  (Cloud VPS)
                    │  Public: 1.2.3.4     │
                    │  VPN: 10.66.0.1      │
                    └──────────┬───────────┘
                               │
        ┏━━━━━━━━━━━━━━━━━━━━━━┻━━━━━━━━━━━━━━━━━━━━━━┓
        ┃                                              ┃
   ┌────┴─────┐                                  ┌────┴─────┐
   │  Subnet  │                                  │  Client  │
   │  Router  │  (Home/Office Gateway)           │  Peers   │
   │ 10.66.0.20                                  │ 10.66.0.x │
   └────┬─────┘                                  └──────────┘
        │                                          • Laptops
   192.168.12.0/24                                 • Phones
   (LAN devices)                                   • Tablets
```

### Network Topology

**Coordination Server (CS)**
- Cloud VPS or dedicated server with public IP
- Hub of the WireGuard network
- All peers connect here
- Routes traffic between peers and subnet routers

**Subnet Routers (SN)**
- WireGuard peers that advertise LAN networks
- Gateway to home/office networks
- Handle NAT and forwarding via PostUp/PostDown rules
- Multiple subnet routers supported

**Client Peers**
- Individual devices (laptops, phones, tablets)
- Access levels: full (VPN+LANs), vpn_only, lan_only, custom
- Mobile device support with QR codes

## Use Cases

### 1. **Existing WireGuard Setup** (Import & Manage)

You already have WireGuard configs running. Import them to get:
- Centralized management in SQLite database
- Key rotation without manual config editing
- Access level management
- QR code generation for mobile devices
- SSH deployment automation

```bash
# Place your configs in import/
./wg-friend-onboard.py --import-dir import/ --yes

# Start managing
./wg-friend-maintain.py
```

**Preserves everything:** PostUp/PostDown rules, comments, peer order, all settings.

### 2. **New WireGuard Network** (De Novo Setup)

Building from scratch:
1. Create coordination server config manually or from template
2. Import the CS config
3. Use maintenance mode to:
   - Add subnet routers with advertised networks
   - Create client peers with auto IP allocation
   - Generate QR codes for mobile devices
   - Deploy to servers via SSH

### 3. **Hybrid Setup** (Mix of Import + New)

Common scenario:
- Import existing coordination server + subnet routers
- Add new client peers as needed
- Expand network by adding subnet routers
- Rotate compromised keys
- Change access levels

### 4. **Multi-Site Network**

Multiple offices/homes connected:
- One coordination server (cloud VPS)
- Subnet router at each site
- Each site advertises its LAN networks
- Clients can access all sites (or restricted by access level)
- Centralized management of the entire topology

### 5. **Access Level Control**

Different peers need different access:
- **IT staff**: Full access to all networks
- **Remote workers**: VPN + specific LAN subnets
- **Contractors**: VPN only, no LAN access
- **IoT devices**: Custom restricted access

Change access levels without manual config editing.

## Key Features

### Perfect Configuration Fidelity

Generated configs are **byte-for-byte identical** to originals:
- Raw block storage preserves exact text
- PostUp/PostDown rules never parsed
- Multi-line comments preserved
- Peer order maintained
- No loss of any configuration data

### Dual Storage Model

```
Config File → ┌─ Raw Blocks (exact text preservation)
              └─ Structured Data (queryable IPs, keys, networks)

Database → Reconstructor → Identical Config File
```

**Why both?**
- Raw blocks ensure perfect reconstruction
- Structured data enables queries, logic, IP allocation
- Best of both worlds: fidelity + functionality

### Complete Management Workflow

**Import** (`wg-friend-onboard.py`)
1. Auto-detect coordination server, subnet routers, clients
2. Extract and preserve raw blocks + structured data
3. Verify byte-for-byte reconstruction
4. Store in SQLite database

**Maintain** (`wg-friend-maintain.py`)
- View and export configs
- Rotate keys atomically (peer + CS updated together)
- Add/remove peers
- Generate QR codes
- Add preshared keys
- Deploy to servers via SSH
- Manage access levels

## Quick Start

### Import Existing Configs

```bash
# 1. Place configs in import/
cp /etc/wireguard/wg0.conf import/coordination.conf
cp ~/wireguard-configs/*.conf import/

# 2. Import
./wg-friend-onboard.py --import-dir import/ --yes

# 3. Verify perfect fidelity
diff import/coordination.conf output/coordination.conf
# (no output = perfect match)
```

### Maintenance Mode

```bash
./wg-friend-maintain.py

# Interactive menu:
# [1] Manage Coordination Server - view, export, deploy
# [2] Manage Subnet Routers - configs, key rotation
# [3] Manage Peers - QR codes, keys, access, delete
# [4] Create New Peer - auto IP allocation
# [5] List All Entities - network overview
# [6] Deploy Configs - SSH deployment
```

### Create New Peer

```bash
./wg-friend-maintain.py
# [4] Create New Peer
# → Auto-assigns next available IP
# → Generates keypair
# → Creates client config
# → Generates QR code (optional)
# → Updates coordination server config
```

## Architecture Highlights

### PostUp/PostDown Rules

Subnet routers use iptables/ip6tables rules for:
- IP forwarding
- NAT/Masquerading
- MSS clamping for PMTU
- Custom firewall rules

**WireGuard Friend never parses these.** Stored as exact text blocks.

### Access Levels

| Level | Networks | Use Case |
|-------|----------|----------|
| `full_access` | VPN + all LANs | IT staff, administrators |
| `vpn_only` | VPN network only | Contractors, guests |
| `lan_only` | VPN + specific LANs | Remote workers |
| `custom` | User-defined | IoT, restricted devices |

### Key Rotation

Rotate a peer's keys:
1. Generate new keypair
2. Update peer's client config (raw block)
3. Update CS peer entry (raw block)
4. Mark rotation timestamp
5. Deploy both configs

**Atomic operation.** Both sides updated together.

## Network Examples

### Simple: VPS + Clients

```
Cloud VPS (CS) ←→ Laptop
               ←→ Phone
               ←→ Tablet
```

Use case: Personal VPN for secure browsing

### Standard: VPS + Home Network + Clients

```
Cloud VPS (CS) ←→ Home Router (SN, advertises 192.168.1.0/24)
               ←→ Laptop (can access home devices)
               ←→ Phone (can access home devices)
```

Use case: Remote access to home network

### Advanced: Multi-Site + Clients

```
Cloud VPS (CS) ←→ Office Router (SN, advertises 10.0.0.0/24)
               ←→ Home Router (SN, advertises 192.168.1.0/24)
               ←→ Branch Router (SN, advertises 172.16.0.0/24)
               ←→ Employee Laptops (full access)
               ←→ Contractor Laptops (vpn_only)
```

Use case: Corporate network with multiple locations

## Documentation

Comprehensive documentation for all use cases:

- **[QUICK_START.md](QUICK_START.md)** - Step-by-step walkthrough with examples
- **[ARCHITECTURE.md](ARCHITECTURE.md)** - Deep dive into design decisions
- **[DOCUMENTATION.md](DOCUMENTATION.md)** - Documentation index and guide

**In-code documentation:**
- src/database.py (442 lines) - Database operations with full docstrings
- src/raw_parser.py (358 lines) - Raw block extraction and parsing
- All functions fully documented

## Requirements

- Python 3.8+
- WireGuard tools (`wg`, `wg-quick`)
- SQLite 3
- SSH access to servers (for deployment)

```bash
# Install dependencies
pip install -r requirements.txt

# Install WireGuard tools
sudo apt install wireguard-tools
```

## Project Structure

```
wireguard-friend/
├── README.md                    # This file (overview)
├── QUICK_START.md               # Detailed walkthrough
├── ARCHITECTURE.md              # Design deep-dive
├── DOCUMENTATION.md             # Documentation index
├── requirements.txt             # Python dependencies
│
├── wg-friend-onboard.py         # Import existing configs
├── wg-friend-maintain.py        # Maintenance mode
├── wg-friend.db                 # SQLite database
│
├── src/                         # Source modules
│   ├── database.py              # Database operations
│   ├── raw_parser.py            # Raw block extraction
│   ├── keygen.py                # Key generation
│   ├── ssh_client.py            # SSH deployment
│   └── qr_generator.py          # QR code generation
│
├── import/                      # Place configs here for import
└── output/                      # Generated configs
```

## Why WireGuard Friend?

**For existing WireGuard users:**
- Centralized management without losing manual control
- Perfect fidelity means configs always match originals
- Key rotation without manual editing
- Access level management
- Deployment automation

**For new WireGuard deployments:**
- Structured approach to building hub-and-spoke topology
- Auto IP allocation
- QR code generation for mobile
- Built-in best practices (PostUp/PostDown templates)
- SQLite database for queries and reporting

**For everyone:**
- No YAML configuration files to maintain
- No Git repository required (though you can version control the DB)
- Pure SQLite + raw blocks = simple, reliable, portable
- Command-line interface, no web dashboard bloat
- Works with any WireGuard setup (wg-quick, systemd, etc.)

## Security Notes

- Configs saved with `600` permissions (owner read/write only)
- Private keys stored in database (protect `wg-friend.db`)
- Keys masked in terminal display
- Deployment creates backups before overwriting
- No keys transmitted except via SSH (encrypted)

## Getting Help

1. Check **[DOCUMENTATION.md](DOCUMENTATION.md)** for index of all docs
2. Read **[QUICK_START.md](QUICK_START.md)** for detailed examples
3. Review **[ARCHITECTURE.md](ARCHITECTURE.md)** for design rationale
4. Check troubleshooting sections in docs
5. Open an issue on GitHub

## License

[Add your license here]

---

**Built with perfect configuration fidelity in mind.**

No YAML. No Git. Just SQLite + Raw Blocks. 🎯
