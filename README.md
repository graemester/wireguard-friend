# WireGuard Friend

**Build and manage reliable Wireguard networks.  Learn and have fun!**

WireGuard Friend helps you *establish and maintain* sophisticated WireGuard network topologies using a BYO VPS coordination server, a subnet router on a host you probably already have, and client peers (your mobile devices). Import existing configurations or build from scratch, manage access levels, rotate keys, and deploy to servers —- all through an intuitive, fast command-line interface.  It can work from a setup you already have or help you build a complete set of configs from scratch

## What It Builds For You

WireGuard Friend establishes this network architecture:

```
                               +------------------------------------------------------+
                               |                 Coordination Server                  |
                               |                  (BYO Cloud VPS)                     |
                               |                                                      |
                               |                 Public IP: 1.2.3.4                   |
                               |                  VPN IP: 10.20.0.1                   |
                               +---------------------------+--------------------------+
                                                           |
                                                           |
                                 +-------------------------+------------------------+
                                 |                                                  |
                                 |                                                  |
              +----------------------------------------+        +----------------------------------------+
              |             Subnet Router              |        |             Client Peers               |
              |             (On your LAN)              |        |          (Anywhere you are.)           |
              |                                        |        |                                        |
              |            VPN: 10.20.0.20             |        |            VPN: 10.20.0.x              |
              |            LAN: 192.168.1.1            |        |                                        |
              +----------------------------------------+        +----------------------------------------+
              192.168.1.0/24                                      Laptops, Phones, Tablets, Friend's Computer
              Samba Shares, Jellyfin, Media Server, SSH...
        
```

### Network Components

**Coordination Server (CS)**
- Cloud VPS or dedicated server with public IP
- Central hub of your WireGuard network
- All peers connect here for routing
- Deployed and managed via SSH

**Subnet Routers**
- WireGuard peers that advertise LAN networks
- Gateway between VPN and home/office networks
- Handle NAT, forwarding, and firewall rules
- Support for multiple sites

**Client Peers**
- Individual devices (laptops, phones, tablets)
- Configurable access levels (full, VPN-only, LAN-only, custom)
- QR code generation for mobile setup
- Automatic IP allocation

## What Problems It Solves

### For EXISTING WireGuard Networks

You already have WireGuard running but:
- Key rotation requires manual config editing
- Adding peers means editing files on the server
- Managing access levels is error-prone
- No centralized view of your network
- Deployment is manual SSH + file copying

**WireGuard Friend fixes this:**
- Import your existing configs into SQLite database
- Rotate keys through interactive menu
- Create/delete peers with automatic config updates
- Manage access levels without editing configs
- One-command SSH deployment with backups

### For NEW WireGuard Networks

You want to build a WireGuard network but:
- Hub-and-spoke topology is complex to plan
- IP allocation across subnet routers is tedious
- PostUp/PostDown rules are hard to get right
- No template for coordination server setup
- Mobile device onboarding is manual

**WireGuard Friend helps:**
- Wizard mode for creating configs from scratch
- Structured approach to network topology
- Automatic IP allocation for all peers
- Subnet router setup with default NAT rules
- QR code generation for mobile devices
- SSH deployment automation

**Wizard mode:** If `import/` is empty, the onboard script **offers to create a network from scratch** through an interactive wizard.

## Use Cases

### 1. **Remote Access to Home/Office**

**Setup:**
- Cloud VPS as coordination server
- Subnet router at home/office
- Client devices (laptop, phone, tablet)

**What you get:**
- Access home devices from anywhere
- Secure tunnel for internet browsing
- No port forwarding needed on home router
- Automatic routing between VPN and LAN

### 2. **Multi-Site Corporate Network**

**Setup:**
- Cloud VPS as coordination server
- Subnet router at each office location
- Employee devices with appropriate access levels

**What you get:**
- All offices connected via VPN
- Employees can access any office network (if permitted)
- Contractors can be restricted to VPN-only
- Centralized management of all peers

### 3. **Personal VPN Service**

**Setup:**
- Cloud VPS as coordination server
- Client devices only (no subnet routers)

**What you get:**
- Secure internet browsing via VPS
- All traffic encrypted
- Easy device onboarding via QR codes
- Key rotation for compromised devices

### 4. **Hybrid Cloud + On-Premise**

**Setup:**
- Cloud VPS as coordination server
- Subnet router at data center/office location #1
- Subnet router at office location #2
- Employee laptops + cloud services

**What you get:**
- Cloud services can reach on-premise resources
- Employees can access both cloud and on-premise
- Secure inter-site communication
- Managed access levels per user/service

## Key Capabilities

### Import & Manage Existing Configs

```bash
# Place configs in import/ and run wg-friend
wg-friend

# Database now contains:
# - Coordination server with all settings
# - Subnet routers with advertised networks
# - Client peers with access levels
# - All PostUp/PostDown rules preserved
```

The import process preserves everything exactly as-is - no data loss, no reformatting.

### Interactive Maintenance

```bash
wg-friend

# Menu-driven interface for:
# [1] Manage Coordination Server - view, export, deploy
# [2] Manage Subnet Routers - configs, key rotation
# [3] Manage Peers - QR codes, keys, access, delete
# [4] Create New Peer - auto IP allocation
# [5] List All Entities - network overview
# [6] Deploy Configs - SSH deployment
```

### Access Level Management

Control what each peer can reach:

| Level | Networks | Use Case |
|-------|----------|----------|
| `full_access` | VPN + all LANs | IT staff, administrators |
| `vpn_only` | VPN network only | Contractors, guests |
| `lan_only` | VPN + specific LANs | Remote workers |
| `custom` | User-defined | IoT, restricted devices |

Change access levels through maintenance menu - configs update automatically.

### Key Rotation

Rotate a compromised peer's keys:
1. Select peer in maintenance menu
2. Choose "Rotate Keys"
3. New keypair generated
4. Peer's client config updated
5. Coordination server peer entry updated
6. Deploy both configs

Both sides stay in sync - no manual editing.

### Mobile Device Support

Add a phone or tablet:
1. Create new peer (auto-assigned IPs)
2. Generate QR code
3. Scan with WireGuard mobile app
4. Deploy updated coordination server config
5. Device is connected

No typing long keys or IPs on mobile keyboards.

### SSH Deployment

Deploy configs to servers:
- Automatic backup of existing config
- Upload via SSH
- Set proper permissions (600)
- Optional WireGuard service restart
- Works with any SSH-accessible server

## Where Should I Run This?

**TL;DR: Run it on your subnet router, or your laptop - it works anywhere!**

WireGuard Friend is a **management tool**, not a runtime service. It doesn't need to run 24/7. Run it when you need to manage your network, then it sits idle.

**Pragmatic choice:** Run on your subnet router
- Already managing WireGuard configs
- On your local network (easy access)
- Single point of management

**Power user choice:** Run on your workstation/laptop
- Keep servers minimal and clean
- Work offline (except deployments)
- Database travels with you

**The key insight:** WireGuard Friend just needs SSH access to your WireGuard hosts. It doesn't need to be on the same machine as WireGuard itself!

📖 **See [docs/WHERE_TO_RUN.md](docs/WHERE_TO_RUN.md) for comprehensive guidance** including:
- Detailed pros/cons of each location
- Security considerations
- Multi-admin scenarios
- Migration between machines
- Requirements checklist

## Installation

### Download Binary (Recommended)

Download a pre-built binary - no Python or dependencies required:

```bash
# Linux
curl -LO https://github.com/graemester/wireguard-friend/releases/latest/download/wg-friend-linux-x86_64
chmod +x wg-friend-linux-x86_64
sudo mv wg-friend-linux-x86_64 /usr/local/bin/wg-friend

# macOS (Intel)
curl -LO https://github.com/graemester/wireguard-friend/releases/latest/download/wg-friend-darwin-x86_64
chmod +x wg-friend-darwin-x86_64
sudo mv wg-friend-darwin-x86_64 /usr/local/bin/wg-friend

# macOS (Apple Silicon)
curl -LO https://github.com/graemester/wireguard-friend/releases/latest/download/wg-friend-darwin-arm64
chmod +x wg-friend-darwin-arm64
sudo mv wg-friend-darwin-arm64 /usr/local/bin/wg-friend
```

### Update

```bash
wg-friend --update
```

### From Source (Development)

```bash
git clone https://github.com/graemester/wireguard-friend.git
cd wireguard-friend
pip install -r requirements.txt
./wg-friend
```

## Quick Start

### First Run - Create or Import

```bash
wg-friend

# If no database exists, you'll see:
# → No WireGuard configs found in import/
# → Create new WireGuard network from scratch? [y/N]: y
#   OR
#   Place your existing .conf files in import/ and run again
```

### Create New Network (Wizard Mode)

```bash
# Just run wg-friend in an empty directory
wg-friend

# Wizard walks through:
#    • Coordination server setup
#    • Subnet routers (optional, with default NAT rules)
#    • Client peers (optional)
# → Generates configs in import/
# → Automatically imports into database
```

### Import Existing Network

```bash
# 1. Place your configs in import/
mkdir import
cp /etc/wireguard/wg0.conf import/coordination.conf
cp ~/configs/*.conf import/

# 2. Run wg-friend - it auto-detects and imports
wg-friend

# 3. After import, you're in maintenance mode
# → [5] List All Entities to verify
```

### Add a New Peer

```bash
wg-friend

# [4] Create New Peer
# → Name: alice-laptop
# → Auto-assigned: 10.66.0.25, fd66:6666::25
# → Access: [1] Full access
# → Generate QR code: Yes

# Result:
# - output/alice-laptop.conf (client config)
# - output/alice-laptop-qr.png (QR code)
# - Coordination server updated in database

# [1] Manage Coordination Server → [3] Deploy
# → Uploads new config to VPS
```

### Rotate Compromised Keys

```bash
wg-friend

# [3] Manage Peers → Select peer → [3] Rotate Keys
# → New keypair generated
# → Client config updated
# → CS config updated

# Deploy both:
# 1. Export peer config and send to user
# 2. Deploy CS config to server
```

## Network Architecture Examples

### Simple: Personal VPN

```
Cloud VPS (CS) ←→ Laptop
               ←→ Phone
               ←→ Tablet
```

**What you get:** Secure browsing, encrypted traffic, privacy

### Standard: Remote Home Access

```
Cloud VPS (CS) ←→ Home Router (SN, advertises 192.168.1.0/24)
               ←→ Laptop (can access home devices)
               ←→ Phone (can access home devices)
```

**What you get:** Remote access to home network, file servers, IoT devices

### Advanced: Multi-Site Business

```
Cloud VPS (CS) ←→ Office Router (SN, advertises 10.0.0.0/24)
               ←→ Home Office (SN, advertises 192.168.1.0/24)
               ←→ Branch Office (SN, advertises 172.16.0.0/24)
               ←→ Employee Laptops (full_access)
               ←→ Contractor Laptops (vpn_only)
```

**What you get:** All sites interconnected, flexible access control, centralized management

## Technical Details

### Storage Architecture

WireGuard Friend stores configurations in two forms:

1. **Text blocks** - Original configuration text
2. **Structured data** - Extracted fields (IPs, keys, networks) for queries

### PostUp/PostDown Rules

Subnet router firewall rules are stored as text:
- IP forwarding settings
- NAT/Masquerading rules
- MSS clamping for PMTU
- Port forwarding
- Custom iptables rules

Import preserves your exact rules. No risk of modification or loss.

### Database Schema

SQLite database with tables for:
- Coordination server (endpoint, networks, SSH info)
- Subnet routers (with advertised LAN networks)
- Peers (with access levels and client configs)
- Peer ordering (maintains original config order)
- PostUp/PostDown rules (stored separately)

Query with standard SQL:
```bash
sqlite3 wg-friend.db "SELECT name, ipv4_address, access_level FROM peer;"
```

## Documentation

Comprehensive guides for all use cases:

- **[QUICK_START.md](QUICK_START.md)** - Step-by-step walkthrough
- **[ARCHITECTURE.md](ARCHITECTURE.md)** - Design decisions and internals
- **[DOCUMENTATION.md](DOCUMENTATION.md)** - Documentation index

All source code is fully documented with docstrings.

## Requirements

**Binary version (recommended):**
- WireGuard tools (`wg`, `wg-quick`)
- SSH access to servers (for deployment)

```bash
# Install WireGuard tools
sudo apt install wireguard-tools  # Debian/Ubuntu
brew install wireguard-tools      # macOS
```

**From source:**
- Python 3.8+
- WireGuard tools
- pip install -r requirements.txt

## Project Structure

```
wireguard-friend/
├── wg-friend                    # Main entry point (run this)
├── wg-friend.spec               # PyInstaller build config
├── README.md                    # This file
├── QUICK_START.md               # Detailed walkthrough
├── requirements.txt             # Python dependencies (dev only)
│
├── src/                         # Source modules
│   ├── app.py                   # Unified application logic
│   ├── database.py              # Database operations
│   ├── raw_parser.py            # Configuration parsing
│   ├── keygen.py                # Key generation
│   ├── ssh_client.py            # SSH deployment
│   └── qr_generator.py          # QR code generation
│
├── wg-friend-onboard.py         # Onboarding (imported by app.py)
├── wg-friend-maintain.py        # Maintenance (imported by app.py)
│
├── import/                      # Place configs here for import
├── output/                      # Generated/exported configs
└── wg-friend.db                 # SQLite database (created on first run)
```

## Why WireGuard Friend?

**For existing WireGuard users:**
- Stop manually editing config files on servers
- Key rotation through simple menu interface
- Access level management without config editing
- QR codes for mobile devices
- Automated SSH deployment with backups

**For new deployments:**
- Structured approach to hub-and-spoke topology
- Automatic IP allocation
- Subnet router management
- Network overview and reporting
- Foundation for growing your VPN network

**For everyone:**
- SQLite database = portable, queryable, reliable
- Command-line interface = scriptable, automatable
- No web dashboard = no security surface, no dependencies
- Works with standard WireGuard tools
- Import existing configs = no migration pain

## Security Considerations

- Configs saved with `600` permissions (owner-only access)
- Private keys stored in database - protect `wg-friend.db` appropriately
- Keys masked in terminal display (shown as *****)
- SSH deployment creates backups before overwriting
- All key transmission happens over SSH (encrypted)

## Getting Help

1. **[DOCUMENTATION.md](DOCUMENTATION.md)** - Documentation index
2. **[QUICK_START.md](QUICK_START.md)** - Detailed examples
3. **[ARCHITECTURE.md](ARCHITECTURE.md)** - Design rationale
4. Troubleshooting sections in each doc
5. Open an issue on GitHub

## License

MIT License
