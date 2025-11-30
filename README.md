# WireGuard Friend

Command-line tool for managing WireGuard VPN networks with hub-and-spoke topology.

> **Repository Structure:**
> **v1/** - Current stable release (v1.0.1)
> **v-alpha/** - Archived original version

---

## Overview

WireGuard Friend manages WireGuard configurations for networks using a coordination server (BYO cloud VPS), subnet routers (LAN gateways), and client peers (individual devices). Configurations are stored in a SQLite database for querying and automated deployment.

```
                                 ┌──────────────────────────────────────────────────────┐
                                 │                 Coordination Server                  │
                                 │                  (BYO Cloud VPS)                     │
                                 │                                                      │
                                 │                 Public IP: 1.2.3.4                   │
                                 │                  VPN IP: 10.20.0.1                   │
                                 └───────────────────────────┬──────────────────────────┘
                                                             │
                                                             │
                                 ┌───────────────────────────┴──────────────────────────┐
                                 │                                                      │
                                 │                                                      │
              ┌──────────────────────────────────────────┐        ┌──────────────────────────────────────────┐
              │             Subnet Router                │        │              Client Peers                │
              │             (On your LAN)                │        │           (Anywhere you are.)            │
              │                                          │        │                                          │
              │            VPN: 10.20.0.20               │        │             VPN: 10.20.0.x               │
              │            LAN: 192.168.1.1              │        │                                          │
              └──────────────────────────────────────────┘        └──────────────────────────────────────────┘
              192.168.1.0/24                                      Laptops, Phones, Tablets, Friend's Computer
              Samba, HAOS, Jellyfin, Media Server, SSH...

```

## Features

### Mesh Network Management
- Import existing WireGuard configurations into SQLite database
- Generate new configurations from scratch via interactive wizard
- Automated IP allocation for new peers
- Key rotation with database tracking
- Access level management (full, VPN-only, LAN-only, custom)
- QR code generation for mobile devices
- SSH deployment with automatic backups
- Live peer status monitoring via wg show
- Preshared key support for post-quantum resistance

### Extramural Configs (NEW in v1.0.1) 
- **Manage external VPN configs** from commercial providers (Mullvad, ProtonVPN, etc.)
- **Import sponsor-provided configs** with automatic parsing
- **Switch between server endpoints** easily
- **Update configs** when providers send changes
- **Complete separation** from mesh infrastructure
- See [Extramural Configs Guide](v1/docs/EXTRAMURAL_CONFIGS.md) for details

## Installation

### From Release

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

### From Source

```bash
git clone https://github.com/graemester/wireguard-friend.git
cd wireguard-friend
pip install -r requirements.txt
./v1/wg-friend
```

## Usage

### Import Existing Configurations

```bash
wg-friend
# Places configs in import/ directory
# Auto-detects coordination server, subnet routers, and clients
# Imports into SQLite database
```

### Create New Network

```bash
wg-friend
# If no database exists, offers wizard mode
# Walks through coordination server, subnet router, and peer setup
# Generates all configurations
```

### Add Peer

```bash
wg-friend add peer
# Auto-assigns IP addresses
# Generates keypair
# Creates client configuration
# Updates coordination server configuration
```

### Rotate Keys

```bash
wg-friend rotate
# Select peer from list
# Generates new keypair
# Updates both peer and coordination server configs
# Maintains permanent GUID for tracking
```

### Deploy Configurations

```bash
wg-friend deploy
# Backs up existing configurations
# Uploads new configurations via SSH
# Sets proper file permissions
# Optionally restarts WireGuard service
```

### Live Status Monitoring

```bash
wg-friend status --live
# Connects to coordination server
# Runs wg show to get peer status
# Displays online/offline status, transfer stats, last handshake
```

### Generate QR Code

```bash
wg-friend qr
# Select peer from list
# Generates QR code PNG
# For scanning with WireGuard mobile app
```

### Manage External VPN Configs (Extramural)

```bash
# Import config from Mullvad, ProtonVPN, etc.
wg-friend extramural import mullvad.conf --sponsor "Mullvad VPN" --peer "my-laptop"

# List all external configs
wg-friend extramural list

# Switch between VPN server locations
wg-friend extramural switch-peer my-laptop/Mullvad-VPN eu-central-1

# Generate .conf file
wg-friend extramural generate my-laptop/Mullvad-VPN --output /etc/wireguard/wg-mullvad.conf

# See complete guide
# v1/docs/EXTRAMURAL_CONFIGS.md
```

### SSH Setup

```bash
wg-friend ssh-setup
# Interactive wizard for SSH key setup
# Generates keypair if needed
# Installs public key to servers
# Tests authentication
```

## Network Components

### Coordination Server
- Cloud VPS or dedicated server with public IP
- Central routing point for all peers
- Managed via SSH deployment

### Subnet Routers
- WireGuard peers advertising LAN networks
- Gateway between VPN and local networks
- Handle NAT and firewall rules
- Support multiple sites

### Client Peers
- Individual devices (laptops, phones, tablets)
- Configurable access levels
- Mobile devices use QR codes

## Access Levels

| Level | Access | Use Case |
|-------|--------|----------|
| full_access | VPN + all LANs | Administrators |
| vpn_only | VPN only | Contractors |
| lan_only | VPN + specific LANs | Remote workers |
| custom | User-defined | Special cases |

## Database Schema

SQLite database stores:
- Coordination server configuration (endpoint, networks, keys)
- Subnet router configurations (LAN networks, forwarding rules)
- Client peer configurations (access levels, keys, IPs)
- Key rotation history (permanent GUID tracking)
- PostUp/PostDown rules (preserved as text blocks)

Query directly with SQL:
```bash
sqlite3 wg-friend.db "SELECT hostname, ipv4_address FROM remote;"
```

## Configuration Storage

Configurations are stored in two forms:
1. Structured data in SQLite tables (queryable, validated)
2. Text blocks for PostUp/PostDown rules (preserved exactly)

Import process maintains original formatting for firewall rules.

## Requirements

- WireGuard tools (wg, wg-quick)
- SSH access to servers (for deployment)
- Python 3.8+ (if running from source)

```bash
# Install WireGuard tools
sudo apt install wireguard-tools  # Debian/Ubuntu
brew install wireguard-tools      # macOS
```

## Commands

```
wg-friend                    # Smart routing (import/init/maintain)
wg-friend init               # Create new network
wg-friend import             # Import existing configs
wg-friend add peer           # Add new peer
wg-friend add router         # Add subnet router
wg-friend rotate             # Rotate peer keys
wg-friend psk                # Add/update preshared key
wg-friend qr                 # Generate QR code
wg-friend generate           # Generate all configs
wg-friend deploy             # Deploy via SSH
wg-friend status             # Network overview
wg-friend status --live      # Live peer status
wg-friend ssh-setup          # SSH key setup wizard
wg-friend maintain           # Interactive TUI
```

## Documentation

- **[Quick Start](v1/quick-start.md)** - Detailed walkthrough for mesh networks
- **[Command Reference](v1/COMMAND_REFERENCE.md)** - All commands
- **[Extramural Configs Guide](v1/docs/EXTRAMURAL_CONFIGS.md)** - NEW: External VPN management
- **[Release Notes](RELEASE_NOTES_v1.0.1.md)** - What's new in v1.0.1

## Project Structure

```
wireguard-friend/
├── v1/
│   ├── wg-friend           # Main CLI
│   ├── cli/                # CLI modules
│   ├── *.py                # Core modules
│   └── *.md                # Documentation
├── v-alpha/                # Archived version
├── README.md               # This file
└── requirements.txt        # Python dependencies
```

## Use Cases

**Remote Access:** VPS + home router + laptops/phones for accessing home network remotely

**Multi-Site:** VPS + routers at each office location for interconnecting sites

**Personal VPN:** VPS + client devices for secure internet browsing

**Hybrid Cloud:** VPS + on-premise routers + cloud services for mixed infrastructure

## Security

- Configuration files saved with 600 permissions
- Private keys stored in database (protect wg-friend.db file)
- Keys masked in terminal output
- SSH deployment creates backups before overwriting
- Key transmission over SSH only

## Where to Run

WireGuard Friend is a management tool, not a runtime service. Run it when needed for network management.

Options:
- Subnet router (already managing configs, local network access)
- Workstation/laptop (keep servers minimal, work offline)
- Any machine with SSH access to WireGuard hosts

## License

MIT License
