# WireGuard Friend

Menu-driven tool for managing WireGuard VPN networks. All operations available through an interactive TUI - no commands to memorize.

> **Repository Structure:**
> **v1/** - Current stable release (v1.0.7)
> **v-alpha/** - Archived original version (deprecated)

---

## Overview

WireGuard Friend manages WireGuard configurations for networks using a coordination server (BYO cloud VPS), subnet routers (LAN gateways), and client peers (individual devices). Configurations are stored in a SQLite database for querying and automated deployment.

**Just run `wg-friend` and use the menu.** Everything described below is available through the interactive interface with built-in help and documentation.

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

### Extramural Configs
- **Manage external VPN configs** from commercial providers (Mullvad, ProtonVPN, etc.)
- **Import sponsor-provided configs** with automatic parsing (marked as deployed)
- **Switch between server endpoints** easily
- **Update configs** when providers send changes
- **Complete separation** from mesh infrastructure
- See [Extramural Configs Guide](v1/docs/EXTRAMURAL_CONFIGS.md) for details

### Interactive TUI (Primary Interface)

Run `wg-friend` with no arguments to launch the menu-driven interface:

- **Single-keypress navigation** - press 1-9 to select options instantly
- **Manage Peers** - drill-down interface to view, edit, and manage any peer
- **Built-in documentation** - full help system accessible from the menu
- **Diagnostics** - system info, dependency checks, connectivity tests
- **Config preview** - see exactly what config will be generated before adding peers
- **State history timeline** - git-log style view of all network changes
- **Edit hostnames** - rename peers directly from the interface
- **Key rotation** - rotate keys with audit trail
- **QR code generation** - for mobile device onboarding
- **SSH deployment** - push configs with progress indicators and automatic backups
- **Extramural management** - full UI for external VPN configs

All CLI commands listed below are also accessible through the TUI menus.

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

### Interactive Mode (Recommended)

```bash
wg-friend
```

This launches the full menu-driven interface. From here you can:
- Import existing configs or create a new network
- Add, remove, and manage peers
- Rotate keys and view history
- Generate configs and QR codes
- Deploy via SSH
- Manage extramural (external VPN) configs
- Access built-in documentation

### CLI Commands (Alternative)

For scripting or quick operations, direct commands are available:

```bash
wg-friend import              # Import existing configs
wg-friend add peer            # Add new client peer
wg-friend add router          # Add subnet router
wg-friend rotate              # Rotate peer keys
wg-friend generate            # Generate all configs
wg-friend deploy              # Deploy via SSH
wg-friend qr                  # Generate QR code
wg-friend status --live       # Live peer status
```

See [Command Reference](v1/COMMAND_REFERENCE.md) for full CLI documentation.

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

## Documentation

- **[Quick Start](v1/quick-start.md)** - Detailed walkthrough for mesh networks
- **[Command Reference](v1/COMMAND_REFERENCE.md)** - All commands
- **[Extramural Configs Guide](v1/docs/EXTRAMURAL_CONFIGS.md)** - External VPN management

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
