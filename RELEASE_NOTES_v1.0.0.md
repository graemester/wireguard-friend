# WireGuard Friend v1.0.0

First stable release.

## Features

- **Import existing configs** with automatic type detection (coordination server, subnet router, client)
- **Smart CLI routing** - run `wg-friend` and it detects what to do
- **Peer management** - add, remove, rotate keys with permanent GUID tracking
- **Preshared keys** - post-quantum resistance support
- **Live status monitoring** - see connected peers in real-time
- **SSH setup wizard** - one-time setup for passwordless deployments
- **QR codes** - generate on demand for mobile devices
- **Interactive TUI** - maintenance mode

## Installation

```bash
git clone https://github.com/graemester/wireguard-friend.git
cd wireguard-friend
pip install -r requirements.txt

# Add to PATH (optional)
sudo ln -s $(pwd)/v1/wg-friend /usr/local/bin/wg-friend
```

## Quick Start

```bash
# Import existing configs
wg-friend

# Or start fresh
wg-friend init

# Then use
wg-friend add peer
wg-friend generate
wg-friend deploy
wg-friend status --live
```

## Documentation

- [README](README.md) - Overview and installation
- [Quick Start](v1/QUICK_START_V2.md) - Detailed walkthrough
- [Command Reference](v1/COMMAND_REFERENCE.md) - All commands

## Core Features
- Import existing WireGuard configs
- Auto-detect config types (coordination server, subnet router, client)
- Smart CLI routing
- Peer management (add/remove/modify)
- Key rotation with permanent GUID tracking
- Config generation from database
- SSH deployment with backup

## New in v1.0.0
- **Localhost detection** - automatic detection of local deployments (skip SSH)
- **Preshared key support** - add/update PSK for post-quantum resistance
- **Per-peer QR codes** - generate QR for specific peer on demand
- **Live peer status** - real-time monitoring with `wg show` parsing
- **SSH setup wizard** - interactive setup for passwordless deployment

## Interactive Features
- Interactive TUI mode
- Maintenance mode
- Guided wizards for all operations

## Requirements

- Python 3.7+
- WireGuard tools (`wg`, `wg-quick`)
- SSH client (for remote deployments)
- qrcode library (for QR generation): `pip install qrcode[pil]`
