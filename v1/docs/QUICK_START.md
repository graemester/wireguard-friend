# WireGuard Friend - Quick Start Guide

## Installation

### Download the Binary

```bash
# Linux
curl -LO https://github.com/graemester/wireguard-friend/releases/latest/download/wg-friend-linux-x86_64
chmod +x wg-friend-linux-x86_64
sudo mv wg-friend-linux-x86_64 /usr/local/bin/wg-friend

# macOS (Apple Silicon)
curl -LO https://github.com/graemester/wireguard-friend/releases/latest/download/wg-friend-darwin-arm64
chmod +x wg-friend-darwin-arm64
sudo mv wg-friend-darwin-arm64 /usr/local/bin/wg-friend

# macOS (Intel)
curl -LO https://github.com/graemester/wireguard-friend/releases/latest/download/wg-friend-darwin-x86_64
chmod +x wg-friend-darwin-x86_64
sudo mv wg-friend-darwin-x86_64 /usr/local/bin/wg-friend
```

### Create a Folder and Run

```bash
mkdir ~/wireguard-friend
cd ~/wireguard-friend
wg-friend
```

That's it. The app will guide you from there.

## First Run

When you run `wg-friend` for the first time, it asks one question:

```
Do you have existing WireGuard configs to import? [y/N]:
```

### If You Have Existing Configs

1. Answer **yes**
2. It creates an `import/` folder
3. Copy your `.conf` files there (coordination server, routers, clients)
4. Press Enter
5. The import wizard walks you through confirming each config

### If You're Starting Fresh

1. Answer **no**
2. The wizard walks you through creating:
   - Coordination server (your cloud VPS)
   - Subnet routers (optional - for home/office LAN access)
   - Client peers (laptops, phones, etc.)

Either way, you end up with a database and can manage your network.

## Main Menu

After setup, you'll see the main menu:

```
Main Menu:
  [1] Manage Coordination Server
  [2] Manage Subnet Routers
  [3] Manage Peers
  [4] Create New Peer
  [5] List All Entities
  [6] Deploy Configs
  [7] SSH Setup (Key Generation & Installation)
  [8] Check for Updates
  [0] Exit
```

## Common Tasks

### Add a New Peer

```
[4] Create New Peer
→ Name: alice-phone
→ Access level: [1] Full access
→ Generate QR code: Yes

Result:
  output/alice-phone.conf (client config)
  output/alice-phone-qr.png (QR code for mobile)
```

### Rotate Compromised Keys

```
[3] Manage Peers
→ Select peer
→ [3] Rotate Keys

New keypair generated, both configs updated.
```

### Generate QR Code

```
[3] Manage Peers
→ Select peer
→ [2] Generate QR Code

Saves to output/{peer-name}-qr.png
```

### Deploy to Servers

```
[1] Manage Coordination Server
→ [3] Deploy to Server
```

The app detects whether you're on the server (uses sudo) or remote (uses SSH).

## SSH Setup (One-Time)

Before deploying to remote servers:

```
[7] SSH Setup
```

This wizard:
1. Generates an SSH key (if needed)
2. Installs it on your coordination server
3. Installs it on subnet routers
4. Tests that it works

After that, deployments are passwordless.

## Updating

From the menu:
```
[8] Check for Updates
```

Or from command line:
```bash
wg-friend --update
```

## Files

After running, your folder contains:

```
~/wireguard-friend/
├── wg-friend.db      # Your network database
├── import/           # Original configs (if imported)
└── output/           # Generated configs and QR codes
```

## Access Levels

When creating peers, choose access:

| Level | What They Can Reach |
|-------|---------------------|
| Full access | VPN + all LANs |
| VPN only | Just the VPN network |
| LAN only | VPN + specific LANs |

## Troubleshooting

### "No database found"
Normal on first run. Follow the setup prompts.

### "Failed to derive public key"
Install WireGuard tools:
```bash
sudo apt install wireguard-tools  # Debian/Ubuntu
brew install wireguard-tools      # macOS
```

### SSH deployment fails
Run `[7] SSH Setup` to configure keys.

### Need to start over
Delete the database and run again:
```bash
rm wg-friend.db
wg-friend
```

## Command Line Options

```bash
wg-friend              # Run interactive mode
wg-friend --version    # Show version
wg-friend --update     # Update to latest version
wg-friend --help       # Show help
```
