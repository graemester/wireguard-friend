# wg-friend

**WireGuard Peer Manager** - A friendly terminal UI for managing WireGuard VPN peers with ease.

## Features

- 🎨 **Rich Terminal UI** - Clean, intuitive interface built with Rich
- 👥 **Peer Management** - Add, revoke, and rotate peer keys
- 📊 **Live Status** - View online/offline status with handshake timing
- 📱 **QR Code Generation** - Instant QR codes for mobile device setup
- 🔄 **Key Rotation** - Seamless security key updates
- 📝 **Audit Trail** - Full peer history with creation and revocation dates
- 🏗️ **Peer Templates** - Predefined configs for common use cases
- 🔌 **Coordinator Integration** - Automatic remote config updates
- 🗄️ **SQLite Database** - Track all peers and metadata locally

## Architecture

wg-friend is designed for WireGuard mesh networks with three key components:

1. **Coordinator** - Public VPS with static IP (hub server)
2. **Subnet Router** - Internal LAN gateway (e.g., home server)
3. **Clients** - Mobile/desktop devices connecting to the mesh

## Installation

### Prerequisites

- Python 3.10+
- WireGuard tools (`wg` command)
- SSH access to coordinator server

```bash
# Install WireGuard tools
sudo apt install wireguard-tools

# Install Python dependencies
cd wg-friend
pip install -r requirements.txt
```

### Quick Start: Onboarding Script

**NEW!** Use the interactive onboarding script for easy setup:

```bash
# Setup from scratch (interactive wizard)
./wg-friend-onboard.py --wizard

# Import existing WireGuard configs (place .conf files in ./import/ first)
mkdir import
cp /path/to/*.conf import/
./wg-friend-onboard.py --scan ./import

# Import and recover missing peer configs
./wg-friend-onboard.py --scan ./import --recover
```

The onboarding script will:
- ✅ Guide you through setup with step-by-step questions
- ✅ Detect existing configs and import them
- ✅ Generate config.yaml automatically
- ✅ Recover missing client configs from coordinator
- ✅ Handle partial imports (coordinator + some clients)

### Manual Configuration

If you prefer manual setup:

1. Copy example config:
```bash
cp config.example.yaml ~/.wg-friend/config.yaml
```

2. Edit `~/.wg-friend/config.yaml` with your settings:
   - Coordinator details (host, endpoint, public key)
   - Subnet router information
   - SSH credentials
   - Network ranges

3. Setup SSH key authentication to your coordinator:
```bash
ssh-copy-id -p 2223 user@coordinator.example.com
```

## Usage

### Interactive TUI

Launch the full terminal UI:

```bash
./wg-friend.py tui
```

**TUI Features:**
- View peer status with live handshake data
- Add new peers with template selection
- Rotate keys for existing peers
- Revoke peers with confirmation
- View peer history

### Command Line Interface

```bash
# View peer status
./wg-friend.py status

# Add a new peer
./wg-friend.py add iphone-graeme --qr --add-to-coordinator

# Add with custom IP
./wg-friend.py add laptop-work --ip 10.66.0.75 --type restricted_external

# Revoke a peer
./wg-friend.py revoke old-phone

# List all peers
./wg-friend.py list

# Export coordinator config for deployment
./wg-friend.py export
./wg-friend.py export -o /tmp/custom-path.conf
```

## Peer Templates

wg-friend includes 4 predefined peer templates:

### 1. Mobile Client (Default)
- **Use:** Phones, laptops, tablets
- **Access:** Full VPN mesh + home LAN
- **Config:** DNS via Pi-hole, 25s keepalive

### 2. Mesh Only
- **Use:** Less trusted devices
- **Access:** VPN mesh only (no LAN access)
- **Config:** Coordinator DNS, 25s keepalive

### 3. Restricted External
- **Use:** External collaborators, limited access
- **Access:** Specific resources only
- **Config:** Custom AllowedIPs

### 4. Server Peer
- **Use:** Always-on services
- **Access:** Full mesh + LAN
- **Config:** No keepalive (servers are always reachable)

## Workflows

### Adding a Mobile Device

```bash
$ ./wg-friend.py tui
# Select "2. Add new peer"
# Enter name: iphone-graeme
# Select type: mobile_client
# Accept auto-assigned IP
# Scan QR code with WireGuard app
# Peer automatically added to coordinator
```

### Key Rotation

```bash
$ ./wg-friend.py tui
# Select "3. Rotate peer keys"
# Choose peer from list
# New keys generated and applied
# Old config replaced on coordinator
# New QR code displayed
```

### Revoking a Peer

```bash
$ ./wg-friend.py revoke lost-phone
# Removes from coordinator wg0.conf
# Marks as revoked in database
# Restarts WireGuard service
```

## Automated Deployment

**NEW!** wg-friend now includes automated deployment to coordinator and subnet router.

### One-Time Setup

Configure SSH key-based authentication and system settings once:

```bash
./wg-friend-deploy.py --setup
```

**SSH Key Setup:**
- ✅ Generates a dedicated SSH keypair for wg-friend
- ✅ Installs the public key to your coordinator
- ✅ Installs the public key to your subnet router
- ✅ Tests key-based authentication
- ✅ You'll enter passwords once - never again!

**Subnet Router System Configuration:**
- ✅ Checks IP forwarding (IPv4/IPv6)
- ✅ **Prefers PostUp rules** (more secure - only active when VPN up)
- ✅ Falls back to system-level sysctl if needed
- ✅ Verifies PostUp/PostDown routing rules exist
- ✅ Shows existing rules and confirms they're correct
- ✅ Offers to add routing rules with IP forwarding included
- ✅ Respects your existing sophisticated rules (IPv6, MSS clamping, etc.)

### Daily Workflow: Adding a Peer

After you add, rotate, or revoke a peer, deploy the changes:

```bash
# 1. Add a peer (via TUI or CLI)
./wg-friend.py add iphone-graeme --qr

# 2. Export coordinator config with all active peers
./wg-friend.py export

# 3. Deploy to infrastructure (one command!)
./wg-friend-deploy.py

# Pre-flight checks run automatically:
# ✓ Verifies IP forwarding is enabled
# ✓ Confirms PostUp routing rules exist
# ⚠ Warns if misconfigured (but continues deployment)
```

**That's it!** The deployment script will:
- ✅ Backup existing configs on remote hosts
- ✅ Upload new coordinator config
- ✅ Upload new subnet router config (if changed)
- ✅ Restart WireGuard services
- ✅ Verify both are running
- ✅ Complete in ~5 seconds!

### Local vs Remote Deployment

**Smart Detection:** The deployment script automatically detects if you're running ON the coordinator or subnet router and adjusts accordingly!

#### Scenario 1: Running on your laptop (both remote)
```bash
./wg-friend-deploy.py
# ✓ Coordinator: Deployed via SSH
# ✓ Subnet router: Deployed via SSH
```

#### Scenario 2: Running ON the coordinator
```bash
sudo ./wg-friend-deploy.py
# ✓ Coordinator: Deployed locally (no SSH)
# ✓ Subnet router: Deployed via SSH
```
**Note:** Requires sudo for local deployment to write to `/etc/wireguard/` and restart services.

#### Scenario 3: Running ON the subnet router
```bash
sudo ./wg-friend-deploy.py
# ✓ Coordinator: Deployed via SSH
# ✓ Subnet router: Deployed locally (no SSH)
```

#### Scenario 4: All local (development/testing)
```bash
sudo ./wg-friend-deploy.py
# ✓ Coordinator: Deployed locally (no SSH)
# ✓ Subnet router: Deployed locally (no SSH)
# (No SSH keys needed in this case!)
```

**Benefits:**
- ⚡ **Faster:** Local deployments skip SSH overhead
- 🔒 **Simpler:** No SSH key management for local hosts
- 🎯 **Flexible:** Works in mixed environments (one local, one remote)

### Deployment Options

```bash
# Deploy to both coordinator and subnet router (default)
./wg-friend-deploy.py

# Deploy to coordinator only
./wg-friend-deploy.py --coordinator-only

# Deploy to subnet router only
./wg-friend-deploy.py --subnet-only

# Dry run (show what would be deployed)
./wg-friend-deploy.py --dry-run

# Upload configs without restarting services
./wg-friend-deploy.py --no-restart
```

### Security Features

**Key-based authentication**: No passwords stored anywhere! The deployment script uses a dedicated SSH keypair (`~/.wg-friend/ssh/wg-friend-deploy`) that's generated during setup and installed to your endpoints.

**Automatic backups**: Before uploading, the script creates timestamped backups of existing configs on remote hosts (e.g., `/etc/wireguard/wg0.conf.backup.20251126-143022`).

**Verification**: After deployment, the script runs `wg show` on each endpoint to verify WireGuard is running correctly.

### Complete Workflow Example

```bash
# Add new peer
$ ./wg-friend.py tui
# (add iphone-graeme via TUI)

# Export updated coordinator config
$ ./wg-friend.py export
Exporting coordinator config to /home/user/.wg-friend/coordinator-wg0.conf...
✓ Exported config with 15 active peers
✓ Ready for deployment: /home/user/.wg-friend/coordinator-wg0.conf

# Deploy to infrastructure
$ ./wg-friend-deploy.py

🌐 Deploying to Coordinator
  Coordinator: ged@oh.higrae.me:2223
  Config: /etc/wireguard/wg0.conf
  Interface: wg0

✓ Backed up to: /etc/wireguard/wg0.conf.backup.20251126-143022
✓ Uploaded to: /etc/wireguard/wg0.conf
🔄 Restarting wg-quick@wg0...
✓ WireGuard restarted
🔍 Verifying WireGuard status...
✓ WireGuard is running
✓ Coordinator deployment complete!

🏠 Deploying to Subnet Router
  Subnet Router: ged@192.168.12.20:22
  Config: /etc/wireguard/wg0.conf
  Interface: wg0

✓ Backed up to: /etc/wireguard/wg0.conf.backup.20251126-143023
✓ Uploaded to: /etc/wireguard/wg0.conf
🔄 Restarting wg-quick@wg0...
✓ WireGuard restarted
🔍 Verifying WireGuard status...
✓ WireGuard is running
✓ Subnet router deployment complete!

✓ Deployment Complete!

# Done! New peer is online and accessible.
```

## Configuration File

### Coordinator Section

```yaml
coordinator:
  name: oh.higrae.me
  host: oh.higrae.me
  port: 2223
  user: ged
  config_path: /etc/wireguard/wg0.conf
  interface: wg0
  endpoint: oh.higrae.me:51820
  public_key: <coordinator-public-key>
  network:
    ipv4: 10.66.0.0/24
    ipv6: fd66:6666::/64
```

### Subnet Router Section

```yaml
subnet_router:
  name: icculus
  host: 192.168.12.20
  vpn_ip:
    ipv4: 10.66.0.20
  routed_subnets:
    - 192.168.12.0/24
  dns: 192.168.12.20  # Pi-hole
```

### IP Allocation

```yaml
ip_allocation:
  start_ipv4: 10.66.0.50
  end_ipv4: 10.66.0.254
  reserved:
    - 10.66.0.1   # Coordinator
    - 10.66.0.20  # Subnet router
```

## Database Schema

wg-friend uses SQLite to track peers:

```sql
CREATE TABLE peers (
    id INTEGER PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    public_key TEXT NOT NULL,
    private_key TEXT,
    ipv4 TEXT NOT NULL,
    ipv6 TEXT NOT NULL,
    peer_type TEXT NOT NULL,
    allowed_ips TEXT,
    comment TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT,
    revoked_at TEXT,
    config_path TEXT,
    qr_code_path TEXT
);
```

Location: `~/.wg-friend/peers.db`

## Security Considerations

1. **Private Keys**: Stored in database with 600 permissions
2. **SSH Access**: Uses key-based auth (no passwords)
3. **Sudo Operations**: Required for reading/writing /etc/wireguard/
4. **Revocation**: Immediate removal from coordinator + service restart
5. **Audit Trail**: All peer operations logged with timestamps

## Troubleshooting

### Cannot connect to coordinator

```bash
# Test SSH connection
ssh -p 2223 user@coordinator.example.com

# Verify WireGuard config path
ssh -p 2223 user@coordinator.example.com "sudo cat /etc/wireguard/wg0.conf"
```

### QR code not generating

```bash
# Install qrencode
sudo apt install qrencode

# Or reinstall Python package
pip install segno --force-reinstall
```

### Peer not showing in status

```bash
# Check if peer was added to coordinator
ssh -p 2223 user@coordinator.example.com "sudo wg show wg0"

# Verify WireGuard is running
ssh -p 2223 user@coordinator.example.com "sudo systemctl status wg-quick@wg0"
```

## Troubleshooting

### Subnet Router Not Routing Traffic

**Symptom:** Clients can connect to coordinator but can't reach home LAN resources.

**Cause:** IP forwarding disabled or missing PostUp rules.

**Fix (Option 1 - Recommended):** Add IP forwarding to PostUp rules
```bash
# Edit /etc/wireguard/wg0.conf and add to [Interface] section:
PostUp = sysctl -w net.ipv4.ip_forward=1
PostUp = sysctl -w net.ipv6.conf.all.forwarding=1

# This is more secure - IP forwarding only enabled when VPN is up!
# Then restart WireGuard:
sudo systemctl restart wg-quick@wg0
```

**Fix (Option 2):** Enable system-wide (always on)
```bash
# Enable runtime
sudo sysctl -w net.ipv4.ip_forward=1
sudo sysctl -w net.ipv6.conf.all.forwarding=1

# Make permanent
echo 'net.ipv4.ip_forward=1' | sudo tee -a /etc/sysctl.conf
echo 'net.ipv6.conf.all.forwarding=1' | sudo tee -a /etc/sysctl.conf
```

**Or run setup to configure everything:**
```bash
./wg-friend-deploy.py --setup
```

### MTU/Fragmentation Issues (5G/LTE)

**Symptom:** Some websites don't load, SSH works but HTTP times out.

**Cause:** MTU mismatch between cellular network and VPN tunnel.

**Fix:** Add MSS clamping to subnet router PostUp rules:
```bash
# Add to /etc/wireguard/wg0.conf [Interface] section:
PostUp = iptables -t mangle -A FORWARD -i wg0 -o <WAN_INTERFACE> -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
PostUp = iptables -t mangle -A FORWARD -i <WAN_INTERFACE> -o wg0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
PostDown = iptables -t mangle -D FORWARD -i wg0 -o <WAN_INTERFACE> -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
PostDown = iptables -t mangle -D FORWARD -i <WAN_INTERFACE> -o wg0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

# Replace <WAN_INTERFACE> with your interface (e.g., enp1s0, eth0)
```

### Deployment Warnings

**Warning:** "⚠ IPv4 forwarding is DISABLED on subnet router"

**Fix (Option 1 - Recommended):** Add to PostUp rules in `/etc/wireguard/wg0.conf`:
```bash
PostUp = sysctl -w net.ipv4.ip_forward=1
PostUp = sysctl -w net.ipv6.conf.all.forwarding=1
```

**Fix (Option 2):** Enable system-wide:
```bash
sudo sysctl -w net.ipv4.ip_forward=1
echo 'net.ipv4.ip_forward=1' | sudo tee -a /etc/sysctl.conf
```

**Or run setup:**
```bash
./wg-friend-deploy.py --setup
```

**Warning:** "⚠ No routing rules (MASQUERADE/FORWARD) found in subnet router config"

**Fix:**
```bash
# Run setup mode to add them interactively:
./wg-friend-deploy.py --setup

# Or manually add to /etc/wireguard/wg0.conf [Interface] section:
# Enable IP forwarding
PostUp = sysctl -w net.ipv4.ip_forward=1
PostUp = sysctl -w net.ipv6.conf.all.forwarding=1

# Forwarding rules
PostUp = iptables -A FORWARD -i %i -j ACCEPT
PostUp = iptables -A FORWARD -o %i -j ACCEPT
PostUp = iptables -t nat -A POSTROUTING -o <WAN_INTERFACE> -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT
PostDown = iptables -D FORWARD -o %i -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o <WAN_INTERFACE> -j MASQUERADE
```

### Existing Rules Not Detected

**Symptom:** Setup mode doesn't find your existing PostUp rules.

**Cause:** Rules might be in a separate file or use unconventional format.

**Fix:** Tell setup your rules are correct when prompted. wg-friend respects existing configurations.

## Development

### Project Structure

```
wg-friend/
├── wg-friend.py           # CLI entry point
├── config.example.yaml    # Example configuration
├── requirements.txt       # Python dependencies
├── src/
│   ├── __init__.py
│   ├── ssh_client.py      # SSH operations
│   ├── peer_manager.py    # WireGuard peer management
│   ├── config_builder.py  # Config generation
│   ├── metadata_db.py     # SQLite database
│   ├── keygen.py          # Key generation
│   ├── qr_generator.py    # QR codes
│   ├── templates.py       # Config templates
│   └── tui.py             # Rich TUI interface
├── docs/
│   ├── ARCHITECTURE.md    # Design docs
│   └── USAGE.md          # Usage examples
└── README.md
```

### Running Tests

```bash
# TODO: Add tests
python -m pytest tests/
```

## License

MIT License - See LICENSE file

## Contributing

Contributions welcome! Please open an issue or PR on GitHub.

## Acknowledgments

- Built with [Rich](https://github.com/Textualize/rich) for beautiful terminal output
- Uses [Paramiko](https://www.paramiko.org/) for SSH operations
- QR codes via [segno](https://github.com/heuer/segno)
- Inspired by the need for better WireGuard peer management

## Related

- **homelab-backup-manager** - Automated config backup with Gatus integration (sibling project)

---

Made with ❤️ for home lab enthusiasts
