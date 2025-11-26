# wg-friend Setup Guide

## Quick Start (5 minutes)

### Step 1: Install Prerequisites

```bash
# Install WireGuard tools and Python
sudo apt update
sudo apt install wireguard-tools python3-pip

# Navigate to wg-friend
cd wg-friend

# Install Python dependencies
pip3 install -r requirements.txt
```

### Step 2: Choose Your Setup Path

**Option A: Import Existing Configs** (recommended if you already have WireGuard running)
Note: You don't have the name the files any special way; the script will inspect them.
```bash
# Gather your existing configs into import/ directory
mkdir import
cp /path/to/coordinator-wg0.conf import/
cp /path/to/subnet-router-wg0.conf import/
cp /path/to/client-*.conf import/  # Optional: existing client configs

# Run onboarding (detects and imports everything)
./wg-friend-onboard.py --scan ./import
```

**Option B: Setup from Scratch** (interactive wizard for new deployments)
```bash
./wg-friend-onboard.py --wizard
```

The onboarding script will:
- ✅ Import your existing WireGuard configs (Option A) or guide you through setup (Option B)
- ✅ Create `~/.wg-friend/config.yaml` with coordinator/subnet router details
- ✅ Initialize the peer database (`~/.wg-friend/peers.db`)
- ✅ Detect infrastructure vs client peers
- ✅ Preserve comments and metadata from existing configs

### Step 3: Configure Automated Deployment (One-Time Setup)

```bash
# Run setup mode to configure SSH keys and verify system settings
./wg-friend-deploy.py --setup
```

This will:
- ✅ Generate a dedicated SSH keypair (`~/.wg-friend/ssh/wg-friend-deploy`)
- ✅ Install the public key to your coordinator
- ✅ Install the public key to your subnet router (if configured)
- ✅ Test SSH authentication
- ✅ Verify IP forwarding on subnet router (PostUp rules or system-level)
- ✅ Confirm routing rules (iptables MASQUERADE, FORWARD chains)
- ✅ Offer to add missing PostUp rules if needed

**Note:** Setup mode is interactive - you'll enter SSH passwords once to install the keys, then never again!

### Step 4: Daily Workflow

Now you're ready for the streamlined workflow:

```bash
# 1. Add a new peer (TUI or CLI)
./wg-friend.py add iphone-graeme --qr

# 2. Export coordinator config with all active peers
./wg-friend.py export

# 3. Deploy to infrastructure (one command!)
./wg-friend-deploy.py
```

The deploy script:
- ✓ Detects if running locally (uses sudo) or remotely (uses SSH)
- ✓ Backs up existing configs before uploading
- ✓ Uploads new configs to coordinator and subnet router
- ✓ Restarts WireGuard services
- ✓ Verifies deployment success
- ✓ Runs pre-flight checks (IP forwarding, routing rules)

## Detailed Setup

### Onboarding: Import Workflow

The import workflow is designed for users with existing WireGuard setups:

**Step 1: Gather your configs**
```bash
mkdir import

# From coordinator (public VPS)
scp -P 2223 user@oh.higrae.me:/etc/wireguard/wg0.conf import/coordinator-wg0.conf

# From subnet router (home LAN gateway)
scp user@192.168.12.20:/etc/wireguard/wg0.conf import/icculus-wg0.conf

# Optional: existing client configs
cp ~/wireguard-backups/*.conf import/
```

**Step 2: Run onboarding**
```bash
./wg-friend-onboard.py --scan ./import
```

The script will:
- Parse all `.conf` files in `import/`
- Detect config types (coordinator, subnet_router, client)
- Extract peer information and comments
- Suggest next available IPs
- Generate `~/.wg-friend/config.yaml`
- Create peer database with all discovered peers

**Step 3: Review and confirm**

The script shows what it found and asks for confirmation before writing files.

**Recovery Mode:**

If you have a coordinator config but missing client configs for some peers:
```bash
./wg-friend-onboard.py --scan ./import --recover
```

This will offer to rotate keys for "orphan" peers (exist on coordinator but no client config).

### Onboarding: Wizard (From Scratch)

If you're setting up WireGuard for the first time:

```bash
./wg-friend-onboard.py --wizard
```

The wizard will ask:
1. **Coordinator details** (hostname, SSH port, endpoint)
2. **Network settings** (IPv4/IPv6 subnets, DNS)
3. **Subnet router** (optional - for LAN access)
4. **Peer templates** (mobile vs desktop defaults)

It will generate:
- Coordinator config (`/etc/wireguard/wg0.conf` on VPS)
- Subnet router config (if applicable)
- wg-friend config (`~/.wg-friend/config.yaml`)

**Warning:** Wizard mode will SSH to your servers and create configs. Review carefully!

### Deployment: Setup Mode

Before you can deploy, run one-time setup:

```bash
./wg-friend-deploy.py --setup
```

**What happens:**

1. **SSH Key Generation**
   - Creates `~/.wg-friend/ssh/wg-friend-deploy` (ed25519 keypair)
   - Installs public key to coordinator and subnet router
   - Tests authentication

2. **System Configuration Check (Subnet Router)**
   - Checks for IP forwarding:
     - **Prefers PostUp rules** (e.g., `PostUp = sysctl -w net.ipv4.ip_forward=1`)
     - Falls back to system-level `/etc/sysctl.conf` if not in PostUp
   - Verifies routing rules exist:
     - `iptables -A FORWARD -i wg0 -j ACCEPT`
     - `iptables -t nat -A POSTROUTING -o <WAN> -j MASQUERADE`
   - Shows your existing PostUp/PostDown rules
   - Offers to add missing rules (only if you confirm)

3. **Local vs Remote Detection**
   - If you're running on the coordinator or subnet router, setup skips SSH key install for that host
   - You'll use sudo for local deployments instead

**Example Setup Output:**
```
🔐 SSH Key Setup
✓ Generated keypair: ~/.wg-friend/ssh/wg-friend-deploy

🌐 Setting up coordinator (oh.higrae.me:2223)
  Enter SSH password: ********
✓ Public key installed
✓ Authentication test successful

🏠 Setting up subnet router (192.168.12.20:22)
  Enter SSH password: ********
✓ Public key installed
✓ Authentication test successful

🛠️ Subnet Router System Configuration

Checking IP forwarding...
✓ IPv4 forwarding enabled in PostUp rules (best practice!)
✓ IPv6 forwarding enabled in PostUp rules (best practice!)

Verifying PostUp/PostDown routing rules...
✓ Found 18 PostUp rules (includes IP forwarding, FORWARD chains, MASQUERADE, MSS clamping)
✓ Found 10 PostDown rules (cleanup)

✅ Subnet router is properly configured!

Setup complete! You can now use ./wg-friend-deploy.py without passwords.
```

### Deployment: Daily Usage

After setup, deployment is a single command:

```bash
./wg-friend-deploy.py
```

**What happens:**

1. **Pre-flight Checks** (non-blocking warnings)
   - Verify IP forwarding is enabled (PostUp or system-level)
   - Confirm routing rules exist
   - Warn if misconfigured (but continue deployment)

2. **Coordinator Deployment**
   - Detect if local or remote
   - Backup existing config (timestamped)
   - Upload new config from `~/.wg-friend/coordinator-wg0.conf`
   - Restart `wg-quick@wg0` service
   - Verify `wg show` reports peers

3. **Subnet Router Deployment** (if configured)
   - Same steps as coordinator
   - Additional verification of routing rules

**Example Deployment Output:**
```
🚀 wg-friend Deployment

🌐 Deploying to Coordinator
  Coordinator: ged@oh.higrae.me:2223
  Config: /etc/wireguard/wg0.conf
  Interface: wg0

✓ Backed up to: /etc/wireguard/wg0.conf.backup.20251126-143022
✓ Uploaded to: /etc/wireguard/wg0.conf
🔄 Restarting wg-quick@wg0...
✓ WireGuard restarted
✓ Verified: 12 peers active

🏠 Deploying to Subnet Router
  Subnet Router: ged@192.168.12.20:22 (localhost detected)
  Config: /etc/wireguard/wg0.conf
  Interface: wg0

✓ Backed up to: /etc/wireguard/wg0.conf.backup.20251126-143023
✓ Deployed locally (with sudo)
🔄 Restarting wg-quick@wg0...
✓ WireGuard restarted

✅ Deployment complete!
```

**Local Deployment:**

If you're running on the coordinator or subnet router:
```bash
sudo ./wg-friend-deploy.py
```

It will detect the local host and use filesystem operations instead of SSH.

### Configuration File

After onboarding, you'll have `~/.wg-friend/config.yaml`:

```yaml
coordinator:
  name: oh.higrae.me
  host: oh.higrae.me
  port: 2223
  user: ged
  config_path: /etc/wireguard/wg0.conf
  interface: wg0
  endpoint: oh.higrae.me:51820
  public_key: Yk+VD886XMnyu2EUGWFoLKXJAwkN7wtCauQzq32KUC8=
  local_config_path: ~/.wg-friend/coordinator-wg0.conf
  vpn_ip:
    ipv4: 10.66.0.1
    ipv6: fd66:6666::1
  network:
    ipv4: 10.66.0.0/24
    ipv6: fd66:6666::/64

subnet_router:
  name: icculus
  host: 192.168.12.20
  port: 22
  user: ged
  config_path: /etc/wireguard/wg0.conf
  interface: wg0
  vpn_ip:
    ipv4: 10.66.0.20
    ipv6: fd66:6666::20
  routed_subnets:
    - 192.168.12.0/24
  dns: 192.168.12.20

peer_templates:
  mobile_client:
    description: Full access mobile device
    persistent_keepalive: 25
    dns: 192.168.12.20
    allowed_ips:
      - 10.66.0.0/24
      - fd66:6666::/64
      - 192.168.12.0/24
    mtu: 1280

  desktop_client:
    description: Desktop/laptop with full access
    persistent_keepalive: 25
    dns: 192.168.12.20
    allowed_ips:
      - 10.66.0.0/24
      - fd66:6666::/64
      - 192.168.12.0/24
    mtu: 1420

ip_allocation:
  start_ipv4: 10.66.0.50
  end_ipv4: 10.66.0.254
  reserved:
    - 10.66.0.1   # Coordinator
    - 10.66.0.20  # Subnet router

metadata_db: ~/.wg-friend/peers.db
```

## CLI Commands

### Add a Peer

```bash
# Mobile client with QR code
./wg-friend.py add iphone-graeme --qr

# Desktop client (no QR code)
./wg-friend.py add laptop-work

# Server peer with custom settings
./wg-friend.py add remote-server --ip 10.66.0.30 --type server_peer
```

### List Peers

```bash
# All peers
./wg-friend.py list

# Active peers only
./wg-friend.py list --active

# JSON output
./wg-friend.py list --json
```

### Export Coordinator Config

```bash
# Export to default location (~/.wg-friend/coordinator-wg0.conf)
./wg-friend.py export

# Export to custom location
./wg-friend.py export --output /tmp/wg0.conf
```

This generates the full coordinator config with all active peers from the database.

### Rotate Peer Keys

```bash
# Rotate a specific peer
./wg-friend.py rotate iphone-graeme --qr

# The old keys are marked as revoked in the database
```

### Revoke a Peer

```bash
# Revoke peer (removes from coordinator and subnet router)
./wg-friend.py revoke iphone-graeme
```

**Note:** After rotate or revoke, run `./wg-friend.py export && ./wg-friend-deploy.py` to update infrastructure.

### TUI Mode

```bash
# Launch interactive TUI
./wg-friend.py tui
```

Features:
- Navigate with arrow keys
- View peer details
- Add new peers
- Rotate keys
- Revoke peers
- Real-time QR code display

## Permissions

wg-friend needs sudo access on coordinator and subnet router to:
- Read `/etc/wireguard/wg0.conf`
- Write to `/etc/wireguard/wg0.conf`
- Restart `wg-quick@wg0.service`
- Run `wg show` command

**Option 1: Full sudo** (easiest)

Your user already has full sudo access.

**Option 2: Limited sudo** (more secure)

Create sudoers rule:

```bash
# On coordinator/subnet router:
sudo visudo -f /etc/sudoers.d/wg-friend

# Add:
your_user ALL=(ALL) NOPASSWD: /usr/bin/wg, /bin/cat /etc/wireguard/wg0.conf, /bin/cp * /etc/wireguard/wg0.conf, /bin/chmod 600 /etc/wireguard/wg0.conf, /bin/systemctl restart wg-quick@wg0
```

## Subnet Router: IP Forwarding and Routing Rules

For the subnet router to route traffic between VPN and LAN, you need:

1. **IP forwarding enabled**
2. **iptables routing rules**

### Recommended Approach: PostUp Rules

Add to `/etc/wireguard/wg0.conf` [Interface] section:

```ini
[Interface]
Address = 10.66.0.20/24, fd66:6666::20/64
ListenPort = 51820
PrivateKey = <private-key>

# Enable IP forwarding (only when VPN is up - more secure!)
PostUp = sysctl -w net.ipv4.ip_forward=1
PostUp = sysctl -w net.ipv6.conf.all.forwarding=1

# Forwarding rules
PostUp = iptables -A FORWARD -i wg0 -o enp1s0 -j ACCEPT
PostUp = iptables -A FORWARD -i enp1s0 -o wg0 -j ACCEPT
PostUp = iptables -t nat -A POSTROUTING -o enp1s0 -s 10.66.0.0/24 -j MASQUERADE
PostUp = ip6tables -A FORWARD -i wg0 -o enp1s0 -j ACCEPT
PostUp = ip6tables -A FORWARD -i enp1s0 -o wg0 -j ACCEPT

# Cleanup
PostDown = iptables -D FORWARD -i wg0 -o enp1s0 -j ACCEPT
PostDown = iptables -D FORWARD -i enp1s0 -o wg0 -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o enp1s0 -s 10.66.0.0/24 -j MASQUERADE
PostDown = ip6tables -D FORWARD -i wg0 -o enp1s0 -j ACCEPT
PostDown = ip6tables -D FORWARD -i enp1s0 -o wg0 -j ACCEPT
```

**Benefits:**
- IP forwarding only enabled when VPN is up (more secure)
- Self-contained in WireGuard config
- Automatic cleanup when WireGuard stops
- Recognized by `wg-friend-deploy.py` as best practice

### Alternative: System-Level (Always On)

```bash
# Enable runtime
sudo sysctl -w net.ipv4.ip_forward=1
sudo sysctl -w net.ipv6.conf.all.forwarding=1

# Make permanent
echo 'net.ipv4.ip_forward=1' | sudo tee -a /etc/sysctl.conf
echo 'net.ipv6.conf.all.forwarding=1' | sudo tee -a /etc/sysctl.conf

# Still need iptables rules in PostUp/PostDown (see above)
```

The deployment script (`./wg-friend-deploy.py --setup`) will:
- Check for IP forwarding in PostUp rules first
- Fall back to system-level if not in PostUp
- Offer to add missing rules if needed

## Troubleshooting

### Onboarding: "No coordinator config found"

**Problem:** The import directory has client configs but no coordinator config.

**Fix:**
```bash
# Make sure you copied the coordinator config (the one with multiple peers)
scp -P 2223 user@coordinator:/etc/wireguard/wg0.conf import/coordinator-wg0.conf

# Or use --wizard to setup from scratch
./wg-friend-onboard.py --wizard
```

### Deployment: SSH Authentication Failed

**Problem:** Can't connect to coordinator/subnet router via SSH.

**Fix:**
```bash
# Re-run setup
./wg-friend-deploy.py --setup

# Or test SSH manually
ssh -p 2223 -i ~/.wg-friend/ssh/wg-friend-deploy user@coordinator
```

### Deployment: "Permission denied" on /etc/wireguard/

**Problem:** User doesn't have sudo access.

**Fix:**
```bash
# On coordinator/subnet router, verify sudo:
sudo -v

# If using local deployment, make sure to run with sudo:
sudo ./wg-friend-deploy.py
```

### Subnet Router Not Routing Traffic

**Problem:** Can ping VPN IPs but not LAN IPs (e.g., 192.168.12.x).

**Fix:**
```bash
# Verify IP forwarding
sudo sysctl net.ipv4.ip_forward
# Should output: net.ipv4.ip_forward = 1

# Check iptables rules
sudo iptables -t nat -L POSTROUTING -v -n
# Should see MASQUERADE rule for 10.66.0.0/24

# If missing, add to PostUp rules (see section above)
```

### Pre-flight Warning: "IPv4 forwarding is DISABLED"

**Problem:** Deployment warns about IP forwarding.

**Fix (Option 1 - Recommended):** Add to PostUp rules in `/etc/wireguard/wg0.conf`:
```ini
PostUp = sysctl -w net.ipv4.ip_forward=1
PostUp = sysctl -w net.ipv6.conf.all.forwarding=1
```

**Fix (Option 2):** Enable system-wide:
```bash
sudo sysctl -w net.ipv4.ip_forward=1
echo 'net.ipv4.ip_forward=1' | sudo tee -a /etc/sysctl.conf
```

Then redeploy:
```bash
./wg-friend-deploy.py
```

### QR Code Not Displaying

**Problem:** QR code garbled or not showing in terminal.

**Fix:**
```bash
# Reinstall segno
pip3 install segno --force-reinstall

# Or save to PNG file
./wg-friend.py add test-peer --qr
# QR PNG saved to ~/.wg-friend/qr-codes/test-peer.png
```

## Next Steps

1. **Add peers**: `./wg-friend.py add my-phone --qr`
2. **Export config**: `./wg-friend.py export`
3. **Deploy**: `./wg-friend-deploy.py`
4. **Verify**: `ssh coordinator "sudo wg show"`
5. **Connect from mobile**: Scan QR code, test connectivity
6. **Explore TUI**: `./wg-friend.py tui`

For more details, see:
- [README.md](../README.md) - Complete feature overview
- [config.example.yaml](../config.example.yaml) - Configuration reference
