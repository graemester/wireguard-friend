# wg-friend Setup Guide

## Quick Start (5 minutes)

### Step 1: Install Prerequisites

```bash
# Install WireGuard tools
sudo apt update
sudo apt install wireguard-tools python3-pip

# Clone or navigate to wg-friend
cd wg-friend

# Install Python dependencies
pip3 install -r requirements.txt
```

### Step 2: Configure

```bash
# Create config directory
mkdir -p ~/.wg-friend

# Copy example config
cp config.example.yaml ~/.wg-friend/config.yaml

# Edit configuration
nano ~/.wg-friend/config.yaml
```

**Minimum Required Settings:**

```yaml
coordinator:
  name: oh.higrae.me
  host: oh.higrae.me  # Your VPS hostname/IP
  port: 2223          # SSH port
  user: ged           # SSH username
  config_path: /etc/wireguard/wg0.conf
  endpoint: oh.higrae.me:51820
  public_key: YOUR_COORDINATOR_PUBLIC_KEY
  network:
    ipv4: 10.66.0.0/24
    ipv6: fd66:6666::/64

ssh:
  key_path: ~/.ssh/id_ed25519  # Your SSH key
```

### Step 3: Setup SSH Access

```bash
# Generate SSH key if you don't have one
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519

# Copy to coordinator
ssh-copy-id -p 2223 ged@oh.higrae.me

# Test connection
ssh -p 2223 ged@oh.higrae.me "sudo wg show"
```

### Step 4: Launch wg-friend

```bash
./wg-friend.py tui
```

## Detailed Configuration

### 1. Coordinator Setup

Your coordinator is the central WireGuard server (usually a VPS with a public IP).

**Get Coordinator Public Key:**

```bash
ssh -p 2223 user@coordinator.example.com "sudo wg show wg0 public-key"
```

**Verify wg0.conf location:**

```bash
ssh -p 2223 user@coordinator.example.com "ls -la /etc/wireguard/"
```

### 2. Subnet Router (Optional)

If you have a home server routing LAN traffic:

```yaml
subnet_router:
  name: icculus
  host: 192.168.12.20
  vpn_ip:
    ipv4: 10.66.0.20
  routed_subnets:
    - 192.168.12.0/24  # Your home LAN
  dns: 192.168.12.20   # Pi-hole or local DNS
```

### 3. Peer Templates

Customize peer types for your needs:

```yaml
peer_templates:
  mobile_client:
    description: "Full access mobile device"
    persistent_keepalive: 25
    dns: 192.168.12.20
    allowed_ips:
      - 10.66.0.0/24        # VPN mesh
      - fd66:6666::/64      # VPN IPv6
      - 192.168.12.0/24     # Home LAN
    mtu: 1280

  restricted_guest:
    description: "Guest device with limited access"
    persistent_keepalive: 25
    dns: 10.66.0.1
    allowed_ips:
      - 10.66.0.0/24        # VPN mesh only
    mtu: 1280
```

### 4. IP Allocation

Reserve IPs for infrastructure:

```yaml
ip_allocation:
  start_ipv4: 10.66.0.50    # Start of client range
  end_ipv4: 10.66.0.254
  reserved:
    - 10.66.0.1   # Coordinator
    - 10.66.0.20  # Subnet router
    - 10.66.0.30  # Another server
```

## Common Setups

### Scenario 1: Simple VPN (No LAN Access)

Just a coordinator and mobile clients:

```yaml
coordinator:
  name: my-vpn-server
  host: vpn.example.com
  endpoint: vpn.example.com:51820
  network:
    ipv4: 10.99.0.0/24
    ipv6: fd99:9999::/64

peer_templates:
  mobile_client:
    allowed_ips:
      - 10.99.0.0/24       # VPN mesh only
      - fd99:9999::/64
```

### Scenario 2: Home Lab Access

Coordinator + subnet router + clients accessing home network:

```yaml
coordinator:
  name: cloud-vps
  host: vps.example.com
  endpoint: vps.example.com:51820

subnet_router:
  name: home-server
  host: 192.168.1.10
  vpn_ip:
    ipv4: 10.66.0.10
  routed_subnets:
    - 192.168.1.0/24

peer_templates:
  mobile_client:
    allowed_ips:
      - 10.66.0.0/24       # VPN mesh
      - 192.168.1.0/24     # Home LAN via subnet router
```

### Scenario 3: Multi-Site Mesh

Multiple sites connected via WireGuard:

```yaml
coordinator:
  name: central-hub
  endpoint: hub.example.com:51820

peer_templates:
  site_router:
    description: "Site-to-site router"
    persistent_keepalive: 15
    allowed_ips:
      - 10.66.0.0/24       # Mesh
      - 192.168.1.0/24     # Site A
      - 192.168.2.0/24     # Site B
```

## Permissions

wg-friend needs sudo access on the coordinator to:
- Read `/etc/wireguard/wg0.conf`
- Write to `/etc/wireguard/wg0.conf`
- Restart `wg-quick@wg0.service`
- Run `wg show` command

**Option 1: Full sudo** (easiest)

User already has full sudo access.

**Option 2: Limited sudo** (more secure)

Create sudoers rule:

```bash
# On coordinator:
sudo visudo -f /etc/sudoers.d/wg-friend

# Add:
your_user ALL=(ALL) NOPASSWD: /usr/bin/wg, /bin/cat /etc/wireguard/wg0.conf, /bin/cp * /etc/wireguard/wg0.conf, /bin/chmod 600 /etc/wireguard/wg0.conf, /bin/systemctl restart wg-quick@wg0
```

## First Peer

Add your first peer:

```bash
./wg-friend.py add my-phone --qr --add-to-coordinator
```

This will:
1. Generate WireGuard keypair
2. Assign next available IP (10.66.0.50)
3. Create client config
4. Display QR code
5. Add peer to coordinator wg0.conf
6. Restart WireGuard on coordinator
7. Save to local database

Scan the QR code with WireGuard mobile app and connect!

## Verification

Test your setup:

```bash
# View status
./wg-friend.py status

# Check peer on coordinator
ssh -p 2223 user@coordinator "sudo wg show wg0"

# Test connectivity from mobile device
# (After connecting via WireGuard app)
ping 10.66.0.1         # Coordinator
ping 192.168.12.20     # Home server (if subnet router configured)
```

## Troubleshooting

### SSH Connection Failed

```bash
# Test basic SSH
ssh -v -p 2223 user@coordinator.example.com

# Check SSH key
ssh-add -l
```

### Peer Not Added

```bash
# Check coordinator config manually
ssh -p 2223 user@coordinator "sudo cat /etc/wireguard/wg0.conf"

# Check WireGuard status
ssh -p 2223 user@coordinator "sudo wg show wg0"
```

### QR Code Not Displaying

```bash
# Reinstall segno
pip3 install segno --force-reinstall

# Or use file output
./wg-friend.py add test-peer --qr
# QR PNG saved to ~/.wg-friend/qr-codes/test-peer.png
```

## Next Steps

- Add more peers: `./wg-friend.py add laptop-work`
- View all peers: `./wg-friend.py list`
- Explore TUI: `./wg-friend.py tui`
- Customize peer templates in config.yaml
- Setup automated backups of `~/.wg-friend/peers.db`
