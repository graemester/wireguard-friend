# Running Integration Tests on Your Local Machine

Complete guide for running WireGuard Friend integration tests **on your own computer** (no cloud, no special tools needed).

## What You're Running

A complete WireGuard network simulation using Docker containers:
- 5 containers (CS, SNR, 2 remotes, LAN device)
- Real WireGuard interfaces
- Actual network connectivity tests
- All running locally on your machine

**Runtime:** ~30-60 seconds per test run
**Disk space:** ~200MB (Docker images)
**RAM:** ~500MB while tests are running

---

## Prerequisites

### 1. Linux Machine

These tests require Linux because:
- WireGuard is a Linux kernel module
- Docker on Mac/Windows uses a Linux VM (tests will still work, but need extra setup)

**Supported:**
- Ubuntu 20.04+ ✓
- Debian 11+ ✓
- Fedora 33+ ✓
- Arch Linux ✓
- Any Linux with kernel 5.6+ ✓

### 2. Install Docker

#### Ubuntu/Debian
```bash
# Remove old versions
sudo apt remove docker docker-engine docker.io containerd runc

# Install Docker
sudo apt update
sudo apt install -y docker.io docker-compose

# Add yourself to docker group (avoid sudo)
sudo usermod -aG docker $USER

# Log out and back in for group to take effect
# Or run: newgrp docker

# Verify
docker --version
docker-compose --version
```

#### Fedora
```bash
sudo dnf install docker docker-compose
sudo systemctl start docker
sudo systemctl enable docker
sudo usermod -aG docker $USER
# Log out and back in
```

#### Arch Linux
```bash
sudo pacman -S docker docker-compose
sudo systemctl start docker
sudo systemctl enable docker
sudo usermod -aG docker $USER
# Log out and back in
```

### 3. Install WireGuard Tools

#### Ubuntu/Debian
```bash
sudo apt install wireguard wireguard-tools
```

#### Fedora
```bash
sudo dnf install wireguard-tools
```

#### Arch Linux
```bash
sudo pacman -S wireguard-tools
```

#### Verify WireGuard Module
```bash
# Load module
sudo modprobe wireguard

# Check it's loaded
lsmod | grep wireguard

# Should show:
# wireguard             102400  0
```

**Note:** On kernel 5.6+, WireGuard is built-in. On older kernels, you may need `wireguard-dkms`:
```bash
sudo apt install wireguard-dkms  # Ubuntu/Debian
```

### 4. Install Python Dependencies

```bash
# Install PyNaCl (for key derivation)
pip3 install pynacl

# Or with user install (no sudo)
pip3 install --user pynacl
```

---

## Quick Start (5 Steps)

### Step 1: Navigate to Test Directory
```bash
cd ~/wireguard-friend/v2/integration-tests
```

### Step 2: Verify Prerequisites
```bash
# Check Docker
docker --version
# Should show: Docker version 20.x.x or higher

# Check Docker Compose
docker-compose --version
# Should show: docker-compose version 1.x.x or higher

# Check WireGuard
sudo modprobe wireguard && lsmod | grep wireguard
# Should show wireguard module loaded

# Check Python
python3 --version
# Should show: Python 3.8 or higher

# Check PyNaCl
python3 -c "import nacl; print('PyNaCl OK')"
# Should show: PyNaCl OK
```

### Step 3: Run Key Validation Test (No Docker Needed)
```bash
python3 test_key_validation.py
```

**Expected output:**
```
======================================================================
KEY VALIDATION TEST
======================================================================

Generated keypairs:
  CS:     abc123...
  SNR:    xyz789...
  Remote: def456...

...

✓ All public keys validated 
```

This test doesn't need Docker - it just validates the key derivation logic.

### Step 4: Build Docker Images (First Time Only)
```bash
make build
```

**Expected output:**
```
Building coordination-server
Building subnet-router
Building remote-1
Building remote-2
Building lan-device
built...
```

This takes ~2-5 minutes the first time (downloads Alpine Linux, installs WireGuard).

### Step 5: Run Complete Integration Test
```bash
make test
```

**Expected output:**
```
============================================================
WIREGUARD FRIEND - INTEGRATION TEST
============================================================

Generating test configs...
  CS permanent_guid:      abc123...
  SNR permanent_guid:     xyz789...

Deploying configs...
  ✓ cs: configs/cs/wg0.conf
  ✓ snr: configs/snr/wg0.conf

Starting Docker containers...
  ✓ Containers ready

Starting WireGuard interfaces...
  ✓ cs: wg0 up
  ✓ snr: wg0 up
  ✓ remote-1: wg0 up
  ✓ remote-2: wg0 up

============================================================
CONNECTIVITY TESTS
============================================================

Testing: Remote-1 → CS
  ✓ PASS

Testing: Remote-1 → SNR
  ✓ PASS

Testing: Remote-1 → Remote-2
  ✓ PASS

Testing: Remote-1 → LAN device (via SNR)
  ✓ PASS

...

============================================================
RESULTS: 9 passed, 0 failed
============================================================
```

---

## Makefile Commands

All commands run from `v2/integration-tests/` directory:

```bash
make help      # Show all available commands
make test      # Run complete integration test suite
make build     # Build Docker images (first time only)
make up        # Start containers for manual testing
make down      # Stop containers
make clean     # Stop containers and delete generated configs
make logs      # Show container logs
make status    # Show WireGuard status on all containers
```

---

## Manual Testing Workflow

Want to manually inspect the test environment?

### 1. Start Containers
```bash
make up
```

Containers are now running in the background.

### 2. Generate Configs Manually
```bash
python3 -c "
from test_connectivity import generate_test_configs, deploy_configs
configs = generate_test_configs()
deploy_configs(configs)
"
```

### 3. Deploy Config to a Container
```bash
# Copy config to CS container
docker exec wgf-cs cp /etc/wireguard/cs/wg0.conf /etc/wireguard/wg0.conf

# Start WireGuard on CS
docker exec wgf-cs wg-quick up wg0

# Check status
docker exec wgf-cs wg show
```

### 4. Test Connectivity Manually
```bash
# From remote-1, ping CS
docker exec wgf-remote1 ping -c 3 10.66.0.1

# From remote-1, ping SNR
docker exec wgf-remote1 ping -c 3 10.66.0.20

# From remote-1, ping LAN device (through SNR)
docker exec wgf-remote1 ping -c 3 192.168.100.10
```

### 5. Inspect Container
```bash
# Get a shell in CS container
docker exec -it wgf-cs /bin/sh

# Inside container:
ip addr show wg0        # Show WireGuard interface
wg show                 # Show WireGuard status
cat /etc/wireguard/wg0.conf  # Show config
exit
```

### 6. View Logs
```bash
# All containers
make logs

# Specific container
docker logs wgf-cs
docker logs wgf-remote1
```

### 7. Cleanup
```bash
make down    # Stop containers
make clean   # Stop + delete configs
```

---

## Troubleshooting

### Problem: `docker: command not found`

**Solution:** Docker not installed.
```bash
sudo apt install docker.io docker-compose
sudo usermod -aG docker $USER
# Log out and back in
```

### Problem: `permission denied while trying to connect to Docker`

**Solution:** Not in docker group.
```bash
sudo usermod -aG docker $USER
# Log out and back in
# Or: newgrp docker
```

### Problem: `wireguard module not found`

**Solution:** WireGuard not installed.
```bash
# On Ubuntu/Debian
sudo apt install wireguard wireguard-tools

# Load module
sudo modprobe wireguard

# Check
lsmod | grep wireguard
```

### Problem: `ModuleNotFoundError: No module named 'nacl'`

**Solution:** PyNaCl not installed.
```bash
pip3 install pynacl
# Or: pip3 install --user pynacl
```

### Problem: Test fails with `network timeout` or `no route to host`

**Possible causes:**
1. WireGuard not starting in containers
2. Docker network issues

**Debug:**
```bash
# Check if WireGuard started
make status

# Check container networking
docker exec wgf-cs ip addr
docker exec wgf-cs ip route

# Check iptables (may need privileged mode)
docker exec wgf-cs iptables -L -n -v
```

### Problem: `failed to start wg0: Operation not permitted`

**Solution:** Container needs NET_ADMIN capability.

Already configured in `docker-compose.yml`:
```yaml
cap_add:
  - NET_ADMIN
  - SYS_MODULE
privileged: true
```

If still failing, check Docker daemon is running:
```bash
sudo systemctl status docker
sudo systemctl start docker
```

### Problem: Containers won't start

**Debug:**
```bash
# Check Docker daemon
sudo systemctl status docker

# Check logs
docker-compose logs

# Rebuild from scratch
make clean
docker-compose build --no-cache
```

---

## What's Happening Behind the Scenes

### When You Run `make test`:

1. **Generate Configs** (`test_connectivity.py`)
   - Creates 4 WireGuard keypairs
   - Generates configs for CS, SNR, Remote-1, Remote-2
   - Writes to `configs/` directory

2. **Start Docker Compose**
   - Launches 5 Alpine Linux containers
   - Creates 2 Docker networks (internet, lan)
   - Mounts `configs/` into containers

3. **Start WireGuard**
   - Copies entity-specific config to `/etc/wireguard/wg0.conf`
   - Runs `wg-quick up wg0` in each container
   - WireGuard interface comes up

4. **Test Connectivity**
   - Pings between all peer combinations
   - Tests routing through subnet router
   - Tests LAN access

5. **Cleanup**
   - Stops all containers
   - Removes Docker networks
   - Leaves configs for inspection (use `make clean` to remove)

### Docker Network Layout

```
Docker Host (your machine)
├─ Bridge: internet (172.20.0.0/16)
│  ├─ wgf-cs (172.20.0.10)
│  ├─ wgf-snr (172.20.0.20)
│  ├─ wgf-remote1 (172.20.0.30)
│  └─ wgf-remote2 (172.20.0.31)
│
└─ Bridge: lan (192.168.100.0/24)
   ├─ wgf-snr (192.168.100.1)
   └─ wgf-lan-device (192.168.100.10)
```

WireGuard creates overlay network:
```
WireGuard VPN (10.66.0.0/24)
├─ CS: 10.66.0.1
├─ SNR: 10.66.0.20 (advertises 192.168.100.0/24)
├─ Remote-1: 10.66.0.30
└─ Remote-2: 10.66.0.31
```

---

## Performance & Resources

### Disk Space
- Docker images: ~200MB
- Generated configs: <1KB
- Container overlays: ~50MB while running

**Total:** ~250MB

### Memory Usage
- Each container: ~30-50MB
- 5 containers: ~250MB total
- WireGuard: negligible overhead

**Total:** ~500MB while tests running

### Runtime
- First build: 2-5 minutes (downloads images)
- Subsequent runs: 30-60 seconds
- Key validation only: <1 second

---

## Additional: Running Without Docker

If you can't use Docker, you can test with **Linux network namespaces**:

```bash
# Create namespaces
sudo ip netns add cs
sudo ip netns add snr
sudo ip netns add remote1

# Generate configs (same as Docker test)
python3 test_connectivity.py  # Extract config generation

# Copy configs to /etc/wireguard/
sudo cp configs/cs/wg0.conf /etc/wireguard/cs-wg0.conf
sudo cp configs/snr/wg0.conf /etc/wireguard/snr-wg0.conf
sudo cp configs/remote-1/wg0.conf /etc/wireguard/remote1-wg0.conf

# Start WireGuard in namespaces
sudo ip netns exec cs wg-quick up cs-wg0
sudo ip netns exec snr wg-quick up snr-wg0
sudo ip netns exec remote1 wg-quick up remote1-wg0

# Test
sudo ip netns exec remote1 ping 10.66.0.1  # remote1 → CS
sudo ip netns exec remote1 ping 10.66.0.20 # remote1 → SNR

# Cleanup
sudo ip netns exec cs wg-quick down cs-wg0
sudo ip netns delete cs
# ... repeat for other namespaces
```

This is more manual but doesn't require Docker.

---

## CI/CD Integration

Want to run tests automatically on every commit?

### GitHub Actions

Create `.github/workflows/integration-test.yml`:

```yaml
name: Integration Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v3

      - name: Install WireGuard
        run: |
          sudo apt update
          sudo apt install -y wireguard wireguard-tools
          sudo modprobe wireguard

      - name: Install Python dependencies
        run: pip3 install pynacl

      - name: Run integration tests
        run: |
          cd v2/integration-tests
          make test
```

Tests run automatically on GitHub's servers.

---

## Summary

**Offline usage is simple:**

```bash
# One-time setup
sudo apt install docker.io docker-compose wireguard wireguard-tools
sudo usermod -aG docker $USER
pip3 install pynacl
# Log out and back in

# Run tests anytime
cd ~/wireguard-friend/v2/integration-tests
make test
```

**No internet required** after initial Docker image download.
**No cloud servers** - runs entirely on your machine.
**No special tools** - just Docker + Python + WireGuard.

**Questions?** Check the troubleshooting section or `README.md`.
