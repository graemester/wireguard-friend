# WireGuard Friend - Integration Tests

End-to-end tests that verify WireGuard configurations actually work with real network connectivity.

---

 **[→ LOCAL_TESTING.md - Complete guide for running tests on your own machine](LOCAL_TESTING.md)**

---

## What This Tests

✓ **Config Generation**: WireGuard-friend generates valid configs
✓ **WireGuard Startup**: Configs can actually start WireGuard
✓ **Basic Connectivity**: Peers can ping each other through VPN
✓ **Routing**: Traffic routes correctly through subnet router
✓ **LAN Access**: Remote clients can reach devices behind subnet router

## Architecture

Uses Docker Compose to simulate a multi-host WireGuard network:

```
┌─────────────────────────────────────────────────────────┐
│                   Internet (172.20.0.0/16)              │
│                                                         │
│  ┌──────────────┐      ┌──────────────┐                │
│  │ Coordination │      │Subnet Router │                │
│  │   Server     │◄────►│  (Gateway)   │                │
│  │  10.66.0.1   │      │  10.66.0.20  │                │
│  └──────────────┘      └───────┬──────┘                │
│         ▲                      │                        │
│         │                      ▼                        │
│         │              ┌───────────────┐                │
│         │              │      LAN      │                │
│         │              │ 192.168.100.0 │                │
│  ┌──────┴────┐         │               │                │
│  │  Remote-1 │         │  ┌─────────┐  │                │
│  │10.66.0.30 │         │  │LAN Dev. │  │                │
│  └───────────┘         │  │.100.10  │  │                │
│                        │  └─────────┘  │                │
│  ┌───────────┐         └───────────────┘                │
│  │  Remote-2 │                                          │
│  │10.66.0.31 │                                          │
│  └───────────┘                                          │
└─────────────────────────────────────────────────────────┘
```

## Requirements

- Docker & Docker Compose
- Linux kernel with WireGuard module (or `wireguard-dkms`)
- Python 3.8+
- WireGuard tools (`wg`, `wg-quick`)

## Quick Start

```bash
# From project root
cd v2/integration-tests

# Run basic connectivity test
python3 test_connectivity.py

# Or use the Makefile
make test
```

## What Gets Tested

### 1. Config Generation
- Generates configs for 4 entities (CS, SNR, 2 remotes)
- Each entity gets unique keypair
- Public keys derived from private keys (NOT stored separately!)
- Each entity assigned `permanent_guid = derived_public_key`

### 2. Deployment
- Configs deployed to Docker containers
- WireGuard started on all peers

### 3. Connectivity Tests
- Remote-1 → CS ✓
- Remote-1 → SNR ✓
- Remote-1 → Remote-2 ✓
- Remote-2 → CS ✓
- Remote-2 → SNR ✓
- SNR → CS ✓

### 4. Routing Tests
- Remote-1 → LAN device (192.168.100.10) ✓
- Remote-2 → LAN device ✓
- Traffic correctly routes through SNR

## Key Concepts Tested

### Public Key Derivation
```python
# Config contains ONLY private key in [Interface]
[Interface]
PrivateKey = ABC123...  ← Only this is stored

# Public key is DERIVED from private key
public_key = derive_public_key(private_key)

# This becomes the permanent_guid
permanent_guid = public_key
```

### Minimal Network
The test validates that minimal setup (1 CS, 1 SNR, 1 Remote) works because:
- CS config contains CS's private key → derive CS's public key
- SNR config contains SNR's private key → derive SNR's public key
- Remote config contains Remote's private key → derive Remote's public key

All three get `permanent_guid` on first import.

## Files

```
integration-tests/
├── README.md              ← This file
├── Dockerfile             ← Alpine + WireGuard container
├── docker-compose.yml     ← Multi-container network
├── wg_keys.py            ← Key generation & derivation
├── test_connectivity.py  ← Basic connectivity test
└── configs/              ← Generated configs (gitignored)
```

## Expected Output

```
============================================================
WIREGUARD FRIEND - INTEGRATION TEST
============================================================

Generating test configs...
  CS permanent_guid:      abc123...
  SNR permanent_guid:     xyz789...
  Remote-1 permanent_guid: def456...
  Remote-2 permanent_guid: ghi789...

Deploying configs...
  ✓ cs: configs/cs/wg0.conf
  ✓ snr: configs/snr/wg0.conf
  ✓ remote-1: configs/remote-1/wg0.conf
  ✓ remote-2: configs/remote-2/wg0.conf

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

... [more tests]

============================================================
RESULTS: 9 passed, 0 failed
============================================================
```

## Troubleshooting

### WireGuard module not loaded
```bash
# Check if module is available
sudo modprobe wireguard
lsmod | grep wireguard

# If not, install wireguard-dkms
sudo apt install wireguard-dkms
```

### Permission denied
```bash
# Tests require Docker access
sudo usermod -aG docker $USER
# Log out and back in
```

### Containers won't start
```bash
# Clean up old containers
cd v2/integration-tests
docker-compose down -v

# Rebuild
docker-compose build --no-cache
```

## Future Tests

Planned additions:
- `test_key_rotation.py` - Rotate a key, verify connectivity maintained
- `test_add_peer.py` - Add new peer dynamically, test connectivity
- `test_ssh_deployment.py` - Test SSH-based config deployment
- `test_failover.py` - Kill CS, verify peers still communicate

## CI/CD Integration

Can be integrated into GitHub Actions:

```yaml
# .github/workflows/integration-test.yml
name: Integration Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Install WireGuard
        run: sudo apt install wireguard wireguard-tools
      - name: Run integration tests
        run: |
          cd v2/integration-tests
          python3 test_connectivity.py
```

## Notes

- Tests run in **isolated Docker network** (no impact on host WireGuard)
- Each test run generates **new keypairs** (no key reuse)
- Containers are **ephemeral** (destroyed after test)
- Test duration: ~30-60 seconds

## Why This Matters

Unit tests verify configs are **syntactically valid**.
Integration tests verify configs **actually work** with real WireGuard.

This catches bugs like:
- Invalid IP routing
- Incorrect firewall rules
- Missing kernel modules
- Key derivation errors
- AllowedIPs misconfigurations
