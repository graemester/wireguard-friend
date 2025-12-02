# WireGuard Friend Test Lab

Comprehensive test suite for wireguard-friend reliability validation.

## Quick Start

```bash
# Run all unit/integration tests (fast, no Docker)
./test-lab/run-all-tests.sh

# Run everything including Docker network tests (slower, real WireGuard tunnels)
./test-lab/run-all-tests.sh --docker
```

Exit code 0 = all tests passed.

## What Gets Tested

### Unit/Integration Tests (always run)

| Suite | Tests | What It Validates |
|-------|-------|-------------------|
| Comprehensive | 36 | Roundtrip fidelity, key rotation, GUID preservation, access levels, DB integrity, stress |
| Import Workflows | 22 | Config type detection (CS/SNR/client), parsing, re-import, error handling |
| Extramural | 15 | Isolation from mesh, sponsor/peer operations, no cross-contamination |
| Fidelity | 15 | Export-import functional equivalence, field preservation, round-trips |
| CLI Behavior | 9 | Error messages, help system, input validation |
| Config Detector | 8 | Entity type detection heuristics |
| Roundtrip | 84 | Import -> DB -> export byte comparison |
| Extramural E2E | 13 | End-to-end extramural workflows |

### Docker Network Tests (with --docker flag)

Spins up 5 Alpine Linux containers to test real WireGuard connectivity:

```
Network Topology:

    [CS] 172.20.0.10 (VPN: 10.99.0.1)
      |
      +--[SNR] 172.20.0.20 (VPN: 10.99.0.20)
      |         \
      |          \-- [lan-device] 192.168.100.10
      |                (simulated LAN behind SNR)
      |
      +--[Remote1] 172.20.0.30 (VPN: 10.99.0.30)
      |
      +--[Remote2] 172.20.0.31 (VPN: 10.99.0.31)
```

Tests:
- All containers can ping each other over WireGuard tunnel
- Remote1 can reach lan-device through SNR
- Tunnel survives CS restart
- Key rotation doesn't break connectivity

## Individual Test Suites

Run a specific suite manually:

```bash
PYTHONPATH=/home/ged/wireguard-friend python3 test-lab/test_comprehensive.py
PYTHONPATH=/home/ged/wireguard-friend python3 test-lab/test_import_workflows.py
PYTHONPATH=/home/ged/wireguard-friend python3 test-lab/test_extramural.py
PYTHONPATH=/home/ged/wireguard-friend python3 test-lab/test_fidelity.py
PYTHONPATH=/home/ged/wireguard-friend python3 test-lab/test_cli_behavior.py
```

## Docker Tests Manually

The connectivity test handles its own Docker lifecycle (start, test, cleanup):

```bash
# Run connectivity tests (auto-starts and stops containers)
PYTHONPATH=/home/ged/wireguard-friend python3 test-lab/test_docker_connectivity.py
```

Or use docker-compose directly for debugging:

```bash
# Start containers
docker-compose -f test-lab/docker-compose.test.yml up -d --build

# Debug inside containers
docker exec -it wgf-cs sh
docker exec wgf-snr wg show

# Cleanup
docker-compose -f test-lab/docker-compose.test.yml down --volumes
```

**Requirements:** Docker, docker-compose (standalone, not plugin), privileged mode support (NET_ADMIN).

## Docker Daemon Management

The test runner automatically manages the Docker daemon:
- **If Docker is already running:** Tests run normally, daemon left running afterward
- **If Docker is not running:** Starts daemon, runs tests, stops daemon when done

This keeps Docker from running continuously on systems where it's not needed.

To manually control Docker:
```bash
# Start Docker daemon
sudo systemctl start docker

# Stop Docker daemon
sudo systemctl stop docker

# Check status
systemctl is-active docker
```

## Sample Configs

Test configs in `test-lab/configs/`:

| File | Description |
|------|-------------|
| `sample_cs.conf` | Coordination server with 5 peers, dual-stack IPv4/IPv6, PostUp/PostDown |
| `sample_snr.conf` | Subnet router advertising 192.168.1.0/24, with forwarding rules |
| `sample_client.conf` | Client with DNS servers and multiple AllowedIPs |
| `sample_extramural_mullvad.conf` | Mullvad-style external VPN (0.0.0.0/0 routing) |
| `sample_edge_cases.conf` | PresharedKey, IPv6 endpoint, unusual formatting |

## Test Results

JSON reports saved to `test-lab/results/` with timestamps:
```
test_report_20251202_150733.json
```

## Files in This Directory

```
test-lab/
├── run-all-tests.sh           # Main test runner (use this)
├── README.md                  # This file
├── Dockerfile.wg-test         # Alpine container with WireGuard
├── docker-compose.test.yml    # 5-container test network
├── COMPREHENSIVE_TEST_REPORT.md
│
├── test_comprehensive.py      # Core functionality tests
├── test_import_workflows.py   # Import/detection tests
├── test_extramural.py         # Extramural isolation tests
├── test_fidelity.py           # Export-import fidelity tests
├── test_cli_behavior.py       # CLI error handling tests
├── test_docker_connectivity.py # Docker network tests
│
├── configs/                   # Sample WireGuard configs
│   ├── sample_cs.conf
│   ├── sample_snr.conf
│   ├── sample_client.conf
│   ├── sample_extramural_mullvad.conf
│   └── sample_edge_cases.conf
│
└── results/                   # Test run JSON reports
```

## Exit Codes

- `0` - All tests passed
- `1` - One or more tests failed
