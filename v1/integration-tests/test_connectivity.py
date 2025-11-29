#!/usr/bin/env python3
"""
Integration Test: Basic WireGuard Connectivity

Tests the complete workflow:
1. Generate configs for minimal network (CS + SNR + 2 remotes)
2. Deploy to Docker containers
3. Start WireGuard interfaces
4. Test connectivity between all peers
5. Test routing through subnet router
"""

import subprocess
import time
import sys
from pathlib import Path
from typing import Dict

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from v1.integration_tests.wg_keys import generate_keypair, derive_public_key


def run_cmd(cmd: str, check: bool = True) -> subprocess.CompletedProcess:
    """Run shell command"""
    return subprocess.run(cmd, shell=True, capture_output=True, check=check, text=True)


def exec_in_container(container: str, cmd: str) -> str:
    """Execute command in Docker container"""
    result = run_cmd(f"docker exec {container} {cmd}")
    return result.stdout


def ping_test(from_container: str, to_ip: str, count: int = 3) -> bool:
    """Test ping connectivity"""
    result = run_cmd(
        f"docker exec {from_container} ping -c {count} -W 2 {to_ip}",
        check=False
    )
    return result.returncode == 0


def generate_test_configs() -> Dict[str, str]:
    """
    Generate WireGuard configs for test network.

    Network topology:
      CS (10.66.0.1) - hub
        ├─ SNR (10.66.0.20) - advertises 192.168.100.0/24
        ├─ Remote-1 (10.66.0.30)
        └─ Remote-2 (10.66.0.31)
    """
    print("Generating test configs...")

    # Generate keypairs
    cs_private, cs_public = generate_keypair()
    snr_private, snr_public = generate_keypair()
    r1_private, r1_public = generate_keypair()
    r2_private, r2_public = generate_keypair()

    print(f"  CS permanent_guid:      {cs_public}")
    print(f"  SNR permanent_guid:     {snr_public}")
    print(f"  Remote-1 permanent_guid: {r1_public}")
    print(f"  Remote-2 permanent_guid: {r2_public}")
    print()

    # Coordination Server config
    cs_config = f"""[Interface]
Address = 10.66.0.1/24
PrivateKey = {cs_private}
ListenPort = 51820

# Enable IP forwarding
PostUp = sysctl -w net.ipv4.ip_forward=1

[Peer]
# subnet-router
PublicKey = {snr_public}
AllowedIPs = 10.66.0.20/32, 192.168.100.0/24

[Peer]
# remote-1
PublicKey = {r1_public}
AllowedIPs = 10.66.0.30/32

[Peer]
# remote-2
PublicKey = {r2_public}
AllowedIPs = 10.66.0.31/32
"""

    # Subnet Router config
    snr_config = f"""[Interface]
Address = 10.66.0.20/32
PrivateKey = {snr_private}

# Enable IP forwarding
PostUp = sysctl -w net.ipv4.ip_forward=1
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT
PostUp = iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

PostDown = iptables -D FORWARD -i wg0 -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

[Peer]
# coordination-server
PublicKey = {cs_public}
Endpoint = 172.20.0.10:51820
AllowedIPs = 10.66.0.0/24
PersistentKeepalive = 25
"""

    # Remote-1 config
    r1_config = f"""[Interface]
Address = 10.66.0.30/32
PrivateKey = {r1_private}
DNS = 1.1.1.1

[Peer]
# coordination-server
PublicKey = {cs_public}
Endpoint = 172.20.0.10:51820
AllowedIPs = 10.66.0.0/24, 192.168.100.0/24
PersistentKeepalive = 25
"""

    # Remote-2 config
    r2_config = f"""[Interface]
Address = 10.66.0.31/32
PrivateKey = {r2_private}
DNS = 1.1.1.1

[Peer]
# coordination-server
PublicKey = {cs_public}
Endpoint = 172.20.0.10:51820
AllowedIPs = 10.66.0.0/24, 192.168.100.0/24
PersistentKeepalive = 25
"""

    return {
        'cs': cs_config,
        'snr': snr_config,
        'remote-1': r1_config,
        'remote-2': r2_config,
    }


def deploy_configs(configs: Dict[str, str]):
    """Write configs to files for Docker volume mount"""
    print("Deploying configs...")

    config_dir = Path(__file__).parent / "configs"
    config_dir.mkdir(exist_ok=True)

    # Map config keys to filenames
    config_map = {
        'cs': 'wg0.conf',
        'snr': 'wg0.conf',
        'remote-1': 'wg0.conf',
        'remote-2': 'wg0.conf',
    }

    for entity, config in configs.items():
        # Create entity-specific directory
        entity_dir = config_dir / entity
        entity_dir.mkdir(exist_ok=True)

        # Write config
        config_file = entity_dir / config_map[entity]
        config_file.write_text(config)
        config_file.chmod(0o600)

        print(f"  ✓ {entity}: {config_file}")

    print()


def start_containers():
    """Start Docker containers"""
    print("Starting Docker containers...")
    run_cmd("cd v2/integration-tests && docker-compose up -d --build")

    # Wait for containers to be ready
    print("  Waiting for containers to initialize...")
    time.sleep(5)
    print("  ✓ Containers ready")
    print()


def stop_containers():
    """Stop Docker containers"""
    print("\nStopping containers...")
    run_cmd("cd v2/integration-tests && docker-compose down", check=False)
    print("  ✓ Containers stopped")


def start_wireguard():
    """Start WireGuard on all containers"""
    print("Starting WireGuard interfaces...")

    containers = {
        'wgf-cs': 'cs',
        'wgf-snr': 'snr',
        'wgf-remote1': 'remote-1',
        'wgf-remote2': 'remote-2',
    }

    for container, entity in containers.items():
        # Copy config from entity-specific directory
        exec_in_container(
            container,
            f"cp /etc/wireguard/{entity}/wg0.conf /etc/wireguard/wg0.conf"
        )

        # Start WireGuard
        result = run_cmd(f"docker exec {container} wg-quick up wg0", check=False)

        if result.returncode == 0:
            print(f"  ✓ {entity}: wg0 up")
        else:
            print(f"  ✗ {entity}: failed - {result.stderr}")
            return False

    print()
    return True


def test_connectivity():
    """Test connectivity between all peers"""
    print("=" * 60)
    print("CONNECTIVITY TESTS")
    print("=" * 60)
    print()

    tests = [
        # (from, to, description)
        ("wgf-remote1", "10.66.0.1", "Remote-1 → CS"),
        ("wgf-remote1", "10.66.0.20", "Remote-1 → SNR"),
        ("wgf-remote1", "10.66.0.31", "Remote-1 → Remote-2"),
        ("wgf-remote2", "10.66.0.1", "Remote-2 → CS"),
        ("wgf-remote2", "10.66.0.20", "Remote-2 → SNR"),
        ("wgf-snr", "10.66.0.1", "SNR → CS"),
        ("wgf-snr", "10.66.0.30", "SNR → Remote-1"),

        # Test routing through SNR to LAN
        ("wgf-remote1", "192.168.100.10", "Remote-1 → LAN device (via SNR)"),
        ("wgf-remote2", "192.168.100.10", "Remote-2 → LAN device (via SNR)"),
    ]

    passed = 0
    failed = 0

    for from_container, to_ip, description in tests:
        print(f"Testing: {description}")
        if ping_test(from_container, to_ip, count=2):
            print(f"  ✓ PASS")
            passed += 1
        else:
            print(f"  ✗ FAIL")
            failed += 1
        print()

    print("=" * 60)
    print(f"RESULTS: {passed} passed, {failed} failed")
    print("=" * 60)
    print()

    return failed == 0


def show_wireguard_status():
    """Show WireGuard status on all peers"""
    print("\n" + "=" * 60)
    print("WIREGUARD STATUS")
    print("=" * 60)

    containers = ['wgf-cs', 'wgf-snr', 'wgf-remote1', 'wgf-remote2']

    for container in containers:
        print(f"\n{container}:")
        status = exec_in_container(container, "wg show")
        print(status if status else "  (no output)")


def main():
    """Run integration test"""
    print("\n" + "=" * 60)
    print("WIREGUARD FRIEND - INTEGRATION TEST")
    print("=" * 60)
    print()

    try:
        # 1. Generate configs
        configs = generate_test_configs()

        # 2. Deploy configs
        deploy_configs(configs)

        # 3. Start containers
        start_containers()

        # 4. Start WireGuard
        if not start_wireguard():
            print("Failed to start WireGuard")
            return False

        # 5. Test connectivity
        success = test_connectivity()

        # 6. Show status
        show_wireguard_status()

        return success

    except Exception as e:
        print(f"\n✗ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        return False

    finally:
        # Always cleanup
        stop_containers()


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
