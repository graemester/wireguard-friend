#!/usr/bin/env python3
"""
Docker-based WireGuard Connectivity Test

Tests real WireGuard connectivity in Docker containers:
1. Generate configs for test network
2. Start Docker containers
3. Configure WireGuard interfaces
4. Test connectivity across the mesh
5. Test LAN routing through SNR

Prerequisites:
- Docker and docker-compose installed
- Root/sudo access for WireGuard

Run with: sudo python3 test_docker_connectivity.py
"""

import sys
import os
import subprocess
import time
import shutil
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass

# Add project to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from v1.keygen import generate_keypair


@dataclass
class TestResult:
    """Result of a connectivity test"""
    test_name: str
    source: str
    destination: str
    expected_ip: str
    success: bool
    latency_ms: Optional[float] = None
    error: Optional[str] = None


class DockerConnectivityTest:
    """Docker-based WireGuard connectivity testing"""

    def __init__(self):
        self.test_lab_dir = Path(__file__).parent
        self.configs_dir = self.test_lab_dir / "configs"
        self.results: List[TestResult] = []

        # Container names
        self.containers = {
            'cs': 'wgf-cs',
            'snr': 'wgf-snr',
            'remote1': 'wgf-remote1',
            'remote2': 'wgf-remote2',
            'lan-device': 'wgf-lan-device'
        }

        # VPN IPs
        self.vpn_ips = {
            'cs': '10.99.0.1',
            'snr': '10.99.0.20',
            'remote1': '10.99.0.30',
            'remote2': '10.99.0.31'
        }

        # LAN IPs
        self.lan_ips = {
            'snr': '192.168.100.2',
            'lan-device': '192.168.100.10'
        }

        # Docker network IPs (for WireGuard endpoints)
        self.docker_ips = {
            'cs': '172.20.0.10',
            'snr': '172.20.0.20',
            'remote1': '172.20.0.30',
            'remote2': '172.20.0.31'
        }

    def run(self) -> bool:
        """Run complete connectivity test"""
        print("=" * 80)
        print("WIREGUARD DOCKER CONNECTIVITY TEST")
        print("=" * 80)
        print()

        try:
            # Check prerequisites
            if not self._check_prerequisites():
                return False

            # Generate configs
            print("1. Generating WireGuard configs...")
            keys = self._generate_configs()
            print("   Done.\n")

            # Start containers
            print("2. Starting Docker containers...")
            if not self._start_containers():
                return False
            print("   Done.\n")

            # Wait for containers
            print("3. Waiting for containers to initialize...")
            time.sleep(5)
            print("   Done.\n")

            # Configure WireGuard
            print("4. Starting WireGuard interfaces...")
            if not self._start_wireguard():
                return False
            print("   Done.\n")

            # Wait for WireGuard handshakes
            print("5. Waiting for WireGuard handshakes...")
            time.sleep(3)
            print("   Done.\n")

            # Run connectivity tests
            print("6. Running connectivity tests...")
            self._run_connectivity_tests()
            print()

            # Print results
            self._print_results()

            return all(r.success for r in self.results)

        except Exception as e:
            print(f"\nError: {e}")
            import traceback
            traceback.print_exc()
            return False

        finally:
            # Cleanup
            print("\n7. Cleaning up...")
            self._cleanup()
            print("   Done.")

    def _check_prerequisites(self) -> bool:
        """Check that Docker is available"""
        try:
            result = subprocess.run(
                ['docker', '--version'],
                capture_output=True,
                check=True
            )
            print(f"Docker: {result.stdout.decode().strip()}")

            result = subprocess.run(
                ['docker-compose', '--version'],
                capture_output=True,
                check=True
            )
            print(f"Docker Compose: {result.stdout.decode().strip()}")

            return True

        except FileNotFoundError:
            print("ERROR: Docker not found. Please install Docker.")
            return False
        except subprocess.CalledProcessError as e:
            print(f"ERROR: Docker check failed: {e}")
            return False

    def _generate_configs(self) -> Dict[str, Tuple[str, str]]:
        """Generate WireGuard configs for all entities"""
        # Generate keypairs
        cs_private, cs_public = generate_keypair()
        snr_private, snr_public = generate_keypair()
        r1_private, r1_public = generate_keypair()
        r2_private, r2_public = generate_keypair()

        keys = {
            'cs': (cs_private, cs_public),
            'snr': (snr_private, snr_public),
            'remote1': (r1_private, r1_public),
            'remote2': (r2_private, r2_public)
        }

        # Create config directories
        for entity in ['cs', 'snr', 'remote1', 'remote2']:
            entity_dir = self.configs_dir / entity
            entity_dir.mkdir(parents=True, exist_ok=True)

        # CS Config
        cs_config = f"""[Interface]
Address = 10.99.0.1/24
PrivateKey = {cs_private}
ListenPort = 51820

PostUp = sysctl -w net.ipv4.ip_forward=1

[Peer]
# snr
PublicKey = {snr_public}
AllowedIPs = 10.99.0.20/32, 192.168.100.0/24

[Peer]
# remote1
PublicKey = {r1_public}
AllowedIPs = 10.99.0.30/32

[Peer]
# remote2
PublicKey = {r2_public}
AllowedIPs = 10.99.0.31/32
"""
        (self.configs_dir / "cs" / "wg0.conf").write_text(cs_config)
        (self.configs_dir / "cs" / "wg0.conf").chmod(0o600)

        # SNR Config
        snr_config = f"""[Interface]
Address = 10.99.0.20/32
PrivateKey = {snr_private}

PostUp = sysctl -w net.ipv4.ip_forward=1
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT
PostUp = iptables -A FORWARD -o wg0 -j ACCEPT
PostUp = iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

PostDown = iptables -D FORWARD -i wg0 -j ACCEPT
PostDown = iptables -D FORWARD -o wg0 -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

[Peer]
# cs
PublicKey = {cs_public}
Endpoint = {self.docker_ips['cs']}:51820
AllowedIPs = 10.99.0.0/24
PersistentKeepalive = 25
"""
        (self.configs_dir / "snr" / "wg0.conf").write_text(snr_config)
        (self.configs_dir / "snr" / "wg0.conf").chmod(0o600)

        # Remote1 Config
        r1_config = f"""[Interface]
Address = 10.99.0.30/32
PrivateKey = {r1_private}

[Peer]
# cs
PublicKey = {cs_public}
Endpoint = {self.docker_ips['cs']}:51820
AllowedIPs = 10.99.0.0/24, 192.168.100.0/24
PersistentKeepalive = 25
"""
        (self.configs_dir / "remote1" / "wg0.conf").write_text(r1_config)
        (self.configs_dir / "remote1" / "wg0.conf").chmod(0o600)

        # Remote2 Config
        r2_config = f"""[Interface]
Address = 10.99.0.31/32
PrivateKey = {r2_private}

[Peer]
# cs
PublicKey = {cs_public}
Endpoint = {self.docker_ips['cs']}:51820
AllowedIPs = 10.99.0.0/24, 192.168.100.0/24
PersistentKeepalive = 25
"""
        (self.configs_dir / "remote2" / "wg0.conf").write_text(r2_config)
        (self.configs_dir / "remote2" / "wg0.conf").chmod(0o600)

        return keys

    def _start_containers(self) -> bool:
        """Start Docker containers"""
        try:
            compose_file = self.test_lab_dir / "docker-compose.test.yml"

            # Build and start
            result = subprocess.run(
                ['docker-compose', '-f', str(compose_file), 'up', '-d', '--build'],
                cwd=self.test_lab_dir,
                capture_output=True,
                check=True
            )

            return True

        except subprocess.CalledProcessError as e:
            print(f"ERROR: Failed to start containers: {e.stderr.decode()}")
            return False

    def _start_wireguard(self) -> bool:
        """Start WireGuard on all containers"""
        wg_containers = ['cs', 'snr', 'remote1', 'remote2']

        for entity in wg_containers:
            container = self.containers[entity]

            try:
                # Start WireGuard
                result = subprocess.run(
                    ['docker', 'exec', container, 'wg-quick', 'up', 'wg0'],
                    capture_output=True,
                    timeout=30
                )

                if result.returncode != 0:
                    # Check if already running
                    if b'already exists' not in result.stderr:
                        print(f"   Warning: {entity} wg-quick failed: {result.stderr.decode()}")
                        # Don't fail - might be recoverable
                else:
                    print(f"   {entity}: wg0 up")

            except subprocess.TimeoutExpired:
                print(f"   Warning: {entity} wg-quick timed out")
            except Exception as e:
                print(f"   Warning: {entity} wg-quick error: {e}")

        return True

    def _run_connectivity_tests(self):
        """Run all connectivity tests"""
        tests = [
            # VPN Mesh Tests
            ("VPN: Remote1 -> CS", 'remote1', 'cs', self.vpn_ips['cs']),
            ("VPN: Remote1 -> SNR", 'remote1', 'snr', self.vpn_ips['snr']),
            ("VPN: Remote1 -> Remote2", 'remote1', 'remote2', self.vpn_ips['remote2']),
            ("VPN: Remote2 -> CS", 'remote2', 'cs', self.vpn_ips['cs']),
            ("VPN: Remote2 -> SNR", 'remote2', 'snr', self.vpn_ips['snr']),
            ("VPN: SNR -> CS", 'snr', 'cs', self.vpn_ips['cs']),
            ("VPN: SNR -> Remote1", 'snr', 'remote1', self.vpn_ips['remote1']),

            # LAN Routing Tests (through SNR)
            ("LAN: Remote1 -> LAN Device (via SNR)", 'remote1', 'lan-device', self.lan_ips['lan-device']),
            ("LAN: Remote2 -> LAN Device (via SNR)", 'remote2', 'lan-device', self.lan_ips['lan-device']),
        ]

        for test_name, source, dest, dest_ip in tests:
            result = self._ping_test(test_name, source, dest_ip)
            self.results.append(TestResult(
                test_name=test_name,
                source=source,
                destination=dest,
                expected_ip=dest_ip,
                success=result[0],
                latency_ms=result[1],
                error=result[2]
            ))

    def _ping_test(self, test_name: str, source: str, dest_ip: str, count: int = 3) -> Tuple[bool, Optional[float], Optional[str]]:
        """Run ping test from container"""
        container = self.containers[source]

        try:
            result = subprocess.run(
                ['docker', 'exec', container, 'ping', '-c', str(count), '-W', '2', dest_ip],
                capture_output=True,
                timeout=30
            )

            if result.returncode == 0:
                # Parse latency from output
                output = result.stdout.decode()
                # Look for "time=X.XXX ms"
                import re
                match = re.search(r'time=(\d+\.?\d*)\s*ms', output)
                latency = float(match.group(1)) if match else None
                return True, latency, None
            else:
                return False, None, result.stderr.decode()[:100]

        except subprocess.TimeoutExpired:
            return False, None, "Timeout"
        except Exception as e:
            return False, None, str(e)

    def _print_results(self):
        """Print test results"""
        print("\n" + "=" * 80)
        print("CONNECTIVITY TEST RESULTS")
        print("=" * 80)
        print()

        passed = 0
        failed = 0

        for r in self.results:
            status = "[PASS]" if r.success else "[FAIL]"
            latency_str = f" ({r.latency_ms:.1f}ms)" if r.latency_ms else ""

            print(f"{status} {r.test_name}{latency_str}")

            if not r.success and r.error:
                print(f"       Error: {r.error}")

            if r.success:
                passed += 1
            else:
                failed += 1

        print()
        print("-" * 40)
        print(f"Total: {len(self.results)}, Passed: {passed}, Failed: {failed}")

        if failed == 0:
            print("\nALL CONNECTIVITY TESTS PASSED")
        else:
            print(f"\nWARNING: {failed} test(s) failed")

    def _cleanup(self):
        """Stop and remove containers"""
        try:
            compose_file = self.test_lab_dir / "docker-compose.test.yml"

            subprocess.run(
                ['docker-compose', '-f', str(compose_file), 'down', '--volumes'],
                cwd=self.test_lab_dir,
                capture_output=True,
                check=False  # Don't fail if already down
            )

        except Exception as e:
            print(f"   Warning during cleanup: {e}")

    def show_wireguard_status(self):
        """Show WireGuard status on all containers"""
        print("\n" + "=" * 80)
        print("WIREGUARD STATUS")
        print("=" * 80)

        for entity in ['cs', 'snr', 'remote1', 'remote2']:
            container = self.containers[entity]
            print(f"\n{entity.upper()}:")
            print("-" * 40)

            try:
                result = subprocess.run(
                    ['docker', 'exec', container, 'wg', 'show'],
                    capture_output=True,
                    timeout=10
                )
                print(result.stdout.decode() if result.stdout else "(no output)")
            except Exception as e:
                print(f"Error: {e}")


def main():
    """Run Docker connectivity test"""
    # Check if running as root (needed for WireGuard)
    if os.geteuid() != 0:
        print("WARNING: This test may need root/sudo for WireGuard operations")
        print("If tests fail, try: sudo python3 test_docker_connectivity.py")
        print()

    test = DockerConnectivityTest()
    success = test.run()

    # Show WireGuard status if tests failed
    if not success:
        test.show_wireguard_status()

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
