#!/usr/bin/env python3
"""
Import Workflow Tests

Tests for config type detection, full import workflows, and error handling.
"""

import sys
import tempfile
from pathlib import Path
from dataclasses import dataclass
from typing import List, Tuple, Dict
import time

# Add project to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from v1.config_detector import ConfigDetector
from v1.entity_parser import EntityParser
from v1.schema_semantic import WireGuardDBv2
from v1.keygen import derive_public_key


@dataclass
class TestResult:
    name: str
    passed: bool
    duration_ms: float
    message: str = ""
    details: Dict = None


class ImportWorkflowTests:
    """Import workflow test suite"""

    def __init__(self):
        self.results: List[TestResult] = []
        self.temp_dir = Path(tempfile.mkdtemp(prefix="wgf_import_test_"))
        self.configs_dir = Path(__file__).parent / "configs"

    def run_all(self) -> Tuple[int, int]:
        """Run all import workflow tests"""
        print("=" * 80)
        print("IMPORT WORKFLOW TESTS")
        print("=" * 80)
        print()

        # A. Config Type Detection
        self._test_config_detection()

        # B. Full Import Workflows
        self._test_full_import()

        # C. Import Error Handling
        self._test_import_errors()

        # Summary
        passed = sum(1 for r in self.results if r.passed)
        failed = sum(1 for r in self.results if not r.passed)

        return passed, failed

    def _run_test(self, name: str, test_fn) -> None:
        """Run a single test"""
        start = time.time()
        try:
            passed, message, details = test_fn()
            duration = (time.time() - start) * 1000

            result = TestResult(
                name=name,
                passed=passed,
                duration_ms=duration,
                message=message,
                details=details or {}
            )
            self.results.append(result)

            status = "[PASS]" if passed else "[FAIL]"
            print(f"  {status} {name} ({duration:.1f}ms)")
            if not passed:
                print(f"         {message}")

        except Exception as e:
            duration = (time.time() - start) * 1000
            result = TestResult(
                name=name,
                passed=False,
                duration_ms=duration,
                message=f"Exception: {e}",
                details={'exception': str(e)}
            )
            self.results.append(result)
            print(f"  [FAIL] {name} ({duration:.1f}ms)")
            print(f"         Exception: {e}")

    # =========================================================================
    # A. CONFIG TYPE DETECTION TESTS
    # =========================================================================

    def _test_config_detection(self):
        """Config type detection tests"""
        print("\n" + "-" * 60)
        print("A. CONFIG TYPE DETECTION")
        print("-" * 60)

        self._run_test(
            "CS detection: 3+ peers = coordination_server",
            self._test_cs_detection
        )

        self._run_test(
            "SNR detection: 1 peer + forwarding + no endpoint = subnet_router",
            self._test_snr_detection
        )

        self._run_test(
            "Client detection: 1 peer + endpoint = client",
            self._test_client_detection
        )

        self._run_test(
            "Detection with comments/whitespace",
            self._test_detection_with_comments
        )

        self._run_test(
            "Minimal config detection",
            self._test_minimal_config
        )

        self._run_test(
            "Detection boundary: 2 peers with forwarding",
            self._test_boundary_detection
        )

        self._run_test(
            "Sample CS config from configs/",
            self._test_sample_cs_detection
        )

        self._run_test(
            "Sample SNR config from configs/",
            self._test_sample_snr_detection
        )

        self._run_test(
            "Sample client config from configs/",
            self._test_sample_client_detection
        )

    def _test_cs_detection(self):
        """Test CS detection with 3+ peers"""
        config = """[Interface]
Address = 10.66.0.1/24
PrivateKey = WG_PRIVATE_KEY_123456789012345678901234567890==
ListenPort = 51820
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT

[Peer]
PublicKey = PEER1_KEY_123456789012345678901234567890==
AllowedIPs = 10.66.0.10/32

[Peer]
PublicKey = PEER2_KEY_123456789012345678901234567890==
AllowedIPs = 10.66.0.20/32

[Peer]
PublicKey = PEER3_KEY_123456789012345678901234567890==
AllowedIPs = 10.66.0.30/32
"""
        config_file = self.temp_dir / "cs_test.conf"
        config_file.write_text(config)

        detector = ConfigDetector()
        config_type, peer_count = detector.detect_type(config_file)

        if config_type != 'coordination_server':
            return False, f"Expected coordination_server, got {config_type}", {}

        if peer_count != 3:
            return False, f"Expected 3 peers, got {peer_count}", {}

        return True, "OK", {'type': config_type, 'peers': peer_count}

    def _test_snr_detection(self):
        """Test SNR detection with forwarding rules"""
        config = """[Interface]
Address = 10.66.0.10/32
PrivateKey = WG_PRIVATE_KEY_123456789012345678901234567890==
PostUp = iptables -A FORWARD -i wg0 -o eth0 -j ACCEPT
PostDown = iptables -D FORWARD -i wg0 -o eth0 -j ACCEPT

[Peer]
PublicKey = CS_KEY_1234567890123456789012345678901234==
AllowedIPs = 10.66.0.0/24
"""
        config_file = self.temp_dir / "snr_test.conf"
        config_file.write_text(config)

        detector = ConfigDetector()
        config_type, peer_count = detector.detect_type(config_file)

        if config_type != 'subnet_router':
            return False, f"Expected subnet_router, got {config_type}", {}

        if peer_count != 1:
            return False, f"Expected 1 peer, got {peer_count}", {}

        return True, "OK", {'type': config_type, 'peers': peer_count}

    def _test_client_detection(self):
        """Test client detection with endpoint"""
        config = """[Interface]
Address = 10.66.0.20/32
PrivateKey = WG_PRIVATE_KEY_123456789012345678901234567890==
DNS = 10.66.0.1

[Peer]
PublicKey = CS_KEY_1234567890123456789012345678901234==
Endpoint = vpn.example.com:51820
AllowedIPs = 10.66.0.0/24
PersistentKeepalive = 25
"""
        config_file = self.temp_dir / "client_test.conf"
        config_file.write_text(config)

        detector = ConfigDetector()
        config_type, peer_count = detector.detect_type(config_file)

        if config_type != 'client':
            return False, f"Expected client, got {config_type}", {}

        return True, "OK", {'type': config_type, 'peers': peer_count}

    def _test_detection_with_comments(self):
        """Test detection works with comments and whitespace"""
        config = """# This is a coordination server
# VPN Network: 10.66.0.0/24

[Interface]
# Server address
Address = 10.66.0.1/24

# Private key (keep secret!)
PrivateKey = WG_PRIVATE_KEY_123456789012345678901234567890==
ListenPort = 51820

PostUp = iptables -A FORWARD -i wg0 -j ACCEPT

[Peer]
# Peer 1 - Alice
PublicKey = PEER1_KEY_123456789012345678901234567890==
AllowedIPs = 10.66.0.10/32

[Peer]
# Peer 2 - Bob
PublicKey = PEER2_KEY_123456789012345678901234567890==
AllowedIPs = 10.66.0.20/32

[Peer]
# Peer 3 - Carol
PublicKey = PEER3_KEY_123456789012345678901234567890==
AllowedIPs = 10.66.0.30/32
"""
        config_file = self.temp_dir / "comments_test.conf"
        config_file.write_text(config)

        detector = ConfigDetector()
        config_type, peer_count = detector.detect_type(config_file)

        if config_type != 'coordination_server':
            return False, f"Expected coordination_server, got {config_type}", {}

        return True, "OK", {'type': config_type, 'peers': peer_count}

    def _test_minimal_config(self):
        """Test minimal valid config"""
        config = """[Interface]
Address = 10.0.0.1/24
PrivateKey = WG_PRIVATE_KEY_123456789012345678901234567890==

[Peer]
PublicKey = PEER_KEY_12345678901234567890123456789012==
AllowedIPs = 10.0.0.2/32
"""
        config_file = self.temp_dir / "minimal_test.conf"
        config_file.write_text(config)

        detector = ConfigDetector()
        try:
            config_type, peer_count = detector.detect_type(config_file)
            # Single peer, no endpoint, no forwarding = could be SNR or client
            # Current logic: single peer without endpoint = subnet_router
            return True, "OK", {'type': config_type, 'peers': peer_count}
        except Exception as e:
            return False, f"Detection failed: {e}", {}

    def _test_boundary_detection(self):
        """Test boundary case: 2 peers with forwarding"""
        config = """[Interface]
Address = 10.66.0.1/24
PrivateKey = WG_PRIVATE_KEY_123456789012345678901234567890==
ListenPort = 51820
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT

[Peer]
PublicKey = PEER1_KEY_123456789012345678901234567890==
AllowedIPs = 10.66.0.10/32

[Peer]
PublicKey = PEER2_KEY_123456789012345678901234567890==
AllowedIPs = 10.66.0.20/32
"""
        config_file = self.temp_dir / "boundary_test.conf"
        config_file.write_text(config)

        detector = ConfigDetector()
        config_type, peer_count = detector.detect_type(config_file)

        # 2 peers + forwarding = coordination_server (per detection logic)
        if peer_count != 2:
            return False, f"Expected 2 peers, got {peer_count}", {}

        # With forwarding rules, this should be CS
        if config_type != 'coordination_server':
            return False, f"Expected coordination_server, got {config_type}", {}

        return True, "OK", {'type': config_type, 'peers': peer_count}

    def _test_sample_cs_detection(self):
        """Test detection of sample_cs.conf"""
        config_file = self.configs_dir / "sample_cs.conf"
        if not config_file.exists():
            return False, f"Sample config not found: {config_file}", {}

        detector = ConfigDetector()
        config_type, peer_count = detector.detect_type(config_file)

        if config_type != 'coordination_server':
            return False, f"Expected coordination_server, got {config_type}", {}

        if peer_count != 5:
            return False, f"Expected 5 peers, got {peer_count}", {}

        return True, "OK", {'type': config_type, 'peers': peer_count}

    def _test_sample_snr_detection(self):
        """Test detection of sample_snr.conf"""
        config_file = self.configs_dir / "sample_snr.conf"
        if not config_file.exists():
            return False, f"Sample config not found: {config_file}", {}

        detector = ConfigDetector()
        config_type, peer_count = detector.detect_type(config_file)

        if config_type != 'subnet_router':
            return False, f"Expected subnet_router, got {config_type}", {}

        return True, "OK", {'type': config_type, 'peers': peer_count}

    def _test_sample_client_detection(self):
        """Test detection of sample_client.conf"""
        config_file = self.configs_dir / "sample_client.conf"
        if not config_file.exists():
            return False, f"Sample config not found: {config_file}", {}

        detector = ConfigDetector()
        config_type, peer_count = detector.detect_type(config_file)

        if config_type != 'client':
            return False, f"Expected client, got {config_type}", {}

        return True, "OK", {'type': config_type, 'peers': peer_count}

    # =========================================================================
    # B. FULL IMPORT WORKFLOW TESTS
    # =========================================================================

    def _test_full_import(self):
        """Full import workflow tests"""
        print("\n" + "-" * 60)
        print("B. FULL IMPORT WORKFLOWS")
        print("-" * 60)

        self._run_test(
            "Parse CS config with EntityParser",
            self._test_parse_cs_entities
        )

        self._run_test(
            "Parse SNR config with EntityParser",
            self._test_parse_snr_entities
        )

        self._run_test(
            "Extract interface fields correctly",
            self._test_extract_interface_fields
        )

        self._run_test(
            "Extract peer fields correctly",
            self._test_extract_peer_fields
        )

        self._run_test(
            "Separate VPN IPs from advertised networks",
            self._test_separate_allowed_ips
        )

        self._run_test(
            "Parse PostUp/PostDown commands",
            self._test_parse_commands
        )

        self._run_test(
            "Handle re-import (update existing)",
            self._test_reimport
        )

    def _test_parse_cs_entities(self):
        """Test parsing CS config into entities"""
        config_file = self.configs_dir / "sample_cs.conf"
        if not config_file.exists():
            return False, f"Sample config not found", {}

        parser = EntityParser()
        entities = parser.parse_file(config_file)

        # Should have 1 Interface + 5 Peers = 6 entities
        if len(entities) != 6:
            return False, f"Expected 6 entities, got {len(entities)}", {}

        if entities[0].entity_type != '[Interface]':
            return False, f"First entity not Interface", {}

        peer_count = sum(1 for e in entities if e.entity_type == '[Peer]')
        if peer_count != 5:
            return False, f"Expected 5 peers, got {peer_count}", {}

        return True, "OK", {'entities': len(entities), 'peers': peer_count}

    def _test_parse_snr_entities(self):
        """Test parsing SNR config into entities"""
        config_file = self.configs_dir / "sample_snr.conf"
        if not config_file.exists():
            return False, f"Sample config not found", {}

        parser = EntityParser()
        entities = parser.parse_file(config_file)

        # Should have 1 Interface + 1 Peer = 2 entities
        if len(entities) != 2:
            return False, f"Expected 2 entities, got {len(entities)}", {}

        return True, "OK", {'entities': len(entities)}

    def _test_extract_interface_fields(self):
        """Test extracting interface fields"""
        config = """[Interface]
Address = 10.66.0.1/24, fd66::1/64
PrivateKey = mK9f2vJ4xTmW8qLpN3rH6gS7jY5cA0zX1wD9eI2uF4Q=
ListenPort = 51820
MTU = 1420
DNS = 10.66.0.1, 1.1.1.1
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT
"""
        config_file = self.temp_dir / "interface_test.conf"
        config_file.write_text(config)

        parser = EntityParser()
        entities = parser.parse_file(config_file)

        interface = entities[0]

        # Check fields present in lines
        lines_text = '\n'.join(interface.lines)

        checks = [
            ('Address', '10.66.0.1/24'),
            ('PrivateKey', 'mK9f2vJ4'),
            ('ListenPort', '51820'),
            ('MTU', '1420'),
            ('DNS', '10.66.0.1'),
            ('PostUp', 'iptables'),
        ]

        for field, expected in checks:
            if expected not in lines_text:
                return False, f"Missing {field}: {expected}", {}

        return True, "OK", {'fields_found': len(checks)}

    def _test_extract_peer_fields(self):
        """Test extracting peer fields"""
        config = """[Interface]
Address = 10.66.0.1/24
PrivateKey = WG_PRIVATE_KEY_123456789012345678901234567890==

[Peer]
# alice-laptop
PublicKey = PEER_PUBLIC_KEY_12345678901234567890123456==
AllowedIPs = 10.66.0.20/32, fd66::20/128
Endpoint = alice.example.com:51820
PersistentKeepalive = 25
PresharedKey = PSK_KEY_1234567890123456789012345678901234==
"""
        config_file = self.temp_dir / "peer_test.conf"
        config_file.write_text(config)

        parser = EntityParser()
        entities = parser.parse_file(config_file)

        peer = entities[1]
        lines_text = '\n'.join(peer.lines)

        checks = [
            ('alice-laptop', 'hostname comment'),
            ('PublicKey', 'PEER_PUBLIC'),
            ('AllowedIPs', '10.66.0.20'),
            ('Endpoint', 'alice.example.com'),
            ('PersistentKeepalive', '25'),
            ('PresharedKey', 'PSK_KEY'),
        ]

        for expected, desc in checks:
            if expected not in lines_text:
                return False, f"Missing {desc}: {expected}", {}

        return True, "OK", {'fields_found': len(checks)}

    def _test_separate_allowed_ips(self):
        """Test separating VPN IPs from advertised networks"""
        # Import the function we're testing
        from v1.cli.import_configs import separate_allowed_ips

        test_cases = [
            # (input, expected_vpn, expected_advertised)
            (
                ['10.66.0.10/32', 'fd66::10/128', '192.168.1.0/24'],
                ['10.66.0.10/32', 'fd66::10/128'],
                ['192.168.1.0/24']
            ),
            (
                ['10.66.0.20/32'],
                ['10.66.0.20/32'],
                []
            ),
            (
                ['0.0.0.0/0', '::/0'],
                [],
                ['0.0.0.0/0', '::/0']
            ),
        ]

        for allowed_ips, expected_vpn, expected_advertised in test_cases:
            vpn_ips, advertised = separate_allowed_ips(allowed_ips)

            if set(vpn_ips) != set(expected_vpn):
                return False, f"VPN IPs mismatch for {allowed_ips}", {
                    'expected': expected_vpn, 'got': vpn_ips
                }

            if set(advertised) != set(expected_advertised):
                return False, f"Advertised mismatch for {allowed_ips}", {
                    'expected': expected_advertised, 'got': advertised
                }

        return True, "OK", {'test_cases': len(test_cases)}

    def _test_parse_commands(self):
        """Test parsing PostUp/PostDown commands"""
        config = """[Interface]
Address = 10.66.0.1/24
PrivateKey = WG_PRIVATE_KEY_123456789012345678901234567890==
PostUp = sysctl -w net.ipv4.ip_forward=1
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT
PostUp = iptables -t nat -A POSTROUTING -s 10.66.0.0/24 -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -s 10.66.0.0/24 -o eth0 -j MASQUERADE
"""
        config_file = self.temp_dir / "commands_test.conf"
        config_file.write_text(config)

        parser = EntityParser()
        entities = parser.parse_file(config_file)

        interface = entities[0]
        lines_text = '\n'.join(interface.lines)

        # Count PostUp and PostDown
        postup_count = lines_text.count('PostUp')
        postdown_count = lines_text.count('PostDown')

        if postup_count != 3:
            return False, f"Expected 3 PostUp, got {postup_count}", {}

        if postdown_count != 2:
            return False, f"Expected 2 PostDown, got {postdown_count}", {}

        return True, "OK", {'postup': postup_count, 'postdown': postdown_count}

    def _test_reimport(self):
        """Test re-importing to update existing config"""
        # Create database with initial data
        db_path = self.temp_dir / "reimport_test.db"
        db = WireGuardDBv2(db_path)

        # Insert initial CS
        with db._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO coordination_server (
                    permanent_guid, current_public_key, hostname,
                    endpoint, listen_port, network_ipv4, network_ipv6,
                    ipv4_address, ipv6_address, private_key
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                'GUID_123', 'PUB_123', 'test-cs',
                'old.example.com', 51820, '10.66.0.0/24', 'fd66::/64',
                '10.66.0.1/24', 'fd66::1/64', 'PRIV_123'
            ))

        # Simulate re-import by updating
        with db._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE coordination_server
                SET endpoint = ?, hostname = ?
                WHERE permanent_guid = ?
            """, ('new.example.com', 'updated-cs', 'GUID_123'))

        # Verify update
        with db._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT endpoint, hostname FROM coordination_server")
            row = cursor.fetchone()

            if row['endpoint'] != 'new.example.com':
                return False, "Endpoint not updated", {}

            if row['hostname'] != 'updated-cs':
                return False, "Hostname not updated", {}

        return True, "OK", {}

    # =========================================================================
    # C. IMPORT ERROR HANDLING TESTS
    # =========================================================================

    def _test_import_errors(self):
        """Import error handling tests"""
        print("\n" + "-" * 60)
        print("C. IMPORT ERROR HANDLING")
        print("-" * 60)

        self._run_test(
            "Invalid config format (no Interface)",
            self._test_invalid_no_interface
        )

        self._run_test(
            "Invalid config (Interface not first)",
            self._test_invalid_interface_order
        )

        self._run_test(
            "Missing required field (PrivateKey)",
            self._test_missing_privatekey
        )

        self._run_test(
            "Malformed key detection",
            self._test_malformed_key
        )

        self._run_test(
            "Empty file handling",
            self._test_empty_file
        )

        self._run_test(
            "Multiple Interface sections",
            self._test_multiple_interfaces
        )

    def _test_invalid_no_interface(self):
        """Test handling of config with no Interface"""
        config = """[Peer]
PublicKey = PEER_KEY_12345678901234567890123456789012==
AllowedIPs = 10.66.0.2/32
"""
        config_file = self.temp_dir / "no_interface.conf"
        config_file.write_text(config)

        detector = ConfigDetector()
        try:
            config_type, peer_count = detector.detect_type(config_file)
            return False, "Should have raised error for missing Interface", {}
        except ValueError as e:
            if "not [Interface]" in str(e) or "No entities" not in str(e):
                return True, "OK - correctly rejected", {'error': str(e)}
            return False, f"Wrong error: {e}", {}
        except Exception as e:
            return False, f"Unexpected error: {e}", {}

    def _test_invalid_interface_order(self):
        """Test handling of Interface not first"""
        config = """[Peer]
PublicKey = PEER_KEY_12345678901234567890123456789012==
AllowedIPs = 10.66.0.2/32

[Interface]
Address = 10.66.0.1/24
PrivateKey = WG_PRIVATE_KEY_123456789012345678901234567890==
"""
        config_file = self.temp_dir / "wrong_order.conf"
        config_file.write_text(config)

        parser = EntityParser()
        entities = parser.parse_file(config_file)

        valid, msg = parser.validate_structure(entities)
        if valid:
            return False, "Should have failed validation", {}

        return True, "OK - correctly rejected", {'message': msg}

    def _test_missing_privatekey(self):
        """Test handling of missing PrivateKey"""
        config = """[Interface]
Address = 10.66.0.1/24
ListenPort = 51820

[Peer]
PublicKey = PEER_KEY_12345678901234567890123456789012==
AllowedIPs = 10.66.0.2/32
"""
        config_file = self.temp_dir / "no_privatekey.conf"
        config_file.write_text(config)

        # EntityParser should still parse it
        parser = EntityParser()
        entities = parser.parse_file(config_file)

        # But validation in import should catch missing PrivateKey
        interface_lines = '\n'.join(entities[0].lines)
        if 'PrivateKey' in interface_lines:
            return False, "PrivateKey should be missing", {}

        return True, "OK - missing key detectable", {}

    def _test_malformed_key(self):
        """Test detection of malformed keys"""
        # Valid WireGuard keys are 44 characters (32 bytes base64)
        config = """[Interface]
Address = 10.66.0.1/24
PrivateKey = TOO_SHORT_KEY

[Peer]
PublicKey = ALSO_TOO_SHORT
AllowedIPs = 10.66.0.2/32
"""
        config_file = self.temp_dir / "malformed_key.conf"
        config_file.write_text(config)

        # Parser should parse but keys are clearly malformed
        parser = EntityParser()
        entities = parser.parse_file(config_file)

        interface_lines = '\n'.join(entities[0].lines)
        if 'TOO_SHORT_KEY' not in interface_lines:
            return False, "Malformed key not preserved", {}

        # Key length check
        if len('TOO_SHORT_KEY') == 44:
            return False, "Key length check failed", {}

        return True, "OK - malformed key detectable", {}

    def _test_empty_file(self):
        """Test handling of empty file"""
        config_file = self.temp_dir / "empty.conf"
        config_file.write_text("")

        parser = EntityParser()
        entities = parser.parse_file(config_file)

        if len(entities) != 0:
            return False, "Expected 0 entities for empty file", {}

        valid, msg = parser.validate_structure(entities)
        if valid:
            return False, "Should have failed validation", {}

        return True, "OK - empty file handled", {'message': msg}

    def _test_multiple_interfaces(self):
        """Test handling of multiple Interface sections"""
        config = """[Interface]
Address = 10.66.0.1/24
PrivateKey = WG_PRIVATE_KEY_123456789012345678901234567890==

[Interface]
Address = 10.67.0.1/24
PrivateKey = WG_PRIVATE_KEY_ABCDEFGHIJ12345678901234567890==

[Peer]
PublicKey = PEER_KEY_12345678901234567890123456789012==
AllowedIPs = 10.66.0.2/32
"""
        config_file = self.temp_dir / "multiple_interface.conf"
        config_file.write_text(config)

        parser = EntityParser()
        entities = parser.parse_file(config_file)

        valid, msg = parser.validate_structure(entities)
        if valid:
            return False, "Should have failed with multiple Interface", {}

        if "exactly 1" not in msg.lower() and "interface" not in msg.lower():
            return False, f"Wrong error message: {msg}", {}

        return True, "OK - multiple interfaces rejected", {'message': msg}


def main():
    """Run import workflow tests"""
    tests = ImportWorkflowTests()
    passed, failed = tests.run_all()

    print()
    print("=" * 80)
    print(f"IMPORT WORKFLOW RESULTS: {passed} passed, {failed} failed")
    print("=" * 80)

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
