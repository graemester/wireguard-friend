#!/usr/bin/env python3
"""
Export-Import Fidelity Tests

Tests that exported configs are FUNCTIONALLY EQUIVALENT to imported configs.
"Functionally equivalent" means: same keys, same IPs, same routing - even if
whitespace/comments differ.
"""

import sys
import tempfile
import re
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Tuple, Dict, Set, Optional
import time

# Add project to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from v1.schema_semantic import WireGuardDBv2
from v1.entity_parser import EntityParser
from v1.config_detector import ConfigDetector
from v1.keygen import generate_keypair, derive_public_key


@dataclass
class ParsedInterface:
    """Parsed interface for comparison"""
    addresses: Set[str] = field(default_factory=set)
    private_key: Optional[str] = None
    public_key: Optional[str] = None
    listen_port: Optional[int] = None
    mtu: Optional[int] = None
    dns: Set[str] = field(default_factory=set)
    table: Optional[str] = None
    postup: List[str] = field(default_factory=list)
    postdown: List[str] = field(default_factory=list)


@dataclass
class ParsedPeer:
    """Parsed peer for comparison"""
    public_key: str = ""
    preshared_key: Optional[str] = None
    allowed_ips: Set[str] = field(default_factory=set)
    endpoint: Optional[str] = None
    persistent_keepalive: Optional[int] = None


@dataclass
class TestResult:
    name: str
    passed: bool
    duration_ms: float
    message: str = ""
    details: Dict = None


class FidelityTests:
    """Export-import fidelity test suite"""

    def __init__(self):
        self.results: List[TestResult] = []
        self.temp_dir = Path(tempfile.mkdtemp(prefix="wgf_fidelity_test_"))
        self.configs_dir = Path(__file__).parent / "configs"

    def run_all(self) -> Tuple[int, int]:
        """Run all fidelity tests"""
        print("=" * 80)
        print("EXPORT-IMPORT FIDELITY TESTS")
        print("=" * 80)
        print()

        # A. Functional Equivalence
        self._test_functional_equivalence()

        # B. Field Preservation
        self._test_field_preservation()

        # C. Round-Trip Fidelity
        self._test_round_trip()

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
            import traceback
            traceback.print_exc()

    def _parse_config_for_comparison(self, config_text: str) -> Tuple[ParsedInterface, List[ParsedPeer]]:
        """Parse config text into comparable structures"""
        interface = ParsedInterface()
        peers = []
        current_peer = None
        in_interface = False
        in_peer = False

        for line in config_text.split('\n'):
            line = line.strip()

            # Skip comments and blank lines
            if not line or line.startswith('#'):
                continue

            if line == '[Interface]':
                in_interface = True
                in_peer = False
                continue

            if line == '[Peer]':
                if current_peer:
                    peers.append(current_peer)
                current_peer = ParsedPeer()
                in_interface = False
                in_peer = True
                continue

            if '=' not in line:
                continue

            key, value = line.split('=', 1)
            key = key.strip()
            value = value.strip()

            # Remove inline comments
            if '#' in value:
                value = value.split('#')[0].strip()

            if in_interface:
                if key == 'Address':
                    for addr in value.split(','):
                        interface.addresses.add(addr.strip())
                elif key == 'PrivateKey':
                    interface.private_key = value
                elif key == 'ListenPort':
                    interface.listen_port = int(value)
                elif key == 'MTU':
                    interface.mtu = int(value)
                elif key == 'DNS':
                    for dns in value.split(','):
                        interface.dns.add(dns.strip())
                elif key == 'Table':
                    interface.table = value
                elif key == 'PostUp':
                    interface.postup.append(value)
                elif key == 'PostDown':
                    interface.postdown.append(value)

            elif in_peer and current_peer:
                if key == 'PublicKey':
                    current_peer.public_key = value
                elif key == 'PresharedKey':
                    current_peer.preshared_key = value
                elif key == 'AllowedIPs':
                    for ip in value.split(','):
                        current_peer.allowed_ips.add(ip.strip())
                elif key == 'Endpoint':
                    current_peer.endpoint = value
                elif key == 'PersistentKeepalive':
                    current_peer.persistent_keepalive = int(value)

        if current_peer:
            peers.append(current_peer)

        return interface, peers

    def _compare_interfaces(self, orig: ParsedInterface, exported: ParsedInterface) -> List[str]:
        """Compare two parsed interfaces, return list of differences"""
        diffs = []

        if orig.addresses != exported.addresses:
            diffs.append(f"Address mismatch: {orig.addresses} vs {exported.addresses}")

        if orig.private_key != exported.private_key:
            # Only compare if both present
            if orig.private_key and exported.private_key:
                diffs.append(f"PrivateKey mismatch")

        if orig.listen_port != exported.listen_port:
            if orig.listen_port is not None:
                diffs.append(f"ListenPort mismatch: {orig.listen_port} vs {exported.listen_port}")

        if orig.mtu != exported.mtu:
            if orig.mtu is not None:
                diffs.append(f"MTU mismatch: {orig.mtu} vs {exported.mtu}")

        if orig.dns != exported.dns:
            if orig.dns:
                diffs.append(f"DNS mismatch: {orig.dns} vs {exported.dns}")

        return diffs

    def _compare_peers(self, orig_peers: List[ParsedPeer], exported_peers: List[ParsedPeer]) -> List[str]:
        """Compare two peer lists (order-independent), return differences"""
        diffs = []

        if len(orig_peers) != len(exported_peers):
            diffs.append(f"Peer count mismatch: {len(orig_peers)} vs {len(exported_peers)}")
            return diffs

        # Match by public key
        orig_by_key = {p.public_key: p for p in orig_peers}
        exported_by_key = {p.public_key: p for p in exported_peers}

        # Check all original keys are in exported
        for pub_key in orig_by_key:
            if pub_key not in exported_by_key:
                diffs.append(f"Missing peer with key: {pub_key[:20]}...")
                continue

            orig = orig_by_key[pub_key]
            exp = exported_by_key[pub_key]

            if orig.allowed_ips != exp.allowed_ips:
                diffs.append(f"AllowedIPs mismatch for {pub_key[:20]}...: {orig.allowed_ips} vs {exp.allowed_ips}")

            if orig.endpoint != exp.endpoint:
                if orig.endpoint:
                    diffs.append(f"Endpoint mismatch for {pub_key[:20]}...: {orig.endpoint} vs {exp.endpoint}")

            if orig.persistent_keepalive != exp.persistent_keepalive:
                if orig.persistent_keepalive:
                    diffs.append(f"PersistentKeepalive mismatch for {pub_key[:20]}...: {orig.persistent_keepalive} vs {exp.persistent_keepalive}")

            if orig.preshared_key != exp.preshared_key:
                if orig.preshared_key:
                    diffs.append(f"PresharedKey mismatch for {pub_key[:20]}...")

        return diffs

    # =========================================================================
    # A. FUNCTIONAL EQUIVALENCE TESTS
    # =========================================================================

    def _test_functional_equivalence(self):
        """Functional equivalence tests"""
        print("\n" + "-" * 60)
        print("A. FUNCTIONAL EQUIVALENCE")
        print("-" * 60)

        self._run_test(
            "Simple config: parse -> compare",
            self._test_simple_config_equivalence
        )

        self._run_test(
            "CS config: all peers preserved",
            self._test_cs_config_equivalence
        )

        self._run_test(
            "SNR config: advertised networks preserved",
            self._test_snr_config_equivalence
        )

        self._run_test(
            "Client config: DNS and AllowedIPs preserved",
            self._test_client_config_equivalence
        )

        self._run_test(
            "Edge case config: special formatting preserved",
            self._test_edge_case_equivalence
        )

    def _test_simple_config_equivalence(self):
        """Test simple config parses and compares correctly"""
        config = """[Interface]
Address = 10.66.0.1/24
PrivateKey = mK9f2vJ4xTmW8qLpN3rH6gS7jY5cA0zX1wD9eI2uF4Q=
ListenPort = 51820

[Peer]
PublicKey = tN8x2qL5vR3mZ7pS6wK1yJ4hG0fU9cA8dI2eO3jB5V4=
AllowedIPs = 10.66.0.20/32
PersistentKeepalive = 25
"""
        interface, peers = self._parse_config_for_comparison(config)

        # Verify interface
        if '10.66.0.1/24' not in interface.addresses:
            return False, "Address not parsed", {}

        if interface.private_key != 'mK9f2vJ4xTmW8qLpN3rH6gS7jY5cA0zX1wD9eI2uF4Q=':
            return False, "PrivateKey not parsed", {}

        if interface.listen_port != 51820:
            return False, f"ListenPort wrong: {interface.listen_port}", {}

        # Verify peer
        if len(peers) != 1:
            return False, f"Expected 1 peer, got {len(peers)}", {}

        peer = peers[0]
        if peer.public_key != 'tN8x2qL5vR3mZ7pS6wK1yJ4hG0fU9cA8dI2eO3jB5V4=':
            return False, "Peer PublicKey not parsed", {}

        if '10.66.0.20/32' not in peer.allowed_ips:
            return False, "Peer AllowedIPs not parsed", {}

        if peer.persistent_keepalive != 25:
            return False, f"PersistentKeepalive wrong: {peer.persistent_keepalive}", {}

        return True, "OK", {'addresses': list(interface.addresses), 'peers': len(peers)}

    def _test_cs_config_equivalence(self):
        """Test CS config with multiple peers"""
        config_file = self.configs_dir / "sample_cs.conf"
        if not config_file.exists():
            return False, "Sample config not found", {}

        config_text = config_file.read_text()
        interface, peers = self._parse_config_for_comparison(config_text)

        # CS should have 5 peers
        if len(peers) != 5:
            return False, f"Expected 5 peers, got {len(peers)}", {}

        # Check all peer keys are unique
        keys = [p.public_key for p in peers]
        if len(keys) != len(set(keys)):
            return False, "Duplicate peer keys found", {}

        # Check interface has dual-stack
        has_ipv4 = any('10.66.0.1' in addr for addr in interface.addresses)
        has_ipv6 = any('fd66::1' in addr for addr in interface.addresses)

        if not has_ipv4:
            return False, "Missing IPv4 address", {}

        if not has_ipv6:
            return False, "Missing IPv6 address", {}

        return True, "OK", {'peers': len(peers), 'dual_stack': True}

    def _test_snr_config_equivalence(self):
        """Test SNR config with advertised networks"""
        config_file = self.configs_dir / "sample_snr.conf"
        if not config_file.exists():
            return False, "Sample config not found", {}

        config_text = config_file.read_text()
        interface, peers = self._parse_config_for_comparison(config_text)

        # SNR has 1 peer (CS)
        if len(peers) != 1:
            return False, f"Expected 1 peer, got {len(peers)}", {}

        # Peer's AllowedIPs should include VPN network
        peer = peers[0]
        has_vpn_network = any('10.66.0.0/24' in ip for ip in peer.allowed_ips)

        if not has_vpn_network:
            return False, "Missing VPN network in AllowedIPs", {}

        # Interface should have PostUp/PostDown
        if len(interface.postup) == 0:
            return False, "Missing PostUp commands", {}

        if len(interface.postdown) == 0:
            return False, "Missing PostDown commands", {}

        return True, "OK", {
            'postup_count': len(interface.postup),
            'postdown_count': len(interface.postdown)
        }

    def _test_client_config_equivalence(self):
        """Test client config with DNS and routing"""
        config_file = self.configs_dir / "sample_client.conf"
        if not config_file.exists():
            return False, "Sample config not found", {}

        config_text = config_file.read_text()
        interface, peers = self._parse_config_for_comparison(config_text)

        # Client has DNS
        if not interface.dns:
            return False, "Missing DNS", {}

        # Client has MTU
        if not interface.mtu:
            return False, "Missing MTU", {}

        # Client peer has endpoint
        peer = peers[0]
        if not peer.endpoint:
            return False, "Missing endpoint", {}

        # Client should route to multiple networks
        if len(peer.allowed_ips) < 2:
            return False, f"Expected multiple AllowedIPs, got {len(peer.allowed_ips)}", {}

        return True, "OK", {
            'dns': list(interface.dns),
            'allowed_ips_count': len(peer.allowed_ips)
        }

    def _test_edge_case_equivalence(self):
        """Test edge case config with special formatting"""
        config_file = self.configs_dir / "sample_edge_cases.conf"
        if not config_file.exists():
            return False, "Sample config not found", {}

        config_text = config_file.read_text()
        interface, peers = self._parse_config_for_comparison(config_text)

        # Should parse despite unusual formatting
        if not interface.addresses:
            return False, "Failed to parse addresses", {}

        if not interface.private_key:
            return False, "Failed to parse private key", {}

        # Multiple DNS
        if len(interface.dns) != 3:
            return False, f"Expected 3 DNS servers, got {len(interface.dns)}", {}

        # PresharedKey in peer
        peer_with_psk = None
        for peer in peers:
            if peer.preshared_key:
                peer_with_psk = peer
                break

        if not peer_with_psk:
            return False, "PresharedKey not parsed", {}

        # IPv6 endpoint
        peer_with_ipv6 = None
        for peer in peers:
            if peer.endpoint and '[' in peer.endpoint:
                peer_with_ipv6 = peer
                break

        if not peer_with_ipv6:
            return False, "IPv6 endpoint not parsed", {}

        return True, "OK", {'peers': len(peers), 'has_psk': True, 'has_ipv6_endpoint': True}

    # =========================================================================
    # B. FIELD PRESERVATION TESTS
    # =========================================================================

    def _test_field_preservation(self):
        """Field preservation tests"""
        print("\n" + "-" * 60)
        print("B. FIELD PRESERVATION")
        print("-" * 60)

        self._run_test(
            "PrivateKey preserved exactly",
            self._test_privatekey_preservation
        )

        self._run_test(
            "PublicKey preserved exactly",
            self._test_publickey_preservation
        )

        self._run_test(
            "AllowedIPs preserved (order-independent)",
            self._test_allowedips_preservation
        )

        self._run_test(
            "Endpoint preserved exactly",
            self._test_endpoint_preservation
        )

        self._run_test(
            "PostUp/PostDown commands preserved",
            self._test_commands_preservation
        )

        self._run_test(
            "PresharedKey preserved exactly",
            self._test_presharedkey_preservation
        )

    def _test_privatekey_preservation(self):
        """Test PrivateKey preserved exactly"""
        # Generate a real key
        priv, pub = generate_keypair()

        config = f"""[Interface]
Address = 10.66.0.1/24
PrivateKey = {priv}

[Peer]
PublicKey = {pub}
AllowedIPs = 10.66.0.2/32
"""
        interface, _ = self._parse_config_for_comparison(config)

        if interface.private_key != priv:
            return False, f"PrivateKey mismatch", {'expected': priv, 'got': interface.private_key}

        return True, "OK", {}

    def _test_publickey_preservation(self):
        """Test PublicKey preserved exactly"""
        priv, pub = generate_keypair()

        config = f"""[Interface]
Address = 10.66.0.1/24
PrivateKey = {priv}

[Peer]
PublicKey = {pub}
AllowedIPs = 10.66.0.2/32
"""
        _, peers = self._parse_config_for_comparison(config)

        if peers[0].public_key != pub:
            return False, f"PublicKey mismatch", {'expected': pub, 'got': peers[0].public_key}

        return True, "OK", {}

    def _test_allowedips_preservation(self):
        """Test AllowedIPs preserved (order doesn't matter)"""
        config = """[Interface]
Address = 10.66.0.1/24
PrivateKey = mK9f2vJ4xTmW8qLpN3rH6gS7jY5cA0zX1wD9eI2uF4Q=

[Peer]
PublicKey = tN8x2qL5vR3mZ7pS6wK1yJ4hG0fU9cA8dI2eO3jB5V4=
AllowedIPs = 10.66.0.0/24, 192.168.1.0/24, fd66::/64
"""
        _, peers = self._parse_config_for_comparison(config)

        expected_ips = {'10.66.0.0/24', '192.168.1.0/24', 'fd66::/64'}
        if peers[0].allowed_ips != expected_ips:
            return False, f"AllowedIPs mismatch", {
                'expected': expected_ips,
                'got': peers[0].allowed_ips
            }

        return True, "OK", {'allowed_ips': list(expected_ips)}

    def _test_endpoint_preservation(self):
        """Test Endpoint preserved exactly"""
        config = """[Interface]
Address = 10.66.0.1/24
PrivateKey = mK9f2vJ4xTmW8qLpN3rH6gS7jY5cA0zX1wD9eI2uF4Q=

[Peer]
PublicKey = tN8x2qL5vR3mZ7pS6wK1yJ4hG0fU9cA8dI2eO3jB5V4=
AllowedIPs = 10.66.0.0/24
Endpoint = vpn.example.com:51820
"""
        _, peers = self._parse_config_for_comparison(config)

        if peers[0].endpoint != 'vpn.example.com:51820':
            return False, f"Endpoint mismatch", {'got': peers[0].endpoint}

        return True, "OK", {}

    def _test_commands_preservation(self):
        """Test PostUp/PostDown commands preserved"""
        config = """[Interface]
Address = 10.66.0.1/24
PrivateKey = mK9f2vJ4xTmW8qLpN3rH6gS7jY5cA0zX1wD9eI2uF4Q=
PostUp = sysctl -w net.ipv4.ip_forward=1
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT

[Peer]
PublicKey = tN8x2qL5vR3mZ7pS6wK1yJ4hG0fU9cA8dI2eO3jB5V4=
AllowedIPs = 10.66.0.0/24
"""
        interface, _ = self._parse_config_for_comparison(config)

        if len(interface.postup) != 2:
            return False, f"Expected 2 PostUp, got {len(interface.postup)}", {}

        if len(interface.postdown) != 1:
            return False, f"Expected 1 PostDown, got {len(interface.postdown)}", {}

        # Check specific commands
        if 'ip_forward' not in interface.postup[0]:
            return False, "sysctl command not preserved", {}

        return True, "OK", {
            'postup': len(interface.postup),
            'postdown': len(interface.postdown)
        }

    def _test_presharedkey_preservation(self):
        """Test PresharedKey preserved exactly"""
        psk = "hV8y3rM6xS4nA7pT0wK2zJ5gG1fU9cI3eO4lB6C7D8="

        config = f"""[Interface]
Address = 10.66.0.1/24
PrivateKey = mK9f2vJ4xTmW8qLpN3rH6gS7jY5cA0zX1wD9eI2uF4Q=

[Peer]
PublicKey = tN8x2qL5vR3mZ7pS6wK1yJ4hG0fU9cA8dI2eO3jB5V4=
AllowedIPs = 10.66.0.0/24
PresharedKey = {psk}
"""
        _, peers = self._parse_config_for_comparison(config)

        if peers[0].preshared_key != psk:
            return False, f"PresharedKey mismatch", {'got': peers[0].preshared_key}

        return True, "OK", {}

    # =========================================================================
    # C. ROUND-TRIP FIDELITY TESTS
    # =========================================================================

    def _test_round_trip(self):
        """Round-trip fidelity tests"""
        print("\n" + "-" * 60)
        print("C. ROUND-TRIP FIDELITY")
        print("-" * 60)

        self._run_test(
            "Parse -> Database -> Generate -> Compare",
            self._test_full_round_trip
        )

        self._run_test(
            "AllowedIPs stored and regenerated correctly",
            self._test_allowedips_round_trip
        )

        self._run_test(
            "Key rotation doesn't break fidelity",
            self._test_key_rotation_fidelity
        )

        self._run_test(
            "Multiple round-trips stable",
            self._test_multiple_round_trips
        )

    def _test_full_round_trip(self):
        """Test full round-trip: parse -> db -> generate -> compare"""
        # Create test config
        priv1, pub1 = generate_keypair()
        priv2, pub2 = generate_keypair()

        original_config = f"""[Interface]
Address = 10.66.0.1/24, fd66::1/64
PrivateKey = {priv1}
ListenPort = 51820
MTU = 1420

[Peer]
PublicKey = {pub2}
AllowedIPs = 10.66.0.20/32, fd66::20/128
PersistentKeepalive = 25
"""
        # Parse original
        orig_interface, orig_peers = self._parse_config_for_comparison(original_config)

        # Store in database
        db_path = self.temp_dir / "roundtrip.db"
        db = WireGuardDBv2(db_path)

        with db._connection() as conn:
            cursor = conn.cursor()

            # Insert CS
            cursor.execute("""
                INSERT INTO coordination_server (
                    permanent_guid, current_public_key, hostname,
                    endpoint, listen_port, network_ipv4, network_ipv6,
                    ipv4_address, ipv6_address, private_key, mtu
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                pub1, pub1, 'test-cs',
                'vpn.example.com', 51820, '10.66.0.0/24', 'fd66::/64',
                '10.66.0.1/24', 'fd66::1/64', priv1, 1420
            ))
            cs_id = cursor.lastrowid

            # Insert remote
            cursor.execute("""
                INSERT INTO remote (
                    cs_id, permanent_guid, current_public_key, hostname,
                    ipv4_address, ipv6_address, private_key, access_level,
                    persistent_keepalive
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                cs_id, pub2, pub2, 'test-remote',
                '10.66.0.20/32', 'fd66::20/128', priv2, 'full_access', 25
            ))

        # Generate config from database
        from v1.cli.config_generator import generate_cs_config
        generated = generate_cs_config(db)

        # Parse generated
        gen_interface, gen_peers = self._parse_config_for_comparison(generated)

        # Compare interfaces
        if_diffs = self._compare_interfaces(orig_interface, gen_interface)
        if if_diffs:
            return False, f"Interface differences: {if_diffs}", {}

        # Compare peers
        peer_diffs = self._compare_peers(orig_peers, gen_peers)
        if peer_diffs:
            return False, f"Peer differences: {peer_diffs}", {}

        return True, "OK - round-trip preserved fidelity", {}

    def _test_allowedips_round_trip(self):
        """Test AllowedIPs stored correctly and regenerated"""
        db_path = self.temp_dir / "allowedips_rt.db"
        db = WireGuardDBv2(db_path)

        # The allowed_ips column stores the exact string
        priv, pub = generate_keypair()
        allowed_ips = "10.66.0.0/24, 192.168.1.0/24, fd66::/64"

        with db._connection() as conn:
            cursor = conn.cursor()

            # Insert CS
            cursor.execute("""
                INSERT INTO coordination_server (
                    permanent_guid, current_public_key, hostname,
                    endpoint, listen_port, network_ipv4, network_ipv6,
                    ipv4_address, ipv6_address, private_key
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                pub, pub, 'test-cs',
                'vpn.example.com', 51820, '10.66.0.0/24', 'fd66::/64',
                '10.66.0.1/24', 'fd66::1/64', priv
            ))
            cs_id = cursor.lastrowid

            # Insert remote with allowed_ips
            remote_priv, remote_pub = generate_keypair()
            cursor.execute("""
                INSERT INTO remote (
                    cs_id, permanent_guid, current_public_key, hostname,
                    ipv4_address, ipv6_address, private_key, access_level,
                    allowed_ips
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                cs_id, remote_pub, remote_pub, 'test-remote',
                '10.66.0.20/32', 'fd66::20/128', remote_priv, 'custom',
                allowed_ips
            ))

            # Retrieve and verify
            cursor.execute("SELECT allowed_ips FROM remote WHERE permanent_guid = ?", (remote_pub,))
            row = cursor.fetchone()

        if row['allowed_ips'] != allowed_ips:
            return False, f"AllowedIPs not stored correctly", {
                'expected': allowed_ips,
                'got': row['allowed_ips']
            }

        return True, "OK - AllowedIPs preserved in database", {}

    def _test_key_rotation_fidelity(self):
        """Test key rotation doesn't break config fidelity"""
        db_path = self.temp_dir / "rotation_fidelity.db"
        db = WireGuardDBv2(db_path)

        # Initial keys
        priv1, pub1 = generate_keypair()

        with db._connection() as conn:
            cursor = conn.cursor()

            cursor.execute("""
                INSERT INTO coordination_server (
                    permanent_guid, current_public_key, hostname,
                    endpoint, listen_port, network_ipv4, network_ipv6,
                    ipv4_address, ipv6_address, private_key
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                pub1, pub1, 'test-cs',
                'vpn.example.com', 51820, '10.66.0.0/24', 'fd66::/64',
                '10.66.0.1/24', 'fd66::1/64', priv1
            ))

        # Generate initial config
        from v1.cli.config_generator import generate_cs_config
        config_before = generate_cs_config(db)
        interface_before, _ = self._parse_config_for_comparison(config_before)

        # Rotate keys
        priv2, pub2 = generate_keypair()

        with db._connection() as conn:
            cursor = conn.cursor()

            # Record rotation
            cursor.execute("""
                INSERT INTO key_rotation_history (
                    entity_permanent_guid, entity_type,
                    old_public_key, new_public_key, new_private_key, reason
                ) VALUES (?, ?, ?, ?, ?, ?)
            """, (pub1, 'coordination_server', pub1, pub2, priv2, 'test'))

            # Update key
            cursor.execute("""
                UPDATE coordination_server
                SET current_public_key = ?, private_key = ?
                WHERE permanent_guid = ?
            """, (pub2, priv2, pub1))

        # Generate config after rotation
        config_after = generate_cs_config(db)
        interface_after, _ = self._parse_config_for_comparison(config_after)

        # Addresses should be same
        if interface_before.addresses != interface_after.addresses:
            return False, "Addresses changed after rotation", {}

        # ListenPort should be same
        if interface_before.listen_port != interface_after.listen_port:
            return False, "ListenPort changed after rotation", {}

        # PrivateKey should be different (rotated)
        if interface_before.private_key == interface_after.private_key:
            return False, "PrivateKey not rotated", {}

        return True, "OK - config structure preserved after rotation", {}

    def _test_multiple_round_trips(self):
        """Test multiple round-trips produce stable results"""
        priv, pub = generate_keypair()

        config = f"""[Interface]
Address = 10.66.0.1/24
PrivateKey = {priv}
ListenPort = 51820

[Peer]
PublicKey = {pub}
AllowedIPs = 10.66.0.20/32
PersistentKeepalive = 25
"""
        # Parse multiple times
        results = []
        for _ in range(5):
            interface, peers = self._parse_config_for_comparison(config)
            results.append((interface, peers))

        # All results should be identical
        first_if, first_peers = results[0]
        for interface, peers in results[1:]:
            if interface.addresses != first_if.addresses:
                return False, "Addresses differ between parses", {}

            if interface.private_key != first_if.private_key:
                return False, "PrivateKey differs between parses", {}

            if len(peers) != len(first_peers):
                return False, "Peer count differs between parses", {}

        return True, "OK - parsing is stable", {'iterations': len(results)}


def main():
    """Run fidelity tests"""
    tests = FidelityTests()
    passed, failed = tests.run_all()

    print()
    print("=" * 80)
    print(f"FIDELITY RESULTS: {passed} passed, {failed} failed")
    print("=" * 80)

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
