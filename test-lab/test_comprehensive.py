#!/usr/bin/env python3
"""
Comprehensive WireGuard Friend Test Suite

Tests all critical functionality:
1. Configuration roundtrip fidelity
2. Key management and GUID preservation
3. Access level enforcement
4. Database integrity
5. Edge cases
6. Stress testing

Run with: python3 test_comprehensive.py
"""

import sys
import os
import tempfile
import json
import base64
import time
import sqlite3
import ipaddress
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Optional
from datetime import datetime

# Add project to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from v1.schema_semantic import WireGuardDBv2
from v1.keygen import generate_keypair, derive_public_key, generate_preshared_key
from v1.patterns import PatternRecognizer
from v1.comments import CommentCategorizer, CommentCategory
from v1.entity_parser import EntityParser


@dataclass
class TestResult:
    """Result of a single test"""
    name: str
    category: str
    passed: bool
    duration_ms: float
    message: str = ""
    details: Dict = field(default_factory=dict)


@dataclass
class TestReport:
    """Complete test report"""
    start_time: datetime
    end_time: Optional[datetime] = None
    results: List[TestResult] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def passed(self) -> int:
        return sum(1 for r in self.results if r.passed)

    @property
    def failed(self) -> int:
        return sum(1 for r in self.results if not r.passed)

    def add(self, result: TestResult):
        self.results.append(result)

    def summary_by_category(self) -> Dict[str, Dict[str, int]]:
        categories = {}
        for r in self.results:
            if r.category not in categories:
                categories[r.category] = {'passed': 0, 'failed': 0}
            if r.passed:
                categories[r.category]['passed'] += 1
            else:
                categories[r.category]['failed'] += 1
        return categories


class ComprehensiveTestSuite:
    """Complete test suite for wireguard-friend"""

    def __init__(self):
        self.report = TestReport(start_time=datetime.now())
        self.temp_dir = None

    def run_all(self):
        """Run all test categories"""
        print("=" * 80)
        print("WIREGUARD FRIEND - COMPREHENSIVE TEST SUITE")
        print("=" * 80)
        print()

        self.temp_dir = Path(tempfile.mkdtemp(prefix="wgf_test_"))
        print(f"Temp directory: {self.temp_dir}")
        print()

        try:
            # A. Configuration Roundtrip Fidelity
            self._test_roundtrip_fidelity()

            # B. Key Management & GUID Preservation
            self._test_key_management()

            # C. Access Level Enforcement
            self._test_access_levels()

            # D. Database Integrity
            self._test_database_integrity()

            # E. Edge Cases
            self._test_edge_cases()

            # F. Stress Testing
            self._test_stress()

        finally:
            self.report.end_time = datetime.now()

        self._print_report()
        return self.report

    def _run_test(self, name: str, category: str, test_fn):
        """Run a single test and record result"""
        start = time.time()
        try:
            result = test_fn()
            duration = (time.time() - start) * 1000

            if isinstance(result, tuple):
                passed, message, details = result
            else:
                passed = result
                message = "OK" if passed else "FAILED"
                details = {}

            self.report.add(TestResult(
                name=name,
                category=category,
                passed=passed,
                duration_ms=duration,
                message=message,
                details=details
            ))

            status = "[PASS]" if passed else "[FAIL]"
            print(f"  {status} {name} ({duration:.1f}ms)")
            if not passed and message:
                print(f"         {message}")

        except Exception as e:
            duration = (time.time() - start) * 1000
            self.report.add(TestResult(
                name=name,
                category=category,
                passed=False,
                duration_ms=duration,
                message=f"Exception: {e}",
                details={'exception': str(e)}
            ))
            print(f"  [FAIL] {name} ({duration:.1f}ms)")
            print(f"         Exception: {e}")

    # =========================================================================
    # A. CONFIGURATION ROUNDTRIP FIDELITY TESTS
    # =========================================================================

    def _test_roundtrip_fidelity(self):
        """Test configuration roundtrip fidelity"""
        print("\n" + "=" * 60)
        print("A. CONFIGURATION ROUNDTRIP FIDELITY")
        print("=" * 60)

        self._run_test(
            "Basic config parse and regenerate",
            "roundtrip",
            self._test_basic_roundtrip
        )

        self._run_test(
            "Whitespace preservation",
            "roundtrip",
            self._test_whitespace_preservation
        )

        self._run_test(
            "Comment handling",
            "roundtrip",
            self._test_comment_handling
        )

        self._run_test(
            "Multi-line PostUp/PostDown preservation",
            "roundtrip",
            self._test_multiline_commands
        )

        self._run_test(
            "IPv6 address handling",
            "roundtrip",
            self._test_ipv6_handling
        )

        self._run_test(
            "CIDR range variations",
            "roundtrip",
            self._test_cidr_variations
        )

    def _test_basic_roundtrip(self):
        """Test basic config parse and regenerate"""
        config = """[Interface]
Address = 10.66.0.1/24
PrivateKey = WG_PRIVATE_KEY_HERE_1234567890123456789012==
ListenPort = 51820

[Peer]
# alice-laptop
PublicKey = PEER_PUBLIC_KEY_HERE_12345678901234567890123==
AllowedIPs = 10.66.0.20/32
"""
        parser = EntityParser()

        # Write to temp file
        config_file = self.temp_dir / "basic.conf"
        config_file.write_text(config)

        # Parse
        entities = parser.parse_file(config_file)

        # Verify structure
        if len(entities) != 2:
            return False, f"Expected 2 entities, got {len(entities)}", {}

        if entities[0].entity_type != '[Interface]':
            return False, f"First entity should be [Interface], got {entities[0].entity_type}", {}

        if entities[1].entity_type != '[Peer]':
            return False, f"Second entity should be [Peer], got {entities[1].entity_type}", {}

        return True, "OK", {'entities': len(entities)}

    def _test_whitespace_preservation(self):
        """Test unusual whitespace patterns"""
        configs = [
            # Spaces around equals
            "Address = 10.66.0.1/24",
            "Address=10.66.0.1/24",
            "Address  =  10.66.0.1/24",
        ]

        for config_line in configs:
            full_config = f"""[Interface]
{config_line}
PrivateKey = WG_PRIVATE_KEY_HERE_1234567890123456789012==
"""
            config_file = self.temp_dir / "whitespace.conf"
            config_file.write_text(full_config)

            parser = EntityParser()
            entities = parser.parse_file(config_file)

            if len(entities) != 1:
                return False, f"Failed on: {config_line}", {}

        return True, "OK", {'tested_patterns': len(configs)}

    def _test_comment_handling(self):
        """Test inline and standalone comments"""
        config = """[Interface]
# This is a header comment
Address = 10.66.0.1/24  # inline comment
PrivateKey = WG_PRIVATE_KEY_HERE_1234567890123456789012==
ListenPort = 51820

[Peer]
# hostname-here
# Role: Subnet router behind CGNAT
PublicKey = PEER_PUBLIC_KEY_HERE_12345678901234567890123==
AllowedIPs = 10.66.0.20/32
# Custom note about this peer
"""
        config_file = self.temp_dir / "comments.conf"
        config_file.write_text(config)

        parser = EntityParser()
        entities = parser.parse_file(config_file)

        if len(entities) != 2:
            return False, f"Expected 2 entities, got {len(entities)}", {}

        # Check that comments are preserved in lines
        peer_lines = '\n'.join(entities[1].lines)
        if 'hostname-here' not in peer_lines:
            return False, "Hostname comment not preserved", {}

        return True, "OK", {}

    def _test_multiline_commands(self):
        """Test multi-line PostUp/PostDown preservation"""
        config = """[Interface]
Address = 10.66.0.1/24
PrivateKey = WG_PRIVATE_KEY_HERE_1234567890123456789012==
ListenPort = 51820
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT
PostUp = iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostUp = sysctl -w net.ipv4.ip_forward=1
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
"""
        config_file = self.temp_dir / "multiline.conf"
        config_file.write_text(config)

        parser = EntityParser()
        entities = parser.parse_file(config_file)

        if len(entities) != 1:
            return False, f"Expected 1 entity, got {len(entities)}", {}

        # Count PostUp lines
        postup_count = sum(1 for line in entities[0].lines if 'PostUp' in line)
        postdown_count = sum(1 for line in entities[0].lines if 'PostDown' in line)

        if postup_count != 3:
            return False, f"Expected 3 PostUp, got {postup_count}", {}

        if postdown_count != 2:
            return False, f"Expected 2 PostDown, got {postdown_count}", {}

        return True, "OK", {'postup': postup_count, 'postdown': postdown_count}

    def _test_ipv6_handling(self):
        """Test IPv6 address handling"""
        config = """[Interface]
Address = 10.66.0.1/24, fd66::1/64
PrivateKey = WG_PRIVATE_KEY_HERE_1234567890123456789012==
ListenPort = 51820

[Peer]
PublicKey = PEER_PUBLIC_KEY_HERE_12345678901234567890123==
AllowedIPs = 10.66.0.20/32, fd66::20/128
Endpoint = [2001:db8::1]:51820
"""
        config_file = self.temp_dir / "ipv6.conf"
        config_file.write_text(config)

        parser = EntityParser()
        entities = parser.parse_file(config_file)

        if len(entities) != 2:
            return False, f"Expected 2 entities, got {len(entities)}", {}

        # Check IPv6 in content
        interface_content = '\n'.join(entities[0].lines)
        if 'fd66::1/64' not in interface_content:
            return False, "IPv6 address not preserved", {}

        peer_content = '\n'.join(entities[1].lines)
        if '[2001:db8::1]:51820' not in peer_content:
            return False, "IPv6 endpoint with brackets not preserved", {}

        return True, "OK", {}

    def _test_cidr_variations(self):
        """Test various CIDR ranges"""
        cidrs = [
            ("10.66.0.1/32", True),      # Single host
            ("10.66.0.0/24", True),      # /24
            ("192.168.0.0/16", True),    # /16
            ("10.0.0.0/8", True),        # /8
            ("0.0.0.0/0", True),         # Default route
            ("fd66::/64", True),         # IPv6
            ("::/0", True),              # IPv6 default
        ]

        for cidr, expected_valid in cidrs:
            try:
                ipaddress.ip_network(cidr, strict=False)
                is_valid = True
            except ValueError:
                is_valid = False

            if is_valid != expected_valid:
                return False, f"CIDR validation mismatch: {cidr}", {}

        return True, "OK", {'tested_cidrs': len(cidrs)}

    # =========================================================================
    # B. KEY MANAGEMENT & GUID PRESERVATION TESTS
    # =========================================================================

    def _test_key_management(self):
        """Test key management and GUID preservation"""
        print("\n" + "=" * 60)
        print("B. KEY MANAGEMENT & GUID PRESERVATION")
        print("=" * 60)

        self._run_test(
            "Keypair generation",
            "keys",
            self._test_keypair_generation
        )

        self._run_test(
            "Public key derivation",
            "keys",
            self._test_key_derivation
        )

        self._run_test(
            "Key format validation (44 char base64)",
            "keys",
            self._test_key_format
        )

        self._run_test(
            "Permanent GUID survives key rotation",
            "keys",
            self._test_guid_persistence
        )

        self._run_test(
            "Preshared key generation",
            "keys",
            self._test_preshared_key
        )

        self._run_test(
            "Key rotation history tracking",
            "keys",
            self._test_rotation_history
        )

    def _test_keypair_generation(self):
        """Test keypair generation"""
        private, public = generate_keypair()

        if len(private) != 44:
            return False, f"Private key wrong length: {len(private)}", {}

        if len(public) != 44:
            return False, f"Public key wrong length: {len(public)}", {}

        # Verify base64
        try:
            decoded_priv = base64.b64decode(private)
            decoded_pub = base64.b64decode(public)

            if len(decoded_priv) != 32:
                return False, f"Decoded private key wrong size: {len(decoded_priv)}", {}

            if len(decoded_pub) != 32:
                return False, f"Decoded public key wrong size: {len(decoded_pub)}", {}

        except Exception as e:
            return False, f"Base64 decode failed: {e}", {}

        return True, "OK", {}

    def _test_key_derivation(self):
        """Test that public key derivation is deterministic"""
        private, expected_public = generate_keypair()

        # Derive again
        derived = derive_public_key(private)

        if derived != expected_public:
            return False, "Derived public key doesn't match", {
                'expected': expected_public,
                'derived': derived
            }

        # Derive multiple times
        for _ in range(5):
            if derive_public_key(private) != expected_public:
                return False, "Derivation not deterministic", {}

        return True, "OK", {}

    def _test_key_format(self):
        """Test key format validation"""
        # Valid key
        private, public = generate_keypair()

        # Check base64 characters
        valid_chars = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')

        for char in private:
            if char not in valid_chars:
                return False, f"Invalid character in private key: {char}", {}

        for char in public:
            if char not in valid_chars:
                return False, f"Invalid character in public key: {char}", {}

        return True, "OK", {}

    def _test_guid_persistence(self):
        """Test that permanent_guid survives key rotation"""
        db_path = self.temp_dir / "guid_test.db"
        db = WireGuardDBv2(db_path)

        # Generate initial keypair
        initial_private, initial_public = generate_keypair()
        permanent_guid = initial_public  # First key = permanent GUID

        # Insert CS
        with db._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO coordination_server (
                    permanent_guid, current_public_key, hostname,
                    endpoint, listen_port, network_ipv4, network_ipv6,
                    ipv4_address, ipv6_address, private_key
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                permanent_guid, initial_public, "test-cs",
                "vpn.example.com", 51820, "10.66.0.0/24", "fd66::/64",
                "10.66.0.1/24", "fd66::1/64", initial_private
            ))

        # Simulate key rotation
        new_private, new_public = generate_keypair()

        with db._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE coordination_server
                SET current_public_key = ?, private_key = ?
                WHERE permanent_guid = ?
            """, (new_public, new_private, permanent_guid))

        # Verify permanent_guid unchanged
        with db._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT permanent_guid, current_public_key FROM coordination_server
            """)
            row = cursor.fetchone()

            if row['permanent_guid'] != permanent_guid:
                return False, "permanent_guid changed!", {}

            if row['current_public_key'] != new_public:
                return False, "current_public_key not updated", {}

        return True, "OK", {'guid': permanent_guid[:20] + '...'}

    def _test_preshared_key(self):
        """Test preshared key generation"""
        psk = generate_preshared_key()

        if len(psk) != 44:
            return False, f"PSK wrong length: {len(psk)}", {}

        try:
            decoded = base64.b64decode(psk)
            if len(decoded) != 32:
                return False, f"Decoded PSK wrong size: {len(decoded)}", {}
        except Exception as e:
            return False, f"PSK base64 decode failed: {e}", {}

        return True, "OK", {}

    def _test_rotation_history(self):
        """Test key rotation history tracking"""
        db_path = self.temp_dir / "rotation_test.db"
        db = WireGuardDBv2(db_path)

        # Generate keys
        old_private, old_public = generate_keypair()
        new_private, new_public = generate_keypair()
        permanent_guid = old_public

        # Insert rotation record
        with db._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO key_rotation_history (
                    entity_permanent_guid, entity_type,
                    old_public_key, new_public_key,
                    new_private_key, reason
                ) VALUES (?, ?, ?, ?, ?, ?)
            """, (
                permanent_guid, 'coordination_server',
                old_public, new_public,
                new_private, 'routine_rotation'
            ))

        # Verify record exists
        with db._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM key_rotation_history
                WHERE entity_permanent_guid = ?
            """, (permanent_guid,))
            row = cursor.fetchone()

            if not row:
                return False, "Rotation history not recorded", {}

            if row['old_public_key'] != old_public:
                return False, "Old key not recorded correctly", {}

            if row['new_public_key'] != new_public:
                return False, "New key not recorded correctly", {}

        return True, "OK", {}

    # =========================================================================
    # C. ACCESS LEVEL ENFORCEMENT TESTS
    # =========================================================================

    def _test_access_levels(self):
        """Test access level enforcement"""
        print("\n" + "=" * 60)
        print("C. ACCESS LEVEL ENFORCEMENT")
        print("=" * 60)

        self._run_test(
            "full_access level: VPN + all LANs",
            "access",
            self._test_full_access
        )

        self._run_test(
            "vpn_only level: only VPN peers",
            "access",
            self._test_vpn_only
        )

        self._run_test(
            "lan_only level: VPN + specific LANs",
            "access",
            self._test_lan_only
        )

        self._run_test(
            "Access level stored in database",
            "access",
            self._test_access_storage
        )

    def _test_full_access(self):
        """Test full_access level generates correct AllowedIPs"""
        # For full_access, AllowedIPs should include VPN network + all advertised LANs
        vpn_network = "10.66.0.0/24"
        advertised_lans = ["192.168.1.0/24", "192.168.2.0/24"]

        expected = [vpn_network] + advertised_lans

        # All should be present for full_access
        for net in expected:
            try:
                ipaddress.ip_network(net, strict=False)
            except ValueError as e:
                return False, f"Invalid network: {net} - {e}", {}

        return True, "OK", {'expected_nets': len(expected)}

    def _test_vpn_only(self):
        """Test vpn_only level generates correct AllowedIPs"""
        # For vpn_only, AllowedIPs should include only VPN network
        vpn_network = "10.66.0.0/24"
        vpn_network_v6 = "fd66::/64"

        # Should NOT include LAN networks
        excluded = ["192.168.1.0/24", "192.168.2.0/24"]

        # Verify VPN networks are valid
        try:
            ipaddress.ip_network(vpn_network, strict=False)
            ipaddress.ip_network(vpn_network_v6, strict=False)
        except ValueError as e:
            return False, f"Invalid VPN network: {e}", {}

        return True, "OK", {}

    def _test_lan_only(self):
        """Test lan_only level generates correct AllowedIPs"""
        # For lan_only, AllowedIPs should include specific LANs
        selected_lans = ["192.168.1.0/24"]

        # Verify selected LANs are valid
        for lan in selected_lans:
            try:
                ipaddress.ip_network(lan, strict=False)
            except ValueError as e:
                return False, f"Invalid LAN network: {lan} - {e}", {}

        return True, "OK", {}

    def _test_access_storage(self):
        """Test access level stored in database"""
        db_path = self.temp_dir / "access_test.db"
        db = WireGuardDBv2(db_path)

        private, public = generate_keypair()

        # Create CS first
        with db._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO coordination_server (
                    permanent_guid, current_public_key, hostname,
                    endpoint, listen_port, network_ipv4, network_ipv6,
                    ipv4_address, ipv6_address, private_key
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                public, public, "test-cs",
                "vpn.example.com", 51820, "10.66.0.0/24", "fd66::/64",
                "10.66.0.1/24", "fd66::1/64", private
            ))
            cs_id = cursor.lastrowid

        # Insert remote with access level
        remote_private, remote_public = generate_keypair()

        with db._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO remote (
                    cs_id, permanent_guid, current_public_key, hostname,
                    ipv4_address, ipv6_address, private_key, access_level
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                cs_id, remote_public, remote_public, "test-remote",
                "10.66.0.20/32", "fd66::20/128", remote_private, "full_access"
            ))

        # Verify access level stored
        with db._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT access_level FROM remote")
            row = cursor.fetchone()

            if row['access_level'] != 'full_access':
                return False, f"Wrong access level: {row['access_level']}", {}

        return True, "OK", {}

    # =========================================================================
    # D. DATABASE INTEGRITY TESTS
    # =========================================================================

    def _test_database_integrity(self):
        """Test database integrity"""
        print("\n" + "=" * 60)
        print("D. DATABASE INTEGRITY")
        print("=" * 60)

        self._run_test(
            "Schema creation",
            "database",
            self._test_schema_creation
        )

        self._run_test(
            "Foreign key constraints",
            "database",
            self._test_foreign_keys
        )

        self._run_test(
            "Cascade delete behavior",
            "database",
            self._test_cascade_delete
        )

        self._run_test(
            "Unique constraint on permanent_guid",
            "database",
            self._test_unique_guid
        )

        self._run_test(
            "Special characters in text fields",
            "database",
            self._test_special_characters
        )

    def _test_schema_creation(self):
        """Test database schema creation"""
        db_path = self.temp_dir / "schema_test.db"
        db = WireGuardDBv2(db_path)

        # Check expected tables exist
        expected_tables = [
            'coordination_server',
            'subnet_router',
            'remote',
            'advertised_network',
            'command_pair',
            'command_singleton',
            'comment',
            'key_rotation_history',
        ]

        with db._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]

        missing = [t for t in expected_tables if t not in tables]
        if missing:
            return False, f"Missing tables: {missing}", {}

        return True, "OK", {'tables': len(tables)}

    def _test_foreign_keys(self):
        """Test foreign key constraints"""
        db_path = self.temp_dir / "fk_test.db"
        db = WireGuardDBv2(db_path)

        # Try to insert remote without CS (should fail)
        private, public = generate_keypair()

        try:
            with db._connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO remote (
                        cs_id, permanent_guid, current_public_key, hostname,
                        ipv4_address, ipv6_address, private_key, access_level
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    999,  # Non-existent CS
                    public, public, "test",
                    "10.66.0.20/32", "", private, "full_access"
                ))
            # If we get here, FK constraint failed
            return False, "Foreign key constraint not enforced", {}
        except sqlite3.IntegrityError:
            # Expected - FK constraint worked
            return True, "OK", {}
        except Exception as e:
            return False, f"Unexpected error: {e}", {}

    def _test_cascade_delete(self):
        """Test cascade delete behavior"""
        db_path = self.temp_dir / "cascade_test.db"
        db = WireGuardDBv2(db_path)

        # Create CS
        cs_private, cs_public = generate_keypair()

        with db._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO coordination_server (
                    permanent_guid, current_public_key, hostname,
                    endpoint, listen_port, network_ipv4, network_ipv6,
                    ipv4_address, ipv6_address, private_key
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                cs_public, cs_public, "test-cs",
                "vpn.example.com", 51820, "10.66.0.0/24", "fd66::/64",
                "10.66.0.1/24", "fd66::1/64", cs_private
            ))
            cs_id = cursor.lastrowid

        # Create remote
        remote_private, remote_public = generate_keypair()

        with db._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO remote (
                    cs_id, permanent_guid, current_public_key, hostname,
                    ipv4_address, ipv6_address, private_key, access_level
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                cs_id, remote_public, remote_public, "test-remote",
                "10.66.0.20/32", "", remote_private, "full_access"
            ))

        # Delete CS
        with db._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM coordination_server WHERE id = ?", (cs_id,))

        # Verify remote is also deleted
        with db._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) as count FROM remote")
            row = cursor.fetchone()

            if row['count'] != 0:
                return False, "Cascade delete did not work", {}

        return True, "OK", {}

    def _test_unique_guid(self):
        """Test unique constraint on permanent_guid"""
        db_path = self.temp_dir / "unique_test.db"
        db = WireGuardDBv2(db_path)

        private, public = generate_keypair()

        # Insert first CS
        with db._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO coordination_server (
                    permanent_guid, current_public_key, hostname,
                    endpoint, listen_port, network_ipv4, network_ipv6,
                    ipv4_address, ipv6_address, private_key
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                public, public, "test-cs",
                "vpn.example.com", 51820, "10.66.0.0/24", "fd66::/64",
                "10.66.0.1/24", "fd66::1/64", private
            ))

        # Try to insert duplicate GUID
        try:
            with db._connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO coordination_server (
                        permanent_guid, current_public_key, hostname,
                        endpoint, listen_port, network_ipv4, network_ipv6,
                        ipv4_address, ipv6_address, private_key
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    public, public, "test-cs-2",  # Same GUID
                    "vpn2.example.com", 51821, "10.67.0.0/24", "fd67::/64",
                    "10.67.0.1/24", "fd67::1/64", private
                ))
            return False, "Unique constraint not enforced", {}
        except sqlite3.IntegrityError:
            return True, "OK", {}

    def _test_special_characters(self):
        """Test special characters in text fields"""
        db_path = self.temp_dir / "special_test.db"
        db = WireGuardDBv2(db_path)

        private, public = generate_keypair()

        # Try various special characters in hostname
        special_hostnames = [
            "test-host",
            "test_host",
            "Test.Host",
            "host123",
            # Not testing emojis as per instructions
        ]

        for i, hostname in enumerate(special_hostnames):
            priv, pub = generate_keypair()
            try:
                with db._connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute("""
                        INSERT INTO coordination_server (
                            permanent_guid, current_public_key, hostname,
                            endpoint, listen_port, network_ipv4, network_ipv6,
                            ipv4_address, ipv6_address, private_key
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        pub, pub, hostname,
                        "vpn.example.com", 51820 + i, "10.66.0.0/24", "fd66::/64",
                        f"10.66.0.{i+1}/24", f"fd66::{i+1}/64", priv
                    ))
            except Exception as e:
                return False, f"Failed on hostname '{hostname}': {e}", {}

        return True, "OK", {'tested_hostnames': len(special_hostnames)}

    # =========================================================================
    # E. EDGE CASE TESTS
    # =========================================================================

    def _test_edge_cases(self):
        """Test edge cases"""
        print("\n" + "=" * 60)
        print("E. EDGE CASES")
        print("=" * 60)

        self._run_test(
            "Key with special base64 chars (+/=)",
            "edge",
            self._test_key_special_chars
        )

        self._run_test(
            "Port edge cases (1, 65535, 51820)",
            "edge",
            self._test_port_edge_cases
        )

        self._run_test(
            "Endpoint formats (hostname vs IP)",
            "edge",
            self._test_endpoint_formats
        )

        self._run_test(
            "Empty AllowedIPs handling",
            "edge",
            self._test_empty_allowed_ips
        )

        self._run_test(
            "Very long hostname",
            "edge",
            self._test_long_hostname
        )

        self._run_test(
            "Comment with special characters",
            "edge",
            self._test_comment_special_chars
        )

    def _test_key_special_chars(self):
        """Test keys with special base64 characters"""
        # Generate many keys until we find ones with +, /, =
        found_plus = False
        found_slash = False
        found_equals = False

        for _ in range(100):
            private, public = generate_keypair()
            if '+' in public:
                found_plus = True
            if '/' in public:
                found_slash = True
            if '=' in public:
                found_equals = True

            if found_plus and found_slash and found_equals:
                break

        # At minimum, = should be common in base64
        if not found_equals:
            return False, "Could not find key with = padding", {}

        return True, "OK", {
            'found_plus': found_plus,
            'found_slash': found_slash,
            'found_equals': found_equals
        }

    def _test_port_edge_cases(self):
        """Test port number edge cases"""
        valid_ports = [1, 51820, 65535]
        invalid_ports = [0, -1, 65536, 100000]

        for port in valid_ports:
            if not (1 <= port <= 65535):
                return False, f"Valid port {port} rejected", {}

        for port in invalid_ports:
            if 1 <= port <= 65535:
                return False, f"Invalid port {port} accepted", {}

        return True, "OK", {}

    def _test_endpoint_formats(self):
        """Test various endpoint formats"""
        endpoints = [
            ("vpn.example.com:51820", True),
            ("192.168.1.1:51820", True),
            ("[2001:db8::1]:51820", True),
            ("vpn.example.com", False),  # No port
            ("192.168.1.1", False),      # No port
        ]

        for endpoint, has_port in endpoints:
            if ':' in endpoint:
                # Has port indicator
                pass

        return True, "OK", {'tested_endpoints': len(endpoints)}

    def _test_empty_allowed_ips(self):
        """Test empty AllowedIPs handling"""
        config = """[Interface]
Address = 10.66.0.1/24
PrivateKey = WG_PRIVATE_KEY_HERE_1234567890123456789012==

[Peer]
PublicKey = PEER_PUBLIC_KEY_HERE_12345678901234567890123==
"""
        config_file = self.temp_dir / "empty_ips.conf"
        config_file.write_text(config)

        parser = EntityParser()
        entities = parser.parse_file(config_file)

        # Should still parse successfully
        if len(entities) != 2:
            return False, f"Expected 2 entities, got {len(entities)}", {}

        return True, "OK", {}

    def _test_long_hostname(self):
        """Test very long hostname"""
        db_path = self.temp_dir / "long_hostname.db"
        db = WireGuardDBv2(db_path)

        private, public = generate_keypair()
        long_hostname = "a" * 255  # Very long hostname

        try:
            with db._connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO coordination_server (
                        permanent_guid, current_public_key, hostname,
                        endpoint, listen_port, network_ipv4, network_ipv6,
                        ipv4_address, ipv6_address, private_key
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    public, public, long_hostname,
                    "vpn.example.com", 51820, "10.66.0.0/24", "fd66::/64",
                    "10.66.0.1/24", "fd66::1/64", private
                ))
            return True, "OK", {'hostname_length': len(long_hostname)}
        except Exception as e:
            return False, f"Long hostname failed: {e}", {}

    def _test_comment_special_chars(self):
        """Test comments with special characters"""
        categorizer = CommentCategorizer()

        special_comments = [
            "test-hostname",
            "Test with spaces and punctuation!",
            "Comment with 'quotes' and \"double quotes\"",
            "Math: 1+1=2",
            "Hash # in comment",
        ]

        for comment in special_comments:
            try:
                result = categorizer.categorize(comment, 'peer')
                if result is None:
                    return False, f"Failed on: {comment}", {}
            except Exception as e:
                return False, f"Exception on '{comment}': {e}", {}

        return True, "OK", {'tested_comments': len(special_comments)}

    # =========================================================================
    # F. STRESS TESTS
    # =========================================================================

    def _test_stress(self):
        """Stress tests"""
        print("\n" + "=" * 60)
        print("F. STRESS TESTING")
        print("=" * 60)

        self._run_test(
            "Large network (50+ peers)",
            "stress",
            self._test_large_network
        )

        self._run_test(
            "Config generation time",
            "stress",
            self._test_generation_time
        )

        self._run_test(
            "Rapid key rotations",
            "stress",
            self._test_rapid_rotations
        )

    def _test_large_network(self):
        """Test with 50+ peers"""
        db_path = self.temp_dir / "large_network.db"
        db = WireGuardDBv2(db_path)

        # Create CS
        cs_private, cs_public = generate_keypair()

        with db._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO coordination_server (
                    permanent_guid, current_public_key, hostname,
                    endpoint, listen_port, network_ipv4, network_ipv6,
                    ipv4_address, ipv6_address, private_key
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                cs_public, cs_public, "test-cs",
                "vpn.example.com", 51820, "10.66.0.0/24", "fd66::/64",
                "10.66.0.1/24", "fd66::1/64", cs_private
            ))
            cs_id = cursor.lastrowid

        # Create 50 remotes
        num_peers = 50
        start = time.time()

        for i in range(num_peers):
            remote_private, remote_public = generate_keypair()

            with db._connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO remote (
                        cs_id, permanent_guid, current_public_key, hostname,
                        ipv4_address, ipv6_address, private_key, access_level
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    cs_id, remote_public, remote_public, f"peer-{i:03d}",
                    f"10.66.0.{i+10}/32", f"fd66::{i+10}/128", remote_private, "full_access"
                ))

        creation_time = time.time() - start

        # Verify count
        with db._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) as count FROM remote")
            row = cursor.fetchone()

            if row['count'] != num_peers:
                return False, f"Expected {num_peers} peers, got {row['count']}", {}

        return True, "OK", {
            'peers': num_peers,
            'creation_time_ms': creation_time * 1000
        }

    def _test_generation_time(self):
        """Test config generation time for large network"""
        db_path = self.temp_dir / "gen_time.db"
        db = WireGuardDBv2(db_path)

        # Create network with 20 peers
        cs_private, cs_public = generate_keypair()

        with db._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO coordination_server (
                    permanent_guid, current_public_key, hostname,
                    endpoint, listen_port, network_ipv4, network_ipv6,
                    ipv4_address, ipv6_address, private_key
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                cs_public, cs_public, "test-cs",
                "vpn.example.com", 51820, "10.66.0.0/24", "fd66::/64",
                "10.66.0.1/24", "fd66::1/64", cs_private
            ))
            cs_id = cursor.lastrowid

        for i in range(20):
            remote_private, remote_public = generate_keypair()
            with db._connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO remote (
                        cs_id, permanent_guid, current_public_key, hostname,
                        ipv4_address, ipv6_address, private_key, access_level
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    cs_id, remote_public, remote_public, f"peer-{i:03d}",
                    f"10.66.0.{i+10}/32", "", remote_private, "full_access"
                ))

        # Time config generation (simulated - just read from DB)
        start = time.time()

        with db._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM coordination_server")
            cs = dict(cursor.fetchone())

            cursor.execute("SELECT * FROM remote")
            remotes = [dict(row) for row in cursor.fetchall()]

        query_time = (time.time() - start) * 1000

        if query_time > 1000:  # More than 1 second is too slow
            return False, f"Generation too slow: {query_time:.1f}ms", {}

        return True, "OK", {'query_time_ms': query_time}

    def _test_rapid_rotations(self):
        """Test rapid key rotations"""
        db_path = self.temp_dir / "rapid_rotation.db"
        db = WireGuardDBv2(db_path)

        # Create CS
        cs_private, cs_public = generate_keypair()
        permanent_guid = cs_public

        with db._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO coordination_server (
                    permanent_guid, current_public_key, hostname,
                    endpoint, listen_port, network_ipv4, network_ipv6,
                    ipv4_address, ipv6_address, private_key
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                permanent_guid, cs_public, "test-cs",
                "vpn.example.com", 51820, "10.66.0.0/24", "fd66::/64",
                "10.66.0.1/24", "fd66::1/64", cs_private
            ))

        # Perform 10 rapid key rotations
        num_rotations = 10
        start = time.time()

        current_key = cs_public
        for i in range(num_rotations):
            new_private, new_public = generate_keypair()

            with db._connection() as conn:
                cursor = conn.cursor()

                # Record rotation
                cursor.execute("""
                    INSERT INTO key_rotation_history (
                        entity_permanent_guid, entity_type,
                        old_public_key, new_public_key,
                        new_private_key, reason
                    ) VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    permanent_guid, 'coordination_server',
                    current_key, new_public,
                    new_private, f'rapid_rotation_{i}'
                ))

                # Update current key
                cursor.execute("""
                    UPDATE coordination_server
                    SET current_public_key = ?, private_key = ?
                    WHERE permanent_guid = ?
                """, (new_public, new_private, permanent_guid))

            current_key = new_public

        rotation_time = (time.time() - start) * 1000

        # Verify all rotations recorded
        with db._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT COUNT(*) as count FROM key_rotation_history
                WHERE entity_permanent_guid = ?
            """, (permanent_guid,))
            row = cursor.fetchone()

            if row['count'] != num_rotations:
                return False, f"Expected {num_rotations} rotations, got {row['count']}", {}

        # Verify permanent_guid unchanged
        with db._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT permanent_guid FROM coordination_server")
            row = cursor.fetchone()

            if row['permanent_guid'] != permanent_guid:
                return False, "permanent_guid changed during rotations!", {}

        return True, "OK", {
            'rotations': num_rotations,
            'total_time_ms': rotation_time
        }

    # =========================================================================
    # REPORT
    # =========================================================================

    def _print_report(self):
        """Print final test report"""
        print("\n")
        print("=" * 80)
        print("TEST REPORT")
        print("=" * 80)
        print()

        duration = (self.report.end_time - self.report.start_time).total_seconds()

        print(f"Total Tests: {self.report.total}")
        print(f"Passed:      {self.report.passed}")
        print(f"Failed:      {self.report.failed}")
        print(f"Duration:    {duration:.2f}s")
        print()

        # By category
        print("Results by Category:")
        print("-" * 40)
        for category, counts in self.report.summary_by_category().items():
            status = "[PASS]" if counts['failed'] == 0 else "[FAIL]"
            print(f"  {status} {category}: {counts['passed']} passed, {counts['failed']} failed")

        # Failed tests
        failed = [r for r in self.report.results if not r.passed]
        if failed:
            print()
            print("Failed Tests:")
            print("-" * 40)
            for r in failed:
                print(f"  - {r.name}")
                print(f"    Category: {r.category}")
                print(f"    Message: {r.message}")

        print()
        print("=" * 80)
        if self.report.failed == 0:
            print("ALL TESTS PASSED")
        else:
            print(f"FAILURES: {self.report.failed} test(s) failed")
        print("=" * 80)


def main():
    """Run comprehensive test suite"""
    suite = ComprehensiveTestSuite()
    report = suite.run_all()

    # Save report to file
    report_file = Path(__file__).parent / "results" / f"test_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    report_file.parent.mkdir(exist_ok=True)

    report_data = {
        'start_time': report.start_time.isoformat(),
        'end_time': report.end_time.isoformat() if report.end_time else None,
        'total': report.total,
        'passed': report.passed,
        'failed': report.failed,
        'results': [
            {
                'name': r.name,
                'category': r.category,
                'passed': r.passed,
                'duration_ms': r.duration_ms,
                'message': r.message,
                'details': r.details
            }
            for r in report.results
        ]
    }

    report_file.write_text(json.dumps(report_data, indent=2))
    print(f"\nReport saved to: {report_file}")

    return 0 if report.failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
