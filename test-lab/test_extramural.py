#!/usr/bin/env python3
"""
Extramural Workflow Tests

Tests for extramural config isolation from mesh configs.
Verifies that external VPN configs (Mullvad, NordVPN, etc.) never mix with mesh.
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

from v1.schema_semantic import WireGuardDBv2
from v1.extramural_ops import ExtramuralOps
from v1.extramural_import import ExtramuralConfigParser
from v1.extramural_generator import ExtramuralConfigGenerator
from v1.keygen import generate_keypair


@dataclass
class TestResult:
    name: str
    passed: bool
    duration_ms: float
    message: str = ""
    details: Dict = None


class ExtramuralTests:
    """Extramural isolation test suite"""

    def __init__(self):
        self.results: List[TestResult] = []
        self.temp_dir = Path(tempfile.mkdtemp(prefix="wgf_extramural_test_"))
        self.configs_dir = Path(__file__).parent / "configs"

    def run_all(self) -> Tuple[int, int]:
        """Run all extramural tests"""
        print("=" * 80)
        print("EXTRAMURAL WORKFLOW TESTS")
        print("=" * 80)
        print()

        # A. Extramural Isolation
        self._test_isolation()

        # B. Extramural Operations
        self._test_operations()

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

    # =========================================================================
    # A. EXTRAMURAL ISOLATION TESTS
    # =========================================================================

    def _test_isolation(self):
        """Extramural isolation tests"""
        print("\n" + "-" * 60)
        print("A. EXTRAMURAL ISOLATION")
        print("-" * 60)

        self._run_test(
            "Separate database tables for mesh vs extramural",
            self._test_separate_tables
        )

        self._run_test(
            "Mesh peers not visible in extramural queries",
            self._test_mesh_not_in_extramural
        )

        self._run_test(
            "Extramural peers not visible in mesh queries",
            self._test_extramural_not_in_mesh
        )

        self._run_test(
            "Same public key allowed in mesh and extramural",
            self._test_same_key_both_contexts
        )

        self._run_test(
            "Extramural config cannot reference mesh CS",
            self._test_no_cross_reference
        )

        self._run_test(
            "Extramural schema integrated in same DB file",
            self._test_schema_integration
        )

    def _test_separate_tables(self):
        """Test that mesh and extramural use separate tables"""
        db_path = self.temp_dir / "separate_tables.db"
        db = WireGuardDBv2(db_path)

        # Check mesh tables exist
        mesh_tables = [
            'coordination_server',
            'subnet_router',
            'remote',
            'advertised_network',
        ]

        # Check extramural tables exist
        extramural_tables = [
            'sponsor',
            'local_peer',
            'extramural_config',
            'extramural_peer',
        ]

        with db._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]

        missing_mesh = [t for t in mesh_tables if t not in tables]
        missing_extramural = [t for t in extramural_tables if t not in tables]

        if missing_mesh:
            return False, f"Missing mesh tables: {missing_mesh}", {}

        if missing_extramural:
            return False, f"Missing extramural tables: {missing_extramural}", {}

        return True, "OK", {
            'mesh_tables': len(mesh_tables),
            'extramural_tables': len(extramural_tables)
        }

    def _test_mesh_not_in_extramural(self):
        """Test that mesh peers don't appear in extramural queries"""
        db_path = self.temp_dir / "isolation_test_1.db"
        db = WireGuardDBv2(db_path)
        ops = ExtramuralOps(db_path)

        # Create mesh CS and remote
        cs_private, cs_public = generate_keypair()
        remote_private, remote_public = generate_keypair()

        with db._connection() as conn:
            cursor = conn.cursor()

            # Insert mesh CS
            cursor.execute("""
                INSERT INTO coordination_server (
                    permanent_guid, current_public_key, hostname,
                    endpoint, listen_port, network_ipv4, network_ipv6,
                    ipv4_address, ipv6_address, private_key
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                cs_public, cs_public, 'mesh-cs',
                'vpn.example.com', 51820, '10.66.0.0/24', 'fd66::/64',
                '10.66.0.1/24', 'fd66::1/64', cs_private
            ))
            cs_id = cursor.lastrowid

            # Insert mesh remote
            cursor.execute("""
                INSERT INTO remote (
                    cs_id, permanent_guid, current_public_key, hostname,
                    ipv4_address, ipv6_address, private_key, access_level
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                cs_id, remote_public, remote_public, 'mesh-remote',
                '10.66.0.20/32', '', remote_private, 'full_access'
            ))

        # Now query extramural - should NOT see mesh peers
        extramural_configs = ops.list_extramural_configs()
        extramural_sponsors = ops.list_sponsors()
        extramural_local_peers = ops.list_local_peers()

        if len(extramural_configs) != 0:
            return False, f"Extramural configs should be empty, got {len(extramural_configs)}", {}

        if len(extramural_sponsors) != 0:
            return False, f"Extramural sponsors should be empty, got {len(extramural_sponsors)}", {}

        if len(extramural_local_peers) != 0:
            return False, f"Extramural local peers should be empty, got {len(extramural_local_peers)}", {}

        return True, "OK - mesh data not visible in extramural", {}

    def _test_extramural_not_in_mesh(self):
        """Test that extramural peers don't appear in mesh queries"""
        db_path = self.temp_dir / "isolation_test_2.db"
        db = WireGuardDBv2(db_path)
        ops = ExtramuralOps(db_path)

        # Create extramural sponsor and config
        sponsor_id = ops.add_sponsor(
            name="Mullvad VPN",
            website="https://mullvad.net"
        )

        local_peer_id = ops.add_local_peer(
            name="my-laptop",
            notes="Test device"
        )

        ext_private, ext_public = generate_keypair()
        config_id = ops.add_extramural_config(
            local_peer_id=local_peer_id,
            sponsor_id=sponsor_id,
            local_private_key=ext_private,
            local_public_key=ext_public,
            interface_name="wg-mullvad",
            assigned_ipv4="10.64.1.1/32"
        )

        # Query mesh tables - should be empty
        with db._connection() as conn:
            cursor = conn.cursor()

            cursor.execute("SELECT COUNT(*) as count FROM coordination_server")
            cs_count = cursor.fetchone()['count']

            cursor.execute("SELECT COUNT(*) as count FROM subnet_router")
            snr_count = cursor.fetchone()['count']

            cursor.execute("SELECT COUNT(*) as count FROM remote")
            remote_count = cursor.fetchone()['count']

        if cs_count != 0:
            return False, f"Mesh CS should be empty, got {cs_count}", {}

        if snr_count != 0:
            return False, f"Mesh SNR should be empty, got {snr_count}", {}

        if remote_count != 0:
            return False, f"Mesh remote should be empty, got {remote_count}", {}

        return True, "OK - extramural data not visible in mesh", {}

    def _test_same_key_both_contexts(self):
        """Test that same public key can exist in mesh and extramural"""
        db_path = self.temp_dir / "same_key_test.db"
        db = WireGuardDBv2(db_path)
        ops = ExtramuralOps(db_path)

        # Generate one key to use in both contexts
        shared_private, shared_public = generate_keypair()

        # Insert into mesh as CS
        with db._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO coordination_server (
                    permanent_guid, current_public_key, hostname,
                    endpoint, listen_port, network_ipv4, network_ipv6,
                    ipv4_address, ipv6_address, private_key
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                shared_public, shared_public, 'mesh-cs',
                'vpn.example.com', 51820, '10.66.0.0/24', 'fd66::/64',
                '10.66.0.1/24', 'fd66::1/64', shared_private
            ))

        # Insert into extramural with same key
        sponsor_id = ops.add_sponsor(name="TestVPN")
        local_peer_id = ops.add_local_peer(name="test-device")

        try:
            config_id = ops.add_extramural_config(
                local_peer_id=local_peer_id,
                sponsor_id=sponsor_id,
                local_private_key=shared_private,
                local_public_key=shared_public,
                interface_name="wg-test"
            )

            # Both should exist independently
            with db._connection() as conn:
                cursor = conn.cursor()

                cursor.execute("SELECT COUNT(*) as count FROM coordination_server")
                mesh_count = cursor.fetchone()['count']

                cursor.execute("SELECT COUNT(*) as count FROM extramural_config")
                ext_count = cursor.fetchone()['count']

            if mesh_count != 1 or ext_count != 1:
                return False, f"Expected 1 each, got mesh={mesh_count}, ext={ext_count}", {}

            return True, "OK - same key allowed in both contexts", {}

        except Exception as e:
            return False, f"Failed to create with same key: {e}", {}

    def _test_no_cross_reference(self):
        """Test that extramural cannot reference mesh entities"""
        db_path = self.temp_dir / "no_cross_ref.db"
        db = WireGuardDBv2(db_path)
        ops = ExtramuralOps(db_path)

        # Create mesh CS
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
                cs_public, cs_public, 'mesh-cs',
                'vpn.example.com', 51820, '10.66.0.0/24', 'fd66::/64',
                '10.66.0.1/24', 'fd66::1/64', cs_private
            ))

        # Extramural tables have their own FKs (sponsor, local_peer)
        # They cannot reference coordination_server or remote
        # The schema enforces this through separate FK relationships

        # Verify extramural_config does NOT have cs_id FK
        with db._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("PRAGMA table_info(extramural_config)")
            columns = [row[1] for row in cursor.fetchall()]

        if 'cs_id' in columns:
            return False, "extramural_config should not have cs_id column", {}

        return True, "OK - no cross-reference columns", {'columns': columns}

    def _test_schema_integration(self):
        """Test that extramural schema is integrated in same DB"""
        db_path = self.temp_dir / "integration_test.db"

        # Create single DB with WireGuardDBv2 (includes extramural)
        db = WireGuardDBv2(db_path)

        # Both mesh and extramural should work
        with db._connection() as conn:
            cursor = conn.cursor()

            # Count all tables
            cursor.execute("SELECT COUNT(*) as count FROM sqlite_master WHERE type='table'")
            total_tables = cursor.fetchone()['count']

            # Try inserting into both
            try:
                # Mesh
                priv1, pub1 = generate_keypair()
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

                # Extramural
                cursor.execute("""
                    INSERT INTO sponsor (name, website) VALUES (?, ?)
                """, ('TestVPN', 'https://testvpn.com'))

            except Exception as e:
                return False, f"Integration failed: {e}", {}

        return True, "OK - both schemas work in same DB", {'tables': total_tables}

    # =========================================================================
    # B. EXTRAMURAL OPERATIONS TESTS
    # =========================================================================

    def _test_operations(self):
        """Extramural operations tests"""
        print("\n" + "-" * 60)
        print("B. EXTRAMURAL OPERATIONS")
        print("-" * 60)

        self._run_test(
            "Add sponsor",
            self._test_add_sponsor
        )

        self._run_test(
            "Add local peer",
            self._test_add_local_peer
        )

        self._run_test(
            "Add extramural config",
            self._test_add_extramural_config
        )

        self._run_test(
            "Add extramural peer (sponsor endpoint)",
            self._test_add_extramural_peer
        )

        self._run_test(
            "List extramural configs by sponsor",
            self._test_list_by_sponsor
        )

        self._run_test(
            "Remove extramural config (cascade)",
            self._test_remove_config
        )

        self._run_test(
            "Parse sample extramural config",
            self._test_parse_extramural_config
        )

        self._run_test(
            "Switch active peer",
            self._test_switch_active_peer
        )

        self._run_test(
            "No impact on mesh after extramural operations",
            self._test_no_mesh_impact
        )

    def _test_add_sponsor(self):
        """Test adding a sponsor"""
        db_path = self.temp_dir / "add_sponsor.db"
        db = WireGuardDBv2(db_path)
        ops = ExtramuralOps(db_path)

        sponsor_id = ops.add_sponsor(
            name="Mullvad VPN",
            website="https://mullvad.net",
            support_url="https://mullvad.net/help",
            notes="Privacy-focused VPN"
        )

        if not sponsor_id:
            return False, "Failed to get sponsor_id", {}

        sponsor = ops.get_sponsor(sponsor_id)
        if not sponsor:
            return False, "Failed to retrieve sponsor", {}

        if sponsor.name != "Mullvad VPN":
            return False, f"Wrong name: {sponsor.name}", {}

        return True, "OK", {'sponsor_id': sponsor_id}

    def _test_add_local_peer(self):
        """Test adding a local peer"""
        db_path = self.temp_dir / "add_local_peer.db"
        db = WireGuardDBv2(db_path)
        ops = ExtramuralOps(db_path)

        peer_id = ops.add_local_peer(
            name="my-laptop",
            notes="Personal laptop"
        )

        if not peer_id:
            return False, "Failed to get peer_id", {}

        peer = ops.get_local_peer(peer_id)
        if not peer:
            return False, "Failed to retrieve local peer", {}

        if peer.name != "my-laptop":
            return False, f"Wrong name: {peer.name}", {}

        # Should have auto-generated GUID
        if not peer.permanent_guid:
            return False, "Missing permanent_guid", {}

        return True, "OK", {'peer_id': peer_id}

    def _test_add_extramural_config(self):
        """Test adding an extramural config"""
        db_path = self.temp_dir / "add_config.db"
        db = WireGuardDBv2(db_path)
        ops = ExtramuralOps(db_path)

        # Setup
        sponsor_id = ops.add_sponsor(name="TestVPN")
        peer_id = ops.add_local_peer(name="test-device")
        priv, pub = generate_keypair()

        config_id = ops.add_extramural_config(
            local_peer_id=peer_id,
            sponsor_id=sponsor_id,
            local_private_key=priv,
            local_public_key=pub,
            interface_name="wg-test",
            assigned_ipv4="10.64.1.1/32",
            assigned_ipv6="fc00::1/128",
            dns_servers="10.64.0.1",
            mtu=1420
        )

        if not config_id:
            return False, "Failed to get config_id", {}

        config = ops.get_extramural_config(config_id)
        if not config:
            return False, "Failed to retrieve config", {}

        if config.interface_name != "wg-test":
            return False, f"Wrong interface: {config.interface_name}", {}

        return True, "OK", {'config_id': config_id}

    def _test_add_extramural_peer(self):
        """Test adding an extramural peer (sponsor endpoint)"""
        db_path = self.temp_dir / "add_ext_peer.db"
        db = WireGuardDBv2(db_path)
        ops = ExtramuralOps(db_path)

        # Setup
        sponsor_id = ops.add_sponsor(name="TestVPN")
        local_peer_id = ops.add_local_peer(name="test-device")
        priv, pub = generate_keypair()

        config_id = ops.add_extramural_config(
            local_peer_id=local_peer_id,
            sponsor_id=sponsor_id,
            local_private_key=priv,
            local_public_key=pub,
            interface_name="wg-test"
        )

        # Add peer
        peer_pub, _ = generate_keypair()
        peer_id = ops.add_extramural_peer(
            config_id=config_id,
            name="us-east-1",
            public_key=peer_pub,
            endpoint="us1.testvpn.com:51820",
            allowed_ips="0.0.0.0/0, ::/0",
            persistent_keepalive=25,
            is_active=True
        )

        if not peer_id:
            return False, "Failed to get peer_id", {}

        peer = ops.get_extramural_peer(peer_id)
        if not peer:
            return False, "Failed to retrieve peer", {}

        if peer.name != "us-east-1":
            return False, f"Wrong name: {peer.name}", {}

        if not peer.is_active:
            return False, "Peer should be active", {}

        return True, "OK", {'peer_id': peer_id}

    def _test_list_by_sponsor(self):
        """Test listing configs by sponsor"""
        db_path = self.temp_dir / "list_by_sponsor.db"
        db = WireGuardDBv2(db_path)
        ops = ExtramuralOps(db_path)

        # Create two sponsors
        mullvad_id = ops.add_sponsor(name="Mullvad")
        proton_id = ops.add_sponsor(name="ProtonVPN")
        local_peer_id = ops.add_local_peer(name="test-device")

        # Create configs for both
        priv1, pub1 = generate_keypair()
        priv2, pub2 = generate_keypair()

        ops.add_extramural_config(
            local_peer_id=local_peer_id,
            sponsor_id=mullvad_id,
            local_private_key=priv1,
            local_public_key=pub1,
            interface_name="wg-mullvad"
        )

        ops.add_extramural_config(
            local_peer_id=local_peer_id,
            sponsor_id=proton_id,
            local_private_key=priv2,
            local_public_key=pub2,
            interface_name="wg-proton"
        )

        # List all
        all_configs = ops.list_extramural_configs()
        if len(all_configs) != 2:
            return False, f"Expected 2 configs, got {len(all_configs)}", {}

        # List by sponsor
        mullvad_configs = ops.list_extramural_configs(sponsor_id=mullvad_id)
        if len(mullvad_configs) != 1:
            return False, f"Expected 1 Mullvad config, got {len(mullvad_configs)}", {}

        if mullvad_configs[0].interface_name != "wg-mullvad":
            return False, f"Wrong interface: {mullvad_configs[0].interface_name}", {}

        return True, "OK", {'total': len(all_configs), 'mullvad': len(mullvad_configs)}

    def _test_remove_config(self):
        """Test removing extramural config cascades to peers"""
        db_path = self.temp_dir / "remove_config.db"
        db = WireGuardDBv2(db_path)
        ops = ExtramuralOps(db_path)

        # Setup
        sponsor_id = ops.add_sponsor(name="TestVPN")
        local_peer_id = ops.add_local_peer(name="test-device")
        priv, pub = generate_keypair()

        config_id = ops.add_extramural_config(
            local_peer_id=local_peer_id,
            sponsor_id=sponsor_id,
            local_private_key=priv,
            local_public_key=pub,
            interface_name="wg-test"
        )

        # Add peer
        peer_pub, _ = generate_keypair()
        ops.add_extramural_peer(
            config_id=config_id,
            name="us-east-1",
            public_key=peer_pub,
            endpoint="us1.testvpn.com:51820",
            allowed_ips="0.0.0.0/0",
            is_active=True
        )

        # Verify peer exists
        peers_before = ops.list_extramural_peers(config_id)
        if len(peers_before) != 1:
            return False, f"Expected 1 peer before delete, got {len(peers_before)}", {}

        # Delete config
        ops.delete_extramural_config(config_id)

        # Verify cascade
        with db._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) as count FROM extramural_peer")
            peer_count = cursor.fetchone()['count']

        if peer_count != 0:
            return False, f"Peers should be deleted by cascade, got {peer_count}", {}

        return True, "OK - cascade delete worked", {}

    def _test_parse_extramural_config(self):
        """Test parsing sample extramural config"""
        config_file = self.configs_dir / "sample_extramural_mullvad.conf"
        if not config_file.exists():
            return False, f"Sample config not found", {}

        parser = ExtramuralConfigParser()
        parsed = parser.parse_file(config_file)

        # Verify parsed fields
        if not parsed.private_key:
            return False, "Missing private_key", {}

        if not parsed.addresses:
            return False, "Missing addresses", {}

        if not parsed.peer_public_key:
            return False, "Missing peer public key", {}

        if not parsed.peer_allowed_ips:
            return False, "Missing peer allowed IPs", {}

        if parsed.peer_persistent_keepalive != 25:
            return False, f"Wrong keepalive: {parsed.peer_persistent_keepalive}", {}

        return True, "OK", {
            'addresses': parsed.addresses,
            'endpoint': parsed.peer_endpoint
        }

    def _test_switch_active_peer(self):
        """Test switching active peer triggers deactivation of others"""
        db_path = self.temp_dir / "switch_peer.db"
        db = WireGuardDBv2(db_path)
        ops = ExtramuralOps(db_path)

        # Setup
        sponsor_id = ops.add_sponsor(name="TestVPN")
        local_peer_id = ops.add_local_peer(name="test-device")
        priv, pub = generate_keypair()

        config_id = ops.add_extramural_config(
            local_peer_id=local_peer_id,
            sponsor_id=sponsor_id,
            local_private_key=priv,
            local_public_key=pub,
            interface_name="wg-test"
        )

        # Add two peers
        peer1_pub, _ = generate_keypair()
        peer1_id = ops.add_extramural_peer(
            config_id=config_id,
            name="us-east-1",
            public_key=peer1_pub,
            endpoint="us1.testvpn.com:51820",
            allowed_ips="0.0.0.0/0",
            is_active=True
        )

        peer2_pub, _ = generate_keypair()
        peer2_id = ops.add_extramural_peer(
            config_id=config_id,
            name="eu-west-1",
            public_key=peer2_pub,
            endpoint="eu1.testvpn.com:51820",
            allowed_ips="0.0.0.0/0",
            is_active=False
        )

        # Verify initial state
        active = ops.get_active_peer(config_id)
        if active.name != "us-east-1":
            return False, f"Initial active should be us-east-1, got {active.name}", {}

        # Switch to peer2
        ops.set_active_peer(peer2_id)

        # Verify peer1 deactivated, peer2 active
        peer1 = ops.get_extramural_peer(peer1_id)
        peer2 = ops.get_extramural_peer(peer2_id)

        if peer1.is_active:
            return False, "Peer1 should be deactivated", {}

        if not peer2.is_active:
            return False, "Peer2 should be active", {}

        active = ops.get_active_peer(config_id)
        if active.name != "eu-west-1":
            return False, f"New active should be eu-west-1, got {active.name}", {}

        return True, "OK - single active peer enforced", {}

    def _test_no_mesh_impact(self):
        """Test that extramural operations don't affect mesh"""
        db_path = self.temp_dir / "no_impact.db"
        db = WireGuardDBv2(db_path)
        ops = ExtramuralOps(db_path)

        # Create mesh data first
        cs_priv, cs_pub = generate_keypair()
        remote_priv, remote_pub = generate_keypair()

        with db._connection() as conn:
            cursor = conn.cursor()

            cursor.execute("""
                INSERT INTO coordination_server (
                    permanent_guid, current_public_key, hostname,
                    endpoint, listen_port, network_ipv4, network_ipv6,
                    ipv4_address, ipv6_address, private_key
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                cs_pub, cs_pub, 'mesh-cs',
                'vpn.example.com', 51820, '10.66.0.0/24', 'fd66::/64',
                '10.66.0.1/24', 'fd66::1/64', cs_priv
            ))
            cs_id = cursor.lastrowid

            cursor.execute("""
                INSERT INTO remote (
                    cs_id, permanent_guid, current_public_key, hostname,
                    ipv4_address, ipv6_address, private_key, access_level
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                cs_id, remote_pub, remote_pub, 'mesh-remote',
                '10.66.0.20/32', '', remote_priv, 'full_access'
            ))

        # Count mesh before
        with db._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) as count FROM coordination_server")
            cs_before = cursor.fetchone()['count']
            cursor.execute("SELECT COUNT(*) as count FROM remote")
            remote_before = cursor.fetchone()['count']

        # Do extramural operations
        sponsor_id = ops.add_sponsor(name="TestVPN")
        local_peer_id = ops.add_local_peer(name="test-device")
        priv, pub = generate_keypair()

        config_id = ops.add_extramural_config(
            local_peer_id=local_peer_id,
            sponsor_id=sponsor_id,
            local_private_key=priv,
            local_public_key=pub,
            interface_name="wg-test"
        )

        ops.delete_extramural_config(config_id)
        ops.delete_sponsor(sponsor_id)

        # Count mesh after - should be unchanged
        with db._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) as count FROM coordination_server")
            cs_after = cursor.fetchone()['count']
            cursor.execute("SELECT COUNT(*) as count FROM remote")
            remote_after = cursor.fetchone()['count']

        if cs_before != cs_after:
            return False, f"CS count changed: {cs_before} -> {cs_after}", {}

        if remote_before != remote_after:
            return False, f"Remote count changed: {remote_before} -> {remote_after}", {}

        return True, "OK - mesh unchanged after extramural ops", {
            'cs_count': cs_after,
            'remote_count': remote_after
        }


def main():
    """Run extramural tests"""
    tests = ExtramuralTests()
    passed, failed = tests.run_all()

    print()
    print("=" * 80)
    print(f"EXTRAMURAL RESULTS: {passed} passed, {failed} failed")
    print("=" * 80)

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
