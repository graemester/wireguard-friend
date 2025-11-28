#!/usr/bin/env python3
"""
WireGuard Friend - Comprehensive Test Suite

Tests all critical functionality with minimal verbosity.
Run with: python3 tests/test-suite.py
"""

import sys
import tempfile
from pathlib import Path
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.database import WireGuardDB
from src.keygen import generate_keypair

# Test counters
tests_run = 0
tests_passed = 0
tests_failed = 0

def test(name):
    """Decorator to track test execution"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            global tests_run, tests_passed, tests_failed
            tests_run += 1
            try:
                func(*args, **kwargs)
                print(f"✓ {name}")
                tests_passed += 1
            except AssertionError as e:
                print(f"✗ {name}: {e}")
                tests_failed += 1
            except Exception as e:
                print(f"✗ {name}: EXCEPTION: {e}")
                tests_failed += 1
        return wrapper
    return decorator


class TestSuite:
    """Comprehensive test suite for WireGuard Friend"""

    def __init__(self):
        # Create temporary database
        self.temp_db = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
        self.db_path = Path(self.temp_db.name)
        self.db = WireGuardDB(self.db_path)

        # Test data
        self.cs_id = None
        self.sn_id = None
        self.peer_ids = []

    def cleanup(self):
        """Clean up test database"""
        try:
            self.db_path.unlink()
        except:
            pass

    # ============================================================================
    # Database Schema Tests
    # ============================================================================

    @test("Database initialization")
    def test_db_init(self):
        """Verify database tables exist"""
        with self.db._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = {row['name'] for row in cursor.fetchall()}

            required_tables = {
                'coordination_server', 'subnet_router', 'peer',
                'cs_peer_order', 'peer_ip_restrictions', 'sn_peer_firewall_rules',
                'sn_postup_rules', 'sn_postdown_rules', 'sn_lan_networks'
            }

            missing = required_tables - tables
            assert not missing, f"Missing tables: {missing}"

    @test("Foreign keys enabled")
    def test_foreign_keys(self):
        """Verify foreign key constraints are enabled"""
        with self.db._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("PRAGMA foreign_keys")
            result = cursor.fetchone()
            assert result[0] == 1, "Foreign keys not enabled"

    # ============================================================================
    # Coordination Server Tests
    # ============================================================================

    @test("CS: Save and retrieve")
    def test_cs_save_retrieve(self):
        """Test coordination server creation"""
        private_key, public_key = generate_keypair()

        interface_block = f"""[Interface]
Address = 10.66.0.1/24, fd66:6666::1/64
PrivateKey = {private_key}
ListenPort = 51820
MTU = 1280"""

        self.cs_id = self.db.save_coordination_server(
            endpoint="test.example.com:51820",
            public_key=public_key,
            private_key=private_key,
            network_ipv4="10.66.0.0/24",
            network_ipv6="fd66:6666::/64",
            ipv4_address="10.66.0.1",
            ipv6_address="fd66:6666::1",
            raw_interface_block=interface_block,
            listen_port=51820,
            mtu=1280
        )

        assert self.cs_id is not None, "Failed to save CS"

        cs = self.db.get_coordination_server()
        assert cs is not None, "Failed to retrieve CS"
        assert cs['endpoint'] == "test.example.com:51820"
        assert cs['public_key'] == public_key

    @test("CS: PostUp/PostDown rules")
    def test_cs_postup_postdown(self):
        """Test CS firewall rules storage"""
        postup_rules = [
            "iptables -A FORWARD -i wg0 -j ACCEPT",
            "iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE"
        ]
        postdown_rules = [
            "iptables -D FORWARD -i wg0 -j ACCEPT",
            "iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE"
        ]

        self.db.save_cs_postup_rules(self.cs_id, postup_rules)
        self.db.save_cs_postdown_rules(self.cs_id, postdown_rules)

        retrieved_up = self.db.get_cs_postup_rules(self.cs_id)
        retrieved_down = self.db.get_cs_postdown_rules(self.cs_id)

        assert retrieved_up == postup_rules
        assert retrieved_down == postdown_rules

    # ============================================================================
    # Subnet Router Tests
    # ============================================================================

    @test("SN: Save and retrieve")
    def test_sn_save_retrieve(self):
        """Test subnet router creation"""
        private_key, public_key = generate_keypair()

        interface_block = f"""[Interface]
Address = 10.66.0.20/24
PrivateKey = {private_key}
ListenPort = 51820"""

        peer_block = """[Peer]
PublicKey = TestCSPublicKey
Endpoint = test.example.com:51820
AllowedIPs = 10.66.0.0/24"""

        self.sn_id = self.db.save_subnet_router(
            name="test-router",
            cs_id=self.cs_id,
            public_key=public_key,
            private_key=private_key,
            ipv4_address="10.66.0.20",
            ipv6_address="fd66:6666::20",
            allowed_ips="10.66.0.0/24, fd66:6666::/64",
            raw_interface_block=interface_block,
            raw_peer_block=peer_block,
            mtu=1280
        )

        assert self.sn_id is not None

        routers = self.db.get_subnet_routers(self.cs_id)
        assert len(routers) == 1
        assert routers[0]['name'] == "test-router"

    @test("SN: LAN networks")
    def test_sn_lan_networks(self):
        """Test subnet router LAN network storage"""
        networks = ["192.168.10.0/24", "192.168.20.0/24"]
        self.db.save_sn_lan_networks(self.sn_id, networks)

        retrieved = self.db.get_sn_lan_networks(self.sn_id)
        assert retrieved == networks

    @test("SN: PostUp/PostDown rules")
    def test_sn_postup_postdown(self):
        """Test SN firewall rules storage"""
        postup_rules = ["iptables -A FORWARD -i wg0 -j ACCEPT"]
        postdown_rules = ["iptables -D FORWARD -i wg0 -j ACCEPT"]

        self.db.save_sn_postup_rules(self.sn_id, postup_rules)
        self.db.save_sn_postdown_rules(self.sn_id, postdown_rules)

        retrieved_up = self.db.get_sn_postup_rules(self.sn_id)
        retrieved_down = self.db.get_sn_postdown_rules(self.sn_id)

        assert retrieved_up == postup_rules
        assert retrieved_down == postdown_rules

    @test("SN: Config reconstruction")
    def test_sn_config_reconstruction(self):
        """Test subnet router config rebuilding"""
        config = self.db.reconstruct_sn_config(self.sn_id)

        assert "[Interface]" in config
        assert "Address = 10.66.0.20/24" in config
        assert "[Peer]" in config
        assert "PostUp" in config
        assert "PostDown" in config

    # ============================================================================
    # Peer Tests (All Access Levels)
    # ============================================================================

    @test("Peer: full_access")
    def test_peer_full_access(self):
        """Test peer with full_access level"""
        private_key, public_key = generate_keypair()

        peer_block = f"[Peer]\nPublicKey = {public_key}\nAllowedIPs = 10.66.0.10/32"
        interface_block = f"[Interface]\nPrivateKey = {private_key}\nAddress = 10.66.0.10/24"

        peer_id = self.db.save_peer(
            name="test-full",
            cs_id=self.cs_id,
            public_key=public_key,
            private_key=private_key,
            ipv4_address="10.66.0.10",
            ipv6_address="fd66:6666::10",
            access_level="full_access",
            raw_peer_block=peer_block,
            raw_interface_block=interface_block,
            persistent_keepalive=25
        )

        self.peer_ids.append(peer_id)
        assert peer_id is not None

        peers = self.db.get_peers(self.cs_id)
        assert len(peers) >= 1

    @test("Peer: vpn_only")
    def test_peer_vpn_only(self):
        """Test peer with vpn_only level"""
        private_key, public_key = generate_keypair()

        peer_id = self.db.save_peer(
            name="test-vpn",
            cs_id=self.cs_id,
            public_key=public_key,
            private_key=private_key,
            ipv4_address="10.66.0.11",
            ipv6_address="fd66:6666::11",
            access_level="vpn_only",
            raw_peer_block=f"[Peer]\nPublicKey = {public_key}",
            raw_interface_block=f"[Interface]\nPrivateKey = {private_key}",
            persistent_keepalive=25
        )

        self.peer_ids.append(peer_id)
        assert peer_id is not None

    @test("Peer: restricted_ip (no ports)")
    def test_peer_restricted_ip_all_ports(self):
        """Test peer with restricted_ip (all ports)"""
        private_key, public_key = generate_keypair()

        peer_id = self.db.save_peer(
            name="test-restricted-all",
            cs_id=self.cs_id,
            public_key=public_key,
            private_key=private_key,
            ipv4_address="10.66.0.12",
            ipv6_address="fd66:6666::12",
            access_level="restricted_ip",
            raw_peer_block=f"[Peer]\nPublicKey = {public_key}",
            raw_interface_block=f"[Interface]\nPrivateKey = {private_key}",
            persistent_keepalive=25
        )

        self.peer_ids.append(peer_id)

        # Save restriction (all ports)
        self.db.save_peer_ip_restriction(
            peer_id=peer_id,
            sn_id=self.sn_id,
            target_ip="192.168.10.50",
            allowed_ports=None,
            description="Test restriction - all ports"
        )

        # Save firewall rules
        postup = [
            "iptables -I FORWARD -s 10.66.0.12/32 -d 192.168.10.50/32 -j ACCEPT",
            "iptables -I FORWARD -s 10.66.0.12/32 -j DROP"
        ]
        postdown = [
            "iptables -D FORWARD -s 10.66.0.12/32 -d 192.168.10.50/32 -j ACCEPT",
            "iptables -D FORWARD -s 10.66.0.12/32 -j DROP"
        ]

        self.db.save_sn_peer_firewall_rules(self.sn_id, peer_id, postup, postdown)

        # Verify
        restriction = self.db.get_peer_ip_restriction(peer_id)
        assert restriction is not None
        assert restriction['target_ip'] == "192.168.10.50"
        assert restriction['allowed_ports'] is None

    @test("Peer: restricted_ip (specific ports)")
    def test_peer_restricted_ip_ports(self):
        """Test peer with restricted_ip (specific ports)"""
        private_key, public_key = generate_keypair()

        peer_id = self.db.save_peer(
            name="test-restricted-ports",
            cs_id=self.cs_id,
            public_key=public_key,
            private_key=private_key,
            ipv4_address="10.66.0.13",
            ipv6_address="fd66:6666::13",
            access_level="restricted_ip",
            raw_peer_block=f"[Peer]\nPublicKey = {public_key}",
            raw_interface_block=f"[Interface]\nPrivateKey = {private_key}",
            persistent_keepalive=25
        )

        self.peer_ids.append(peer_id)

        # Save restriction (specific ports)
        self.db.save_peer_ip_restriction(
            peer_id=peer_id,
            sn_id=self.sn_id,
            target_ip="192.168.10.100",
            allowed_ports="22,443,8096",
            description="Test restriction - SSH, HTTPS, Jellyfin"
        )

        # Save firewall rules
        postup = [
            "iptables -I FORWARD -s 10.66.0.13/32 -d 192.168.10.100/32 -p tcp --dport 22 -j ACCEPT",
            "iptables -I FORWARD -s 10.66.0.13/32 -d 192.168.10.100/32 -p tcp --dport 443 -j ACCEPT",
            "iptables -I FORWARD -s 10.66.0.13/32 -d 192.168.10.100/32 -p tcp --dport 8096 -j ACCEPT",
            "iptables -I FORWARD -s 10.66.0.13/32 -j DROP"
        ]
        postdown = [
            "iptables -D FORWARD -s 10.66.0.13/32 -d 192.168.10.100/32 -p tcp --dport 22 -j ACCEPT",
            "iptables -D FORWARD -s 10.66.0.13/32 -d 192.168.10.100/32 -p tcp --dport 443 -j ACCEPT",
            "iptables -D FORWARD -s 10.66.0.13/32 -d 192.168.10.100/32 -p tcp --dport 8096 -j ACCEPT",
            "iptables -D FORWARD -s 10.66.0.13/32 -j DROP"
        ]

        self.db.save_sn_peer_firewall_rules(self.sn_id, peer_id, postup, postdown)

        # Verify
        restriction = self.db.get_peer_ip_restriction(peer_id)
        assert restriction is not None
        assert restriction['allowed_ports'] == "22,443,8096"

        # Verify firewall rules
        rules = self.db.get_sn_peer_firewall_rules(self.sn_id, 'postup')
        assert len(rules) >= 4  # At least 4 rules for this peer

    # ============================================================================
    # Peer Order Tests
    # ============================================================================

    @test("Peer order tracking")
    def test_peer_order(self):
        """Test peer order preservation"""
        cs = self.db.get_coordination_server()

        # Add peers to order
        peers = self.db.get_peers(cs['id'])
        for i, peer in enumerate(peers):
            self.db.save_peer_order(cs['id'], peer['public_key'], i, is_subnet_router=False)

        # Add subnet router to order
        routers = self.db.get_subnet_routers(cs['id'])
        if routers:
            self.db.save_peer_order(cs['id'], routers[0]['public_key'], len(peers), is_subnet_router=True)

        # Verify order
        order = self.db.get_peer_order(cs['id'])
        assert len(order) == len(peers) + len(routers)

    # ============================================================================
    # Config Reconstruction Tests
    # ============================================================================

    @test("CS: Config reconstruction")
    def test_cs_config_reconstruction(self):
        """Test coordination server config rebuilding"""
        config = self.db.reconstruct_cs_config()

        assert "[Interface]" in config
        assert "Address = 10.66.0.1/24" in config
        assert "[Peer]" in config  # Should have at least one peer

    @test("SN: Config with peer rules")
    def test_sn_config_with_peer_rules(self):
        """Test SN config includes peer-specific rules"""
        config = self.db.reconstruct_sn_config(self.sn_id)

        assert "# Peer-specific rule for:" in config
        assert "test-restricted" in config

    @test("Peer: Client config reconstruction")
    def test_peer_config_reconstruction(self):
        """Test peer client config rebuilding"""
        # Find a peer with client config
        peer_id = self.peer_ids[0]
        config = self.db.reconstruct_peer_config(peer_id)

        assert "[Interface]" in config
        assert "PrivateKey" in config

    # ============================================================================
    # Foreign Key CASCADE Tests
    # ============================================================================

    @test("CASCADE: Peer deletion removes restrictions")
    def test_cascade_peer_restriction(self):
        """Test peer deletion cascades to IP restrictions"""
        private_key, public_key = generate_keypair()

        # Create peer with restriction
        peer_id = self.db.save_peer(
            name="test-cascade",
            cs_id=self.cs_id,
            public_key=public_key,
            private_key=private_key,
            ipv4_address="10.66.0.99",
            ipv6_address="fd66:6666::99",
            access_level="restricted_ip",
            raw_peer_block=f"[Peer]\nPublicKey = {public_key}",
            raw_interface_block=f"[Interface]\nPrivateKey = {private_key}"
        )

        self.db.save_peer_ip_restriction(
            peer_id=peer_id,
            sn_id=self.sn_id,
            target_ip="192.168.10.200",
            allowed_ports="22"
        )

        # Verify restriction exists
        restriction = self.db.get_peer_ip_restriction(peer_id)
        assert restriction is not None

        # Delete peer
        with self.db._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM peer WHERE id = ?", (peer_id,))

        # Verify restriction is gone (CASCADE)
        restriction = self.db.get_peer_ip_restriction(peer_id)
        assert restriction is None

    @test("CASCADE: Peer deletion removes firewall rules")
    def test_cascade_peer_firewall(self):
        """Test peer deletion cascades to firewall rules"""
        private_key, public_key = generate_keypair()

        # Create peer with firewall rules
        peer_id = self.db.save_peer(
            name="test-cascade-fw",
            cs_id=self.cs_id,
            public_key=public_key,
            private_key=private_key,
            ipv4_address="10.66.0.98",
            ipv6_address="fd66:6666::98",
            access_level="restricted_ip",
            raw_peer_block=f"[Peer]\nPublicKey = {public_key}",
            raw_interface_block=f"[Interface]\nPrivateKey = {private_key}"
        )

        postup = ["iptables -I FORWARD -s 10.66.0.98/32 -j DROP"]
        postdown = ["iptables -D FORWARD -s 10.66.0.98/32 -j DROP"]

        self.db.save_sn_peer_firewall_rules(self.sn_id, peer_id, postup, postdown)

        # Verify rules exist
        rules = self.db.get_sn_peer_firewall_rules(self.sn_id, 'postup')
        initial_count = len(rules)

        # Delete peer
        with self.db._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM peer WHERE id = ?", (peer_id,))

        # Verify rules are gone (CASCADE)
        rules = self.db.get_sn_peer_firewall_rules(self.sn_id, 'postup')
        final_count = len(rules)

        assert final_count < initial_count

    # ============================================================================
    # Key Generation Tests
    # ============================================================================

    @test("Keygen: WireGuard keypair")
    def test_keygen(self):
        """Test WireGuard key generation"""
        private_key, public_key = generate_keypair()

        assert private_key is not None
        assert public_key is not None
        assert len(private_key) == 44  # Base64 encoded 32 bytes
        assert len(public_key) == 44
        assert private_key != public_key

    @test("Keygen: Unique keys")
    def test_keygen_unique(self):
        """Test that generated keys are unique"""
        key1_priv, key1_pub = generate_keypair()
        key2_priv, key2_pub = generate_keypair()

        assert key1_priv != key2_priv
        assert key1_pub != key2_pub

    # ============================================================================
    # Edge Cases
    # ============================================================================

    @test("Edge: Empty port list")
    def test_empty_port_list(self):
        """Test handling of empty allowed_ports"""
        private_key, public_key = generate_keypair()

        peer_id = self.db.save_peer(
            name="test-empty-ports",
            cs_id=self.cs_id,
            public_key=public_key,
            private_key=private_key,
            ipv4_address="10.66.0.97",
            ipv6_address="fd66:6666::97",
            access_level="restricted_ip",
            raw_peer_block=f"[Peer]\nPublicKey = {public_key}",
            raw_interface_block=f"[Interface]\nPrivateKey = {private_key}"
        )

        # Save with empty string (should be treated as None)
        self.db.save_peer_ip_restriction(
            peer_id=peer_id,
            sn_id=self.sn_id,
            target_ip="192.168.10.250",
            allowed_ports="",
            description="Empty ports"
        )

        restriction = self.db.get_peer_ip_restriction(peer_id)
        assert restriction is not None

    @test("Edge: Multiple LAN networks")
    def test_multiple_lan_networks(self):
        """Test subnet router with multiple LANs"""
        networks = [
            "192.168.10.0/24",
            "192.168.20.0/24",
            "192.168.30.0/24",
            "10.0.0.0/8"
        ]

        # Clear existing networks
        with self.db._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM sn_lan_networks WHERE sn_id = ?", (self.sn_id,))

        self.db.save_sn_lan_networks(self.sn_id, networks)

        retrieved = self.db.get_sn_lan_networks(self.sn_id)
        assert len(retrieved) == 4
        assert set(retrieved) == set(networks)

    # ============================================================================
    # Run All Tests
    # ============================================================================

    def run_all(self):
        """Run all tests in order"""
        print("=" * 70)
        print("WireGuard Friend - Comprehensive Test Suite")
        print("=" * 70)
        print()

        # Database & Schema
        print("[1/8] Database & Schema Tests")
        self.test_db_init()
        self.test_foreign_keys()
        print()

        # Coordination Server
        print("[2/8] Coordination Server Tests")
        self.test_cs_save_retrieve()
        self.test_cs_postup_postdown()
        print()

        # Subnet Router
        print("[3/8] Subnet Router Tests")
        self.test_sn_save_retrieve()
        self.test_sn_lan_networks()
        self.test_sn_postup_postdown()
        self.test_sn_config_reconstruction()
        print()

        # Peers
        print("[4/8] Peer Tests (All Access Levels)")
        self.test_peer_full_access()
        self.test_peer_vpn_only()
        self.test_peer_restricted_ip_all_ports()
        self.test_peer_restricted_ip_ports()
        self.test_peer_order()
        print()

        # Config Reconstruction
        print("[5/8] Config Reconstruction Tests")
        self.test_cs_config_reconstruction()
        self.test_sn_config_with_peer_rules()
        self.test_peer_config_reconstruction()
        print()

        # Foreign Key CASCADE
        print("[6/8] Foreign Key CASCADE Tests")
        self.test_cascade_peer_restriction()
        self.test_cascade_peer_firewall()
        print()

        # Key Generation
        print("[7/8] Key Generation Tests")
        self.test_keygen()
        self.test_keygen_unique()
        print()

        # Edge Cases
        print("[8/8] Edge Case Tests")
        self.test_empty_port_list()
        self.test_multiple_lan_networks()
        print()

        # Summary
        print("=" * 70)
        print(f"Tests Run:    {tests_run}")
        print(f"Tests Passed: {tests_passed} ({100*tests_passed//tests_run if tests_run > 0 else 0}%)")
        print(f"Tests Failed: {tests_failed}")
        print("=" * 70)

        if tests_failed == 0:
            print("\n✓ All tests passed!")
            return 0
        else:
            print(f"\n✗ {tests_failed} test(s) failed")
            return 1


def main():
    """Main entry point"""
    suite = TestSuite()

    try:
        exit_code = suite.run_all()
        return exit_code
    finally:
        suite.cleanup()


if __name__ == "__main__":
    sys.exit(main())
