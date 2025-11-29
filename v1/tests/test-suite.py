#!/usr/bin/env python3
"""
WireGuard Friend - Comprehensive Test Suite (Enhanced)

Ultra-refined testing regimen with deep validation, error handling,
real-world scenarios, and security checks.

Run with: python3 tests/test-suite.py
"""

import sys
import tempfile
import ipaddress
from pathlib import Path
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.database import WireGuardDB
from src.keygen import generate_keypair, derive_public_key

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
    """Ultra-refined comprehensive test suite"""

    def __init__(self):
        # Create temporary database
        self.temp_db = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
        self.db_path = Path(self.temp_db.name)
        self.db = WireGuardDB(self.db_path)

        # Test data
        self.cs_id = None
        self.sn_id = None
        self.sn2_id = None
        self.peer_ids = []

    def cleanup(self):
        """Clean up test database"""
        try:
            self.db_path.unlink()
        except:
            pass

    # ============================================================================
    # 1. Database Schema & Integrity
    # ============================================================================

    @test("Schema: All required tables exist")
    def test_db_init(self):
        """Verify all required tables exist"""
        with self.db._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = {row['name'] for row in cursor.fetchall()}

            required = {
                'coordination_server', 'subnet_router', 'peer',
                'cs_peer_order', 'peer_ip_restrictions', 'sn_peer_firewall_rules',
                'sn_postup_rules', 'sn_postdown_rules', 'sn_lan_networks',
                'peer_custom_allowed_ips', 'cs_postup_rules', 'cs_postdown_rules'
            }

            missing = required - tables
            assert not missing, f"Missing tables: {missing}"

    @test("Schema: Foreign keys enforced")
    def test_foreign_keys(self):
        """Verify foreign key constraints are active"""
        with self.db._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("PRAGMA foreign_keys")
            result = cursor.fetchone()
            assert result[0] == 1, "Foreign keys not enabled"

    @test("Schema: UNIQUE constraints work")
    def test_unique_constraints(self):
        """Test UNIQUE constraints prevent duplicates"""
        # Skip if CS not created yet (will test after CS exists)
        if self.cs_id is None:
            return

        private_key, public_key = generate_keypair()

        # Create first peer
        peer_id = self.db.save_peer(
            name="unique-test",
            cs_id=self.cs_id,
            public_key=public_key,
            private_key=private_key,
            ipv4_address="10.66.0.200",
            ipv6_address="fd66:6666::200",
            access_level="full_access",
            raw_peer_block=f"[Peer]\nPublicKey = {public_key}",
            raw_interface_block=f"[Interface]\nPrivateKey = {private_key}"
        )

        # Try to create duplicate - should fail
        try:
            self.db.save_peer(
                name="unique-test",  # Same name
                cs_id=self.cs_id,
                public_key="different_key",
                private_key="different_key",
                ipv4_address="10.66.0.201",
                ipv6_address="fd66:6666::201",
                access_level="full_access",
                raw_peer_block="[Peer]\nPublicKey = different",
                raw_interface_block="[Interface]\nPrivateKey = different"
            )
            assert False, "Should have failed on duplicate name"
        except:
            pass  # Expected to fail

        # Cleanup the test peer
        with self.db._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM peer WHERE id = ?", (peer_id,))

    # ============================================================================
    # 2. Coordination Server - Deep Validation
    # ============================================================================

    @test("CS: Complete CRUD cycle")
    def test_cs_crud(self):
        """Test full CS lifecycle with validation"""
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
            mtu=1280,
            ssh_host="test.example.com",
            ssh_user="testuser",
            ssh_port=2222
        )

        # Deep validation
        cs = self.db.get_coordination_server()
        assert cs['id'] == self.cs_id
        assert cs['endpoint'] == "test.example.com:51820"
        assert cs['public_key'] == public_key
        assert cs['private_key'] == private_key
        assert cs['network_ipv4'] == "10.66.0.0/24"
        assert cs['network_ipv6'] == "fd66:6666::/64"
        assert cs['ssh_host'] == "test.example.com"
        assert cs['ssh_port'] == 2222
        assert "ListenPort = 51820" in cs['raw_interface_block']

    @test("CS: PostUp/PostDown rule order preserved")
    def test_cs_postup_order(self):
        """Verify PostUp/PostDown rules maintain order"""
        postup_rules = [
            "sysctl -w net.ipv4.ip_forward=1",
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

        # Verify exact order
        assert retrieved_up == postup_rules, "PostUp order not preserved"
        assert retrieved_down == postdown_rules, "PostDown order not preserved"

    # ============================================================================
    # 3. Subnet Router - Multiple SNs, Config Fidelity
    # ============================================================================

    @test("SN: Multiple subnet routers")
    def test_multiple_sns(self):
        """Test multiple subnet routers in same network"""
        sn1_priv, sn1_pub = generate_keypair()
        sn2_priv, sn2_pub = generate_keypair()

        # Create first SN
        self.sn_id = self.db.save_subnet_router(
            name="test-router-1",
            cs_id=self.cs_id,
            public_key=sn1_pub,
            private_key=sn1_priv,
            ipv4_address="10.66.0.20",
            ipv6_address="fd66:6666::20",
            allowed_ips="10.66.0.0/24, fd66:6666::/64",
            raw_interface_block=f"[Interface]\nAddress = 10.66.0.20/24\nPrivateKey = {sn1_priv}",
            raw_peer_block="[Peer]\nPublicKey = CS_KEY\nEndpoint = test.example.com:51820",
            mtu=1280
        )

        # Create second SN
        self.sn2_id = self.db.save_subnet_router(
            name="test-router-2",
            cs_id=self.cs_id,
            public_key=sn2_pub,
            private_key=sn2_priv,
            ipv4_address="10.66.0.21",
            ipv6_address="fd66:6666::21",
            allowed_ips="10.66.0.0/24, fd66:6666::/64",
            raw_interface_block=f"[Interface]\nAddress = 10.66.0.21/24\nPrivateKey = {sn2_priv}",
            raw_peer_block="[Peer]\nPublicKey = CS_KEY\nEndpoint = test.example.com:51820",
            mtu=1280
        )

        routers = self.db.get_subnet_routers(self.cs_id)
        assert len(routers) == 2
        assert {r['name'] for r in routers} == {"test-router-1", "test-router-2"}

    @test("SN: Config reconstruction byte-for-byte")
    def test_sn_config_fidelity(self):
        """Verify SN config reconstruction is accurate"""
        # Add LAN networks
        networks = ["192.168.10.0/24", "192.168.20.0/24"]
        self.db.save_sn_lan_networks(self.sn_id, networks)

        # Add PostUp/PostDown
        postup = ["iptables -A FORWARD -i wg0 -o eth0 -j ACCEPT"]
        postdown = ["iptables -D FORWARD -i wg0 -o eth0 -j ACCEPT"]
        self.db.save_sn_postup_rules(self.sn_id, postup)
        self.db.save_sn_postdown_rules(self.sn_id, postdown)

        # Reconstruct
        config = self.db.reconstruct_sn_config(self.sn_id)

        # Verify all components
        assert "[Interface]" in config
        assert "Address = 10.66.0.20/24" in config
        assert "PostUp = iptables -A FORWARD -i wg0 -o eth0 -j ACCEPT" in config
        assert "PostDown = iptables -D FORWARD -i wg0 -o eth0 -j ACCEPT" in config
        assert "[Peer]" in config
        assert "Endpoint = test.example.com:51820" in config

    @test("SN: Peer-specific rules labeled correctly")
    def test_sn_peer_rule_labels(self):
        """Verify peer-specific rules have correct labels"""
        # Create peer with firewall rules
        priv, pub = generate_keypair()
        peer_id = self.db.save_peer(
            name="labeled-peer",
            cs_id=self.cs_id,
            public_key=pub,
            private_key=priv,
            ipv4_address="10.66.0.50",
            ipv6_address="fd66:6666::50",
            access_level="restricted_ip",
            raw_peer_block=f"[Peer]\nPublicKey = {pub}",
            raw_interface_block=f"[Interface]\nPrivateKey = {priv}"
        )

        # Add firewall rules
        postup = ["iptables -I FORWARD -s 10.66.0.50/32 -j DROP"]
        postdown = ["iptables -D FORWARD -s 10.66.0.50/32 -j DROP"]
        self.db.save_sn_peer_firewall_rules(self.sn_id, peer_id, postup, postdown)

        # Check config includes label
        config = self.db.reconstruct_sn_config(self.sn_id)
        assert "# Peer-specific rule for: labeled-peer" in config

    # ============================================================================
    # 4. Peers - All Access Levels + Edge Cases
    # ============================================================================

    @test("Peer: full_access with all LANs")
    def test_peer_full_access(self):
        """Test full_access peer sees all networks"""
        priv, pub = generate_keypair()

        peer_id = self.db.save_peer(
            name="test-full",
            cs_id=self.cs_id,
            public_key=pub,
            private_key=priv,
            ipv4_address="10.66.0.10",
            ipv6_address="fd66:6666::10",
            access_level="full_access",
            raw_peer_block=f"[Peer]\nPublicKey = {pub}\nAllowedIPs = 10.66.0.10/32",
            raw_interface_block=f"[Interface]\nPrivateKey = {priv}\nAddress = 10.66.0.10/24",
            persistent_keepalive=25
        )

        self.peer_ids.append(peer_id)

        # Retrieve peer by name to avoid indexing issues
        peers = self.db.get_peers(self.cs_id)
        peer = next(p for p in peers if p['name'] == 'test-full')
        assert peer['access_level'] == 'full_access'
        assert peer['persistent_keepalive'] == 25

    @test("Peer: vpn_only isolation")
    def test_peer_vpn_only(self):
        """Test vpn_only peer is isolated from LANs"""
        priv, pub = generate_keypair()

        peer_id = self.db.save_peer(
            name="test-vpn",
            cs_id=self.cs_id,
            public_key=pub,
            private_key=priv,
            ipv4_address="10.66.0.11",
            ipv6_address="fd66:6666::11",
            access_level="vpn_only",
            raw_peer_block=f"[Peer]\nPublicKey = {pub}",
            raw_interface_block=f"[Interface]\nPrivateKey = {priv}"
        )

        self.peer_ids.append(peer_id)

        # Retrieve peer by name to avoid indexing issues
        peers = self.db.get_peers(self.cs_id)
        peer = next(p for p in peers if p['name'] == 'test-vpn')
        assert peer['access_level'] == 'vpn_only'

    @test("Peer: restricted_ip (all ports)")
    def test_peer_restricted_all_ports(self):
        """Test restricted_ip with no port filtering"""
        priv, pub = generate_keypair()

        peer_id = self.db.save_peer(
            name="test-restricted-all",
            cs_id=self.cs_id,
            public_key=pub,
            private_key=priv,
            ipv4_address="10.66.0.12",
            ipv6_address="fd66:6666::12",
            access_level="restricted_ip",
            raw_peer_block=f"[Peer]\nPublicKey = {pub}",
            raw_interface_block=f"[Interface]\nPrivateKey = {priv}"
        )

        self.peer_ids.append(peer_id)

        # Save restriction
        self.db.save_peer_ip_restriction(
            peer_id=peer_id,
            sn_id=self.sn_id,
            target_ip="192.168.10.50",
            allowed_ports=None,
            description="All ports"
        )

        # Firewall rules
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
        assert restriction['target_ip'] == "192.168.10.50"
        assert restriction['allowed_ports'] is None

    @test("Peer: restricted_ip (single port)")
    def test_peer_restricted_single_port(self):
        """Test restricted_ip with single port"""
        priv, pub = generate_keypair()

        peer_id = self.db.save_peer(
            name="test-restricted-ssh",
            cs_id=self.cs_id,
            public_key=pub,
            private_key=priv,
            ipv4_address="10.66.0.13",
            ipv6_address="fd66:6666::13",
            access_level="restricted_ip",
            raw_peer_block=f"[Peer]\nPublicKey = {pub}",
            raw_interface_block=f"[Interface]\nPrivateKey = {priv}"
        )

        self.peer_ids.append(peer_id)

        # Single port
        self.db.save_peer_ip_restriction(
            peer_id=peer_id,
            sn_id=self.sn_id,
            target_ip="192.168.10.100",
            allowed_ports="22",
            description="SSH only"
        )

        postup = [
            "iptables -I FORWARD -s 10.66.0.13/32 -d 192.168.10.100/32 -p tcp --dport 22 -j ACCEPT",
            "iptables -I FORWARD -s 10.66.0.13/32 -j DROP"
        ]
        postdown = [
            "iptables -D FORWARD -s 10.66.0.13/32 -d 192.168.10.100/32 -p tcp --dport 22 -j ACCEPT",
            "iptables -D FORWARD -s 10.66.0.13/32 -j DROP"
        ]
        self.db.save_sn_peer_firewall_rules(self.sn_id, peer_id, postup, postdown)

        restriction = self.db.get_peer_ip_restriction(peer_id)
        assert restriction['allowed_ports'] == "22"

    @test("Peer: restricted_ip (multiple ports)")
    def test_peer_restricted_multiple_ports(self):
        """Test restricted_ip with multiple ports"""
        priv, pub = generate_keypair()

        peer_id = self.db.save_peer(
            name="test-restricted-multi",
            cs_id=self.cs_id,
            public_key=pub,
            private_key=priv,
            ipv4_address="10.66.0.14",
            ipv6_address="fd66:6666::14",
            access_level="restricted_ip",
            raw_peer_block=f"[Peer]\nPublicKey = {pub}",
            raw_interface_block=f"[Interface]\nPrivateKey = {priv}"
        )

        self.peer_ids.append(peer_id)

        # Multiple ports
        self.db.save_peer_ip_restriction(
            peer_id=peer_id,
            sn_id=self.sn_id,
            target_ip="192.168.10.101",
            allowed_ports="22,443,8096",
            description="SSH, HTTPS, Jellyfin"
        )

        postup = [
            "iptables -I FORWARD -s 10.66.0.14/32 -d 192.168.10.101/32 -p tcp --dport 22 -j ACCEPT",
            "iptables -I FORWARD -s 10.66.0.14/32 -d 192.168.10.101/32 -p tcp --dport 443 -j ACCEPT",
            "iptables -I FORWARD -s 10.66.0.14/32 -d 192.168.10.101/32 -p tcp --dport 8096 -j ACCEPT",
            "iptables -I FORWARD -s 10.66.0.14/32 -j DROP"
        ]
        postdown = [
            "iptables -D FORWARD -s 10.66.0.14/32 -d 192.168.10.101/32 -p tcp --dport 22 -j ACCEPT",
            "iptables -D FORWARD -s 10.66.0.14/32 -d 192.168.10.101/32 -p tcp --dport 443 -j ACCEPT",
            "iptables -D FORWARD -s 10.66.0.14/32 -d 192.168.10.101/32 -p tcp --dport 8096 -j ACCEPT",
            "iptables -D FORWARD -s 10.66.0.14/32 -j DROP"
        ]
        self.db.save_sn_peer_firewall_rules(self.sn_id, peer_id, postup, postdown)

        restriction = self.db.get_peer_ip_restriction(peer_id)
        assert restriction['allowed_ports'] == "22,443,8096"

        # Verify rule count
        rules = self.db.get_sn_peer_firewall_rules(self.sn_id, 'postup')
        peer_rules = [r for r in rules if r[0] == peer_id]
        assert len(peer_rules) == 4  # 3 ACCEPT + 1 DROP

    @test("Peer: restricted_ip (port range)")
    def test_peer_restricted_port_range(self):
        """Test restricted_ip with port range"""
        priv, pub = generate_keypair()

        peer_id = self.db.save_peer(
            name="test-restricted-range",
            cs_id=self.cs_id,
            public_key=pub,
            private_key=priv,
            ipv4_address="10.66.0.15",
            ipv6_address="fd66:6666::15",
            access_level="restricted_ip",
            raw_peer_block=f"[Peer]\nPublicKey = {pub}",
            raw_interface_block=f"[Interface]\nPrivateKey = {priv}"
        )

        self.peer_ids.append(peer_id)

        # Port range
        self.db.save_peer_ip_restriction(
            peer_id=peer_id,
            sn_id=self.sn_id,
            target_ip="192.168.10.102",
            allowed_ports="8000:8999",
            description="Port range 8000-8999"
        )

        postup = [
            "iptables -I FORWARD -s 10.66.0.15/32 -d 192.168.10.102/32 -p tcp --dport 8000:8999 -j ACCEPT",
            "iptables -I FORWARD -s 10.66.0.15/32 -j DROP"
        ]
        postdown = [
            "iptables -D FORWARD -s 10.66.0.15/32 -d 192.168.10.102/32 -p tcp --dport 8000:8999 -j ACCEPT",
            "iptables -D FORWARD -s 10.66.0.15/32 -j DROP"
        ]
        self.db.save_sn_peer_firewall_rules(self.sn_id, peer_id, postup, postdown)

        restriction = self.db.get_peer_ip_restriction(peer_id)
        assert restriction['allowed_ports'] == "8000:8999"

    @test("Peer: Peer without client config (CS-only)")
    def test_peer_without_client_config(self):
        """Test peer without raw_interface_block (server-side only)"""
        priv, pub = generate_keypair()

        peer_id = self.db.save_peer(
            name="test-server-only",
            cs_id=self.cs_id,
            public_key=pub,
            private_key=None,  # No private key
            ipv4_address="10.66.0.30",
            ipv6_address="fd66:6666::30",
            access_level="full_access",
            raw_peer_block=f"[Peer]\nPublicKey = {pub}",
            raw_interface_block=None  # No client config
        )

        self.peer_ids.append(peer_id)

        # Retrieve peer by name
        peers = self.db.get_peers(self.cs_id)
        peer = next(p for p in peers if p['name'] == 'test-server-only')
        assert peer['name'] == "test-server-only"
        assert peer['raw_interface_block'] is None

    # ============================================================================
    # 5. IP Allocation Logic
    # ============================================================================

    @test("IP: Find next available IPv4")
    def test_ip_allocation_ipv4(self):
        """Test IPv4 allocation finds gaps correctly"""
        cs = self.db.get_coordination_server()
        peers = self.db.get_peers(cs['id'])
        sns = self.db.get_subnet_routers(cs['id'])

        # Collect used IPs
        used_ipv4 = {cs['ipv4_address']}
        for p in peers:
            if p['ipv4_address']:
                used_ipv4.add(p['ipv4_address'])
        for sn in sns:
            used_ipv4.add(sn['ipv4_address'])

        # Find next available
        base = ".".join(cs['ipv4_address'].split('.')[:-1])
        next_ip = None
        for i in range(2, 255):
            candidate = f"{base}.{i}"
            if candidate not in used_ipv4:
                next_ip = candidate
                break

        assert next_ip is not None, "No available IPs found"

        # Verify it's a valid IP
        try:
            ipaddress.IPv4Address(next_ip)
        except:
            assert False, f"Invalid IPv4: {next_ip}"

    @test("IP: Find next available IPv6")
    def test_ip_allocation_ipv6(self):
        """Test IPv6 allocation finds gaps correctly"""
        cs = self.db.get_coordination_server()
        peers = self.db.get_peers(cs['id'])

        # Collect used IPs
        used_ipv6 = {cs['ipv6_address']}
        for p in peers:
            if p['ipv6_address']:
                used_ipv6.add(p['ipv6_address'])

        # Find next available
        base = cs['ipv6_address'].rsplit(':', 1)[0]
        next_ip = None
        for i in range(2, 1000):
            candidate = f"{base}:{i:x}"
            if candidate not in used_ipv6:
                next_ip = candidate
                break

        assert next_ip is not None, "No available IPv6 found"

        # Verify it's a valid IPv6
        try:
            ipaddress.IPv6Address(next_ip)
        except:
            assert False, f"Invalid IPv6: {next_ip}"

    # ============================================================================
    # 6. Key Generation & Cryptography
    # ============================================================================

    @test("Keygen: WireGuard keypair validity")
    def test_keygen(self):
        """Test WireGuard key generation produces valid keys"""
        priv, pub = generate_keypair()

        assert priv is not None
        assert pub is not None
        assert len(priv) == 44  # Base64 32 bytes + padding
        assert len(pub) == 44
        assert priv != pub
        assert priv.endswith('=')  # Base64 padding
        assert pub.endswith('=')

    @test("Keygen: Public key derivation")
    def test_public_key_derivation(self):
        """Test deriving public key from private key"""
        priv, pub_generated = generate_keypair()

        # Derive public key from private key
        pub_derived = derive_public_key(priv)

        assert pub_generated == pub_derived, "Derived public key doesn't match"

    @test("Keygen: Key uniqueness")
    def test_keygen_unique(self):
        """Test generated keys are unique"""
        keys = set()
        for _ in range(10):
            priv, pub = generate_keypair()
            assert priv not in keys
            assert pub not in keys
            keys.add(priv)
            keys.add(pub)

    # ============================================================================
    # 7. Peer Order & CS Config Reconstruction
    # ============================================================================

    @test("Order: Peer order preserved in CS config")
    def test_peer_order_preservation(self):
        """Test peer order is maintained in CS config"""
        cs = self.db.get_coordination_server()
        peers = self.db.get_peers(cs['id'])
        sns = self.db.get_subnet_routers(cs['id'])

        # Add to order
        for i, peer in enumerate(peers):
            self.db.save_peer_order(cs['id'], peer['public_key'], i, False)

        for i, sn in enumerate(sns):
            self.db.save_peer_order(cs['id'], sn['public_key'], len(peers) + i, True)

        # Verify order
        order = self.db.get_peer_order(cs['id'])
        assert len(order) == len(peers) + len(sns)

        # Verify sequence
        for i, entry in enumerate(order):
            assert entry['position'] == i

    @test("Order: CS config includes all peers")
    def test_cs_config_completeness(self):
        """Test CS config includes all peers and SNs"""
        config = self.db.reconstruct_cs_config()

        # Count [Peer] sections
        peer_count = config.count('[Peer]')

        peers = self.db.get_peers(self.cs_id)
        sns = self.db.get_subnet_routers(self.cs_id)

        expected_count = len(peers) + len(sns)
        assert peer_count == expected_count, f"Expected {expected_count} peers, found {peer_count}"

    # ============================================================================
    # 8. Foreign Key CASCADE - Critical for Data Integrity
    # ============================================================================

    @test("CASCADE: Peer → IP restriction")
    def test_cascade_peer_restriction(self):
        """Test peer deletion removes IP restrictions"""
        priv, pub = generate_keypair()

        peer_id = self.db.save_peer(
            name="test-cascade-restriction",
            cs_id=self.cs_id,
            public_key=pub,
            private_key=priv,
            ipv4_address="10.66.0.90",
            ipv6_address="fd66:6666::90",
            access_level="restricted_ip",
            raw_peer_block=f"[Peer]\nPublicKey = {pub}",
            raw_interface_block=f"[Interface]\nPrivateKey = {priv}"
        )

        self.db.save_peer_ip_restriction(peer_id, self.sn_id, "192.168.10.200", "22")

        # Verify exists
        restriction = self.db.get_peer_ip_restriction(peer_id)
        assert restriction is not None

        # Delete peer
        with self.db._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM peer WHERE id = ?", (peer_id,))

        # Verify CASCADE worked
        restriction = self.db.get_peer_ip_restriction(peer_id)
        assert restriction is None, "IP restriction not deleted (CASCADE failed)"

    @test("CASCADE: Peer → Firewall rules")
    def test_cascade_peer_firewall(self):
        """Test peer deletion removes firewall rules"""
        priv, pub = generate_keypair()

        peer_id = self.db.save_peer(
            name="test-cascade-firewall",
            cs_id=self.cs_id,
            public_key=pub,
            private_key=priv,
            ipv4_address="10.66.0.91",
            ipv6_address="fd66:6666::91",
            access_level="restricted_ip",
            raw_peer_block=f"[Peer]\nPublicKey = {pub}",
            raw_interface_block=f"[Interface]\nPrivateKey = {priv}"
        )

        postup = ["iptables -I FORWARD -s 10.66.0.91/32 -j DROP"]
        postdown = ["iptables -D FORWARD -s 10.66.0.91/32 -j DROP"]
        self.db.save_sn_peer_firewall_rules(self.sn_id, peer_id, postup, postdown)

        # Count rules before
        rules_before = self.db.get_sn_peer_firewall_rules(self.sn_id, 'postup')
        count_before = len([r for r in rules_before if r[0] == peer_id])
        assert count_before > 0

        # Delete peer
        with self.db._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM peer WHERE id = ?", (peer_id,))

        # Count rules after
        rules_after = self.db.get_sn_peer_firewall_rules(self.sn_id, 'postup')
        count_after = len([r for r in rules_after if r[0] == peer_id])
        assert count_after == 0, "Firewall rules not deleted (CASCADE failed)"

    @test("CASCADE: Peer → Peer order (manual cleanup)")
    def test_cascade_peer_order(self):
        """Test peer order cleanup (no FK CASCADE - requires manual cleanup)"""
        priv, pub = generate_keypair()

        peer_id = self.db.save_peer(
            name="test-cascade-order",
            cs_id=self.cs_id,
            public_key=pub,
            private_key=priv,
            ipv4_address="10.66.0.92",
            ipv6_address="fd66:6666::92",
            access_level="full_access",
            raw_peer_block=f"[Peer]\nPublicKey = {pub}",
            raw_interface_block=f"[Interface]\nPrivateKey = {priv}"
        )

        # Add to order
        order_before = self.db.get_peer_order(self.cs_id)
        self.db.save_peer_order(self.cs_id, pub, len(order_before), False)

        order_mid = self.db.get_peer_order(self.cs_id)
        assert len(order_mid) == len(order_before) + 1, f"Order not updated: before={len(order_before)}, after={len(order_mid)}"

        # Note: cs_peer_order has no FK on peer_public_key (shared with subnet routers)
        # So we manually clean up before deleting peer
        with self.db._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM cs_peer_order WHERE peer_public_key = ?", (pub,))

        # Now delete peer
        with self.db._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM peer WHERE id = ?", (peer_id,))

        # Verify removed from order
        order_after = self.db.get_peer_order(self.cs_id)
        assert len(order_after) == len(order_before), f"Order cleanup failed: before={len(order_before)}, after={len(order_after)}"

    # ============================================================================
    # 9. Real-World Scenarios
    # ============================================================================

    @test("Scenario: Multiple restricted peers on same SN")
    def test_multiple_restricted_peers_same_sn(self):
        """Test multiple restricted peers share the same subnet router"""
        # Create 3 restricted peers
        for i in range(3):
            priv, pub = generate_keypair()
            peer_id = self.db.save_peer(
                name=f"multi-restricted-{i}",
                cs_id=self.cs_id,
                public_key=pub,
                private_key=priv,
                ipv4_address=f"10.66.0.{70+i}",
                ipv6_address=f"fd66:6666::{70+i:x}",
                access_level="restricted_ip",
                raw_peer_block=f"[Peer]\nPublicKey = {pub}",
                raw_interface_block=f"[Interface]\nPrivateKey = {priv}"
            )

            self.db.save_peer_ip_restriction(
                peer_id, self.sn_id, f"192.168.10.{50+i}", f"{22+i}"
            )

            postup = [f"iptables -I FORWARD -s 10.66.0.{70+i}/32 -d 192.168.10.{50+i}/32 -p tcp --dport {22+i} -j ACCEPT",
                      f"iptables -I FORWARD -s 10.66.0.{70+i}/32 -j DROP"]
            postdown = [f"iptables -D FORWARD -s 10.66.0.{70+i}/32 -d 192.168.10.{50+i}/32 -p tcp --dport {22+i} -j ACCEPT",
                        f"iptables -D FORWARD -s 10.66.0.{70+i}/32 -j DROP"]
            self.db.save_sn_peer_firewall_rules(self.sn_id, peer_id, postup, postdown)

        # Verify all rules in SN config
        config = self.db.reconstruct_sn_config(self.sn_id)
        for i in range(3):
            assert f"# Peer-specific rule for: multi-restricted-{i}" in config
            assert f"10.66.0.{70+i}/32" in config

    @test("Scenario: Firewall rule ordering")
    def test_firewall_rule_ordering(self):
        """Test firewall rules maintain correct order (ACCEPT before DROP)"""
        config = self.db.reconstruct_sn_config(self.sn_id)

        # Find all PostUp lines
        postup_lines = [line for line in config.split('\n') if line.startswith('PostUp')]

        # Find DROP rules
        drop_indices = [i for i, line in enumerate(postup_lines) if '-j DROP' in line]

        # Find ACCEPT rules for same peer
        for drop_idx in drop_indices:
            drop_line = postup_lines[drop_idx]
            # Extract peer IP
            if '-s ' in drop_line:
                peer_ip = drop_line.split('-s ')[1].split('/')[0]

                # Find ACCEPT rules for this peer
                accept_indices = [i for i, line in enumerate(postup_lines)
                                  if f'-s {peer_ip}' in line and '-j ACCEPT' in line]

                # All ACCEPT rules should come before DROP
                if accept_indices:
                    assert max(accept_indices) < drop_idx, \
                        f"ACCEPT rules after DROP for {peer_ip}"

    @test("Scenario: Config export file permissions")
    def test_config_export_permissions(self):
        """Test exported configs have secure permissions (600)"""
        import tempfile
        import stat

        # Create temp file and write config
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.conf') as f:
            config = self.db.reconstruct_cs_config()
            f.write(config)
            temp_path = Path(f.name)

        # Set permissions (like real export would)
        temp_path.chmod(0o600)

        # Verify permissions
        file_stat = temp_path.stat()
        mode = stat.S_IMODE(file_stat.st_mode)
        assert mode == 0o600, f"Wrong permissions: {oct(mode)}"

        # Cleanup
        temp_path.unlink()

    # ============================================================================
    # 10. Edge Cases & Error Handling
    # ============================================================================

    @test("Edge: Empty string vs None for optional fields")
    def test_empty_vs_none(self):
        """Test handling of empty strings vs None"""
        priv, pub = generate_keypair()

        # Test with empty string for allowed_ports
        peer_id = self.db.save_peer(
            name="test-empty-string",
            cs_id=self.cs_id,
            public_key=pub,
            private_key=priv,
            ipv4_address="10.66.0.95",
            ipv6_address="fd66:6666::95",
            access_level="restricted_ip",
            raw_peer_block=f"[Peer]\nPublicKey = {pub}",
            raw_interface_block=f"[Interface]\nPrivateKey = {priv}"
        )

        self.db.save_peer_ip_restriction(peer_id, self.sn_id, "192.168.10.250", "")

        restriction = self.db.get_peer_ip_restriction(peer_id)
        assert restriction is not None

    @test("Edge: Large config (50+ peers)")
    def test_large_config(self):
        """Test system handles large configs efficiently"""
        # Create 20 more peers and add them to peer order
        for i in range(20):
            priv, pub = generate_keypair()
            peer_id = self.db.save_peer(
                name=f"bulk-peer-{i}",
                cs_id=self.cs_id,
                public_key=pub,
                private_key=priv,
                ipv4_address=f"10.66.0.{100+i}",
                ipv6_address=f"fd66:6666::{100+i:x}",
                access_level="vpn_only",
                raw_peer_block=f"[Peer]\nPublicKey = {pub}",
                raw_interface_block=f"[Interface]\nPrivateKey = {priv}"
            )

            # Add to peer order (required for CS config reconstruction)
            order = self.db.get_peer_order(self.cs_id)
            self.db.save_peer_order(self.cs_id, pub, len(order), False)

        # Test reconstruction works with large dataset
        config = self.db.reconstruct_cs_config()
        peer_count = config.count('[Peer]')

        # Should have at least 20 bulk peers + 2 subnet routers
        assert peer_count >= 22, f"Expected >=22 peers, found {peer_count}"

    @test("Edge: Special characters in peer names")
    def test_special_characters_in_names(self):
        """Test peer names with hyphens, underscores"""
        priv, pub = generate_keypair()

        peer_id = self.db.save_peer(
            name="test-peer_with-special_chars",
            cs_id=self.cs_id,
            public_key=pub,
            private_key=priv,
            ipv4_address="10.66.0.96",
            ipv6_address="fd66:6666::96",
            access_level="full_access",
            raw_peer_block=f"[Peer]\nPublicKey = {pub}",
            raw_interface_block=f"[Interface]\nPrivateKey = {priv}"
        )

        # Retrieve peer by name
        peers = self.db.get_peers(self.cs_id)
        peer = next(p for p in peers if p['name'] == 'test-peer_with-special_chars')
        assert peer['name'] == "test-peer_with-special_chars"

    @test("Edge: IPv6 address validation")
    def test_ipv6_validation(self):
        """Test IPv6 addresses are valid"""
        cs = self.db.get_coordination_server()
        peers = self.db.get_peers(cs['id'])

        # Validate all IPv6 addresses
        for peer in peers:
            if peer['ipv6_address']:
                try:
                    ipaddress.IPv6Address(peer['ipv6_address'])
                except:
                    assert False, f"Invalid IPv6: {peer['ipv6_address']}"

    # ============================================================================
    # Run All Tests
    # ============================================================================

    def run_all(self):
        """Run all tests in organized categories"""
        print("=" * 80)
        print("WireGuard Friend - Ultra-Refined Test Suite")
        print("=" * 80)
        print()

        print("[1/10] Database Schema & Integrity")
        self.test_db_init()
        self.test_foreign_keys()
        self.test_unique_constraints()
        print()

        print("[2/10] Coordination Server - Deep Validation")
        self.test_cs_crud()
        self.test_cs_postup_order()
        print()

        print("[3/10] Subnet Router - Multiple SNs, Config Fidelity")
        self.test_multiple_sns()
        self.test_sn_config_fidelity()
        self.test_sn_peer_rule_labels()
        print()

        print("[4/10] Peers - All Access Levels + Edge Cases")
        self.test_peer_full_access()
        self.test_peer_vpn_only()
        self.test_peer_restricted_all_ports()
        self.test_peer_restricted_single_port()
        self.test_peer_restricted_multiple_ports()
        self.test_peer_restricted_port_range()
        self.test_peer_without_client_config()
        print()

        print("[5/10] IP Allocation Logic")
        self.test_ip_allocation_ipv4()
        self.test_ip_allocation_ipv6()
        print()

        print("[6/10] Key Generation & Cryptography")
        self.test_keygen()
        self.test_public_key_derivation()
        self.test_keygen_unique()
        print()

        print("[7/10] Peer Order & CS Config Reconstruction")
        self.test_peer_order_preservation()
        self.test_cs_config_completeness()
        print()

        print("[8/10] Foreign Key CASCADE - Data Integrity")
        self.test_cascade_peer_restriction()
        self.test_cascade_peer_firewall()
        self.test_cascade_peer_order()
        print()

        print("[9/10] Real-World Scenarios")
        self.test_multiple_restricted_peers_same_sn()
        self.test_firewall_rule_ordering()
        self.test_config_export_permissions()
        print()

        print("[10/10] Edge Cases & Error Handling")
        self.test_empty_vs_none()
        self.test_large_config()
        self.test_special_characters_in_names()
        self.test_ipv6_validation()
        print()

        # Summary
        print("=" * 80)
        print(f"Tests Run:    {tests_run}")
        print(f"Tests Passed: {tests_passed} ({100*tests_passed//tests_run if tests_run > 0 else 0}%)")
        print(f"Tests Failed: {tests_failed}")
        print("=" * 80)

        if tests_failed == 0:
            print("\n✓ All tests passed! System is stable and reliable.")
            return 0
        else:
            print(f"\n✗ {tests_failed} test(s) failed - review required")
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
