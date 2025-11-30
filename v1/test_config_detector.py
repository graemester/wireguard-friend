#!/usr/bin/env python3
"""
Config Detector Tests

Tests that would have caught the entity_type vs lines bug and other
config detection issues.
"""

import sys
from pathlib import Path
import tempfile

sys.path.insert(0, str(Path(__file__).parent.parent))

from v1.config_detector import ConfigDetector


def test_coordination_server_detection():
    """Test detection of coordination server config"""
    config_content = """[Interface]
Address = 10.66.0.1/24
ListenPort = 51820
PrivateKey = test123

PostUp = iptables -A FORWARD -i wg0 -j ACCEPT
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT

[Peer]
PublicKey = peer1
AllowedIPs = 10.66.0.10/32

[Peer]
PublicKey = peer2
AllowedIPs = 10.66.0.20/32

[Peer]
PublicKey = peer3
AllowedIPs = 10.66.0.30/32
"""

    with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
        f.write(config_content)
        f.flush()
        config_path = Path(f.name)

    try:
        detector = ConfigDetector()
        config_type, peer_count = detector.detect_type(config_path)

        assert config_type == 'coordination_server', f"Expected coordination_server, got {config_type}"
        assert peer_count == 3, f"Expected 3 peers, got {peer_count}"
        print("✓ Coordination server detection: PASSED")
    finally:
        config_path.unlink()


def test_subnet_router_detection():
    """Test detection of subnet router config"""
    config_content = """[Interface]
Address = 10.66.0.20/24
PrivateKey = test456
ListenPort = 51820

PostUp = iptables -A FORWARD -i wg0 -o eth0 -j ACCEPT
PostUp = iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -o eth0 -j ACCEPT

[Peer]
PublicKey = cs_key
Endpoint = server.example.com:51820
AllowedIPs = 10.66.0.0/24
"""

    with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
        f.write(config_content)
        f.flush()
        config_path = Path(f.name)

    try:
        detector = ConfigDetector()
        config_type, peer_count = detector.detect_type(config_path)

        assert config_type == 'subnet_router', f"Expected subnet_router, got {config_type}"
        assert peer_count == 1, f"Expected 1 peer, got {peer_count}"
        print("✓ Subnet router detection: PASSED")
    finally:
        config_path.unlink()


def test_client_detection():
    """Test detection of client config"""
    config_content = """[Interface]
PrivateKey = client_key
Address = 10.66.0.50/32
DNS = 10.66.0.1

[Peer]
PublicKey = server_key
Endpoint = vpn.example.com:51820
AllowedIPs = 10.66.0.0/24
PersistentKeepalive = 25
"""

    with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
        f.write(config_content)
        f.flush()
        config_path = Path(f.name)

    try:
        detector = ConfigDetector()
        config_type, peer_count = detector.detect_type(config_path)

        assert config_type == 'client', f"Expected client, got {config_type}"
        assert peer_count == 1, f"Expected 1 peer, got {peer_count}"
        print("✓ Client detection: PASSED")
    finally:
        config_path.unlink()


def test_interface_bracket_detection():
    """
    REGRESSION TEST for the entity_type vs lines bug.

    This test would have caught the bug where we checked:
        if not any('[Interface]' in line for line in interface.lines)

    instead of:
        if interface.entity_type != '[Interface]'

    The bug was that 'lines' contains only the content AFTER the bracket,
    so [Interface] is never in 'lines' - it's in 'entity_type'.
    """
    # Test with minimal config - just Interface and one Peer
    config_content = """[Interface]
Address = 10.0.0.1/24

[Peer]
PublicKey = test
AllowedIPs = 10.0.0.2/32
"""

    with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
        f.write(config_content)
        f.flush()
        config_path = Path(f.name)

    try:
        detector = ConfigDetector()
        # This should NOT raise "First entity is not [Interface]"
        config_type, peer_count = detector.detect_type(config_path)

        # Should detect as client (1 peer, no forwarding rules, no endpoint)
        assert peer_count == 1, f"Expected 1 peer, got {peer_count}"
        print("✓ Interface bracket detection (regression test): PASSED")
    except ValueError as e:
        if "First entity is not [Interface]" in str(e):
            print("✗ REGRESSION: entity_type vs lines bug detected!")
            raise
        else:
            raise
    finally:
        config_path.unlink()


def test_with_comments_and_whitespace():
    """Test that detection works with comments and blank lines"""
    config_content = """# This is a comment
# Another comment

[Interface]
Address = 10.66.0.1/24

# Comment between fields
ListenPort = 51820
PrivateKey = test789

# PostUp rules
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT

# First peer
[Peer]
PublicKey = peer1
AllowedIPs = 10.66.0.10/32

# Second peer
[Peer]
PublicKey = peer2
AllowedIPs = 10.66.0.20/32

# Third peer
[Peer]
PublicKey = peer3
AllowedIPs = 10.66.0.30/32
"""

    with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
        f.write(config_content)
        f.flush()
        config_path = Path(f.name)

    try:
        detector = ConfigDetector()
        config_type, peer_count = detector.detect_type(config_path)

        assert config_type == 'coordination_server', f"Expected coordination_server, got {config_type}"
        assert peer_count == 3, f"Expected 3 peers, got {peer_count}"
        print("✓ Detection with comments and whitespace: PASSED")
    finally:
        config_path.unlink()


def test_real_world_configs():
    """Test with the actual configs from import/ directory"""
    import_dir = Path(__file__).parent.parent / 'import'

    if not import_dir.exists():
        print("SKIP: Skipping real-world config test (import/ not found)")
        return

    configs = list(import_dir.glob('*.conf'))
    if not configs:
        print("SKIP: Skipping real-world config test (no .conf files)")
        return

    detector = ConfigDetector()

    for config_path in configs:
        try:
            config_type, peer_count = detector.detect_type(config_path)
            print(f"  ✓ {config_path.name}: {config_type} ({peer_count} peers)")
        except Exception as e:
            print(f"  ✗ {config_path.name}: ERROR - {e}")
            raise


if __name__ == '__main__':
    print("=" * 70)
    print("CONFIG DETECTOR TESTS")
    print("=" * 70)
    print()

    tests = [
        ("Interface bracket detection (REGRESSION)", test_interface_bracket_detection),
        ("Coordination server detection", test_coordination_server_detection),
        ("Subnet router detection", test_subnet_router_detection),
        ("Client detection", test_client_detection),
        ("Comments and whitespace handling", test_with_comments_and_whitespace),
        ("Real-world configs", test_real_world_configs),
    ]

    passed = 0
    failed = 0

    for name, test_func in tests:
        try:
            print(f"Testing: {name}")
            test_func()
            passed += 1
            print()
        except Exception as e:
            print(f"✗ FAILED: {e}")
            print()
            failed += 1

    print("=" * 70)
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 70)

    sys.exit(0 if failed == 0 else 1)
