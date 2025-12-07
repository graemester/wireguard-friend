"""
Tests for TODO Fix Implementations

Tests covering the four minor TODO fixes:
1. comment_system.py - Handle # in quoted strings
2. import_configs.py - Endpoint validation
3. rotation_policies.py - Deploy integration
4. disaster_recovery.py - Merge logic

Run with: python3 v1/test_todo_fixes.py
"""

import os
import sys
import sqlite3
import tempfile
import shutil
from pathlib import Path
from datetime import datetime, timedelta

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from v1.comment_system import CommentExtractor
from v1.cli.import_configs import validate_endpoint
from v1.rotation_policies import RotationPolicyManager, PolicyType, EntityScope
from v1.disaster_recovery import DisasterRecovery, BackupType, RestoreMode
from v1.schema_semantic import WireGuardDBv2
from v1.keygen import generate_keypair


# =============================================================================
# TEST FIXTURES
# =============================================================================

def create_test_db(suffix=''):
    """Create a temporary database with test data"""
    with tempfile.NamedTemporaryFile(suffix=f'{suffix}.db', delete=False) as f:
        db_path = str(f.name)

    db = WireGuardDBv2(db_path)

    with db._connection() as conn:
        cursor = conn.cursor()

        # Create CS (generate_keypair returns tuple: (private, public))
        cs_private, cs_public = generate_keypair()
        cursor.execute("""
            INSERT INTO coordination_server (
                permanent_guid, current_public_key, hostname,
                endpoint, listen_port, network_ipv4, network_ipv6,
                ipv4_address, ipv6_address, private_key,
                updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            cs_public,
            cs_public,
            'test-cs',
            'cs.example.com:51820',
            51820,
            '10.66.0.0/24',
            'fd66::/64',
            '10.66.0.1/24',
            'fd66::1/64',
            cs_private,
            datetime.now().isoformat()
        ))

        # Create a remote
        remote_private, remote_public = generate_keypair()
        cursor.execute("""
            INSERT INTO remote (
                cs_id, permanent_guid, current_public_key, hostname,
                ipv4_address, ipv6_address, private_key,
                access_level, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            1,
            remote_public,
            remote_public,
            'test-remote',
            '10.66.0.30/32',
            'fd66::30/128',
            remote_private,
            'full',
            datetime.now().isoformat()
        ))

    return db_path


def cleanup_db(db_path):
    """Remove test database"""
    try:
        os.unlink(db_path)
    except OSError:
        pass


# =============================================================================
# COMMENT SYSTEM TESTS
# =============================================================================

def test_comment_simple_inline():
    """Basic inline comment extraction"""
    extractor = CommentExtractor()
    line = "ListenPort = 51820  # Main port"
    result = extractor._extract_inline_comment(line, 1)
    assert result == "Main port", f"Expected 'Main port', got {result!r}"
    print("  [PASS] test_comment_simple_inline")


def test_comment_hash_in_double_quotes():
    """# inside double quotes should not be treated as comment"""
    extractor = CommentExtractor()
    line = 'Description = "Test # value"  # actual comment'
    result = extractor._extract_inline_comment(line, 1)
    assert result == "actual comment", f"Expected 'actual comment', got {result!r}"
    print("  [PASS] test_comment_hash_in_double_quotes")


def test_comment_hash_in_single_quotes():
    """# inside single quotes should not be treated as comment"""
    extractor = CommentExtractor()
    line = "Name = 'Item #1'  # the first item"
    result = extractor._extract_inline_comment(line, 1)
    assert result == "the first item", f"Expected 'the first item', got {result!r}"
    print("  [PASS] test_comment_hash_in_single_quotes")


def test_comment_no_comment():
    """Line with no comment returns None"""
    extractor = CommentExtractor()
    line = 'Value = "no comment here"'
    result = extractor._extract_inline_comment(line, 1)
    assert result is None, f"Expected None, got {result!r}"
    print("  [PASS] test_comment_no_comment")


def test_comment_postup_with_hash():
    """PostUp command with quoted hash"""
    extractor = CommentExtractor()
    line = 'PostUp = echo "Hello World" | logger'
    result = extractor._extract_inline_comment(line, 1)
    assert result is None, f"Expected None, got {result!r}"
    print("  [PASS] test_comment_postup_with_hash")


def test_comment_iptables_with_comment():
    """iptables command with actual comment"""
    extractor = CommentExtractor()
    line = "PostUp = iptables -A FORWARD -i %i -j ACCEPT  # Allow forwarding"
    result = extractor._extract_inline_comment(line, 1)
    assert result == "Allow forwarding", f"Expected 'Allow forwarding', got {result!r}"
    print("  [PASS] test_comment_iptables_with_comment")


# =============================================================================
# ENDPOINT VALIDATION TESTS
# =============================================================================

def test_endpoint_valid_hostname_port():
    """Valid hostname:port format"""
    assert validate_endpoint("cs.example.com:51820") == True
    print("  [PASS] test_endpoint_valid_hostname_port")


def test_endpoint_valid_ip_port():
    """Valid IP:port format"""
    assert validate_endpoint("192.168.1.1:51820") == True
    print("  [PASS] test_endpoint_valid_ip_port")


def test_endpoint_valid_hostname_only():
    """Valid hostname without port"""
    assert validate_endpoint("myhost") == True
    print("  [PASS] test_endpoint_valid_hostname_only")


def test_endpoint_valid_hyphenated():
    """Valid hyphenated hostname"""
    assert validate_endpoint("my-host.example.com") == True
    print("  [PASS] test_endpoint_valid_hyphenated")


def test_endpoint_empty():
    """Empty endpoint is invalid"""
    assert validate_endpoint("") == False
    print("  [PASS] test_endpoint_empty")


def test_endpoint_no_host():
    """Port without host is invalid"""
    assert validate_endpoint(":51820") == False
    print("  [PASS] test_endpoint_no_host")


def test_endpoint_non_numeric_port():
    """Non-numeric port is invalid"""
    assert validate_endpoint("host:abc") == False
    print("  [PASS] test_endpoint_non_numeric_port")


def test_endpoint_port_out_of_range():
    """Port out of range is invalid"""
    assert validate_endpoint("host:99999") == False
    print("  [PASS] test_endpoint_port_out_of_range")


def test_endpoint_port_zero():
    """Port zero is invalid"""
    assert validate_endpoint("host:0") == False
    print("  [PASS] test_endpoint_port_zero")


# =============================================================================
# ROTATION POLICIES DEPLOY INTEGRATION TESTS
# =============================================================================

def test_rotation_policy_manager_init():
    """RotationPolicyManager initializes correctly"""
    db_path = create_test_db('-rotation')
    try:
        manager = RotationPolicyManager(db_path)
        assert manager is not None
        print("  [PASS] test_rotation_policy_manager_init")
    finally:
        cleanup_db(db_path)


def test_rotation_deploy_method_exists():
    """_deploy_after_rotation method exists"""
    db_path = create_test_db('-rotation2')
    try:
        manager = RotationPolicyManager(db_path)
        assert hasattr(manager, '_deploy_after_rotation')
        assert callable(manager._deploy_after_rotation)
        print("  [PASS] test_rotation_deploy_method_exists")
    finally:
        cleanup_db(db_path)


def test_rotation_execute_with_auto_deploy_flag():
    """execute_pending_rotations accepts auto_deploy parameter"""
    db_path = create_test_db('-rotation3')
    try:
        manager = RotationPolicyManager(db_path)
        # Should not raise an error
        results = manager.execute_pending_rotations(auto_deploy=True, dry_run=True)
        assert isinstance(results, list)
        print("  [PASS] test_rotation_execute_with_auto_deploy_flag")
    finally:
        cleanup_db(db_path)


# =============================================================================
# DISASTER RECOVERY MERGE TESTS
# =============================================================================

def test_disaster_recovery_merge_method_exists():
    """_merge_databases method exists"""
    db_path = create_test_db('-dr1')
    try:
        dr = DisasterRecovery(db_path)
        assert hasattr(dr, '_merge_databases')
        assert callable(dr._merge_databases)
        print("  [PASS] test_disaster_recovery_merge_method_exists")
    finally:
        cleanup_db(db_path)


def test_disaster_recovery_merge_new_entities():
    """Merge adds new entities from backup"""
    current_db = create_test_db('-dr-current')
    backup_db = create_test_db('-dr-backup')

    try:
        # Add an extra entity to backup that doesn't exist in current
        backup_conn = sqlite3.connect(backup_db)
        backup_conn.row_factory = sqlite3.Row
        extra_private, extra_public = generate_keypair()
        backup_conn.execute("""
            INSERT INTO remote (
                cs_id, permanent_guid, current_public_key, hostname,
                ipv4_address, ipv6_address, private_key,
                access_level, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            1,
            extra_public,
            extra_public,
            'extra-remote',
            '10.66.0.40/32',
            'fd66::40/128',
            extra_private,
            'full',
            datetime.now().isoformat()
        ))
        backup_conn.commit()
        backup_conn.close()

        # Count remotes before merge
        current_conn = sqlite3.connect(current_db)
        before_count = current_conn.execute("SELECT COUNT(*) FROM remote").fetchone()[0]
        current_conn.close()

        # Perform merge
        dr = DisasterRecovery(current_db)
        result = dr._merge_databases(Path(backup_db))

        # Count remotes after merge
        current_conn = sqlite3.connect(current_db)
        after_count = current_conn.execute("SELECT COUNT(*) FROM remote").fetchone()[0]
        current_conn.close()

        assert after_count > before_count, f"Expected more remotes after merge, got {before_count} -> {after_count}"
        assert result['merged']['remote'] >= 1, f"Expected at least 1 remote merged, got {result['merged']['remote']}"
        print("  [PASS] test_disaster_recovery_merge_new_entities")

    finally:
        cleanup_db(current_db)
        cleanup_db(backup_db)


def test_disaster_recovery_merge_keeps_newer():
    """Merge keeps newer version when entity exists"""
    current_db = create_test_db('-dr-newer1')

    try:
        # Get the remote's GUID from current DB
        current_conn = sqlite3.connect(current_db)
        current_conn.row_factory = sqlite3.Row
        current_remote = current_conn.execute("SELECT * FROM remote WHERE id = 1").fetchone()
        guid = current_remote['permanent_guid']

        # Update current to have a newer timestamp and different hostname
        newer_time = (datetime.now() + timedelta(hours=1)).isoformat()
        current_conn.execute("""
            UPDATE remote SET hostname = 'current-newer', updated_at = ?
            WHERE permanent_guid = ?
        """, (newer_time, guid))
        current_conn.commit()
        current_conn.close()

        # Create backup by copying current and modifying
        backup_db = current_db + '.backup'
        shutil.copy2(current_db, backup_db)

        # Update backup to have an older timestamp
        backup_conn = sqlite3.connect(backup_db)
        older_time = (datetime.now() - timedelta(hours=1)).isoformat()
        backup_conn.execute("""
            UPDATE remote SET hostname = 'backup-older', updated_at = ?
            WHERE permanent_guid = ?
        """, (older_time, guid))
        backup_conn.commit()
        backup_conn.close()

        # Perform merge
        dr = DisasterRecovery(current_db)
        result = dr._merge_databases(Path(backup_db))

        # Check that current (newer) was kept
        current_conn = sqlite3.connect(current_db)
        current_conn.row_factory = sqlite3.Row
        merged_remote = current_conn.execute(
            "SELECT hostname FROM remote WHERE permanent_guid = ?", (guid,)
        ).fetchone()
        current_conn.close()

        assert merged_remote['hostname'] == 'current-newer', \
            f"Expected 'current-newer', got {merged_remote['hostname']!r}"
        assert result['skipped'] >= 1, f"Expected at least 1 skipped, got {result['skipped']}"
        print("  [PASS] test_disaster_recovery_merge_keeps_newer")

    finally:
        cleanup_db(current_db)
        cleanup_db(current_db + '.backup')


def test_disaster_recovery_merge_updates_older():
    """Merge updates current when backup is newer"""
    current_db = create_test_db('-dr-older1')

    try:
        # Get the remote's GUID from current DB
        current_conn = sqlite3.connect(current_db)
        current_conn.row_factory = sqlite3.Row
        current_remote = current_conn.execute("SELECT * FROM remote WHERE id = 1").fetchone()
        guid = current_remote['permanent_guid']

        # Update current to have an older timestamp
        older_time = (datetime.now() - timedelta(hours=1)).isoformat()
        current_conn.execute("""
            UPDATE remote SET hostname = 'current-older', updated_at = ?
            WHERE permanent_guid = ?
        """, (older_time, guid))
        current_conn.commit()
        current_conn.close()

        # Create backup by copying current and modifying
        backup_db = current_db + '.backup'
        shutil.copy2(current_db, backup_db)

        # Update backup to have a newer timestamp
        backup_conn = sqlite3.connect(backup_db)
        newer_time = (datetime.now() + timedelta(hours=1)).isoformat()
        backup_conn.execute("""
            UPDATE remote SET hostname = 'backup-newer', updated_at = ?
            WHERE permanent_guid = ?
        """, (newer_time, guid))
        backup_conn.commit()
        backup_conn.close()

        # Perform merge
        dr = DisasterRecovery(current_db)
        result = dr._merge_databases(Path(backup_db))

        # Check that backup (newer) was applied
        current_conn = sqlite3.connect(current_db)
        current_conn.row_factory = sqlite3.Row
        merged_remote = current_conn.execute(
            "SELECT hostname FROM remote WHERE permanent_guid = ?", (guid,)
        ).fetchone()
        current_conn.close()

        assert merged_remote['hostname'] == 'backup-newer', \
            f"Expected 'backup-newer', got {merged_remote['hostname']!r}"
        assert result['merged']['remote'] >= 1, f"Expected at least 1 merged, got {result['merged']}"
        print("  [PASS] test_disaster_recovery_merge_updates_older")

    finally:
        cleanup_db(current_db)
        cleanup_db(current_db + '.backup')


# =============================================================================
# TEST RUNNER
# =============================================================================

def main():
    print("=" * 60)
    print("TODO FIX TESTS")
    print("=" * 60)

    all_tests = [
        # Comment system tests
        ("Comment System", [
            test_comment_simple_inline,
            test_comment_hash_in_double_quotes,
            test_comment_hash_in_single_quotes,
            test_comment_no_comment,
            test_comment_postup_with_hash,
            test_comment_iptables_with_comment,
        ]),
        # Endpoint validation tests
        ("Endpoint Validation", [
            test_endpoint_valid_hostname_port,
            test_endpoint_valid_ip_port,
            test_endpoint_valid_hostname_only,
            test_endpoint_valid_hyphenated,
            test_endpoint_empty,
            test_endpoint_no_host,
            test_endpoint_non_numeric_port,
            test_endpoint_port_out_of_range,
            test_endpoint_port_zero,
        ]),
        # Rotation policies tests
        ("Rotation Policies Deploy", [
            test_rotation_policy_manager_init,
            test_rotation_deploy_method_exists,
            test_rotation_execute_with_auto_deploy_flag,
        ]),
        # Disaster recovery tests
        ("Disaster Recovery Merge", [
            test_disaster_recovery_merge_method_exists,
            test_disaster_recovery_merge_new_entities,
            test_disaster_recovery_merge_keeps_newer,
            test_disaster_recovery_merge_updates_older,
        ]),
    ]

    total_passed = 0
    total_failed = 0

    for category_name, tests in all_tests:
        print(f"\n{category_name}:")
        for test in tests:
            try:
                test()
                total_passed += 1
            except AssertionError as e:
                print(f"  [FAIL] {test.__name__}: {e}")
                total_failed += 1
            except Exception as e:
                print(f"  [ERROR] {test.__name__}: {e}")
                total_failed += 1

    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    print(f"Total: {total_passed + total_failed}")
    print(f"Passed: {total_passed}")
    print(f"Failed: {total_failed}")

    return 0 if total_failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
