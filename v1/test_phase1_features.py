"""
Phase 1 Feature Tests - Innovation Roadmap 2025

Test coverage for Phase 1 implementation modules:
1. Database Encryption (AES-256-GCM)
2. Audit Logging (hash chain integrity)
3. Rotation Policies (scheduled, usage-based, event-based)
4. Bandwidth Tracking (sampling, aggregation)
5. Exit Node Failover (health checks, circuit breaker)
6. Configuration Drift Detection
7. Disaster Recovery (backup/restore)
8. Dashboard TUI Components

Run with: python3 v1/test_phase1_features.py
Or with pytest: pytest v1/test_phase1_features.py -v
"""

import os
import sqlite3
import tempfile
from datetime import datetime
from pathlib import Path

# Optional pytest support
try:
    import pytest
    PYTEST_AVAILABLE = True
except ImportError:
    PYTEST_AVAILABLE = False
    class pytest:
        @staticmethod
        def fixture(func):
            return func

from v1.schema_semantic import WireGuardDBv2
from v1.keygen import generate_keypair


# =============================================================================
# FIXTURES
# =============================================================================

def create_test_db():
    """Create a temporary database with test data"""
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
        db_path = str(f.name)

    db = WireGuardDBv2(db_path)

    with db._connection() as conn:
        cursor = conn.cursor()

        privkey, pubkey = generate_keypair()
        cursor.execute("""
            INSERT INTO coordination_server (
                permanent_guid, current_public_key, hostname,
                endpoint, listen_port, network_ipv4, network_ipv6,
                ipv4_address, ipv6_address, private_key
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            pubkey, pubkey, 'test-cs',
            'cs.example.com', 51820, '10.66.0.0/24', 'fd66::/64',
            '10.66.0.1/32', 'fd66::1/128', privkey
        ))

        for i, name in enumerate(['alice', 'bob', 'carol'], start=10):
            privkey, pubkey = generate_keypair()
            cursor.execute("""
                INSERT INTO remote (
                    cs_id, permanent_guid, current_public_key, hostname,
                    ipv4_address, ipv6_address, private_key, access_level
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                1, pubkey, pubkey, name,
                f'10.66.0.{i}/32', f'fd66::{i:x}/128', privkey, 'full_access'
            ))

    return db, db_path


# =============================================================================
# ENCRYPTION TESTS
# =============================================================================

def test_encryption_module_imports():
    """Encryption module should import without errors."""
    from v1.encryption import SecureColumn, EncryptionManager, ENCRYPTED_PREFIX
    assert ENCRYPTED_PREFIX == "enc:v1:"
    print("  [PASS] test_encryption_module_imports")


def test_secure_column_with_derived_key():
    """SecureColumn should encrypt and decrypt with proper key."""
    from v1.encryption import SecureColumn
    import hashlib

    # Derive a proper 32-byte key
    key = hashlib.sha256(b"test-password-123").digest()
    sc = SecureColumn(key)

    original = "my-secret-private-key"
    encrypted = sc.encrypt(original)
    decrypted = sc.decrypt(encrypted)

    assert encrypted != original
    assert encrypted.startswith("enc:v1:")
    assert decrypted == original
    print("  [PASS] test_secure_column_with_derived_key")


def test_encryption_manager_init():
    """EncryptionManager should initialize correctly."""
    from v1.encryption import EncryptionManager

    db, db_path = create_test_db()
    try:
        em = EncryptionManager(db_path)
        assert em.db_path == Path(db_path)
        assert not em.is_unlocked
        print("  [PASS] test_encryption_manager_init")
    finally:
        os.unlink(db_path)


# =============================================================================
# AUDIT LOG TESTS
# =============================================================================

def test_audit_log_module_imports():
    """Audit log module should import without errors."""
    from v1.audit_log import AuditLogger, EventType
    assert EventType.KEY_ROTATION.value == "key_rotation"
    print("  [PASS] test_audit_log_module_imports")


def test_audit_logger_creates_tables():
    """AuditLogger should create necessary tables."""
    from v1.audit_log import AuditLogger

    db, db_path = create_test_db()
    try:
        logger = AuditLogger(db_path)

        conn = sqlite3.connect(db_path)
        tables = conn.execute("""
            SELECT name FROM sqlite_master WHERE type='table'
            AND name = 'audit_log'
        """).fetchall()
        conn.close()

        assert len(tables) == 1
        print("  [PASS] test_audit_logger_creates_tables")
    finally:
        os.unlink(db_path)


# =============================================================================
# ROTATION POLICIES TESTS
# =============================================================================

def test_rotation_policies_imports():
    """Rotation policies module should import without errors."""
    from v1.rotation_policies import RotationPolicyManager, PolicyType
    assert PolicyType.TIME_BASED.value == "time"  # value is 'time' not 'time_based'
    print("  [PASS] test_rotation_policies_imports")


def test_rotation_policy_manager_init():
    """RotationPolicyManager should initialize and create tables."""
    from v1.rotation_policies import RotationPolicyManager

    db, db_path = create_test_db()
    try:
        rpm = RotationPolicyManager(db_path)

        conn = sqlite3.connect(db_path)
        tables = conn.execute("""
            SELECT name FROM sqlite_master WHERE type='table'
            AND name LIKE 'rotation_%'
        """).fetchall()
        conn.close()

        assert len(tables) >= 1
        print("  [PASS] test_rotation_policy_manager_init")
    finally:
        os.unlink(db_path)


# =============================================================================
# BANDWIDTH TRACKING TESTS
# =============================================================================

def test_bandwidth_tracking_imports():
    """Bandwidth tracking module should import without errors."""
    from v1.bandwidth_tracking import BandwidthTracker
    print("  [PASS] test_bandwidth_tracking_imports")


def test_bandwidth_tables_created():
    """BandwidthTracker should create necessary tables."""
    from v1.bandwidth_tracking import BandwidthTracker

    db, db_path = create_test_db()
    try:
        bt = BandwidthTracker(db_path)

        conn = sqlite3.connect(db_path)
        tables = conn.execute("""
            SELECT name FROM sqlite_master WHERE type='table'
            AND name LIKE 'bandwidth_%'
        """).fetchall()
        conn.close()

        table_names = [t[0] for t in tables]
        assert 'bandwidth_sample' in table_names
        assert 'bandwidth_aggregate' in table_names
        print("  [PASS] test_bandwidth_tables_created")
    finally:
        os.unlink(db_path)


# =============================================================================
# EXIT FAILOVER TESTS
# =============================================================================

def test_exit_failover_imports():
    """Exit failover module should import without errors."""
    from v1.exit_failover import ExitFailoverManager, FailoverStrategy, HealthStatus
    assert FailoverStrategy.PRIORITY.value == "priority"
    assert HealthStatus.HEALTHY.value == "healthy"
    print("  [PASS] test_exit_failover_imports")


def test_exit_failover_tables_created():
    """ExitFailoverManager should create necessary tables."""
    from v1.exit_failover import ExitFailoverManager

    db, db_path = create_test_db()
    try:
        efm = ExitFailoverManager(db_path)

        conn = sqlite3.connect(db_path)
        tables = conn.execute("""
            SELECT name FROM sqlite_master WHERE type='table'
            AND name LIKE 'exit_%'
        """).fetchall()
        conn.close()

        table_names = [t[0] for t in tables]
        assert 'exit_node_group' in table_names
        print("  [PASS] test_exit_failover_tables_created")
    finally:
        os.unlink(db_path)


def test_create_failover_group():
    """Should create exit node failover group."""
    from v1.exit_failover import ExitFailoverManager, FailoverStrategy

    db, db_path = create_test_db()
    try:
        efm = ExitFailoverManager(db_path)

        group_id = efm.create_group(
            name="us-west-exits",
            strategy=FailoverStrategy.PRIORITY
        )

        assert group_id > 0

        conn = sqlite3.connect(db_path)
        row = conn.execute("""
            SELECT * FROM exit_node_group WHERE id = ?
        """, (group_id,)).fetchone()
        conn.close()

        assert row is not None
        print("  [PASS] test_create_failover_group")
    finally:
        os.unlink(db_path)


# =============================================================================
# DRIFT DETECTION TESTS
# =============================================================================

def test_drift_detection_imports():
    """Drift detection module should import without errors."""
    from v1.drift_detection import DriftDetector, DriftType, DriftSeverity
    assert DriftType.PEER_ADDED.value == "peer_added"
    assert DriftSeverity.CRITICAL.value == "critical"
    print("  [PASS] test_drift_detection_imports")


def test_drift_tables_created():
    """DriftDetector should create necessary tables."""
    from v1.drift_detection import DriftDetector

    db, db_path = create_test_db()
    try:
        dd = DriftDetector(db_path)

        conn = sqlite3.connect(db_path)
        tables = conn.execute("""
            SELECT name FROM sqlite_master WHERE type='table'
            AND name LIKE 'drift_%'
        """).fetchall()
        conn.close()

        table_names = [t[0] for t in tables]
        assert 'drift_scan' in table_names
        assert 'drift_item' in table_names
        assert 'drift_baseline' in table_names
        print("  [PASS] test_drift_tables_created")
    finally:
        os.unlink(db_path)


def test_parse_wg_config():
    """Should parse WireGuard config format correctly."""
    from v1.drift_detection import DriftDetector

    db, db_path = create_test_db()
    try:
        dd = DriftDetector(db_path)

        config = """[Interface]
PrivateKey = testprivkey
Address = 10.66.0.1/24
ListenPort = 51820

[Peer]
PublicKey = peer1pubkey
AllowedIPs = 10.66.0.10/32
Endpoint = 1.2.3.4:51820

[Peer]
PublicKey = peer2pubkey
AllowedIPs = 10.66.0.11/32
PersistentKeepalive = 25
"""

        parsed = dd._parse_wg_config(config)

        assert 'interface' in parsed
        assert 'peers' in parsed
        assert len(parsed['peers']) == 2
        assert 'peer1pubkey' in parsed['peers']
        assert parsed['peers']['peer1pubkey']['allowedips'] == '10.66.0.10/32'
        print("  [PASS] test_parse_wg_config")
    finally:
        os.unlink(db_path)


# =============================================================================
# DISASTER RECOVERY TESTS
# =============================================================================

def test_disaster_recovery_imports():
    """Disaster recovery module should import without errors."""
    from v1.disaster_recovery import DisasterRecovery, BackupType, RestoreMode
    assert BackupType.FULL.value == "full"
    assert RestoreMode.REPLACE.value == "replace"
    print("  [PASS] test_disaster_recovery_imports")


def test_disaster_recovery_tables_created():
    """DisasterRecovery should create necessary tables."""
    from v1.disaster_recovery import DisasterRecovery

    db, db_path = create_test_db()
    try:
        with tempfile.TemporaryDirectory() as backup_dir:
            dr = DisasterRecovery(db_path, backup_dir)

            conn = sqlite3.connect(db_path)
            tables = conn.execute("""
                SELECT name FROM sqlite_master WHERE type='table'
                AND name LIKE 'backup_%'
            """).fetchall()
            conn.close()

            table_names = [t[0] for t in tables]
            assert 'backup_history' in table_names
        print("  [PASS] test_disaster_recovery_tables_created")
    finally:
        os.unlink(db_path)


def test_create_backup():
    """Should create backup archive."""
    from v1.disaster_recovery import DisasterRecovery, BackupType

    db, db_path = create_test_db()
    try:
        with tempfile.TemporaryDirectory() as backup_dir:
            dr = DisasterRecovery(db_path, backup_dir)
            backup_path = dr.create_backup(BackupType.FULL)

            assert os.path.exists(backup_path)
            assert backup_path.endswith('.tar.gz')
        print("  [PASS] test_create_backup")
    finally:
        os.unlink(db_path)


def test_verify_backup():
    """Should verify backup integrity."""
    from v1.disaster_recovery import DisasterRecovery, BackupType

    db, db_path = create_test_db()
    try:
        with tempfile.TemporaryDirectory() as backup_dir:
            dr = DisasterRecovery(db_path, backup_dir)
            backup_path = dr.create_backup(BackupType.FULL)

            result = dr.verify_backup(backup_path)

            assert result['valid']
            assert result['file_integrity']
        print("  [PASS] test_verify_backup")
    finally:
        os.unlink(db_path)


# =============================================================================
# DASHBOARD TESTS
# =============================================================================

def test_dashboard_imports():
    """Dashboard module should import without errors."""
    from v1.cli.dashboard import AlertManager, AlertSeverity, Alert
    assert AlertSeverity.CRITICAL == "critical"
    print("  [PASS] test_dashboard_imports")


def test_alert_manager_init():
    """AlertManager should initialize and create tables."""
    from v1.cli.dashboard import AlertManager

    db, db_path = create_test_db()
    try:
        am = AlertManager(db_path)

        conn = sqlite3.connect(db_path)
        tables = conn.execute("""
            SELECT name FROM sqlite_master WHERE type='table'
            AND name = 'tui_alert'
        """).fetchall()
        conn.close()

        assert len(tables) == 1
        print("  [PASS] test_alert_manager_init")
    finally:
        os.unlink(db_path)


def test_add_and_get_alerts():
    """Should add and retrieve alerts."""
    from v1.cli.dashboard import AlertManager, Alert, AlertSeverity

    db, db_path = create_test_db()
    try:
        am = AlertManager(db_path)

        alert = Alert(
            severity=AlertSeverity.WARNING,
            title="Test Alert",
            message="This is a test alert",
            entity_type="remote",
            entity_name="alice"
        )

        alert_id = am.add_alert(alert)
        assert alert_id > 0

        alerts = am.get_active_alerts()
        assert len(alerts) >= 1
        print("  [PASS] test_add_and_get_alerts")
    finally:
        os.unlink(db_path)


def test_dismiss_alerts():
    """Should dismiss alerts."""
    from v1.cli.dashboard import AlertManager, Alert, AlertSeverity

    db, db_path = create_test_db()
    try:
        am = AlertManager(db_path)

        alert = Alert(
            severity=AlertSeverity.INFO,
            title="Dismissable Alert",
            message="Will be dismissed"
        )
        am.add_alert(alert)

        am.dismiss_all()

        final = len(am.get_active_alerts())
        assert final == 0
        print("  [PASS] test_dismiss_alerts")
    finally:
        os.unlink(db_path)


# =============================================================================
# MAIN EXECUTION
# =============================================================================

def run_all_tests():
    """Run all tests."""
    import traceback

    tests = [
        # Encryption
        test_encryption_module_imports,
        test_secure_column_with_derived_key,
        test_encryption_manager_init,
        # Audit Log
        test_audit_log_module_imports,
        test_audit_logger_creates_tables,
        # Rotation Policies
        test_rotation_policies_imports,
        test_rotation_policy_manager_init,
        # Bandwidth Tracking
        test_bandwidth_tracking_imports,
        test_bandwidth_tables_created,
        # Exit Failover
        test_exit_failover_imports,
        test_exit_failover_tables_created,
        test_create_failover_group,
        # Drift Detection
        test_drift_detection_imports,
        test_drift_tables_created,
        test_parse_wg_config,
        # Disaster Recovery
        test_disaster_recovery_imports,
        test_disaster_recovery_tables_created,
        test_create_backup,
        test_verify_backup,
        # Dashboard
        test_dashboard_imports,
        test_alert_manager_init,
        test_add_and_get_alerts,
        test_dismiss_alerts,
    ]

    passed = 0
    failed = 0
    errors = []

    print("=" * 60)
    print("PHASE 1 FEATURE TESTS")
    print("=" * 60)

    for test in tests:
        try:
            test()
            passed += 1
        except AssertionError as e:
            print(f"  [FAIL] {test.__name__}: {e}")
            failed += 1
            errors.append((test.__name__, str(e)))
        except Exception as e:
            print(f"  [ERROR] {test.__name__}: {e}")
            failed += 1
            errors.append((test.__name__, traceback.format_exc()))

    print()
    print("=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    print(f"Total: {passed + failed}")
    print(f"Passed: {passed}")
    print(f"Failed: {failed}")

    if errors:
        print(f"\nFailed tests:")
        for name, err in errors:
            print(f"  - {name}")

    return failed == 0


if __name__ == '__main__':
    import sys
    success = run_all_tests()
    sys.exit(0 if success else 1)
