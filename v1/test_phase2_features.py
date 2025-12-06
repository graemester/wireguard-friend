"""
Phase 2 Feature Tests - Innovation Roadmap 2025

Test coverage for Phase 2 implementation modules:
1. Compliance Reporting (SOC2, ISO27001 style reports)
2. Intelligent Alerting (thresholds, notification channels)
3. Prometheus Metrics Export
4. Webhook Notifications
5. PSK Management Automation
6. Troubleshooting Wizard

Run with: python3 v1/test_phase2_features.py
Or with pytest: pytest v1/test_phase2_features.py -v
"""

import os
import json
import sqlite3
import tempfile
from datetime import datetime, timedelta
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
# COMPLIANCE REPORTING TESTS
# =============================================================================

def test_compliance_reporting_imports():
    """Compliance reporting module should import without errors."""
    from v1.compliance_reporting import ComplianceReporter, ReportType, OutputFormat
    assert ReportType.FULL_COMPLIANCE.value == "full_compliance"
    assert OutputFormat.MARKDOWN.value == "markdown"
    print("  [PASS] test_compliance_reporting_imports")


def test_compliance_reporter_init():
    """ComplianceReporter should initialize correctly."""
    from v1.compliance_reporting import ComplianceReporter

    db, db_path = create_test_db()
    try:
        cr = ComplianceReporter(db_path)
        assert cr.db_path == db_path
        print("  [PASS] test_compliance_reporter_init")
    finally:
        os.unlink(db_path)


def test_generate_network_inventory_report():
    """Should generate network inventory report."""
    from v1.compliance_reporting import ComplianceReporter, ReportType

    db, db_path = create_test_db()
    try:
        cr = ComplianceReporter(db_path)
        report = cr.generate_report(ReportType.NETWORK_INVENTORY)

        assert report.report_type == ReportType.NETWORK_INVENTORY
        # Inventory contains coordination_servers, remotes, etc.
        assert "summary" in report.data
        assert "remotes" in report.data
        print("  [PASS] test_generate_network_inventory_report")
    finally:
        os.unlink(db_path)


def test_generate_executive_summary():
    """Should generate executive summary report."""
    from v1.compliance_reporting import ComplianceReporter, ReportType

    db, db_path = create_test_db()
    try:
        cr = ComplianceReporter(db_path)
        report = cr.generate_report(ReportType.EXECUTIVE_SUMMARY)

        assert report.report_type == ReportType.EXECUTIVE_SUMMARY
        assert report.data is not None
        print("  [PASS] test_generate_executive_summary")
    finally:
        os.unlink(db_path)


def test_json_output_format():
    """Should generate JSON formatted report."""
    from v1.compliance_reporting import ComplianceReporter, ReportType

    db, db_path = create_test_db()
    try:
        cr = ComplianceReporter(db_path)
        report = cr.generate_report(ReportType.NETWORK_INVENTORY)

        # Convert to dict and then to JSON
        report_dict = report.to_dict()
        json_str = json.dumps(report_dict)

        # Should be valid JSON
        data = json.loads(json_str)
        assert isinstance(data, dict)
        assert "report_type" in data
        print("  [PASS] test_json_output_format")
    finally:
        os.unlink(db_path)


# =============================================================================
# INTELLIGENT ALERTING TESTS
# =============================================================================

def test_alerting_imports():
    """Alerting module should import without errors."""
    from v1.alerting import AlertManager, AlertType, ChannelType, AlertRule, AlertSeverity
    assert AlertType.PEER_OFFLINE.value == "peer_offline"
    assert ChannelType.LOCAL.value == "local"
    print("  [PASS] test_alerting_imports")


def test_alerting_tables_created():
    """AlertManager should create necessary tables."""
    from v1.alerting import AlertManager

    db, db_path = create_test_db()
    try:
        am = AlertManager(db_path)

        conn = sqlite3.connect(db_path)
        tables = conn.execute("""
            SELECT name FROM sqlite_master WHERE type='table'
            AND name LIKE 'alert%'
        """).fetchall()
        conn.close()

        table_names = [t[0] for t in tables]
        assert any('alert' in t.lower() for t in table_names)
        print("  [PASS] test_alerting_tables_created")
    finally:
        os.unlink(db_path)


def test_create_alert_rule():
    """Should create alert rules."""
    from v1.alerting import AlertManager, AlertType, AlertSeverity

    db, db_path = create_test_db()
    try:
        am = AlertManager(db_path)

        rule_id = am.create_rule(
            name="Test Peer Offline Rule",
            alert_type=AlertType.PEER_OFFLINE,
            severity=AlertSeverity.WARNING,
            threshold_value=180,
            threshold_unit="minutes",
            cooldown_minutes=30
        )

        assert rule_id > 0

        rules = am.get_rules(enabled_only=False)
        assert len(rules) >= 1
        print("  [PASS] test_create_alert_rule")
    finally:
        os.unlink(db_path)


def test_alert_active_alerts():
    """Should get active alerts."""
    from v1.alerting import AlertManager

    db, db_path = create_test_db()
    try:
        am = AlertManager(db_path)

        # Get active alerts (may be empty)
        alerts = am.get_active_alerts()

        # Should return a list
        assert isinstance(alerts, list)
        print("  [PASS] test_alert_active_alerts")
    finally:
        os.unlink(db_path)


# =============================================================================
# PROMETHEUS METRICS TESTS
# =============================================================================

def test_prometheus_imports():
    """Prometheus metrics module should import without errors."""
    from v1.prometheus_metrics import (
        PrometheusMetricsCollector, MetricType, Metric, MetricValue
    )
    assert MetricType.GAUGE.value == "gauge"
    assert MetricType.COUNTER.value == "counter"
    print("  [PASS] test_prometheus_imports")


def test_metrics_collector_init():
    """PrometheusMetricsCollector should initialize correctly."""
    from v1.prometheus_metrics import PrometheusMetricsCollector

    db, db_path = create_test_db()
    try:
        collector = PrometheusMetricsCollector(db_path)
        assert collector.db_path == db_path
        print("  [PASS] test_metrics_collector_init")
    finally:
        os.unlink(db_path)


def test_collect_entity_metrics():
    """Should collect entity count metrics."""
    from v1.prometheus_metrics import PrometheusMetricsCollector

    db, db_path = create_test_db()
    try:
        collector = PrometheusMetricsCollector(db_path)
        metrics = collector.collect_all_metrics()

        # Should have at least entity metrics
        metric_names = [m.name for m in metrics]
        assert any('entity' in name for name in metric_names)
        print("  [PASS] test_collect_entity_metrics")
    finally:
        os.unlink(db_path)


def test_prometheus_text_format():
    """Should format metrics in Prometheus text format."""
    from v1.prometheus_metrics import PrometheusMetricsCollector

    db, db_path = create_test_db()
    try:
        collector = PrometheusMetricsCollector(db_path)
        text = collector.get_metrics_text()

        # Should contain Prometheus format markers
        assert "# HELP" in text or "# TYPE" in text or text.strip() == ""
        print("  [PASS] test_prometheus_text_format")
    finally:
        os.unlink(db_path)


def test_metrics_server_class():
    """PrometheusMetricsServer should be importable."""
    from v1.prometheus_metrics import PrometheusMetricsServer, PrometheusMetricsCollector

    db, db_path = create_test_db()
    try:
        collector = PrometheusMetricsCollector(db_path)
        # Just test instantiation, don't actually start the server
        server = PrometheusMetricsServer(collector, host="127.0.0.1", port=19100)
        assert server.port == 19100
        print("  [PASS] test_metrics_server_class")
    finally:
        os.unlink(db_path)


# =============================================================================
# WEBHOOK NOTIFICATIONS TESTS
# =============================================================================

def test_webhook_imports():
    """Webhook notifications module should import without errors."""
    from v1.webhook_notifications import (
        WebhookNotifier, WebhookFormat, DeliveryStatus, WebhookEndpoint
    )
    assert WebhookFormat.SLACK.value == "slack"
    assert WebhookFormat.DISCORD.value == "discord"
    assert DeliveryStatus.PENDING.value == "pending"
    print("  [PASS] test_webhook_imports")


def test_webhook_tables_created():
    """WebhookNotifier should create necessary tables."""
    from v1.webhook_notifications import WebhookNotifier

    db, db_path = create_test_db()
    try:
        wn = WebhookNotifier(db_path)

        conn = sqlite3.connect(db_path)
        tables = conn.execute("""
            SELECT name FROM sqlite_master WHERE type='table'
            AND name LIKE 'webhook_%'
        """).fetchall()
        conn.close()

        table_names = [t[0] for t in tables]
        assert 'webhook_endpoint' in table_names
        assert 'webhook_delivery' in table_names
        print("  [PASS] test_webhook_tables_created")
    finally:
        os.unlink(db_path)


def test_add_webhook_endpoint():
    """Should add webhook endpoint."""
    from v1.webhook_notifications import WebhookNotifier, WebhookEndpoint, WebhookFormat

    db, db_path = create_test_db()
    try:
        wn = WebhookNotifier(db_path)

        endpoint = WebhookEndpoint(
            name="Test Slack",
            url="https://hooks.slack.com/services/test",
            format=WebhookFormat.SLACK,
            min_severity="warning"
        )

        endpoint_id = wn.add_endpoint(endpoint)
        assert endpoint_id > 0

        retrieved = wn.get_endpoint(endpoint_id)
        assert retrieved is not None
        assert retrieved.name == "Test Slack"
        print("  [PASS] test_add_webhook_endpoint")
    finally:
        os.unlink(db_path)


def test_format_slack_payload():
    """Should format Slack webhook payload correctly."""
    from v1.webhook_notifications import WebhookNotifier, WebhookFormat

    db, db_path = create_test_db()
    try:
        wn = WebhookNotifier(db_path)

        payload = wn._format_payload(
            WebhookFormat.SLACK,
            "peer_offline",
            "warning",
            "Peer Offline",
            "alice has been offline for 5 minutes",
            {"peer": "alice", "duration": 300}
        )

        data = json.loads(payload)
        assert "attachments" in data
        print("  [PASS] test_format_slack_payload")
    finally:
        os.unlink(db_path)


def test_format_discord_payload():
    """Should format Discord webhook payload correctly."""
    from v1.webhook_notifications import WebhookNotifier, WebhookFormat

    db, db_path = create_test_db()
    try:
        wn = WebhookNotifier(db_path)

        payload = wn._format_payload(
            WebhookFormat.DISCORD,
            "key_expiry",
            "critical",
            "Key Expiring",
            "Key for bob expires in 7 days",
            {"peer": "bob", "days": 7}
        )

        data = json.loads(payload)
        assert "embeds" in data
        print("  [PASS] test_format_discord_payload")
    finally:
        os.unlink(db_path)


def test_webhook_delivery_stats():
    """Should get delivery statistics."""
    from v1.webhook_notifications import WebhookNotifier

    db, db_path = create_test_db()
    try:
        wn = WebhookNotifier(db_path)
        stats = wn.get_delivery_stats()

        assert "pending" in stats
        assert "delivered" in stats
        assert "failed" in stats
        print("  [PASS] test_webhook_delivery_stats")
    finally:
        os.unlink(db_path)


# =============================================================================
# PSK MANAGEMENT TESTS
# =============================================================================

def test_psk_imports():
    """PSK management module should import without errors."""
    from v1.psk_management import PSKManager, PSKPolicy, PSKRotationTrigger
    assert PSKPolicy.REQUIRED.value == "required"
    assert PSKRotationTrigger.TIME_BASED.value == "time_based"
    print("  [PASS] test_psk_imports")


def test_psk_tables_created():
    """PSKManager should create necessary tables."""
    from v1.psk_management import PSKManager

    db, db_path = create_test_db()
    try:
        pm = PSKManager(db_path)

        conn = sqlite3.connect(db_path)
        tables = conn.execute("""
            SELECT name FROM sqlite_master WHERE type='table'
            AND name LIKE 'psk_%'
        """).fetchall()
        conn.close()

        table_names = [t[0] for t in tables]
        assert 'psk_config' in table_names
        assert 'psk_entry' in table_names
        print("  [PASS] test_psk_tables_created")
    finally:
        os.unlink(db_path)


def test_generate_psk():
    """Should generate valid WireGuard PSK."""
    from v1.psk_management import PSKManager

    psk = PSKManager.generate_psk()

    # WireGuard PSK is 44 chars base64
    assert len(psk) == 44
    assert psk.endswith('=')
    print("  [PASS] test_generate_psk")


def test_create_psk_entry():
    """Should create PSK for peer pair."""
    from v1.psk_management import PSKManager

    db, db_path = create_test_db()
    try:
        pm = PSKManager(db_path)

        psk, entry_id = pm.create_psk(
            "remote", 1,
            "coordination_server", 1,
            expiry_days=90
        )

        assert len(psk) == 44
        assert entry_id > 0

        entry = pm.get_psk_entry("remote", 1, "coordination_server", 1)
        assert entry is not None
        assert entry.id == entry_id
        print("  [PASS] test_create_psk_entry")
    finally:
        os.unlink(db_path)


def test_rotate_psk():
    """Should rotate existing PSK."""
    from v1.psk_management import PSKManager, PSKRotationTrigger

    db, db_path = create_test_db()
    try:
        pm = PSKManager(db_path)

        # Create initial PSK
        psk1, entry_id = pm.create_psk("remote", 1, "coordination_server", 1)

        # Rotate it
        psk2, _ = pm.rotate_psk(
            "remote", 1, "coordination_server", 1,
            trigger=PSKRotationTrigger.MANUAL
        )

        assert psk1 != psk2
        assert len(psk2) == 44

        # Check rotation count increased
        entry = pm.get_psk_entry("remote", 1, "coordination_server", 1)
        assert entry.rotation_count >= 1
        print("  [PASS] test_rotate_psk")
    finally:
        os.unlink(db_path)


def test_psk_policy():
    """Should set and get PSK policy."""
    from v1.psk_management import PSKManager, PSKPolicy

    db, db_path = create_test_db()
    try:
        pm = PSKManager(db_path)

        config_id = pm.set_policy(
            entity_type="remote",
            entity_id=1,
            policy=PSKPolicy.REQUIRED,
            rotation_days=30
        )

        assert config_id > 0

        policy = pm.get_policy("remote", 1)
        assert policy is not None
        assert policy.policy == PSKPolicy.REQUIRED
        assert policy.rotation_days == 30
        print("  [PASS] test_psk_policy")
    finally:
        os.unlink(db_path)


def test_psk_stats():
    """Should get PSK statistics."""
    from v1.psk_management import PSKManager

    db, db_path = create_test_db()
    try:
        pm = PSKManager(db_path)

        # Create a PSK
        pm.create_psk("remote", 1, "coordination_server", 1)

        stats = pm.get_psk_stats()

        assert "total_psks" in stats
        assert stats["total_psks"] >= 1
        print("  [PASS] test_psk_stats")
    finally:
        os.unlink(db_path)


# =============================================================================
# TROUBLESHOOTING WIZARD TESTS
# =============================================================================

def test_troubleshooting_imports():
    """Troubleshooting wizard module should import without errors."""
    from v1.troubleshooting_wizard import (
        TroubleshootingWizard, DiagnosticResult, IssueCategory
    )
    assert DiagnosticResult.PASS.value == "pass"
    assert DiagnosticResult.FAIL.value == "fail"
    assert IssueCategory.CONNECTIVITY.value == "connectivity"
    print("  [PASS] test_troubleshooting_imports")


def test_troubleshooting_session():
    """Should create troubleshooting session."""
    from v1.troubleshooting_wizard import TroubleshootingWizard

    db, db_path = create_test_db()
    try:
        wizard = TroubleshootingWizard(db_path)
        session = wizard.start_session()

        assert session.id.startswith("ts_")
        assert session.started_at is not None
        print("  [PASS] test_troubleshooting_session")
    finally:
        os.unlink(db_path)


def test_run_diagnostic():
    """Should run full diagnostic."""
    from v1.troubleshooting_wizard import TroubleshootingWizard, DiagnosticResult

    db, db_path = create_test_db()
    try:
        wizard = TroubleshootingWizard(db_path)
        session = wizard.run_full_diagnostic()

        assert len(session.checks) > 0
        assert session.summary != ""
        assert session.completed_at is not None
        print("  [PASS] test_run_diagnostic")
    finally:
        os.unlink(db_path)


def test_diagnostic_report_text():
    """Should export diagnostic report as text."""
    from v1.troubleshooting_wizard import TroubleshootingWizard

    db, db_path = create_test_db()
    try:
        wizard = TroubleshootingWizard(db_path)
        session = wizard.run_full_diagnostic()
        report = wizard.export_report(session, format="text")

        assert "DIAGNOSTIC REPORT" in report
        assert "DIAGNOSTIC CHECKS" in report
        print("  [PASS] test_diagnostic_report_text")
    finally:
        os.unlink(db_path)


def test_diagnostic_report_json():
    """Should export diagnostic report as JSON."""
    from v1.troubleshooting_wizard import TroubleshootingWizard

    db, db_path = create_test_db()
    try:
        wizard = TroubleshootingWizard(db_path)
        session = wizard.run_full_diagnostic()
        report = wizard.export_report(session, format="json")

        data = json.loads(report)
        assert "session_id" in data
        assert "checks" in data
        print("  [PASS] test_diagnostic_report_json")
    finally:
        os.unlink(db_path)


def test_remediation_steps():
    """Should get remediation steps from session."""
    from v1.troubleshooting_wizard import TroubleshootingWizard

    db, db_path = create_test_db()
    try:
        wizard = TroubleshootingWizard(db_path)
        session = wizard.run_full_diagnostic()
        steps = wizard.get_remediation_steps(session)

        # Steps should be a list (may be empty if all pass)
        assert isinstance(steps, list)
        print("  [PASS] test_remediation_steps")
    finally:
        os.unlink(db_path)


def test_quick_diagnostic():
    """Quick diagnostic helper should work."""
    from v1.troubleshooting_wizard import quick_diagnostic

    db, db_path = create_test_db()
    try:
        result = quick_diagnostic(db_path)

        assert "summary" in result
        assert "passed" in result
        assert "failed" in result
        print("  [PASS] test_quick_diagnostic")
    finally:
        os.unlink(db_path)


# =============================================================================
# MAIN EXECUTION
# =============================================================================

def run_all_tests():
    """Run all tests."""
    import traceback

    tests = [
        # Compliance Reporting
        test_compliance_reporting_imports,
        test_compliance_reporter_init,
        test_generate_network_inventory_report,
        test_generate_executive_summary,
        test_json_output_format,
        # Intelligent Alerting
        test_alerting_imports,
        test_alerting_tables_created,
        test_create_alert_rule,
        test_alert_active_alerts,
        # Prometheus Metrics
        test_prometheus_imports,
        test_metrics_collector_init,
        test_collect_entity_metrics,
        test_prometheus_text_format,
        test_metrics_server_class,
        # Webhook Notifications
        test_webhook_imports,
        test_webhook_tables_created,
        test_add_webhook_endpoint,
        test_format_slack_payload,
        test_format_discord_payload,
        test_webhook_delivery_stats,
        # PSK Management
        test_psk_imports,
        test_psk_tables_created,
        test_generate_psk,
        test_create_psk_entry,
        test_rotate_psk,
        test_psk_policy,
        test_psk_stats,
        # Troubleshooting Wizard
        test_troubleshooting_imports,
        test_troubleshooting_session,
        test_run_diagnostic,
        test_diagnostic_report_text,
        test_diagnostic_report_json,
        test_remediation_steps,
        test_quick_diagnostic,
    ]

    passed = 0
    failed = 0
    errors = []

    print("=" * 60)
    print("PHASE 2 FEATURE TESTS")
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
            if "Traceback" in err:
                # Print last line of traceback
                print(f"    {err.strip().split(chr(10))[-1]}")

    return failed == 0


if __name__ == '__main__':
    import sys
    success = run_all_tests()
    sys.exit(0 if success else 1)
