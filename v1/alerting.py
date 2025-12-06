"""
Intelligent Alerting System

Configurable alerts based on health metrics with multiple notification channels.

Alert Types:
- Peer Offline: No handshake in N minutes
- High Latency: Latency exceeds N ms
- Bandwidth Spike: Usage exceeds N% of baseline
- Key Expiry: Key not rotated in N days
- Exit Failover: Exit node group switched
- Connection Storm: N+ new connections in M seconds
- Drift Detected: Configuration drift found

Notification Channels:
- Local: Log file, TUI alerts
- Email: SMTP configuration
- Webhook: HTTP POST to arbitrary endpoint
- Slack/Discord: Native integrations (via webhook)
"""

import hashlib
import hmac
import json
import logging
import smtplib
import sqlite3
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from enum import Enum
from typing import List, Dict, Optional, Any, Callable

logger = logging.getLogger(__name__)


class AlertType(Enum):
    """Types of alerts."""
    PEER_OFFLINE = "peer_offline"
    HIGH_LATENCY = "high_latency"
    BANDWIDTH_SPIKE = "bandwidth_spike"
    KEY_EXPIRY = "key_expiry"
    EXIT_FAILOVER = "exit_failover"
    CONNECTION_STORM = "connection_storm"
    DRIFT_DETECTED = "drift_detected"
    HEALTH_DEGRADED = "health_degraded"
    BACKUP_OVERDUE = "backup_overdue"
    CUSTOM = "custom"


class ChannelType(Enum):
    """Notification channel types."""
    LOCAL = "local"
    EMAIL = "email"
    WEBHOOK = "webhook"
    SLACK = "slack"
    DISCORD = "discord"


class AlertSeverity(Enum):
    """Alert severity levels."""
    CRITICAL = "critical"
    WARNING = "warning"
    INFO = "info"


@dataclass
class AlertRule:
    """Alert rule configuration."""
    id: int
    name: str
    alert_type: AlertType
    severity: AlertSeverity
    threshold_value: int
    threshold_unit: str  # 'minutes', 'ms', 'percent', 'days', 'count'
    entity_filter: Optional[str]  # JSON filter or None for all
    enabled: bool
    cooldown_minutes: int
    channels: List[int]  # Channel IDs


@dataclass
class NotificationChannel:
    """Notification channel configuration."""
    id: int
    name: str
    channel_type: ChannelType
    config: Dict[str, Any]
    enabled: bool


@dataclass
class AlertEvent:
    """Single alert event."""
    id: Optional[int]
    rule_id: int
    rule_name: str
    alert_type: AlertType
    severity: AlertSeverity
    entity_type: Optional[str]
    entity_id: Optional[int]
    entity_name: Optional[str]
    message: str
    details: Dict[str, Any]
    triggered_at: datetime
    resolved_at: Optional[datetime]
    acknowledged: bool
    notified_channels: List[int]

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "alert_type": self.alert_type.value,
            "severity": self.severity.value,
            "entity_type": self.entity_type,
            "entity_id": self.entity_id,
            "entity_name": self.entity_name,
            "message": self.message,
            "details": self.details,
            "triggered_at": self.triggered_at.isoformat(),
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "acknowledged": self.acknowledged,
        }


class AlertManager:
    """
    Manages alert rules, notifications, and alert lifecycle.

    Usage:
        manager = AlertManager(db_path)

        # Create rule
        manager.create_rule(
            name="Peer Offline",
            alert_type=AlertType.PEER_OFFLINE,
            severity=AlertSeverity.WARNING,
            threshold_value=10,
            threshold_unit="minutes"
        )

        # Create channel
        manager.create_channel(
            name="Slack Alerts",
            channel_type=ChannelType.SLACK,
            config={"webhook_url": "https://..."}
        )

        # Check alerts
        alerts = manager.check_alerts()

        # Send notifications
        for alert in alerts:
            manager.notify(alert)
    """

    DEFAULT_RULES = [
        {
            "name": "Peer Offline (10 min)",
            "alert_type": AlertType.PEER_OFFLINE,
            "severity": AlertSeverity.WARNING,
            "threshold_value": 10,
            "threshold_unit": "minutes",
        },
        {
            "name": "Key Rotation Overdue (90 days)",
            "alert_type": AlertType.KEY_EXPIRY,
            "severity": AlertSeverity.WARNING,
            "threshold_value": 90,
            "threshold_unit": "days",
        },
        {
            "name": "Backup Overdue (7 days)",
            "alert_type": AlertType.BACKUP_OVERDUE,
            "severity": AlertSeverity.WARNING,
            "threshold_value": 7,
            "threshold_unit": "days",
        },
        {
            "name": "Configuration Drift",
            "alert_type": AlertType.DRIFT_DETECTED,
            "severity": AlertSeverity.CRITICAL,
            "threshold_value": 1,
            "threshold_unit": "count",
        },
    ]

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init_tables()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_tables(self):
        """Create alerting tables."""
        conn = self._get_conn()
        try:
            conn.executescript("""
                -- Alert rules
                CREATE TABLE IF NOT EXISTS alert_rule (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE NOT NULL,
                    alert_type TEXT NOT NULL,
                    severity TEXT NOT NULL DEFAULT 'warning',
                    threshold_value INTEGER NOT NULL,
                    threshold_unit TEXT NOT NULL,
                    entity_filter TEXT,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    cooldown_minutes INTEGER NOT NULL DEFAULT 60,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                );

                -- Notification channels
                CREATE TABLE IF NOT EXISTS notification_channel (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE NOT NULL,
                    channel_type TEXT NOT NULL,
                    config TEXT NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                );

                -- Rule-channel associations
                CREATE TABLE IF NOT EXISTS rule_channel (
                    rule_id INTEGER NOT NULL,
                    channel_id INTEGER NOT NULL,
                    PRIMARY KEY (rule_id, channel_id),
                    FOREIGN KEY (rule_id) REFERENCES alert_rule(id),
                    FOREIGN KEY (channel_id) REFERENCES notification_channel(id)
                );

                -- Alert history
                CREATE TABLE IF NOT EXISTS alert_event (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    rule_id INTEGER NOT NULL,
                    alert_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    entity_type TEXT,
                    entity_id INTEGER,
                    entity_name TEXT,
                    message TEXT NOT NULL,
                    details TEXT,
                    triggered_at TEXT NOT NULL,
                    resolved_at TEXT,
                    acknowledged INTEGER NOT NULL DEFAULT 0,
                    notified_channels TEXT,
                    FOREIGN KEY (rule_id) REFERENCES alert_rule(id)
                );

                -- Last alert time per rule/entity for cooldown
                CREATE TABLE IF NOT EXISTS alert_cooldown (
                    rule_id INTEGER NOT NULL,
                    entity_key TEXT NOT NULL,
                    last_alert_at TEXT NOT NULL,
                    PRIMARY KEY (rule_id, entity_key)
                );

                CREATE INDEX IF NOT EXISTS idx_alert_event_time
                    ON alert_event(triggered_at);
                CREATE INDEX IF NOT EXISTS idx_alert_event_resolved
                    ON alert_event(resolved_at);
            """)
            conn.commit()
        finally:
            conn.close()

    def create_rule(self, name: str, alert_type: AlertType,
                   severity: AlertSeverity = AlertSeverity.WARNING,
                   threshold_value: int = 10,
                   threshold_unit: str = "minutes",
                   entity_filter: str = None,
                   cooldown_minutes: int = 60,
                   channel_ids: List[int] = None) -> int:
        """Create an alert rule."""
        conn = self._get_conn()
        try:
            cursor = conn.execute("""
                INSERT INTO alert_rule
                (name, alert_type, severity, threshold_value, threshold_unit,
                 entity_filter, cooldown_minutes)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                name, alert_type.value, severity.value,
                threshold_value, threshold_unit, entity_filter, cooldown_minutes
            ))
            rule_id = cursor.lastrowid

            # Associate channels
            if channel_ids:
                for channel_id in channel_ids:
                    conn.execute("""
                        INSERT OR IGNORE INTO rule_channel (rule_id, channel_id)
                        VALUES (?, ?)
                    """, (rule_id, channel_id))

            conn.commit()
            return rule_id
        finally:
            conn.close()

    def create_channel(self, name: str, channel_type: ChannelType,
                      config: Dict[str, Any]) -> int:
        """Create a notification channel."""
        conn = self._get_conn()
        try:
            cursor = conn.execute("""
                INSERT INTO notification_channel (name, channel_type, config)
                VALUES (?, ?, ?)
            """, (name, channel_type.value, json.dumps(config)))
            conn.commit()
            return cursor.lastrowid
        finally:
            conn.close()

    def get_rules(self, enabled_only: bool = True) -> List[AlertRule]:
        """Get all alert rules."""
        conn = self._get_conn()
        try:
            query = "SELECT * FROM alert_rule"
            if enabled_only:
                query += " WHERE enabled = 1"

            rows = conn.execute(query).fetchall()
            rules = []

            for row in rows:
                # Get associated channels
                channels = conn.execute("""
                    SELECT channel_id FROM rule_channel WHERE rule_id = ?
                """, (row['id'],)).fetchall()

                rules.append(AlertRule(
                    id=row['id'],
                    name=row['name'],
                    alert_type=AlertType(row['alert_type']),
                    severity=AlertSeverity(row['severity']),
                    threshold_value=row['threshold_value'],
                    threshold_unit=row['threshold_unit'],
                    entity_filter=row['entity_filter'],
                    enabled=bool(row['enabled']),
                    cooldown_minutes=row['cooldown_minutes'],
                    channels=[c['channel_id'] for c in channels]
                ))

            return rules
        finally:
            conn.close()

    def get_channels(self, enabled_only: bool = True) -> List[NotificationChannel]:
        """Get all notification channels."""
        conn = self._get_conn()
        try:
            query = "SELECT * FROM notification_channel"
            if enabled_only:
                query += " WHERE enabled = 1"

            rows = conn.execute(query).fetchall()
            return [
                NotificationChannel(
                    id=row['id'],
                    name=row['name'],
                    channel_type=ChannelType(row['channel_type']),
                    config=json.loads(row['config']),
                    enabled=bool(row['enabled'])
                )
                for row in rows
            ]
        finally:
            conn.close()

    def check_alerts(self) -> List[AlertEvent]:
        """Check all rules and return triggered alerts."""
        alerts = []
        rules = self.get_rules(enabled_only=True)

        for rule in rules:
            rule_alerts = self._check_rule(rule)
            alerts.extend(rule_alerts)

        return alerts

    def _check_rule(self, rule: AlertRule) -> List[AlertEvent]:
        """Check a single rule and return any triggered alerts."""
        alerts = []

        if rule.alert_type == AlertType.PEER_OFFLINE:
            alerts = self._check_peer_offline(rule)
        elif rule.alert_type == AlertType.KEY_EXPIRY:
            alerts = self._check_key_expiry(rule)
        elif rule.alert_type == AlertType.BACKUP_OVERDUE:
            alerts = self._check_backup_overdue(rule)
        elif rule.alert_type == AlertType.DRIFT_DETECTED:
            alerts = self._check_drift_detected(rule)
        elif rule.alert_type == AlertType.HIGH_LATENCY:
            alerts = self._check_high_latency(rule)
        elif rule.alert_type == AlertType.BANDWIDTH_SPIKE:
            alerts = self._check_bandwidth_spike(rule)

        # Filter by cooldown
        alerts = [a for a in alerts if self._check_cooldown(rule, a)]

        return alerts

    def _check_peer_offline(self, rule: AlertRule) -> List[AlertEvent]:
        """Check for offline peers."""
        alerts = []
        conn = self._get_conn()

        try:
            # Check bandwidth_sample for last seen times
            threshold_time = datetime.now() - timedelta(minutes=rule.threshold_value)

            try:
                rows = conn.execute("""
                    SELECT r.id, r.hostname,
                           MAX(bs.sampled_at) as last_seen
                    FROM remote r
                    LEFT JOIN bandwidth_sample bs
                        ON bs.entity_type = 'remote' AND bs.entity_id = r.id
                    GROUP BY r.id
                    HAVING last_seen IS NULL OR last_seen < ?
                """, (threshold_time.isoformat(),)).fetchall()

                for row in rows:
                    alerts.append(AlertEvent(
                        id=None,
                        rule_id=rule.id,
                        rule_name=rule.name,
                        alert_type=rule.alert_type,
                        severity=rule.severity,
                        entity_type="remote",
                        entity_id=row['id'],
                        entity_name=row['hostname'],
                        message=f"Peer '{row['hostname']}' has not been seen in {rule.threshold_value} minutes",
                        details={"last_seen": row['last_seen']},
                        triggered_at=datetime.now(),
                        resolved_at=None,
                        acknowledged=False,
                        notified_channels=[]
                    ))
            except sqlite3.OperationalError:
                pass  # bandwidth_sample not available

        finally:
            conn.close()

        return alerts

    def _check_key_expiry(self, rule: AlertRule) -> List[AlertEvent]:
        """Check for keys needing rotation."""
        alerts = []
        conn = self._get_conn()

        try:
            threshold_date = datetime.now() - timedelta(days=rule.threshold_value)

            for table, entity_type in [
                ('coordination_server', 'cs'),
                ('subnet_router', 'sr'),
                ('remote', 'remote')
            ]:
                rows = conn.execute(f"""
                    SELECT t.id, t.hostname,
                           COALESCE(
                               (SELECT MAX(rotated_at) FROM key_rotation_history
                                WHERE entity_type = ? AND entity_permanent_guid = t.permanent_guid),
                               t.created_at
                           ) as last_rotation
                    FROM {table} t
                    WHERE last_rotation < ?
                """, (entity_type, threshold_date.isoformat())).fetchall()

                for row in rows:
                    if row['last_rotation']:
                        try:
                            rotation_date = datetime.fromisoformat(
                                row['last_rotation'].replace('Z', '+00:00')
                            )
                            days_since = (datetime.now() - rotation_date.replace(tzinfo=None)).days
                        except:
                            days_since = 999
                    else:
                        days_since = 999

                    alerts.append(AlertEvent(
                        id=None,
                        rule_id=rule.id,
                        rule_name=rule.name,
                        alert_type=rule.alert_type,
                        severity=rule.severity,
                        entity_type=entity_type,
                        entity_id=row['id'],
                        entity_name=row['hostname'],
                        message=f"Key for '{row['hostname']}' not rotated in {days_since} days",
                        details={"last_rotation": row['last_rotation'], "days_since": days_since},
                        triggered_at=datetime.now(),
                        resolved_at=None,
                        acknowledged=False,
                        notified_channels=[]
                    ))

        finally:
            conn.close()

        return alerts

    def _check_backup_overdue(self, rule: AlertRule) -> List[AlertEvent]:
        """Check for overdue backups."""
        alerts = []
        conn = self._get_conn()

        try:
            threshold_date = datetime.now() - timedelta(days=rule.threshold_value)

            try:
                row = conn.execute("""
                    SELECT MAX(created_at) as last_backup FROM backup_history
                """).fetchone()

                if row and row['last_backup']:
                    last_backup = datetime.fromisoformat(row['last_backup'])
                    if last_backup < threshold_date:
                        days_since = (datetime.now() - last_backup).days
                        alerts.append(AlertEvent(
                            id=None,
                            rule_id=rule.id,
                            rule_name=rule.name,
                            alert_type=rule.alert_type,
                            severity=rule.severity,
                            entity_type=None,
                            entity_id=None,
                            entity_name=None,
                            message=f"Last backup was {days_since} days ago",
                            details={"last_backup": row['last_backup'], "days_since": days_since},
                            triggered_at=datetime.now(),
                            resolved_at=None,
                            acknowledged=False,
                            notified_channels=[]
                        ))
                else:
                    alerts.append(AlertEvent(
                        id=None,
                        rule_id=rule.id,
                        rule_name=rule.name,
                        alert_type=rule.alert_type,
                        severity=AlertSeverity.WARNING,
                        entity_type=None,
                        entity_id=None,
                        entity_name=None,
                        message="No backups found",
                        details={},
                        triggered_at=datetime.now(),
                        resolved_at=None,
                        acknowledged=False,
                        notified_channels=[]
                    ))
            except sqlite3.OperationalError:
                pass  # backup_history not available

        finally:
            conn.close()

        return alerts

    def _check_drift_detected(self, rule: AlertRule) -> List[AlertEvent]:
        """Check for configuration drift."""
        alerts = []
        conn = self._get_conn()

        try:
            try:
                rows = conn.execute("""
                    SELECT entity_type, entity_name, critical_count, warning_count, scan_time
                    FROM drift_scan
                    WHERE is_drifted = 1
                    AND scan_time > datetime('now', '-1 day')
                """).fetchall()

                for row in rows:
                    severity = AlertSeverity.CRITICAL if row['critical_count'] > 0 else AlertSeverity.WARNING
                    alerts.append(AlertEvent(
                        id=None,
                        rule_id=rule.id,
                        rule_name=rule.name,
                        alert_type=rule.alert_type,
                        severity=severity,
                        entity_type=row['entity_type'],
                        entity_id=None,
                        entity_name=row['entity_name'],
                        message=f"Configuration drift detected on '{row['entity_name']}'",
                        details={
                            "critical_count": row['critical_count'],
                            "warning_count": row['warning_count'],
                            "scan_time": row['scan_time']
                        },
                        triggered_at=datetime.now(),
                        resolved_at=None,
                        acknowledged=False,
                        notified_channels=[]
                    ))
            except sqlite3.OperationalError:
                pass  # drift_scan not available

        finally:
            conn.close()

        return alerts

    def _check_high_latency(self, rule: AlertRule) -> List[AlertEvent]:
        """Check for high latency (placeholder - requires health data)."""
        return []

    def _check_bandwidth_spike(self, rule: AlertRule) -> List[AlertEvent]:
        """Check for bandwidth spikes above baseline."""
        alerts = []
        conn = self._get_conn()

        try:
            try:
                # Compare recent bandwidth against baseline
                rows = conn.execute("""
                    SELECT
                        ba.entity_type, ba.entity_id,
                        SUM(ba.bytes_received + ba.bytes_sent) as recent_total,
                        bb.baseline_bytes
                    FROM bandwidth_aggregate ba
                    LEFT JOIN bandwidth_baseline bb
                        ON bb.entity_type = ba.entity_type
                        AND bb.entity_id = ba.entity_id
                    WHERE ba.period_type = 'hourly'
                    AND ba.period_start > datetime('now', '-24 hours')
                    GROUP BY ba.entity_type, ba.entity_id
                    HAVING bb.baseline_bytes IS NOT NULL
                        AND recent_total > bb.baseline_bytes * ?
                """, (rule.threshold_value / 100.0,)).fetchall()

                for row in rows:
                    # Get entity name
                    entity_name = self._get_entity_name(conn, row['entity_type'], row['entity_id'])
                    spike_percent = int((row['recent_total'] / row['baseline_bytes']) * 100)

                    alerts.append(AlertEvent(
                        id=None,
                        rule_id=rule.id,
                        rule_name=rule.name,
                        alert_type=rule.alert_type,
                        severity=rule.severity,
                        entity_type=row['entity_type'],
                        entity_id=row['entity_id'],
                        entity_name=entity_name,
                        message=f"Bandwidth spike: {entity_name} at {spike_percent}% of baseline",
                        details={
                            "recent_bytes": row['recent_total'],
                            "baseline_bytes": row['baseline_bytes'],
                            "spike_percent": spike_percent
                        },
                        triggered_at=datetime.now(),
                        resolved_at=None,
                        acknowledged=False,
                        notified_channels=[]
                    ))
            except sqlite3.OperationalError:
                pass  # Tables not available

        finally:
            conn.close()

        return alerts

    def _get_entity_name(self, conn, entity_type: str, entity_id: int) -> str:
        """Get entity hostname."""
        table_map = {
            'cs': 'coordination_server',
            'sr': 'subnet_router',
            'remote': 'remote',
            'exit_node': 'exit_node',
        }
        table = table_map.get(entity_type)
        if table:
            row = conn.execute(f"SELECT hostname FROM {table} WHERE id = ?", (entity_id,)).fetchone()
            if row:
                return row['hostname']
        return f"{entity_type}-{entity_id}"

    def _check_cooldown(self, rule: AlertRule, alert: AlertEvent) -> bool:
        """Check if alert is within cooldown period."""
        conn = self._get_conn()
        try:
            entity_key = f"{alert.entity_type or 'global'}-{alert.entity_id or 0}"

            row = conn.execute("""
                SELECT last_alert_at FROM alert_cooldown
                WHERE rule_id = ? AND entity_key = ?
            """, (rule.id, entity_key)).fetchone()

            if row:
                last_alert = datetime.fromisoformat(row['last_alert_at'])
                cooldown_end = last_alert + timedelta(minutes=rule.cooldown_minutes)
                if datetime.now() < cooldown_end:
                    return False

            return True
        finally:
            conn.close()

    def record_alert(self, alert: AlertEvent) -> int:
        """Record an alert event and update cooldown."""
        conn = self._get_conn()
        try:
            cursor = conn.execute("""
                INSERT INTO alert_event
                (rule_id, alert_type, severity, entity_type, entity_id, entity_name,
                 message, details, triggered_at, notified_channels)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                alert.rule_id, alert.alert_type.value, alert.severity.value,
                alert.entity_type, alert.entity_id, alert.entity_name,
                alert.message, json.dumps(alert.details),
                alert.triggered_at.isoformat(),
                json.dumps(alert.notified_channels)
            ))

            alert_id = cursor.lastrowid

            # Update cooldown
            entity_key = f"{alert.entity_type or 'global'}-{alert.entity_id or 0}"
            conn.execute("""
                INSERT OR REPLACE INTO alert_cooldown (rule_id, entity_key, last_alert_at)
                VALUES (?, ?, ?)
            """, (alert.rule_id, entity_key, datetime.now().isoformat()))

            conn.commit()
            return alert_id
        finally:
            conn.close()

    def notify(self, alert: AlertEvent, channel_ids: List[int] = None) -> List[int]:
        """Send alert notifications to channels."""
        notified = []
        channels = self.get_channels(enabled_only=True)

        if channel_ids:
            channels = [c for c in channels if c.id in channel_ids]

        for channel in channels:
            try:
                if channel.channel_type == ChannelType.LOCAL:
                    self._notify_local(alert, channel)
                elif channel.channel_type == ChannelType.WEBHOOK:
                    self._notify_webhook(alert, channel)
                elif channel.channel_type == ChannelType.EMAIL:
                    self._notify_email(alert, channel)
                elif channel.channel_type == ChannelType.SLACK:
                    self._notify_slack(alert, channel)
                elif channel.channel_type == ChannelType.DISCORD:
                    self._notify_discord(alert, channel)

                notified.append(channel.id)
            except Exception as e:
                logger.error(f"Failed to notify channel {channel.name}: {e}")

        return notified

    def _notify_local(self, alert: AlertEvent, channel: NotificationChannel):
        """Log alert locally."""
        log_file = channel.config.get('log_file', '/tmp/wgf-alerts.log')
        with open(log_file, 'a') as f:
            f.write(f"[{alert.triggered_at.isoformat()}] [{alert.severity.value.upper()}] {alert.message}\n")

    def _notify_webhook(self, alert: AlertEvent, channel: NotificationChannel):
        """Send alert to webhook endpoint."""
        url = channel.config.get('url')
        if not url:
            return

        payload = alert.to_dict()
        payload['channel'] = channel.name

        # Add HMAC signature if secret configured
        secret = channel.config.get('secret')
        headers = {'Content-Type': 'application/json'}

        if secret:
            body = json.dumps(payload).encode()
            signature = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
            headers['X-WGF-Signature'] = f"sha256={signature}"

        data = json.dumps(payload).encode()
        req = urllib.request.Request(url, data=data, headers=headers, method='POST')

        try:
            urllib.request.urlopen(req, timeout=10)
        except urllib.error.URLError as e:
            logger.error(f"Webhook failed: {e}")
            raise

    def _notify_email(self, alert: AlertEvent, channel: NotificationChannel):
        """Send alert via email."""
        smtp_host = channel.config.get('smtp_host', 'localhost')
        smtp_port = channel.config.get('smtp_port', 587)
        smtp_user = channel.config.get('smtp_user')
        smtp_pass = channel.config.get('smtp_pass')
        from_addr = channel.config.get('from_addr', 'wgf-alerts@localhost')
        to_addrs = channel.config.get('to_addrs', [])

        if not to_addrs:
            return

        msg = MIMEMultipart()
        msg['From'] = from_addr
        msg['To'] = ', '.join(to_addrs)
        msg['Subject'] = f"[WGF Alert] [{alert.severity.value.upper()}] {alert.rule_name}"

        body = f"""
WireGuard Friend Alert

Severity: {alert.severity.value.upper()}
Type: {alert.alert_type.value}
Time: {alert.triggered_at.isoformat()}

Message: {alert.message}

Entity: {alert.entity_name or 'N/A'}
Details: {json.dumps(alert.details, indent=2)}

---
WireGuard Friend Alerting System
"""
        msg.attach(MIMEText(body, 'plain'))

        try:
            server = smtplib.SMTP(smtp_host, smtp_port)
            server.starttls()
            if smtp_user and smtp_pass:
                server.login(smtp_user, smtp_pass)
            server.sendmail(from_addr, to_addrs, msg.as_string())
            server.quit()
        except Exception as e:
            logger.error(f"Email failed: {e}")
            raise

    def _notify_slack(self, alert: AlertEvent, channel: NotificationChannel):
        """Send alert to Slack via webhook."""
        webhook_url = channel.config.get('webhook_url')
        if not webhook_url:
            return

        color = {
            AlertSeverity.CRITICAL: '#FF0000',
            AlertSeverity.WARNING: '#FFAA00',
            AlertSeverity.INFO: '#0088FF',
        }.get(alert.severity, '#808080')

        payload = {
            "attachments": [{
                "color": color,
                "title": f"{alert.severity.value.upper()}: {alert.rule_name}",
                "text": alert.message,
                "fields": [
                    {"title": "Entity", "value": alert.entity_name or "N/A", "short": True},
                    {"title": "Type", "value": alert.alert_type.value, "short": True},
                ],
                "ts": int(alert.triggered_at.timestamp())
            }]
        }

        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            webhook_url, data=data,
            headers={'Content-Type': 'application/json'},
            method='POST'
        )
        urllib.request.urlopen(req, timeout=10)

    def _notify_discord(self, alert: AlertEvent, channel: NotificationChannel):
        """Send alert to Discord via webhook."""
        webhook_url = channel.config.get('webhook_url')
        if not webhook_url:
            return

        color = {
            AlertSeverity.CRITICAL: 0xFF0000,
            AlertSeverity.WARNING: 0xFFAA00,
            AlertSeverity.INFO: 0x0088FF,
        }.get(alert.severity, 0x808080)

        payload = {
            "embeds": [{
                "title": f"{alert.severity.value.upper()}: {alert.rule_name}",
                "description": alert.message,
                "color": color,
                "fields": [
                    {"name": "Entity", "value": alert.entity_name or "N/A", "inline": True},
                    {"name": "Type", "value": alert.alert_type.value, "inline": True},
                ],
                "timestamp": alert.triggered_at.isoformat()
            }]
        }

        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            webhook_url, data=data,
            headers={'Content-Type': 'application/json'},
            method='POST'
        )
        urllib.request.urlopen(req, timeout=10)

    def get_active_alerts(self, limit: int = 50) -> List[AlertEvent]:
        """Get recent unresolved alerts."""
        conn = self._get_conn()
        try:
            rows = conn.execute("""
                SELECT ae.*, ar.name as rule_name
                FROM alert_event ae
                JOIN alert_rule ar ON ar.id = ae.rule_id
                WHERE ae.resolved_at IS NULL
                ORDER BY ae.triggered_at DESC
                LIMIT ?
            """, (limit,)).fetchall()

            return [
                AlertEvent(
                    id=row['id'],
                    rule_id=row['rule_id'],
                    rule_name=row['rule_name'],
                    alert_type=AlertType(row['alert_type']),
                    severity=AlertSeverity(row['severity']),
                    entity_type=row['entity_type'],
                    entity_id=row['entity_id'],
                    entity_name=row['entity_name'],
                    message=row['message'],
                    details=json.loads(row['details'] or '{}'),
                    triggered_at=datetime.fromisoformat(row['triggered_at']),
                    resolved_at=None,
                    acknowledged=bool(row['acknowledged']),
                    notified_channels=json.loads(row['notified_channels'] or '[]')
                )
                for row in rows
            ]
        finally:
            conn.close()

    def acknowledge_alert(self, alert_id: int):
        """Acknowledge an alert."""
        conn = self._get_conn()
        try:
            conn.execute("""
                UPDATE alert_event SET acknowledged = 1 WHERE id = ?
            """, (alert_id,))
            conn.commit()
        finally:
            conn.close()

    def resolve_alert(self, alert_id: int):
        """Mark an alert as resolved."""
        conn = self._get_conn()
        try:
            conn.execute("""
                UPDATE alert_event SET resolved_at = ? WHERE id = ?
            """, (datetime.now().isoformat(), alert_id))
            conn.commit()
        finally:
            conn.close()

    def initialize_default_rules(self):
        """Create default alert rules if none exist."""
        conn = self._get_conn()
        try:
            count = conn.execute("SELECT COUNT(*) FROM alert_rule").fetchone()[0]
            if count == 0:
                for rule_def in self.DEFAULT_RULES:
                    self.create_rule(**rule_def)
        finally:
            conn.close()
