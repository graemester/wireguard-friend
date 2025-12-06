"""
Webhook Notifications for WireGuard Friend.

Provides robust webhook delivery with retry logic, payload templating,
and support for various webhook formats (generic, Slack, Discord, Teams).

Features:
- Configurable webhook endpoints with authentication
- Retry with exponential backoff
- Payload templating with Jinja2-style variables
- Support for Slack, Discord, Microsoft Teams, and generic webhooks
- Delivery tracking and failure logging
- Rate limiting per endpoint
"""

import sqlite3
import json
import time
import hashlib
import hmac
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable, Tuple
from dataclasses import dataclass, field
from enum import Enum
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from urllib.parse import urlencode
import ssl


class WebhookFormat(Enum):
    """Supported webhook payload formats."""
    GENERIC = "generic"
    SLACK = "slack"
    DISCORD = "discord"
    TEAMS = "teams"
    PAGERDUTY = "pagerduty"
    OPSGENIE = "opsgenie"


class DeliveryStatus(Enum):
    """Webhook delivery status."""
    PENDING = "pending"
    DELIVERED = "delivered"
    FAILED = "failed"
    RETRYING = "retrying"


@dataclass
class WebhookEndpoint:
    """Configuration for a webhook endpoint."""
    id: Optional[int] = None
    name: str = ""
    url: str = ""
    format: WebhookFormat = WebhookFormat.GENERIC
    enabled: bool = True
    secret: Optional[str] = None  # For HMAC signing
    headers: Dict[str, str] = field(default_factory=dict)
    retry_count: int = 3
    retry_delay: int = 60  # seconds
    rate_limit: int = 60  # max calls per minute
    alert_types: List[str] = field(default_factory=list)  # Empty = all types
    min_severity: str = "info"  # Minimum severity to notify


@dataclass
class WebhookDelivery:
    """Record of a webhook delivery attempt."""
    id: Optional[int] = None
    endpoint_id: int = 0
    alert_id: Optional[int] = None
    payload: str = ""
    status: DeliveryStatus = DeliveryStatus.PENDING
    attempts: int = 0
    last_attempt: Optional[datetime] = None
    next_retry: Optional[datetime] = None
    response_code: Optional[int] = None
    error_message: Optional[str] = None
    delivered_at: Optional[datetime] = None


class WebhookNotifier:
    """Manages webhook notifications with retry and delivery tracking."""

    SCHEMA = """
    CREATE TABLE IF NOT EXISTS webhook_endpoint (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        url TEXT NOT NULL,
        format TEXT NOT NULL DEFAULT 'generic',
        enabled INTEGER NOT NULL DEFAULT 1,
        secret TEXT,
        headers TEXT,
        retry_count INTEGER NOT NULL DEFAULT 3,
        retry_delay INTEGER NOT NULL DEFAULT 60,
        rate_limit INTEGER NOT NULL DEFAULT 60,
        alert_types TEXT,
        min_severity TEXT NOT NULL DEFAULT 'info',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS webhook_delivery (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        endpoint_id INTEGER NOT NULL,
        alert_id INTEGER,
        payload TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        attempts INTEGER NOT NULL DEFAULT 0,
        last_attempt TEXT,
        next_retry TEXT,
        response_code INTEGER,
        error_message TEXT,
        delivered_at TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY (endpoint_id) REFERENCES webhook_endpoint(id)
    );

    CREATE TABLE IF NOT EXISTS webhook_rate_limit (
        endpoint_id INTEGER PRIMARY KEY,
        call_count INTEGER NOT NULL DEFAULT 0,
        window_start TEXT NOT NULL,
        FOREIGN KEY (endpoint_id) REFERENCES webhook_endpoint(id)
    );

    CREATE INDEX IF NOT EXISTS idx_webhook_delivery_status
        ON webhook_delivery(status);
    CREATE INDEX IF NOT EXISTS idx_webhook_delivery_next_retry
        ON webhook_delivery(next_retry);
    """

    SEVERITY_ORDER = {"info": 0, "warning": 1, "critical": 2}

    def __init__(self, db_path: str):
        """Initialize the webhook notifier.

        Args:
            db_path: Path to the database
        """
        self.db_path = db_path
        self._lock = threading.Lock()
        self._init_schema()

    def _get_connection(self) -> sqlite3.Connection:
        """Get a database connection."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self):
        """Initialize database schema."""
        conn = self._get_connection()
        conn.executescript(self.SCHEMA)
        conn.commit()
        conn.close()

    def add_endpoint(self, endpoint: WebhookEndpoint) -> int:
        """Add a new webhook endpoint.

        Args:
            endpoint: Endpoint configuration

        Returns:
            ID of the created endpoint
        """
        conn = self._get_connection()
        now = datetime.now().isoformat()

        cursor = conn.execute("""
            INSERT INTO webhook_endpoint
            (name, url, format, enabled, secret, headers, retry_count,
             retry_delay, rate_limit, alert_types, min_severity, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            endpoint.name,
            endpoint.url,
            endpoint.format.value,
            1 if endpoint.enabled else 0,
            endpoint.secret,
            json.dumps(endpoint.headers) if endpoint.headers else None,
            endpoint.retry_count,
            endpoint.retry_delay,
            endpoint.rate_limit,
            json.dumps(endpoint.alert_types) if endpoint.alert_types else None,
            endpoint.min_severity,
            now,
            now
        ))

        endpoint_id = cursor.lastrowid
        conn.commit()
        conn.close()

        return endpoint_id

    def get_endpoint(self, endpoint_id: int) -> Optional[WebhookEndpoint]:
        """Get an endpoint by ID."""
        conn = self._get_connection()
        row = conn.execute(
            "SELECT * FROM webhook_endpoint WHERE id = ?",
            (endpoint_id,)
        ).fetchone()
        conn.close()

        if not row:
            return None

        return self._row_to_endpoint(row)

    def list_endpoints(self, enabled_only: bool = False) -> List[WebhookEndpoint]:
        """List all webhook endpoints."""
        conn = self._get_connection()

        query = "SELECT * FROM webhook_endpoint"
        if enabled_only:
            query += " WHERE enabled = 1"

        rows = conn.execute(query).fetchall()
        conn.close()

        return [self._row_to_endpoint(row) for row in rows]

    def _row_to_endpoint(self, row: sqlite3.Row) -> WebhookEndpoint:
        """Convert a database row to WebhookEndpoint."""
        return WebhookEndpoint(
            id=row['id'],
            name=row['name'],
            url=row['url'],
            format=WebhookFormat(row['format']),
            enabled=bool(row['enabled']),
            secret=row['secret'],
            headers=json.loads(row['headers']) if row['headers'] else {},
            retry_count=row['retry_count'],
            retry_delay=row['retry_delay'],
            rate_limit=row['rate_limit'],
            alert_types=json.loads(row['alert_types']) if row['alert_types'] else [],
            min_severity=row['min_severity']
        )

    def update_endpoint(self, endpoint: WebhookEndpoint) -> bool:
        """Update an existing endpoint."""
        if not endpoint.id:
            return False

        conn = self._get_connection()
        now = datetime.now().isoformat()

        conn.execute("""
            UPDATE webhook_endpoint SET
                name = ?, url = ?, format = ?, enabled = ?, secret = ?,
                headers = ?, retry_count = ?, retry_delay = ?, rate_limit = ?,
                alert_types = ?, min_severity = ?, updated_at = ?
            WHERE id = ?
        """, (
            endpoint.name,
            endpoint.url,
            endpoint.format.value,
            1 if endpoint.enabled else 0,
            endpoint.secret,
            json.dumps(endpoint.headers) if endpoint.headers else None,
            endpoint.retry_count,
            endpoint.retry_delay,
            endpoint.rate_limit,
            json.dumps(endpoint.alert_types) if endpoint.alert_types else None,
            endpoint.min_severity,
            now,
            endpoint.id
        ))

        conn.commit()
        conn.close()
        return True

    def delete_endpoint(self, endpoint_id: int) -> bool:
        """Delete an endpoint and its delivery history."""
        conn = self._get_connection()

        conn.execute("DELETE FROM webhook_delivery WHERE endpoint_id = ?", (endpoint_id,))
        conn.execute("DELETE FROM webhook_rate_limit WHERE endpoint_id = ?", (endpoint_id,))
        conn.execute("DELETE FROM webhook_endpoint WHERE id = ?", (endpoint_id,))

        conn.commit()
        conn.close()
        return True

    def notify(self, alert_type: str, severity: str, title: str,
               message: str, details: Dict[str, Any] = None,
               alert_id: Optional[int] = None) -> List[int]:
        """Send notification to all matching endpoints.

        Args:
            alert_type: Type of alert (e.g., 'peer_offline', 'key_expiry')
            severity: Alert severity ('info', 'warning', 'critical')
            title: Alert title
            message: Alert message
            details: Additional alert details
            alert_id: Optional alert ID for tracking

        Returns:
            List of delivery IDs created
        """
        delivery_ids = []
        endpoints = self.list_endpoints(enabled_only=True)

        for endpoint in endpoints:
            # Check if this endpoint wants this alert type
            if endpoint.alert_types and alert_type not in endpoint.alert_types:
                continue

            # Check severity threshold
            if self.SEVERITY_ORDER.get(severity, 0) < self.SEVERITY_ORDER.get(endpoint.min_severity, 0):
                continue

            # Check rate limit
            if not self._check_rate_limit(endpoint.id, endpoint.rate_limit):
                continue

            # Format payload based on endpoint format
            payload = self._format_payload(
                endpoint.format, alert_type, severity, title, message, details
            )

            # Queue delivery
            delivery_id = self._queue_delivery(endpoint.id, payload, alert_id)
            delivery_ids.append(delivery_id)

            # Attempt immediate delivery
            self._process_delivery(delivery_id)

        return delivery_ids

    def _check_rate_limit(self, endpoint_id: int, limit: int) -> bool:
        """Check if endpoint is within rate limit."""
        with self._lock:
            conn = self._get_connection()
            now = datetime.now()
            window_start = now - timedelta(minutes=1)

            row = conn.execute(
                "SELECT call_count, window_start FROM webhook_rate_limit WHERE endpoint_id = ?",
                (endpoint_id,)
            ).fetchone()

            if row:
                row_window = datetime.fromisoformat(row['window_start'])
                if row_window > window_start:
                    # Still in same window
                    if row['call_count'] >= limit:
                        conn.close()
                        return False
                    conn.execute(
                        "UPDATE webhook_rate_limit SET call_count = call_count + 1 WHERE endpoint_id = ?",
                        (endpoint_id,)
                    )
                else:
                    # New window
                    conn.execute(
                        "UPDATE webhook_rate_limit SET call_count = 1, window_start = ? WHERE endpoint_id = ?",
                        (now.isoformat(), endpoint_id)
                    )
            else:
                # First call
                conn.execute(
                    "INSERT INTO webhook_rate_limit (endpoint_id, call_count, window_start) VALUES (?, 1, ?)",
                    (endpoint_id, now.isoformat())
                )

            conn.commit()
            conn.close()
            return True

    def _format_payload(self, format: WebhookFormat, alert_type: str,
                        severity: str, title: str, message: str,
                        details: Dict[str, Any] = None) -> str:
        """Format payload for specific webhook format."""

        if format == WebhookFormat.SLACK:
            return self._format_slack(alert_type, severity, title, message, details)
        elif format == WebhookFormat.DISCORD:
            return self._format_discord(alert_type, severity, title, message, details)
        elif format == WebhookFormat.TEAMS:
            return self._format_teams(alert_type, severity, title, message, details)
        elif format == WebhookFormat.PAGERDUTY:
            return self._format_pagerduty(alert_type, severity, title, message, details)
        elif format == WebhookFormat.OPSGENIE:
            return self._format_opsgenie(alert_type, severity, title, message, details)
        else:
            return self._format_generic(alert_type, severity, title, message, details)

    def _format_generic(self, alert_type: str, severity: str, title: str,
                        message: str, details: Dict[str, Any] = None) -> str:
        """Format generic JSON payload."""
        payload = {
            "timestamp": datetime.now().isoformat(),
            "source": "wireguard-friend",
            "alert_type": alert_type,
            "severity": severity,
            "title": title,
            "message": message,
            "details": details or {}
        }
        return json.dumps(payload)

    def _format_slack(self, alert_type: str, severity: str, title: str,
                      message: str, details: Dict[str, Any] = None) -> str:
        """Format Slack webhook payload."""
        color_map = {"critical": "#dc3545", "warning": "#ffc107", "info": "#17a2b8"}
        emoji_map = {"critical": ":rotating_light:", "warning": ":warning:", "info": ":information_source:"}

        payload = {
            "attachments": [{
                "color": color_map.get(severity, "#6c757d"),
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": f"{emoji_map.get(severity, '')} {title}",
                            "emoji": True
                        }
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": message
                        }
                    },
                    {
                        "type": "context",
                        "elements": [
                            {
                                "type": "mrkdwn",
                                "text": f"*Type:* {alert_type} | *Severity:* {severity.upper()}"
                            }
                        ]
                    }
                ]
            }]
        }

        if details:
            fields = [{"type": "mrkdwn", "text": f"*{k}:* {v}"} for k, v in details.items()]
            payload["attachments"][0]["blocks"].append({
                "type": "section",
                "fields": fields[:10]  # Slack limit
            })

        return json.dumps(payload)

    def _format_discord(self, alert_type: str, severity: str, title: str,
                        message: str, details: Dict[str, Any] = None) -> str:
        """Format Discord webhook payload."""
        color_map = {"critical": 0xdc3545, "warning": 0xffc107, "info": 0x17a2b8}

        embed = {
            "title": title,
            "description": message,
            "color": color_map.get(severity, 0x6c757d),
            "timestamp": datetime.now().isoformat(),
            "footer": {"text": f"WireGuard Friend | {alert_type}"}
        }

        if details:
            embed["fields"] = [
                {"name": k, "value": str(v), "inline": True}
                for k, v in list(details.items())[:25]  # Discord limit
            ]

        return json.dumps({"embeds": [embed]})

    def _format_teams(self, alert_type: str, severity: str, title: str,
                      message: str, details: Dict[str, Any] = None) -> str:
        """Format Microsoft Teams webhook payload."""
        color_map = {"critical": "dc3545", "warning": "ffc107", "info": "17a2b8"}

        payload = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": color_map.get(severity, "6c757d"),
            "summary": title,
            "sections": [{
                "activityTitle": title,
                "facts": [
                    {"name": "Message", "value": message},
                    {"name": "Type", "value": alert_type},
                    {"name": "Severity", "value": severity.upper()}
                ]
            }]
        }

        if details:
            for k, v in details.items():
                payload["sections"][0]["facts"].append({"name": k, "value": str(v)})

        return json.dumps(payload)

    def _format_pagerduty(self, alert_type: str, severity: str, title: str,
                          message: str, details: Dict[str, Any] = None) -> str:
        """Format PagerDuty Events API v2 payload."""
        severity_map = {"critical": "critical", "warning": "warning", "info": "info"}

        payload = {
            "routing_key": "{{routing_key}}",  # Will be replaced with endpoint secret
            "event_action": "trigger",
            "payload": {
                "summary": title,
                "severity": severity_map.get(severity, "info"),
                "source": "wireguard-friend",
                "custom_details": {
                    "message": message,
                    "alert_type": alert_type,
                    **(details or {})
                }
            }
        }
        return json.dumps(payload)

    def _format_opsgenie(self, alert_type: str, severity: str, title: str,
                         message: str, details: Dict[str, Any] = None) -> str:
        """Format OpsGenie API payload."""
        priority_map = {"critical": "P1", "warning": "P3", "info": "P5"}

        payload = {
            "message": title,
            "description": message,
            "priority": priority_map.get(severity, "P5"),
            "tags": ["wireguard-friend", alert_type, severity],
            "details": details or {}
        }
        return json.dumps(payload)

    def _queue_delivery(self, endpoint_id: int, payload: str,
                        alert_id: Optional[int] = None) -> int:
        """Queue a delivery for processing."""
        conn = self._get_connection()
        now = datetime.now().isoformat()

        cursor = conn.execute("""
            INSERT INTO webhook_delivery
            (endpoint_id, alert_id, payload, status, attempts, created_at)
            VALUES (?, ?, ?, 'pending', 0, ?)
        """, (endpoint_id, alert_id, payload, now))

        delivery_id = cursor.lastrowid
        conn.commit()
        conn.close()

        return delivery_id

    def _process_delivery(self, delivery_id: int) -> bool:
        """Process a single delivery attempt."""
        conn = self._get_connection()

        # Get delivery and endpoint
        delivery_row = conn.execute(
            "SELECT * FROM webhook_delivery WHERE id = ?",
            (delivery_id,)
        ).fetchone()

        if not delivery_row:
            conn.close()
            return False

        endpoint = self.get_endpoint(delivery_row['endpoint_id'])
        if not endpoint:
            conn.close()
            return False

        # Attempt delivery
        now = datetime.now()
        success = False
        response_code = None
        error_message = None

        try:
            # Prepare request
            payload = delivery_row['payload']

            # Replace placeholders (e.g., PagerDuty routing key)
            if endpoint.secret:
                payload = payload.replace("{{routing_key}}", endpoint.secret)

            headers = {"Content-Type": "application/json"}
            headers.update(endpoint.headers)

            # Add HMAC signature if secret is set (for generic webhooks)
            if endpoint.secret and endpoint.format == WebhookFormat.GENERIC:
                signature = hmac.new(
                    endpoint.secret.encode(),
                    payload.encode(),
                    hashlib.sha256
                ).hexdigest()
                headers["X-Webhook-Signature"] = f"sha256={signature}"

            # Make request
            request = Request(
                endpoint.url,
                data=payload.encode('utf-8'),
                headers=headers,
                method='POST'
            )

            # Create SSL context that allows connections
            ssl_context = ssl.create_default_context()

            with urlopen(request, timeout=30, context=ssl_context) as response:
                response_code = response.status
                success = 200 <= response_code < 300

        except HTTPError as e:
            response_code = e.code
            error_message = str(e.reason)
        except URLError as e:
            error_message = str(e.reason)
        except Exception as e:
            error_message = str(e)

        # Update delivery record
        attempts = delivery_row['attempts'] + 1

        if success:
            conn.execute("""
                UPDATE webhook_delivery SET
                    status = 'delivered',
                    attempts = ?,
                    last_attempt = ?,
                    response_code = ?,
                    delivered_at = ?
                WHERE id = ?
            """, (attempts, now.isoformat(), response_code, now.isoformat(), delivery_id))
        elif attempts >= endpoint.retry_count:
            conn.execute("""
                UPDATE webhook_delivery SET
                    status = 'failed',
                    attempts = ?,
                    last_attempt = ?,
                    response_code = ?,
                    error_message = ?
                WHERE id = ?
            """, (attempts, now.isoformat(), response_code, error_message, delivery_id))
        else:
            # Schedule retry with exponential backoff
            delay = endpoint.retry_delay * (2 ** (attempts - 1))
            next_retry = now + timedelta(seconds=delay)

            conn.execute("""
                UPDATE webhook_delivery SET
                    status = 'retrying',
                    attempts = ?,
                    last_attempt = ?,
                    next_retry = ?,
                    response_code = ?,
                    error_message = ?
                WHERE id = ?
            """, (attempts, now.isoformat(), next_retry.isoformat(),
                  response_code, error_message, delivery_id))

        conn.commit()
        conn.close()

        return success

    def process_pending_retries(self) -> int:
        """Process all pending retries that are due.

        Returns:
            Number of deliveries processed
        """
        conn = self._get_connection()
        now = datetime.now().isoformat()

        pending = conn.execute("""
            SELECT id FROM webhook_delivery
            WHERE status = 'retrying' AND next_retry <= ?
        """, (now,)).fetchall()

        conn.close()

        processed = 0
        for row in pending:
            self._process_delivery(row['id'])
            processed += 1

        return processed

    def get_delivery_stats(self) -> Dict[str, int]:
        """Get delivery statistics."""
        conn = self._get_connection()

        stats = {}
        for status in DeliveryStatus:
            count = conn.execute(
                "SELECT COUNT(*) FROM webhook_delivery WHERE status = ?",
                (status.value,)
            ).fetchone()[0]
            stats[status.value] = count

        conn.close()
        return stats

    def get_recent_deliveries(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent delivery history."""
        conn = self._get_connection()

        rows = conn.execute("""
            SELECT d.*, e.name as endpoint_name, e.format
            FROM webhook_delivery d
            JOIN webhook_endpoint e ON d.endpoint_id = e.id
            ORDER BY d.created_at DESC
            LIMIT ?
        """, (limit,)).fetchall()

        conn.close()

        return [dict(row) for row in rows]

    def test_endpoint(self, endpoint_id: int) -> Tuple[bool, str]:
        """Send a test notification to an endpoint.

        Args:
            endpoint_id: Endpoint to test

        Returns:
            Tuple of (success, message)
        """
        endpoint = self.get_endpoint(endpoint_id)
        if not endpoint:
            return False, "Endpoint not found"

        # Create test payload
        payload = self._format_payload(
            endpoint.format,
            "test",
            "info",
            "Test Notification",
            "This is a test notification from WireGuard Friend.",
            {"test": True, "timestamp": datetime.now().isoformat()}
        )

        # Queue and process
        delivery_id = self._queue_delivery(endpoint_id, payload)
        success = self._process_delivery(delivery_id)

        if success:
            return True, "Test notification delivered successfully"
        else:
            conn = self._get_connection()
            row = conn.execute(
                "SELECT error_message FROM webhook_delivery WHERE id = ?",
                (delivery_id,)
            ).fetchone()
            conn.close()

            error = row['error_message'] if row else "Unknown error"
            return False, f"Delivery failed: {error}"


# Convenience functions for integration with alerting system

def send_alert_webhook(db_path: str, alert_type: str, severity: str,
                       title: str, message: str, details: Dict[str, Any] = None,
                       alert_id: Optional[int] = None) -> List[int]:
    """Send alert to all configured webhooks.

    Args:
        db_path: Path to database
        alert_type: Type of alert
        severity: Alert severity
        title: Alert title
        message: Alert message
        details: Additional details
        alert_id: Optional alert ID

    Returns:
        List of delivery IDs
    """
    notifier = WebhookNotifier(db_path)
    return notifier.notify(alert_type, severity, title, message, details, alert_id)


def process_webhook_retries(db_path: str) -> int:
    """Process all pending webhook retries.

    Args:
        db_path: Path to database

    Returns:
        Number of retries processed
    """
    notifier = WebhookNotifier(db_path)
    return notifier.process_pending_retries()
