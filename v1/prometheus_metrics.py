"""
Prometheus Metrics Export for WireGuard Friend.

Exposes metrics in Prometheus exposition format for monitoring integration.
Can run as a standalone HTTP server or generate metrics on-demand.

Metrics exposed:
- wireguard_peer_status (gauge): Peer connection status (1=up, 0=down)
- wireguard_peer_last_handshake_seconds (gauge): Seconds since last handshake
- wireguard_peer_rx_bytes (counter): Total bytes received per peer
- wireguard_peer_tx_bytes (counter): Total bytes transmitted per peer
- wireguard_peer_endpoint_changes (counter): Number of endpoint changes
- wireguard_key_age_seconds (gauge): Age of peer keys in seconds
- wireguard_key_rotation_due (gauge): 1 if key rotation is overdue
- wireguard_backup_age_seconds (gauge): Seconds since last backup
- wireguard_drift_items_total (gauge): Number of detected drift items
- wireguard_alerts_active (gauge): Number of active alerts by severity
- wireguard_entity_count (gauge): Count of entities by type
"""

import sqlite3
import time
import threading
from datetime import datetime, timedelta
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum
import subprocess
import re


class MetricType(Enum):
    """Prometheus metric types."""
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    SUMMARY = "summary"


@dataclass
class MetricValue:
    """A single metric value with labels."""
    value: float
    labels: Dict[str, str] = field(default_factory=dict)
    timestamp: Optional[int] = None  # Unix milliseconds


@dataclass
class Metric:
    """A Prometheus metric definition."""
    name: str
    help_text: str
    metric_type: MetricType
    values: List[MetricValue] = field(default_factory=list)


class PrometheusMetricsCollector:
    """Collects and exposes WireGuard metrics in Prometheus format."""

    def __init__(self, db_path: str):
        """Initialize the metrics collector.

        Args:
            db_path: Path to the WireGuard Friend database
        """
        self.db_path = db_path
        self._lock = threading.Lock()

    def _get_connection(self) -> sqlite3.Connection:
        """Get a database connection."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def collect_all_metrics(self) -> List[Metric]:
        """Collect all available metrics.

        Returns:
            List of Metric objects ready for exposition
        """
        metrics = []

        # Collect each metric category
        metrics.extend(self._collect_entity_metrics())
        metrics.extend(self._collect_peer_status_metrics())
        metrics.extend(self._collect_key_metrics())
        metrics.extend(self._collect_backup_metrics())
        metrics.extend(self._collect_drift_metrics())
        metrics.extend(self._collect_alert_metrics())
        metrics.extend(self._collect_bandwidth_metrics())

        return metrics

    def _collect_entity_metrics(self) -> List[Metric]:
        """Collect entity count metrics."""
        metrics = []

        entity_metric = Metric(
            name="wireguard_entity_count",
            help_text="Count of WireGuard entities by type",
            metric_type=MetricType.GAUGE
        )

        try:
            conn = self._get_connection()

            # Count each entity type
            entity_tables = [
                ("coordination_server", "coordination_server"),
                ("subnet_router", "subnet_router"),
                ("remote", "remote"),
                ("exit_node", "exit_node")
            ]

            for table, entity_type in entity_tables:
                try:
                    count = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                    entity_metric.values.append(MetricValue(
                        value=float(count),
                        labels={"entity_type": entity_type}
                    ))
                except sqlite3.OperationalError:
                    pass  # Table doesn't exist

            conn.close()

        except Exception:
            pass

        if entity_metric.values:
            metrics.append(entity_metric)

        return metrics

    def _collect_peer_status_metrics(self) -> List[Metric]:
        """Collect peer connection status metrics."""
        metrics = []

        status_metric = Metric(
            name="wireguard_peer_status",
            help_text="Peer connection status (1=up, 0=down)",
            metric_type=MetricType.GAUGE
        )

        handshake_metric = Metric(
            name="wireguard_peer_last_handshake_seconds",
            help_text="Seconds since last handshake",
            metric_type=MetricType.GAUGE
        )

        # Try to get live status from wg show
        try:
            result = subprocess.run(
                ["wg", "show", "all", "dump"],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                now = time.time()
                for line in result.stdout.strip().split('\n'):
                    parts = line.split('\t')
                    if len(parts) >= 9:
                        interface = parts[0]
                        public_key = parts[1]
                        # Parts: interface, public_key, psk, endpoint, allowed_ips,
                        #        last_handshake, rx, tx, keepalive
                        try:
                            last_handshake = int(parts[5])
                            rx_bytes = int(parts[6])
                            tx_bytes = int(parts[7])

                            # Peer is "up" if handshake within last 3 minutes
                            handshake_age = now - last_handshake if last_handshake > 0 else float('inf')
                            is_up = 1.0 if handshake_age < 180 else 0.0

                            short_key = public_key[:8] + "..."

                            status_metric.values.append(MetricValue(
                                value=is_up,
                                labels={
                                    "interface": interface,
                                    "public_key": short_key
                                }
                            ))

                            if last_handshake > 0:
                                handshake_metric.values.append(MetricValue(
                                    value=handshake_age,
                                    labels={
                                        "interface": interface,
                                        "public_key": short_key
                                    }
                                ))
                        except (ValueError, IndexError):
                            pass

        except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError):
            pass

        if status_metric.values:
            metrics.append(status_metric)
        if handshake_metric.values:
            metrics.append(handshake_metric)

        return metrics

    def _collect_key_metrics(self) -> List[Metric]:
        """Collect key age and rotation metrics."""
        metrics = []

        key_age_metric = Metric(
            name="wireguard_key_age_seconds",
            help_text="Age of peer keys in seconds",
            metric_type=MetricType.GAUGE
        )

        rotation_due_metric = Metric(
            name="wireguard_key_rotation_due",
            help_text="1 if key rotation is overdue based on policy",
            metric_type=MetricType.GAUGE
        )

        try:
            conn = self._get_connection()
            now = datetime.now()

            # Check remotes for key ages
            try:
                remotes = conn.execute("""
                    SELECT id, name, ipv4_address, key_created_at
                    FROM remote
                    WHERE key_created_at IS NOT NULL
                """).fetchall()

                for remote in remotes:
                    try:
                        created = datetime.fromisoformat(remote['key_created_at'])
                        age_seconds = (now - created).total_seconds()

                        key_age_metric.values.append(MetricValue(
                            value=age_seconds,
                            labels={
                                "entity_type": "remote",
                                "entity_id": str(remote['id']),
                                "name": remote['name'] or remote['ipv4_address'] or "unknown"
                            }
                        ))

                        # Check if rotation is due (default 90 days)
                        is_due = 1.0 if age_seconds > (90 * 24 * 3600) else 0.0
                        rotation_due_metric.values.append(MetricValue(
                            value=is_due,
                            labels={
                                "entity_type": "remote",
                                "entity_id": str(remote['id']),
                                "name": remote['name'] or remote['ipv4_address'] or "unknown"
                            }
                        ))
                    except (ValueError, TypeError):
                        pass

            except sqlite3.OperationalError:
                pass

            conn.close()

        except Exception:
            pass

        if key_age_metric.values:
            metrics.append(key_age_metric)
        if rotation_due_metric.values:
            metrics.append(rotation_due_metric)

        return metrics

    def _collect_backup_metrics(self) -> List[Metric]:
        """Collect backup status metrics."""
        metrics = []

        backup_age_metric = Metric(
            name="wireguard_backup_age_seconds",
            help_text="Seconds since last successful backup",
            metric_type=MetricType.GAUGE
        )

        try:
            conn = self._get_connection()
            now = datetime.now()

            # Check backup history table
            try:
                last_backup = conn.execute("""
                    SELECT created_at FROM backup_history
                    WHERE status = 'success'
                    ORDER BY created_at DESC
                    LIMIT 1
                """).fetchone()

                if last_backup:
                    created = datetime.fromisoformat(last_backup['created_at'])
                    age_seconds = (now - created).total_seconds()

                    backup_age_metric.values.append(MetricValue(
                        value=age_seconds,
                        labels={"backup_type": "database"}
                    ))
                else:
                    # No backups ever taken - report very large age
                    backup_age_metric.values.append(MetricValue(
                        value=float(365 * 24 * 3600),  # 1 year
                        labels={"backup_type": "database"}
                    ))

            except sqlite3.OperationalError:
                pass

            conn.close()

        except Exception:
            pass

        if backup_age_metric.values:
            metrics.append(backup_age_metric)

        return metrics

    def _collect_drift_metrics(self) -> List[Metric]:
        """Collect configuration drift metrics."""
        metrics = []

        drift_metric = Metric(
            name="wireguard_drift_items_total",
            help_text="Number of detected configuration drift items",
            metric_type=MetricType.GAUGE
        )

        try:
            conn = self._get_connection()

            # Get latest drift scan results
            try:
                drift_items = conn.execute("""
                    SELECT di.severity, COUNT(*) as count
                    FROM drift_item di
                    JOIN drift_scan ds ON di.scan_id = ds.id
                    WHERE ds.id = (SELECT MAX(id) FROM drift_scan)
                    AND di.acknowledged = 0
                    GROUP BY di.severity
                """).fetchall()

                for item in drift_items:
                    drift_metric.values.append(MetricValue(
                        value=float(item['count']),
                        labels={"severity": item['severity']}
                    ))

            except sqlite3.OperationalError:
                pass

            conn.close()

        except Exception:
            pass

        if drift_metric.values:
            metrics.append(drift_metric)

        return metrics

    def _collect_alert_metrics(self) -> List[Metric]:
        """Collect alert status metrics."""
        metrics = []

        alert_metric = Metric(
            name="wireguard_alerts_active",
            help_text="Number of active alerts by severity",
            metric_type=MetricType.GAUGE
        )

        try:
            conn = self._get_connection()

            try:
                alerts = conn.execute("""
                    SELECT severity, COUNT(*) as count
                    FROM alert
                    WHERE status = 'active'
                    GROUP BY severity
                """).fetchall()

                for alert in alerts:
                    alert_metric.values.append(MetricValue(
                        value=float(alert['count']),
                        labels={"severity": alert['severity']}
                    ))

            except sqlite3.OperationalError:
                pass

            conn.close()

        except Exception:
            pass

        if alert_metric.values:
            metrics.append(alert_metric)

        return metrics

    def _collect_bandwidth_metrics(self) -> List[Metric]:
        """Collect bandwidth usage metrics."""
        metrics = []

        rx_metric = Metric(
            name="wireguard_peer_rx_bytes_total",
            help_text="Total bytes received per peer",
            metric_type=MetricType.COUNTER
        )

        tx_metric = Metric(
            name="wireguard_peer_tx_bytes_total",
            help_text="Total bytes transmitted per peer",
            metric_type=MetricType.COUNTER
        )

        try:
            conn = self._get_connection()

            # Get latest bandwidth samples
            try:
                samples = conn.execute("""
                    SELECT public_key, rx_bytes, tx_bytes
                    FROM bandwidth_sample
                    WHERE id IN (
                        SELECT MAX(id) FROM bandwidth_sample
                        GROUP BY public_key
                    )
                """).fetchall()

                for sample in samples:
                    short_key = sample['public_key'][:8] + "..."

                    rx_metric.values.append(MetricValue(
                        value=float(sample['rx_bytes']),
                        labels={"public_key": short_key}
                    ))

                    tx_metric.values.append(MetricValue(
                        value=float(sample['tx_bytes']),
                        labels={"public_key": short_key}
                    ))

            except sqlite3.OperationalError:
                pass

            conn.close()

        except Exception:
            pass

        if rx_metric.values:
            metrics.append(rx_metric)
        if tx_metric.values:
            metrics.append(tx_metric)

        return metrics

    def format_prometheus(self, metrics: List[Metric]) -> str:
        """Format metrics in Prometheus exposition format.

        Args:
            metrics: List of Metric objects

        Returns:
            String in Prometheus text exposition format
        """
        lines = []

        for metric in metrics:
            # Add HELP line
            lines.append(f"# HELP {metric.name} {metric.help_text}")
            # Add TYPE line
            lines.append(f"# TYPE {metric.name} {metric.metric_type.value}")

            # Add metric values
            for mv in metric.values:
                if mv.labels:
                    label_str = ",".join(
                        f'{k}="{v}"' for k, v in sorted(mv.labels.items())
                    )
                    lines.append(f"{metric.name}{{{label_str}}} {mv.value}")
                else:
                    lines.append(f"{metric.name} {mv.value}")

            lines.append("")  # Blank line between metrics

        return "\n".join(lines)

    def get_metrics_text(self) -> str:
        """Get all metrics as Prometheus text format.

        Returns:
            Metrics in Prometheus exposition format
        """
        with self._lock:
            metrics = self.collect_all_metrics()
            return self.format_prometheus(metrics)


class MetricsRequestHandler(BaseHTTPRequestHandler):
    """HTTP request handler for Prometheus metrics endpoint."""

    collector: PrometheusMetricsCollector = None

    def do_GET(self):
        """Handle GET requests."""
        if self.path == "/metrics" or self.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
            self.end_headers()

            if self.collector:
                metrics_text = self.collector.get_metrics_text()
                self.wfile.write(metrics_text.encode('utf-8'))
            else:
                self.wfile.write(b"# No collector configured\n")

        elif self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"OK\n")

        else:
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Not Found\n")

    def log_message(self, format, *args):
        """Suppress default logging."""
        pass


class PrometheusMetricsServer:
    """HTTP server for exposing Prometheus metrics."""

    def __init__(self, collector: PrometheusMetricsCollector,
                 host: str = "0.0.0.0", port: int = 9100):
        """Initialize the metrics server.

        Args:
            collector: Metrics collector instance
            host: Bind address (default 0.0.0.0)
            port: Port number (default 9100)
        """
        self.collector = collector
        self.host = host
        self.port = port
        self._server: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def start(self):
        """Start the metrics server in a background thread."""
        # Set collector on handler class
        MetricsRequestHandler.collector = self.collector

        self._server = HTTPServer((self.host, self.port), MetricsRequestHandler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self):
        """Stop the metrics server."""
        if self._server:
            self._server.shutdown()
            self._server = None
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None

    def is_running(self) -> bool:
        """Check if server is running."""
        return self._thread is not None and self._thread.is_alive()


def export_metrics_once(db_path: str) -> str:
    """Export metrics once (for CLI usage).

    Args:
        db_path: Path to database

    Returns:
        Metrics in Prometheus format
    """
    collector = PrometheusMetricsCollector(db_path)
    return collector.get_metrics_text()


def run_metrics_server(db_path: str, host: str = "0.0.0.0", port: int = 9100):
    """Run a standalone metrics server (blocking).

    Args:
        db_path: Path to database
        host: Bind address
        port: Port number
    """
    collector = PrometheusMetricsCollector(db_path)
    server = PrometheusMetricsServer(collector, host, port)

    print(f"Starting Prometheus metrics server on {host}:{port}")
    print(f"Metrics available at http://{host}:{port}/metrics")
    print("Press Ctrl+C to stop")

    server.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down...")
        server.stop()


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python prometheus_metrics.py <db_path> [--serve [host:port]]")
        sys.exit(1)

    db_path = sys.argv[1]

    if "--serve" in sys.argv:
        # Find host:port if specified
        host = "0.0.0.0"
        port = 9100

        serve_idx = sys.argv.index("--serve")
        if serve_idx + 1 < len(sys.argv) and not sys.argv[serve_idx + 1].startswith("-"):
            addr = sys.argv[serve_idx + 1]
            if ":" in addr:
                host, port_str = addr.rsplit(":", 1)
                port = int(port_str)
            else:
                port = int(addr)

        run_metrics_server(db_path, host, port)
    else:
        # One-shot export
        print(export_metrics_once(db_path))
