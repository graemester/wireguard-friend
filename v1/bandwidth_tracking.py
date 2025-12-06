"""
Bandwidth & Usage Tracking

Periodic polling of `wg show` data with historical storage and analytics.
Supports anomaly detection baselines and compliance reporting.

Features:
- Raw sample collection (5-second granularity)
- Hourly/daily/weekly/monthly aggregation
- Statistical baselines for anomaly detection
- Per-entity and network-wide metrics
- SSH-based remote collection

Collection Modes:
1. Manual: Run `wg-friend bandwidth collect` to sample now
2. Scheduled: Cron job or systemd timer for periodic collection
3. Live: Background process with configurable interval

Usage:
    from bandwidth_tracking import BandwidthTracker

    tracker = BandwidthTracker(db_path)

    # Collect current samples
    samples = tracker.collect_samples()

    # Get bandwidth report
    report = tracker.get_bandwidth_report(hours=24)

    # Get top consumers
    top = tracker.get_top_consumers(days=7, limit=10)
"""

import sqlite3
import json
import logging
import subprocess
import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class BandwidthSample:
    """Raw bandwidth sample from wg show"""
    entity_type: str
    entity_id: int
    entity_guid: str
    hostname: str
    sampled_at: datetime
    rx_bytes: int           # Total received (cumulative)
    tx_bytes: int           # Total transmitted (cumulative)
    latest_handshake: Optional[datetime]
    endpoint: Optional[str]
    connected: bool


@dataclass
class BandwidthAggregate:
    """Aggregated bandwidth metrics for a time period"""
    entity_type: str
    entity_id: int
    hostname: str
    period_type: str        # 'hourly', 'daily', 'weekly', 'monthly'
    period_start: datetime
    period_end: datetime
    total_rx_bytes: int
    total_tx_bytes: int
    peak_rx_rate: int       # Bytes per second
    peak_tx_rate: int
    avg_rx_rate: int
    avg_tx_rate: int
    uptime_seconds: int
    availability_pct: float


@dataclass
class PeerBandwidthInfo:
    """Parsed output from wg show"""
    public_key: str
    endpoint: Optional[str]
    allowed_ips: str
    latest_handshake: Optional[datetime]
    transfer_rx: int        # bytes received
    transfer_tx: int        # bytes transmitted


def parse_wg_show_output(output: str) -> Dict[str, PeerBandwidthInfo]:
    """
    Parse output from `wg show wg0 dump` command.

    Returns dict mapping public_key -> PeerBandwidthInfo
    """
    peers = {}

    # wg show dump format:
    # private_key public_key listen_port fwmark
    # public_key preshared_key endpoint allowed_ips latest_handshake transfer_rx transfer_tx persistent_keepalive

    lines = output.strip().split('\n')
    if len(lines) < 2:
        return peers

    # Skip interface line (first line)
    for line in lines[1:]:
        parts = line.split('\t')
        if len(parts) < 8:
            continue

        public_key = parts[0]
        endpoint = parts[2] if parts[2] != '(none)' else None
        allowed_ips = parts[3]

        # Parse handshake timestamp (Unix epoch or 0)
        handshake_ts = int(parts[4]) if parts[4] != '0' else None
        latest_handshake = datetime.fromtimestamp(handshake_ts) if handshake_ts else None

        # Transfer stats (bytes)
        transfer_rx = int(parts[5])
        transfer_tx = int(parts[6])

        peers[public_key] = PeerBandwidthInfo(
            public_key=public_key,
            endpoint=endpoint,
            allowed_ips=allowed_ips,
            latest_handshake=latest_handshake,
            transfer_rx=transfer_rx,
            transfer_tx=transfer_tx
        )

    return peers


def run_wg_show(interface: str = 'wg0') -> str:
    """Run wg show command locally"""
    try:
        result = subprocess.run(
            ['wg', 'show', interface, 'dump'],
            capture_output=True,
            text=True,
            timeout=10
        )
        return result.stdout
    except subprocess.TimeoutExpired:
        logger.error("wg show command timed out")
        return ""
    except FileNotFoundError:
        logger.error("wg command not found")
        return ""
    except Exception as e:
        logger.error(f"Failed to run wg show: {e}")
        return ""


def run_wg_show_remote(ssh_host: str, ssh_user: str = 'root', ssh_port: int = 22, interface: str = 'wg0') -> str:
    """Run wg show command on remote host via SSH"""
    try:
        result = subprocess.run(
            ['ssh', '-p', str(ssh_port), '-o', 'ConnectTimeout=5', '-o', 'BatchMode=yes',
             f'{ssh_user}@{ssh_host}', f'wg show {interface} dump'],
            capture_output=True,
            text=True,
            timeout=30
        )
        return result.stdout
    except subprocess.TimeoutExpired:
        logger.error(f"SSH to {ssh_host} timed out")
        return ""
    except Exception as e:
        logger.error(f"Failed to run remote wg show on {ssh_host}: {e}")
        return ""


class BandwidthTracker:
    """
    Tracks bandwidth usage for all WireGuard peers.

    Collects samples from `wg show` output, stores in database,
    and provides aggregation and analysis.
    """

    # Retention periods
    RAW_SAMPLE_RETENTION_DAYS = 7
    HOURLY_RETENTION_DAYS = 30
    DAILY_RETENTION_DAYS = 365

    def __init__(self, db_path: Path | str):
        self.db_path = Path(db_path) if isinstance(db_path, str) else db_path
        self._init_schema()

    def _get_connection(self):
        """Get database connection"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def _init_schema(self):
        """Initialize bandwidth tracking schema"""
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            # Raw bandwidth samples
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS bandwidth_sample (
                    id INTEGER PRIMARY KEY,
                    entity_type TEXT NOT NULL,
                    entity_id INTEGER NOT NULL,
                    entity_permanent_guid TEXT NOT NULL,
                    sampled_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    rx_bytes INTEGER NOT NULL,
                    tx_bytes INTEGER NOT NULL,
                    latest_handshake TIMESTAMP,
                    endpoint TEXT,
                    connected BOOLEAN NOT NULL
                )
            """)

            # Aggregated bandwidth
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS bandwidth_aggregate (
                    id INTEGER PRIMARY KEY,
                    entity_type TEXT NOT NULL,
                    entity_id INTEGER NOT NULL,
                    entity_permanent_guid TEXT NOT NULL,
                    period_type TEXT NOT NULL,
                    period_start TIMESTAMP NOT NULL,
                    period_end TIMESTAMP NOT NULL,
                    total_rx_bytes INTEGER NOT NULL,
                    total_tx_bytes INTEGER NOT NULL,
                    peak_rx_rate INTEGER,
                    peak_tx_rate INTEGER,
                    avg_rx_rate INTEGER,
                    avg_tx_rate INTEGER,
                    uptime_seconds INTEGER NOT NULL,
                    downtime_seconds INTEGER NOT NULL,
                    availability_percent REAL NOT NULL,
                    sample_count INTEGER NOT NULL,
                    computed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(entity_type, entity_id, period_type, period_start)
                )
            """)

            # Baseline statistics for anomaly detection
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS bandwidth_baseline (
                    entity_type TEXT NOT NULL,
                    entity_id INTEGER NOT NULL,
                    entity_permanent_guid TEXT NOT NULL,
                    avg_daily_bytes INTEGER NOT NULL,
                    stddev_daily_bytes INTEGER NOT NULL,
                    p95_daily_bytes INTEGER NOT NULL,
                    computed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    samples_count INTEGER NOT NULL,
                    PRIMARY KEY (entity_type, entity_id)
                )
            """)

            # Indexes
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_bandwidth_sample_entity
                ON bandwidth_sample(entity_type, entity_id, sampled_at DESC)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_bandwidth_sample_time
                ON bandwidth_sample(sampled_at)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_bandwidth_aggregate_entity
                ON bandwidth_aggregate(entity_type, entity_id, period_type, period_start DESC)
            """)

            conn.commit()
            logger.debug("Bandwidth tracking schema initialized")

        finally:
            conn.close()

    def _get_entity_mapping(self, conn) -> Dict[str, Tuple[str, int, str, str]]:
        """
        Build mapping from public_key to entity info.

        Returns dict: public_key -> (entity_type, entity_id, permanent_guid, hostname)
        """
        cursor = conn.cursor()
        mapping = {}

        # Map all entity types
        tables = [
            ('coordination_server', 'coordination_server'),
            ('subnet_router', 'subnet_router'),
            ('remote', 'remote'),
            ('exit_node', 'exit_node')
        ]

        for table, entity_type in tables:
            try:
                cursor.execute(f"""
                    SELECT id, current_public_key, permanent_guid, hostname
                    FROM {table}
                """)
                for row in cursor.fetchall():
                    mapping[row['current_public_key']] = (
                        entity_type,
                        row['id'],
                        row['permanent_guid'],
                        row['hostname'] or row['permanent_guid'][:16]
                    )
            except sqlite3.OperationalError:
                continue  # Table might not exist

        return mapping

    def collect_samples(
        self,
        ssh_host: Optional[str] = None,
        ssh_user: str = 'root',
        ssh_port: int = 22,
        interface: str = 'wg0'
    ) -> List[BandwidthSample]:
        """
        Collect bandwidth samples from wg show.

        Args:
            ssh_host: If provided, collect from remote host via SSH
            ssh_user: SSH username
            ssh_port: SSH port
            interface: WireGuard interface name

        Returns:
            List of collected samples
        """
        # Get wg show output
        if ssh_host:
            output = run_wg_show_remote(ssh_host, ssh_user, ssh_port, interface)
        else:
            output = run_wg_show(interface)

        if not output:
            logger.warning("No wg show output available")
            return []

        # Parse output
        peer_data = parse_wg_show_output(output)

        if not peer_data:
            logger.warning("No peers found in wg show output")
            return []

        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            # Get entity mapping
            entity_map = self._get_entity_mapping(conn)

            samples = []
            now = datetime.utcnow()

            for public_key, info in peer_data.items():
                # Look up entity
                entity_info = entity_map.get(public_key)
                if not entity_info:
                    logger.debug(f"Unknown public key: {public_key[:16]}...")
                    continue

                entity_type, entity_id, guid, hostname = entity_info

                # Determine if connected (handshake within last 3 minutes)
                connected = False
                if info.latest_handshake:
                    age = now - info.latest_handshake
                    connected = age.total_seconds() < 180

                sample = BandwidthSample(
                    entity_type=entity_type,
                    entity_id=entity_id,
                    entity_guid=guid,
                    hostname=hostname,
                    sampled_at=now,
                    rx_bytes=info.transfer_rx,
                    tx_bytes=info.transfer_tx,
                    latest_handshake=info.latest_handshake,
                    endpoint=info.endpoint,
                    connected=connected
                )
                samples.append(sample)

                # Store sample
                cursor.execute("""
                    INSERT INTO bandwidth_sample (
                        entity_type, entity_id, entity_permanent_guid,
                        sampled_at, rx_bytes, tx_bytes,
                        latest_handshake, endpoint, connected
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    entity_type, entity_id, guid,
                    now.isoformat(), info.transfer_rx, info.transfer_tx,
                    info.latest_handshake.isoformat() if info.latest_handshake else None,
                    info.endpoint, connected
                ))

            conn.commit()
            logger.info(f"Collected {len(samples)} bandwidth samples")
            return samples

        finally:
            conn.close()

    def get_latest_samples(self) -> List[BandwidthSample]:
        """Get most recent sample for each entity"""
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                SELECT bs.*
                FROM bandwidth_sample bs
                INNER JOIN (
                    SELECT entity_type, entity_id, MAX(sampled_at) as max_time
                    FROM bandwidth_sample
                    GROUP BY entity_type, entity_id
                ) latest ON bs.entity_type = latest.entity_type
                           AND bs.entity_id = latest.entity_id
                           AND bs.sampled_at = latest.max_time
                ORDER BY bs.rx_bytes + bs.tx_bytes DESC
            """)

            samples = []
            for row in cursor.fetchall():
                samples.append(BandwidthSample(
                    entity_type=row['entity_type'],
                    entity_id=row['entity_id'],
                    entity_guid=row['entity_permanent_guid'],
                    hostname=self._get_hostname(cursor, row['entity_type'], row['entity_id']),
                    sampled_at=datetime.fromisoformat(row['sampled_at']),
                    rx_bytes=row['rx_bytes'],
                    tx_bytes=row['tx_bytes'],
                    latest_handshake=datetime.fromisoformat(row['latest_handshake']) if row['latest_handshake'] else None,
                    endpoint=row['endpoint'],
                    connected=bool(row['connected'])
                ))

            return samples

        finally:
            conn.close()

    def _get_hostname(self, cursor, entity_type: str, entity_id: int) -> str:
        """Get hostname for entity"""
        table_map = {
            'coordination_server': 'coordination_server',
            'subnet_router': 'subnet_router',
            'remote': 'remote',
            'exit_node': 'exit_node'
        }
        table = table_map.get(entity_type)
        if not table:
            return f"{entity_type}:{entity_id}"

        try:
            cursor.execute(f"SELECT hostname, permanent_guid FROM {table} WHERE id = ?", (entity_id,))
            row = cursor.fetchone()
            return row['hostname'] or row['permanent_guid'][:16] if row else f"{entity_type}:{entity_id}"
        except:
            return f"{entity_type}:{entity_id}"

    def get_bandwidth_report(
        self,
        hours: int = 24,
        entity_type: Optional[str] = None,
        entity_id: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Generate bandwidth report for specified time period.

        Returns:
            Dict with total stats, per-entity breakdown, and timeline
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            cutoff = (datetime.utcnow() - timedelta(hours=hours)).isoformat()

            # Build query
            query = """
                SELECT
                    entity_type, entity_id, entity_permanent_guid,
                    MIN(sampled_at) as first_sample,
                    MAX(sampled_at) as last_sample,
                    MIN(rx_bytes) as min_rx,
                    MAX(rx_bytes) as max_rx,
                    MIN(tx_bytes) as min_tx,
                    MAX(tx_bytes) as max_tx,
                    SUM(connected) as connected_samples,
                    COUNT(*) as total_samples
                FROM bandwidth_sample
                WHERE sampled_at >= ?
            """
            params = [cutoff]

            if entity_type:
                query += " AND entity_type = ?"
                params.append(entity_type)

            if entity_id:
                query += " AND entity_id = ?"
                params.append(entity_id)

            query += " GROUP BY entity_type, entity_id"

            cursor.execute(query, params)

            entities = []
            total_rx = 0
            total_tx = 0

            for row in cursor.fetchall():
                # Calculate delta (max - min represents transfer during period)
                rx_delta = row['max_rx'] - row['min_rx']
                tx_delta = row['max_tx'] - row['min_tx']

                # Handle counter wrap (unlikely but possible)
                if rx_delta < 0:
                    rx_delta = row['max_rx']
                if tx_delta < 0:
                    tx_delta = row['max_tx']

                hostname = self._get_hostname(cursor, row['entity_type'], row['entity_id'])

                availability = (row['connected_samples'] / row['total_samples'] * 100) if row['total_samples'] > 0 else 0

                entities.append({
                    'entity_type': row['entity_type'],
                    'entity_id': row['entity_id'],
                    'hostname': hostname,
                    'rx_bytes': rx_delta,
                    'tx_bytes': tx_delta,
                    'total_bytes': rx_delta + tx_delta,
                    'availability_pct': round(availability, 1),
                    'sample_count': row['total_samples']
                })

                total_rx += rx_delta
                total_tx += tx_delta

            # Sort by total bytes descending
            entities.sort(key=lambda x: x['total_bytes'], reverse=True)

            return {
                'period_hours': hours,
                'generated_at': datetime.utcnow().isoformat(),
                'total_rx_bytes': total_rx,
                'total_tx_bytes': total_tx,
                'total_bytes': total_rx + total_tx,
                'entity_count': len(entities),
                'entities': entities
            }

        finally:
            conn.close()

    def get_top_consumers(self, days: int = 7, limit: int = 10) -> List[Dict[str, Any]]:
        """Get top bandwidth consumers for the period"""
        report = self.get_bandwidth_report(hours=days * 24)
        return report['entities'][:limit]

    def compute_aggregates(self, period_type: str = 'hourly'):
        """
        Compute aggregated bandwidth metrics.

        Args:
            period_type: 'hourly', 'daily', 'weekly', 'monthly'
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            now = datetime.utcnow()

            # Determine period boundaries
            if period_type == 'hourly':
                period_start = now.replace(minute=0, second=0, microsecond=0) - timedelta(hours=1)
                period_end = period_start + timedelta(hours=1)
            elif period_type == 'daily':
                period_start = now.replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=1)
                period_end = period_start + timedelta(days=1)
            elif period_type == 'weekly':
                # Start of previous week
                days_since_monday = now.weekday()
                period_start = (now - timedelta(days=days_since_monday + 7)).replace(hour=0, minute=0, second=0, microsecond=0)
                period_end = period_start + timedelta(weeks=1)
            else:  # monthly
                # Previous month
                if now.month == 1:
                    period_start = now.replace(year=now.year - 1, month=12, day=1, hour=0, minute=0, second=0, microsecond=0)
                else:
                    period_start = now.replace(month=now.month - 1, day=1, hour=0, minute=0, second=0, microsecond=0)
                period_end = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)

            # Get samples in period
            cursor.execute("""
                SELECT entity_type, entity_id, entity_permanent_guid,
                       sampled_at, rx_bytes, tx_bytes, connected
                FROM bandwidth_sample
                WHERE sampled_at >= ? AND sampled_at < ?
                ORDER BY entity_type, entity_id, sampled_at
            """, (period_start.isoformat(), period_end.isoformat()))

            # Group by entity
            entity_samples = {}
            for row in cursor.fetchall():
                key = (row['entity_type'], row['entity_id'], row['entity_permanent_guid'])
                if key not in entity_samples:
                    entity_samples[key] = []
                entity_samples[key].append(row)

            # Compute aggregates for each entity
            for (entity_type, entity_id, guid), samples in entity_samples.items():
                if len(samples) < 2:
                    continue

                # Calculate metrics
                rx_delta = samples[-1]['rx_bytes'] - samples[0]['rx_bytes']
                tx_delta = samples[-1]['tx_bytes'] - samples[0]['tx_bytes']

                # Handle counter wrap
                if rx_delta < 0:
                    rx_delta = samples[-1]['rx_bytes']
                if tx_delta < 0:
                    tx_delta = samples[-1]['tx_bytes']

                # Calculate rates
                period_seconds = (period_end - period_start).total_seconds()
                avg_rx_rate = int(rx_delta / period_seconds) if period_seconds > 0 else 0
                avg_tx_rate = int(tx_delta / period_seconds) if period_seconds > 0 else 0

                # Peak rates (between consecutive samples)
                peak_rx_rate = 0
                peak_tx_rate = 0
                for i in range(1, len(samples)):
                    t1 = datetime.fromisoformat(samples[i-1]['sampled_at'])
                    t2 = datetime.fromisoformat(samples[i]['sampled_at'])
                    dt = (t2 - t1).total_seconds()
                    if dt > 0:
                        rx_rate = (samples[i]['rx_bytes'] - samples[i-1]['rx_bytes']) / dt
                        tx_rate = (samples[i]['tx_bytes'] - samples[i-1]['tx_bytes']) / dt
                        peak_rx_rate = max(peak_rx_rate, int(rx_rate))
                        peak_tx_rate = max(peak_tx_rate, int(tx_rate))

                # Uptime calculation
                connected_samples = sum(1 for s in samples if s['connected'])
                uptime_pct = connected_samples / len(samples) * 100
                uptime_seconds = int(period_seconds * uptime_pct / 100)
                downtime_seconds = int(period_seconds - uptime_seconds)

                # Insert/update aggregate
                cursor.execute("""
                    INSERT OR REPLACE INTO bandwidth_aggregate (
                        entity_type, entity_id, entity_permanent_guid,
                        period_type, period_start, period_end,
                        total_rx_bytes, total_tx_bytes,
                        peak_rx_rate, peak_tx_rate, avg_rx_rate, avg_tx_rate,
                        uptime_seconds, downtime_seconds, availability_percent,
                        sample_count
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    entity_type, entity_id, guid,
                    period_type, period_start.isoformat(), period_end.isoformat(),
                    rx_delta, tx_delta,
                    peak_rx_rate, peak_tx_rate, avg_rx_rate, avg_tx_rate,
                    uptime_seconds, downtime_seconds, round(uptime_pct, 1),
                    len(samples)
                ))

            conn.commit()
            logger.info(f"Computed {period_type} aggregates for {len(entity_samples)} entities")

        finally:
            conn.close()

    def cleanup_old_samples(self):
        """Remove old samples based on retention policy"""
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            # Raw samples
            cutoff = (datetime.utcnow() - timedelta(days=self.RAW_SAMPLE_RETENTION_DAYS)).isoformat()
            cursor.execute("DELETE FROM bandwidth_sample WHERE sampled_at < ?", (cutoff,))
            deleted_samples = cursor.rowcount

            # Hourly aggregates
            cutoff = (datetime.utcnow() - timedelta(days=self.HOURLY_RETENTION_DAYS)).isoformat()
            cursor.execute(
                "DELETE FROM bandwidth_aggregate WHERE period_type = 'hourly' AND period_end < ?",
                (cutoff,)
            )
            deleted_hourly = cursor.rowcount

            # Daily aggregates
            cutoff = (datetime.utcnow() - timedelta(days=self.DAILY_RETENTION_DAYS)).isoformat()
            cursor.execute(
                "DELETE FROM bandwidth_aggregate WHERE period_type = 'daily' AND period_end < ?",
                (cutoff,)
            )
            deleted_daily = cursor.rowcount

            conn.commit()
            logger.info(f"Cleanup: {deleted_samples} samples, {deleted_hourly} hourly, {deleted_daily} daily aggregates")

        finally:
            conn.close()

    def get_statistics(self) -> Dict[str, Any]:
        """Get bandwidth tracking statistics"""
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            stats = {}

            # Sample counts
            cursor.execute("SELECT COUNT(*) FROM bandwidth_sample")
            stats['total_samples'] = cursor.fetchone()[0]

            # Time range
            cursor.execute("SELECT MIN(sampled_at), MAX(sampled_at) FROM bandwidth_sample")
            row = cursor.fetchone()
            stats['oldest_sample'] = row[0]
            stats['newest_sample'] = row[1]

            # Aggregate counts
            cursor.execute("""
                SELECT period_type, COUNT(*)
                FROM bandwidth_aggregate
                GROUP BY period_type
            """)
            stats['aggregates'] = {row[0]: row[1] for row in cursor.fetchall()}

            # Total bandwidth (all time)
            cursor.execute("""
                SELECT SUM(total_rx_bytes), SUM(total_tx_bytes)
                FROM bandwidth_aggregate
                WHERE period_type = 'daily'
            """)
            row = cursor.fetchone()
            stats['total_rx_bytes'] = row[0] or 0
            stats['total_tx_bytes'] = row[1] or 0

            return stats

        finally:
            conn.close()


def format_bytes(bytes_val: int) -> str:
    """Format bytes to human-readable string"""
    if bytes_val < 1024:
        return f"{bytes_val} B"
    elif bytes_val < 1024 * 1024:
        return f"{bytes_val / 1024:.1f} KB"
    elif bytes_val < 1024 * 1024 * 1024:
        return f"{bytes_val / (1024 * 1024):.1f} MB"
    else:
        return f"{bytes_val / (1024 * 1024 * 1024):.2f} GB"


if __name__ == "__main__":
    # Demo with mock data
    import tempfile

    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
        db_path = Path(f.name)

    try:
        print("=== Bandwidth Tracking Demo ===\n")

        # Create mock entity tables
        conn = sqlite3.connect(db_path)
        conn.execute("""
            CREATE TABLE remote (
                id INTEGER PRIMARY KEY,
                permanent_guid TEXT NOT NULL UNIQUE,
                current_public_key TEXT NOT NULL,
                hostname TEXT
            )
        """)
        conn.execute(
            "INSERT INTO remote VALUES (1, 'guid-alice', 'pubkey-alice', 'alice-laptop')"
        )
        conn.execute(
            "INSERT INTO remote VALUES (2, 'guid-bob', 'pubkey-bob', 'bob-phone')"
        )
        conn.commit()
        conn.close()

        tracker = BandwidthTracker(db_path)

        # Insert some mock samples
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        now = datetime.utcnow()
        for i in range(10):
            sample_time = (now - timedelta(hours=i)).isoformat()
            # Alice: increasing traffic
            cursor.execute("""
                INSERT INTO bandwidth_sample (
                    entity_type, entity_id, entity_permanent_guid,
                    sampled_at, rx_bytes, tx_bytes, connected
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """, ('remote', 1, 'guid-alice', sample_time,
                  1000000000 + (10-i) * 100000000,
                  500000000 + (10-i) * 50000000,
                  1))

            # Bob: less traffic
            cursor.execute("""
                INSERT INTO bandwidth_sample (
                    entity_type, entity_id, entity_permanent_guid,
                    sampled_at, rx_bytes, tx_bytes, connected
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """, ('remote', 2, 'guid-bob', sample_time,
                  200000000 + (10-i) * 20000000,
                  100000000 + (10-i) * 10000000,
                  1 if i < 8 else 0))

        conn.commit()
        conn.close()

        # Generate report
        print("24-Hour Bandwidth Report:")
        report = tracker.get_bandwidth_report(hours=24)
        print(f"  Total RX: {format_bytes(report['total_rx_bytes'])}")
        print(f"  Total TX: {format_bytes(report['total_tx_bytes'])}")
        print(f"  Total: {format_bytes(report['total_bytes'])}")
        print(f"\nPer-entity breakdown:")
        for entity in report['entities']:
            print(f"  {entity['hostname']}: RX {format_bytes(entity['rx_bytes'])}, TX {format_bytes(entity['tx_bytes'])} ({entity['availability_pct']}% online)")

        # Get statistics
        print("\nStatistics:")
        stats = tracker.get_statistics()
        print(f"  Total samples: {stats['total_samples']}")
        print(f"  Date range: {stats['oldest_sample']} to {stats['newest_sample']}")

    finally:
        db_path.unlink()
        print("\nDemo complete!")
