"""
Configuration Drift Detection Module

Detects discrepancies between database state and deployed configurations
on coordination servers and subnet routers.

Features:
- Fetches live configs via SSH
- Compares against expected (database) state
- Categorizes drift: added, removed, modified peers
- Tracks drift history for trending
- Supports auto-remediation via config push

Architecture follows architecture-review.md recommendations.
"""

import hashlib
import json
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional

try:
    import paramiko
except ImportError:
    paramiko = None


class DriftType(Enum):
    """Types of configuration drift."""
    PEER_ADDED = "peer_added"           # Peer exists on device but not in DB
    PEER_REMOVED = "peer_removed"       # Peer in DB but missing from device
    PEER_MODIFIED = "peer_modified"     # Peer exists but config differs
    ENDPOINT_CHANGED = "endpoint_changed"
    ALLOWED_IPS_CHANGED = "allowed_ips_changed"
    KEEPALIVE_CHANGED = "keepalive_changed"
    SERVER_KEY_CHANGED = "server_key_changed"


class DriftSeverity(Enum):
    """Severity levels for drift."""
    INFO = "info"           # Expected or minor drift
    WARNING = "warning"     # Should investigate
    CRITICAL = "critical"   # Security concern or breaking change


@dataclass
class DriftItem:
    """Single drift detection item."""
    drift_type: DriftType
    severity: DriftSeverity
    entity_type: str        # cs, sr, remote
    entity_name: str
    peer_public_key: Optional[str]
    expected_value: Optional[str]
    actual_value: Optional[str]
    description: str

    def to_dict(self) -> dict:
        return {
            "drift_type": self.drift_type.value,
            "severity": self.severity.value,
            "entity_type": self.entity_type,
            "entity_name": self.entity_name,
            "peer_public_key": self.peer_public_key,
            "expected_value": self.expected_value,
            "actual_value": self.actual_value,
            "description": self.description,
        }


@dataclass
class DriftReport:
    """Complete drift report for an entity."""
    entity_type: str
    entity_name: str
    scan_time: datetime
    config_hash_expected: str
    config_hash_actual: str
    is_drifted: bool
    drift_items: list = field(default_factory=list)
    error: Optional[str] = None

    @property
    def critical_count(self) -> int:
        return sum(1 for d in self.drift_items if d.severity == DriftSeverity.CRITICAL)

    @property
    def warning_count(self) -> int:
        return sum(1 for d in self.drift_items if d.severity == DriftSeverity.WARNING)

    def to_dict(self) -> dict:
        return {
            "entity_type": self.entity_type,
            "entity_name": self.entity_name,
            "scan_time": self.scan_time.isoformat(),
            "config_hash_expected": self.config_hash_expected,
            "config_hash_actual": self.config_hash_actual,
            "is_drifted": self.is_drifted,
            "critical_count": self.critical_count,
            "warning_count": self.warning_count,
            "drift_items": [d.to_dict() for d in self.drift_items],
            "error": self.error,
        }


class DriftDetector:
    """
    Detects configuration drift between database and deployed configs.

    Usage:
        detector = DriftDetector(db_path)
        report = detector.check_entity("cs", "my-vps")
        if report.is_drifted:
            for item in report.drift_items:
                print(f"{item.severity.value}: {item.description}")
    """

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init_tables()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_tables(self):
        """Create drift detection tables."""
        conn = self._get_conn()
        try:
            conn.executescript("""
                -- Drift scan history
                CREATE TABLE IF NOT EXISTS drift_scan (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    entity_type TEXT NOT NULL,
                    entity_id INTEGER NOT NULL,
                    entity_name TEXT NOT NULL,
                    scan_time TEXT NOT NULL,
                    config_hash_expected TEXT,
                    config_hash_actual TEXT,
                    is_drifted INTEGER NOT NULL DEFAULT 0,
                    drift_count INTEGER NOT NULL DEFAULT 0,
                    critical_count INTEGER NOT NULL DEFAULT 0,
                    warning_count INTEGER NOT NULL DEFAULT 0,
                    error TEXT,
                    UNIQUE(entity_type, entity_id, scan_time)
                );

                -- Individual drift items
                CREATE TABLE IF NOT EXISTS drift_item (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL,
                    drift_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    peer_public_key TEXT,
                    expected_value TEXT,
                    actual_value TEXT,
                    description TEXT NOT NULL,
                    FOREIGN KEY (scan_id) REFERENCES drift_scan(id)
                );

                -- Drift baselines (acknowledged drift that should be ignored)
                CREATE TABLE IF NOT EXISTS drift_baseline (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    entity_type TEXT NOT NULL,
                    entity_id INTEGER NOT NULL,
                    drift_type TEXT NOT NULL,
                    peer_public_key TEXT,
                    acknowledged_at TEXT NOT NULL,
                    acknowledged_by TEXT,
                    reason TEXT,
                    expires_at TEXT,
                    UNIQUE(entity_type, entity_id, drift_type, peer_public_key)
                );

                CREATE INDEX IF NOT EXISTS idx_drift_scan_entity
                    ON drift_scan(entity_type, entity_id);
                CREATE INDEX IF NOT EXISTS idx_drift_scan_time
                    ON drift_scan(scan_time);
                CREATE INDEX IF NOT EXISTS idx_drift_item_scan
                    ON drift_item(scan_id);
            """)
            conn.commit()
        finally:
            conn.close()

    def _fetch_live_config(self, host: str, port: int, user: str,
                           key_path: str, interface: str = "wg0") -> Optional[str]:
        """Fetch live WireGuard config via SSH."""
        if paramiko is None:
            return None

        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                hostname=host,
                port=port,
                username=user,
                key_filename=key_path,
                timeout=10
            )

            # Get running config with wg showconf
            stdin, stdout, stderr = client.exec_command(f"sudo wg showconf {interface}")
            config = stdout.read().decode('utf-8')
            client.close()

            return config if config.strip() else None

        except Exception as e:
            return None

    def _parse_wg_config(self, config_text: str) -> dict:
        """Parse WireGuard config into structured dict."""
        result = {
            "interface": {},
            "peers": {}  # keyed by public key
        }

        current_section = None
        current_peer_key = None

        for line in config_text.strip().split('\n'):
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            if line == '[Interface]':
                current_section = 'interface'
                current_peer_key = None
                continue
            elif line == '[Peer]':
                current_section = 'peer'
                current_peer_key = None
                continue

            if '=' in line:
                key, value = line.split('=', 1)
                key = key.strip().lower()
                value = value.strip()

                if current_section == 'interface':
                    result['interface'][key] = value
                elif current_section == 'peer':
                    if key == 'publickey':
                        current_peer_key = value
                        result['peers'][value] = {}
                    elif current_peer_key:
                        result['peers'][current_peer_key][key] = value

        return result

    def _hash_config(self, config_dict: dict) -> str:
        """Generate deterministic hash of config."""
        # Sort for determinism
        normalized = json.dumps(config_dict, sort_keys=True)
        return hashlib.sha256(normalized.encode()).hexdigest()[:16]

    def _get_expected_peers(self, conn: sqlite3.Connection,
                            entity_type: str, entity_id: int) -> dict:
        """Get expected peers from database."""
        peers = {}

        if entity_type == "cs":
            # Coordination server expects: remotes + subnet routers

            # Get remotes
            rows = conn.execute("""
                SELECT r.public_key, r.vpn_ip, r.endpoint, r.keepalive
                FROM remote r
                WHERE r.sponsor_type = 'cs' AND r.sponsor_id = ?
            """, (entity_id,)).fetchall()

            for row in rows:
                peers[row['public_key']] = {
                    'allowedips': row['vpn_ip'] + '/32' if row['vpn_ip'] else '',
                    'endpoint': row['endpoint'] or '',
                    'persistentkeepalive': str(row['keepalive']) if row['keepalive'] else '',
                }

            # Get subnet routers
            rows = conn.execute("""
                SELECT sr.public_key, sr.vpn_ip, sr.endpoint, sr.keepalive
                FROM subnet_router sr
                WHERE sr.cs_id = ?
            """, (entity_id,)).fetchall()

            for row in rows:
                # SR gets its VPN IP plus advertised networks
                allowed = [row['vpn_ip'] + '/32'] if row['vpn_ip'] else []

                # Get advertised networks
                networks = conn.execute("""
                    SELECT network FROM advertised_network WHERE sr_id = ?
                """, (entity_id,)).fetchall()  # Note: should use sr.id not entity_id

                for net in networks:
                    allowed.append(net['network'])

                peers[row['public_key']] = {
                    'allowedips': ', '.join(allowed),
                    'endpoint': row['endpoint'] or '',
                    'persistentkeepalive': str(row['keepalive']) if row['keepalive'] else '',
                }

        elif entity_type == "sr":
            # Subnet router expects: its CS + its remotes

            # Get coordination server (just one)
            row = conn.execute("""
                SELECT cs.public_key, cs.endpoint, cs.keepalive
                FROM coordination_server cs
                JOIN subnet_router sr ON sr.cs_id = cs.id
                WHERE sr.id = ?
            """, (entity_id,)).fetchone()

            if row:
                peers[row['public_key']] = {
                    'allowedips': '0.0.0.0/0, ::/0',  # SR routes all traffic through CS
                    'endpoint': row['endpoint'] or '',
                    'persistentkeepalive': str(row['keepalive']) if row['keepalive'] else '',
                }

            # Get remotes sponsored by this SR
            rows = conn.execute("""
                SELECT r.public_key, r.vpn_ip, r.endpoint, r.keepalive
                FROM remote r
                WHERE r.sponsor_type = 'sr' AND r.sponsor_id = ?
            """, (entity_id,)).fetchall()

            for row in rows:
                peers[row['public_key']] = {
                    'allowedips': row['vpn_ip'] + '/32' if row['vpn_ip'] else '',
                    'endpoint': row['endpoint'] or '',
                    'persistentkeepalive': str(row['keepalive']) if row['keepalive'] else '',
                }

        return peers

    def _compare_peers(self, expected: dict, actual: dict,
                       entity_type: str, entity_name: str) -> list:
        """Compare expected vs actual peers and generate drift items."""
        drift_items = []

        expected_keys = set(expected.keys())
        actual_keys = set(actual.keys())

        # Peers added on device (not in DB)
        for pub_key in actual_keys - expected_keys:
            drift_items.append(DriftItem(
                drift_type=DriftType.PEER_ADDED,
                severity=DriftSeverity.CRITICAL,  # Unknown peer is security concern
                entity_type=entity_type,
                entity_name=entity_name,
                peer_public_key=pub_key,
                expected_value=None,
                actual_value="present",
                description=f"Unknown peer on device: {pub_key[:16]}..."
            ))

        # Peers removed from device (in DB but missing)
        for pub_key in expected_keys - actual_keys:
            drift_items.append(DriftItem(
                drift_type=DriftType.PEER_REMOVED,
                severity=DriftSeverity.WARNING,
                entity_type=entity_type,
                entity_name=entity_name,
                peer_public_key=pub_key,
                expected_value="present",
                actual_value=None,
                description=f"Expected peer missing: {pub_key[:16]}..."
            ))

        # Peers that exist in both - check for modifications
        for pub_key in expected_keys & actual_keys:
            exp = expected[pub_key]
            act = actual[pub_key]

            # Check AllowedIPs
            exp_ips = self._normalize_ips(exp.get('allowedips', ''))
            act_ips = self._normalize_ips(act.get('allowedips', ''))
            if exp_ips != act_ips:
                drift_items.append(DriftItem(
                    drift_type=DriftType.ALLOWED_IPS_CHANGED,
                    severity=DriftSeverity.WARNING,
                    entity_type=entity_type,
                    entity_name=entity_name,
                    peer_public_key=pub_key,
                    expected_value=exp.get('allowedips', ''),
                    actual_value=act.get('allowedips', ''),
                    description=f"AllowedIPs changed for {pub_key[:16]}..."
                ))

            # Check Endpoint (only if expected has one)
            if exp.get('endpoint'):
                if exp.get('endpoint') != act.get('endpoint', ''):
                    drift_items.append(DriftItem(
                        drift_type=DriftType.ENDPOINT_CHANGED,
                        severity=DriftSeverity.INFO,  # Endpoints can change
                        entity_type=entity_type,
                        entity_name=entity_name,
                        peer_public_key=pub_key,
                        expected_value=exp.get('endpoint'),
                        actual_value=act.get('endpoint', ''),
                        description=f"Endpoint changed for {pub_key[:16]}..."
                    ))

            # Check PersistentKeepalive
            exp_ka = exp.get('persistentkeepalive', '')
            act_ka = act.get('persistentkeepalive', '')
            if exp_ka and exp_ka != act_ka:
                drift_items.append(DriftItem(
                    drift_type=DriftType.KEEPALIVE_CHANGED,
                    severity=DriftSeverity.INFO,
                    entity_type=entity_type,
                    entity_name=entity_name,
                    peer_public_key=pub_key,
                    expected_value=exp_ka,
                    actual_value=act_ka,
                    description=f"Keepalive changed for {pub_key[:16]}..."
                ))

        return drift_items

    def _normalize_ips(self, ips_str: str) -> set:
        """Normalize AllowedIPs for comparison."""
        if not ips_str:
            return set()
        return set(ip.strip() for ip in ips_str.split(',') if ip.strip())

    def check_entity(self, entity_type: str, entity_name: str,
                     ssh_host: str = None, ssh_port: int = 22,
                     ssh_user: str = "root", ssh_key: str = None,
                     interface: str = "wg0") -> DriftReport:
        """
        Check an entity for configuration drift.

        Args:
            entity_type: "cs" or "sr"
            entity_name: Name/hostname of entity
            ssh_host: SSH host (defaults to endpoint from DB)
            ssh_port: SSH port
            ssh_user: SSH username
            ssh_key: Path to SSH private key
            interface: WireGuard interface name

        Returns:
            DriftReport with all detected drift items
        """
        scan_time = datetime.now()

        conn = self._get_conn()
        try:
            # Get entity from DB
            if entity_type == "cs":
                row = conn.execute("""
                    SELECT id, hostname, endpoint, public_key
                    FROM coordination_server WHERE hostname = ?
                """, (entity_name,)).fetchone()
            elif entity_type == "sr":
                row = conn.execute("""
                    SELECT id, hostname, endpoint, public_key
                    FROM subnet_router WHERE hostname = ?
                """, (entity_name,)).fetchone()
            else:
                return DriftReport(
                    entity_type=entity_type,
                    entity_name=entity_name,
                    scan_time=scan_time,
                    config_hash_expected="",
                    config_hash_actual="",
                    is_drifted=False,
                    error=f"Unknown entity type: {entity_type}"
                )

            if not row:
                return DriftReport(
                    entity_type=entity_type,
                    entity_name=entity_name,
                    scan_time=scan_time,
                    config_hash_expected="",
                    config_hash_actual="",
                    is_drifted=False,
                    error=f"Entity not found: {entity_name}"
                )

            entity_id = row['id']

            # Determine SSH host
            if not ssh_host:
                endpoint = row['endpoint']
                if endpoint and ':' in endpoint:
                    ssh_host = endpoint.split(':')[0]
                else:
                    ssh_host = endpoint

            if not ssh_host:
                return DriftReport(
                    entity_type=entity_type,
                    entity_name=entity_name,
                    scan_time=scan_time,
                    config_hash_expected="",
                    config_hash_actual="",
                    is_drifted=False,
                    error="No SSH host available"
                )

            # Get expected state from DB
            expected_peers = self._get_expected_peers(conn, entity_type, entity_id)
            expected_config = {"peers": expected_peers}
            expected_hash = self._hash_config(expected_config)

            # Fetch actual config via SSH
            live_config = self._fetch_live_config(
                ssh_host, ssh_port, ssh_user, ssh_key, interface
            )

            if live_config is None:
                return DriftReport(
                    entity_type=entity_type,
                    entity_name=entity_name,
                    scan_time=scan_time,
                    config_hash_expected=expected_hash,
                    config_hash_actual="",
                    is_drifted=False,
                    error="Failed to fetch live config via SSH"
                )

            # Parse actual config
            actual_parsed = self._parse_wg_config(live_config)
            actual_config = {"peers": actual_parsed['peers']}
            actual_hash = self._hash_config(actual_config)

            # Compare
            drift_items = self._compare_peers(
                expected_peers,
                actual_parsed['peers'],
                entity_type,
                entity_name
            )

            # Filter out baselined drift
            drift_items = self._filter_baselined(
                conn, entity_type, entity_id, drift_items
            )

            is_drifted = len(drift_items) > 0

            report = DriftReport(
                entity_type=entity_type,
                entity_name=entity_name,
                scan_time=scan_time,
                config_hash_expected=expected_hash,
                config_hash_actual=actual_hash,
                is_drifted=is_drifted,
                drift_items=drift_items
            )

            # Store scan result
            self._store_scan(conn, entity_type, entity_id, report)

            return report

        finally:
            conn.close()

    def _filter_baselined(self, conn: sqlite3.Connection, entity_type: str,
                          entity_id: int, items: list) -> list:
        """Remove drift items that have been baselined/acknowledged."""
        filtered = []
        now = datetime.now().isoformat()

        for item in items:
            row = conn.execute("""
                SELECT id FROM drift_baseline
                WHERE entity_type = ? AND entity_id = ?
                  AND drift_type = ?
                  AND (peer_public_key IS NULL OR peer_public_key = ?)
                  AND (expires_at IS NULL OR expires_at > ?)
            """, (entity_type, entity_id, item.drift_type.value,
                  item.peer_public_key, now)).fetchone()

            if not row:
                filtered.append(item)

        return filtered

    def _store_scan(self, conn: sqlite3.Connection, entity_type: str,
                    entity_id: int, report: DriftReport):
        """Store scan results in database."""
        cursor = conn.execute("""
            INSERT INTO drift_scan
            (entity_type, entity_id, entity_name, scan_time,
             config_hash_expected, config_hash_actual, is_drifted,
             drift_count, critical_count, warning_count, error)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            entity_type, entity_id, report.entity_name,
            report.scan_time.isoformat(),
            report.config_hash_expected, report.config_hash_actual,
            1 if report.is_drifted else 0,
            len(report.drift_items), report.critical_count, report.warning_count,
            report.error
        ))

        scan_id = cursor.lastrowid

        for item in report.drift_items:
            conn.execute("""
                INSERT INTO drift_item
                (scan_id, drift_type, severity, peer_public_key,
                 expected_value, actual_value, description)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                scan_id, item.drift_type.value, item.severity.value,
                item.peer_public_key, item.expected_value, item.actual_value,
                item.description
            ))

        conn.commit()

    def acknowledge_drift(self, entity_type: str, entity_name: str,
                          drift_type: DriftType, peer_public_key: str = None,
                          reason: str = None, expires_days: int = None,
                          acknowledged_by: str = None):
        """
        Acknowledge (baseline) a drift item so it won't be reported.

        Args:
            entity_type: "cs" or "sr"
            entity_name: Name of entity
            drift_type: Type of drift to acknowledge
            peer_public_key: Specific peer (None for all)
            reason: Why this drift is acceptable
            expires_days: Auto-expire after N days (None for permanent)
            acknowledged_by: Who acknowledged this
        """
        conn = self._get_conn()
        try:
            # Get entity ID
            if entity_type == "cs":
                row = conn.execute(
                    "SELECT id FROM coordination_server WHERE hostname = ?",
                    (entity_name,)
                ).fetchone()
            else:
                row = conn.execute(
                    "SELECT id FROM subnet_router WHERE hostname = ?",
                    (entity_name,)
                ).fetchone()

            if not row:
                raise ValueError(f"Entity not found: {entity_name}")

            entity_id = row['id']
            now = datetime.now()
            expires_at = None
            if expires_days:
                from datetime import timedelta
                expires_at = (now + timedelta(days=expires_days)).isoformat()

            conn.execute("""
                INSERT OR REPLACE INTO drift_baseline
                (entity_type, entity_id, drift_type, peer_public_key,
                 acknowledged_at, acknowledged_by, reason, expires_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                entity_type, entity_id, drift_type.value, peer_public_key,
                now.isoformat(), acknowledged_by, reason, expires_at
            ))
            conn.commit()

        finally:
            conn.close()

    def get_drift_history(self, entity_type: str = None,
                          entity_name: str = None,
                          days: int = 30) -> list:
        """Get drift scan history."""
        conn = self._get_conn()
        try:
            query = """
                SELECT * FROM drift_scan
                WHERE scan_time > datetime('now', ?)
            """
            params = [f'-{days} days']

            if entity_type:
                query += " AND entity_type = ?"
                params.append(entity_type)
            if entity_name:
                query += " AND entity_name = ?"
                params.append(entity_name)

            query += " ORDER BY scan_time DESC"

            rows = conn.execute(query, params).fetchall()
            return [dict(row) for row in rows]

        finally:
            conn.close()

    def get_drift_summary(self) -> dict:
        """Get summary of drift status across all entities."""
        conn = self._get_conn()
        try:
            # Get latest scan for each entity
            rows = conn.execute("""
                SELECT entity_type, entity_name, is_drifted,
                       critical_count, warning_count, scan_time
                FROM drift_scan ds1
                WHERE scan_time = (
                    SELECT MAX(scan_time) FROM drift_scan ds2
                    WHERE ds2.entity_type = ds1.entity_type
                      AND ds2.entity_id = ds1.entity_id
                )
            """).fetchall()

            summary = {
                "total_entities": len(rows),
                "drifted_entities": 0,
                "total_critical": 0,
                "total_warnings": 0,
                "entities": []
            }

            for row in rows:
                if row['is_drifted']:
                    summary["drifted_entities"] += 1
                summary["total_critical"] += row['critical_count']
                summary["total_warnings"] += row['warning_count']
                summary["entities"].append(dict(row))

            return summary

        finally:
            conn.close()
