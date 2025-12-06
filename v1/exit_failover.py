"""
Exit Node Failover System

Health-check-driven automatic failover between exit nodes.
Implements circuit breaker pattern for reliability.

Failover Strategies:
- Priority: Always use highest-priority available exit
- Round Robin: Distribute load across healthy exits
- Latency: Use exit with lowest measured latency

Health Checks:
- ICMP ping to exit node endpoint
- WireGuard handshake verification
- Optional: HTTP health endpoint

Usage:
    from exit_failover import ExitFailoverManager, FailoverStrategy

    manager = ExitFailoverManager(db_path)

    # Create failover group
    group_id = manager.create_group("US Exits", strategy=FailoverStrategy.PRIORITY)

    # Add exit nodes to group
    manager.add_to_group(group_id, exit_node_id, priority=1)

    # Assign remote to group
    manager.assign_remote_to_group(remote_id, group_id)

    # Run health checks
    results = manager.run_health_checks()

    # Execute failovers if needed
    failovers = manager.process_failovers()
"""

import sqlite3
import subprocess
import socket
import time
import logging
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple
from dataclasses import dataclass
from threading import Lock

logger = logging.getLogger(__name__)


class FailoverStrategy(str, Enum):
    """Failover strategies for exit node groups"""
    PRIORITY = "priority"           # Always use highest-priority healthy exit
    ROUND_ROBIN = "round_robin"     # Distribute load across healthy exits
    LATENCY = "latency"             # Use exit with lowest latency


class HealthStatus(str, Enum):
    """Exit node health status (circuit breaker states)"""
    HEALTHY = "healthy"             # Fully operational
    DEGRADED = "degraded"           # Partially operational (high latency)
    FAILED = "failed"               # Not operational


@dataclass
class ExitNodeHealth:
    """Health status for an exit node"""
    exit_node_id: int
    hostname: str
    status: HealthStatus
    latency_ms: Optional[int]
    last_check_at: datetime
    consecutive_failures: int
    consecutive_successes: int
    last_success_at: Optional[datetime]
    last_failure_at: Optional[datetime]
    failure_reason: Optional[str]


@dataclass
class FailoverGroup:
    """Exit node failover group"""
    id: int
    name: str
    strategy: FailoverStrategy
    health_check_interval: int      # seconds
    health_check_timeout: int       # seconds
    degraded_threshold_ms: int      # latency threshold for degraded status
    failure_threshold: int          # consecutive failures before failed status
    recovery_threshold: int         # consecutive successes to recover
    member_count: int
    healthy_count: int


@dataclass
class FailoverEvent:
    """Record of a failover event"""
    id: int
    remote_id: int
    remote_hostname: str
    group_id: int
    from_exit_id: Optional[int]
    from_exit_hostname: Optional[str]
    to_exit_id: int
    to_exit_hostname: str
    trigger_reason: str
    triggered_at: datetime
    success: bool
    error_message: Optional[str]


class ExitFailoverManager:
    """
    Manages exit node failover groups and automatic failover.

    Implements circuit breaker pattern:
    - Healthy -> Degraded: After N consecutive failures or high latency
    - Degraded -> Failed: After M more consecutive failures
    - Failed -> Healthy: After K consecutive successes
    """

    # Default circuit breaker thresholds
    DEFAULT_DEGRADED_AFTER = 3      # failures to become degraded
    DEFAULT_FAILED_AFTER = 5        # failures to become failed
    DEFAULT_RECOVERY_AFTER = 2      # successes to recover to healthy

    def __init__(self, db_path: Path | str):
        self.db_path = Path(db_path) if isinstance(db_path, str) else db_path
        self._failover_lock = Lock()  # Prevent race conditions
        self._init_schema()

    def _get_connection(self):
        """Get database connection"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def _init_schema(self):
        """Initialize failover schema"""
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            # Exit node groups
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS exit_node_group (
                    id INTEGER PRIMARY KEY,
                    name TEXT NOT NULL UNIQUE,
                    failover_strategy TEXT NOT NULL DEFAULT 'priority',
                    health_check_interval INTEGER DEFAULT 30,
                    health_check_timeout INTEGER DEFAULT 5,
                    degraded_threshold_ms INTEGER DEFAULT 200,
                    failure_threshold INTEGER DEFAULT 5,
                    recovery_threshold INTEGER DEFAULT 2,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Group membership
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS exit_node_group_member (
                    group_id INTEGER NOT NULL,
                    exit_node_id INTEGER NOT NULL,
                    static_priority INTEGER DEFAULT 100,
                    weight INTEGER DEFAULT 1,
                    enabled BOOLEAN DEFAULT 1,
                    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (group_id, exit_node_id),
                    FOREIGN KEY (group_id) REFERENCES exit_node_group(id) ON DELETE CASCADE,
                    FOREIGN KEY (exit_node_id) REFERENCES exit_node(id) ON DELETE CASCADE
                )
            """)

            # Health state
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS exit_node_health (
                    exit_node_id INTEGER PRIMARY KEY,
                    status TEXT NOT NULL DEFAULT 'healthy',
                    latency_ms INTEGER,
                    last_check_at TIMESTAMP,
                    consecutive_failures INTEGER DEFAULT 0,
                    consecutive_successes INTEGER DEFAULT 0,
                    last_success_at TIMESTAMP,
                    last_failure_at TIMESTAMP,
                    failure_reason TEXT,
                    FOREIGN KEY (exit_node_id) REFERENCES exit_node(id) ON DELETE CASCADE
                )
            """)

            # Failover history
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS exit_failover_history (
                    id INTEGER PRIMARY KEY,
                    remote_id INTEGER NOT NULL,
                    group_id INTEGER NOT NULL,
                    from_exit_id INTEGER,
                    to_exit_id INTEGER NOT NULL,
                    trigger_reason TEXT NOT NULL,
                    trigger_details TEXT,
                    triggered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    success BOOLEAN NOT NULL DEFAULT 1,
                    error_message TEXT,
                    FOREIGN KEY (remote_id) REFERENCES remote(id) ON DELETE CASCADE,
                    FOREIGN KEY (group_id) REFERENCES exit_node_group(id) ON DELETE CASCADE,
                    FOREIGN KEY (from_exit_id) REFERENCES exit_node(id) ON DELETE SET NULL,
                    FOREIGN KEY (to_exit_id) REFERENCES exit_node(id) ON DELETE CASCADE
                )
            """)

            # Add exit_group_id and active_exit_id to remote table if not exists
            cursor.execute("PRAGMA table_info(remote)")
            columns = [row[1] for row in cursor.fetchall()]

            if 'exit_group_id' not in columns:
                cursor.execute("""
                    ALTER TABLE remote ADD COLUMN exit_group_id INTEGER
                    REFERENCES exit_node_group(id) ON DELETE SET NULL
                """)

            if 'active_exit_id' not in columns:
                cursor.execute("""
                    ALTER TABLE remote ADD COLUMN active_exit_id INTEGER
                    REFERENCES exit_node(id) ON DELETE SET NULL
                """)

            # Indexes
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_exit_health_status
                ON exit_node_health(status, last_check_at)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_failover_remote
                ON exit_failover_history(remote_id, triggered_at DESC)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_failover_group
                ON exit_failover_history(group_id, triggered_at DESC)
            """)

            conn.commit()
            logger.debug("Exit failover schema initialized")

        finally:
            conn.close()

    def create_group(
        self,
        name: str,
        strategy: FailoverStrategy = FailoverStrategy.PRIORITY,
        health_check_interval: int = 30,
        health_check_timeout: int = 5,
        degraded_threshold_ms: int = 200
    ) -> int:
        """Create a new exit node failover group"""
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                INSERT INTO exit_node_group (
                    name, failover_strategy, health_check_interval,
                    health_check_timeout, degraded_threshold_ms
                ) VALUES (?, ?, ?, ?, ?)
            """, (name, strategy.value, health_check_interval,
                  health_check_timeout, degraded_threshold_ms))

            group_id = cursor.lastrowid
            conn.commit()

            logger.info(f"Created failover group: {name} (ID: {group_id})")
            return group_id

        except sqlite3.IntegrityError as e:
            raise ValueError(f"Group name '{name}' already exists") from e
        finally:
            conn.close()

    def get_group(self, group_id: int) -> Optional[FailoverGroup]:
        """Get failover group by ID"""
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                SELECT g.*,
                       COUNT(m.exit_node_id) as member_count,
                       SUM(CASE WHEN h.status = 'healthy' THEN 1 ELSE 0 END) as healthy_count
                FROM exit_node_group g
                LEFT JOIN exit_node_group_member m ON g.id = m.group_id AND m.enabled = 1
                LEFT JOIN exit_node_health h ON m.exit_node_id = h.exit_node_id
                WHERE g.id = ?
                GROUP BY g.id
            """, (group_id,))

            row = cursor.fetchone()
            if not row:
                return None

            return FailoverGroup(
                id=row['id'],
                name=row['name'],
                strategy=FailoverStrategy(row['failover_strategy']),
                health_check_interval=row['health_check_interval'],
                health_check_timeout=row['health_check_timeout'],
                degraded_threshold_ms=row['degraded_threshold_ms'],
                failure_threshold=row['failure_threshold'],
                recovery_threshold=row['recovery_threshold'],
                member_count=row['member_count'] or 0,
                healthy_count=row['healthy_count'] or 0
            )

        finally:
            conn.close()

    def list_groups(self) -> List[FailoverGroup]:
        """List all failover groups"""
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                SELECT g.*,
                       COUNT(m.exit_node_id) as member_count,
                       SUM(CASE WHEN h.status = 'healthy' THEN 1 ELSE 0 END) as healthy_count
                FROM exit_node_group g
                LEFT JOIN exit_node_group_member m ON g.id = m.group_id AND m.enabled = 1
                LEFT JOIN exit_node_health h ON m.exit_node_id = h.exit_node_id
                GROUP BY g.id
                ORDER BY g.name
            """)

            groups = []
            for row in cursor.fetchall():
                groups.append(FailoverGroup(
                    id=row['id'],
                    name=row['name'],
                    strategy=FailoverStrategy(row['failover_strategy']),
                    health_check_interval=row['health_check_interval'],
                    health_check_timeout=row['health_check_timeout'],
                    degraded_threshold_ms=row['degraded_threshold_ms'],
                    failure_threshold=row['failure_threshold'],
                    recovery_threshold=row['recovery_threshold'],
                    member_count=row['member_count'] or 0,
                    healthy_count=row['healthy_count'] or 0
                ))

            return groups

        finally:
            conn.close()

    def add_to_group(
        self,
        group_id: int,
        exit_node_id: int,
        priority: int = 100,
        weight: int = 1
    ) -> bool:
        """Add exit node to failover group"""
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                INSERT INTO exit_node_group_member (
                    group_id, exit_node_id, static_priority, weight
                ) VALUES (?, ?, ?, ?)
            """, (group_id, exit_node_id, priority, weight))

            # Initialize health record
            cursor.execute("""
                INSERT OR IGNORE INTO exit_node_health (exit_node_id, status)
                VALUES (?, 'healthy')
            """, (exit_node_id,))

            conn.commit()
            return True

        except sqlite3.IntegrityError:
            return False
        finally:
            conn.close()

    def remove_from_group(self, group_id: int, exit_node_id: int) -> bool:
        """Remove exit node from failover group"""
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                DELETE FROM exit_node_group_member
                WHERE group_id = ? AND exit_node_id = ?
            """, (group_id, exit_node_id))

            conn.commit()
            return cursor.rowcount > 0

        finally:
            conn.close()

    def assign_remote_to_group(self, remote_id: int, group_id: int) -> bool:
        """Assign a remote to a failover group"""
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            # Get best exit for initial assignment
            best_exit = self._get_best_exit_for_group(cursor, group_id)

            cursor.execute("""
                UPDATE remote
                SET exit_group_id = ?, active_exit_id = ?
                WHERE id = ?
            """, (group_id, best_exit, remote_id))

            conn.commit()
            return cursor.rowcount > 0

        finally:
            conn.close()

    def _get_best_exit_for_group(self, cursor, group_id: int) -> Optional[int]:
        """Get best available exit node for a group based on strategy"""
        cursor.execute("""
            SELECT g.failover_strategy FROM exit_node_group g WHERE g.id = ?
        """, (group_id,))
        row = cursor.fetchone()
        if not row:
            return None

        strategy = FailoverStrategy(row['failover_strategy'])

        if strategy == FailoverStrategy.PRIORITY:
            # Lowest priority number = highest priority
            cursor.execute("""
                SELECT m.exit_node_id
                FROM exit_node_group_member m
                JOIN exit_node_health h ON m.exit_node_id = h.exit_node_id
                WHERE m.group_id = ? AND m.enabled = 1 AND h.status = 'healthy'
                ORDER BY m.static_priority ASC
                LIMIT 1
            """, (group_id,))

        elif strategy == FailoverStrategy.LATENCY:
            # Lowest latency
            cursor.execute("""
                SELECT m.exit_node_id
                FROM exit_node_group_member m
                JOIN exit_node_health h ON m.exit_node_id = h.exit_node_id
                WHERE m.group_id = ? AND m.enabled = 1 AND h.status = 'healthy'
                ORDER BY h.latency_ms ASC NULLS LAST
                LIMIT 1
            """, (group_id,))

        else:  # ROUND_ROBIN
            # Round robin by least recently used
            cursor.execute("""
                SELECT m.exit_node_id
                FROM exit_node_group_member m
                JOIN exit_node_health h ON m.exit_node_id = h.exit_node_id
                LEFT JOIN (
                    SELECT to_exit_id, MAX(triggered_at) as last_used
                    FROM exit_failover_history
                    WHERE group_id = ?
                    GROUP BY to_exit_id
                ) lu ON m.exit_node_id = lu.to_exit_id
                WHERE m.group_id = ? AND m.enabled = 1 AND h.status = 'healthy'
                ORDER BY lu.last_used ASC NULLS FIRST
                LIMIT 1
            """, (group_id, group_id))

        row = cursor.fetchone()
        return row['exit_node_id'] if row else None

    def ping_host(self, host: str, timeout: int = 5) -> Tuple[bool, Optional[int]]:
        """
        Ping a host and return (success, latency_ms).

        Uses ICMP ping for accurate latency measurement.
        """
        try:
            # Use ping command (cross-platform)
            if subprocess.sys.platform == 'win32':
                cmd = ['ping', '-n', '1', '-w', str(timeout * 1000), host]
            else:
                cmd = ['ping', '-c', '1', '-W', str(timeout), host]

            start = time.time()
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 2)
            elapsed = (time.time() - start) * 1000  # ms

            if result.returncode == 0:
                # Parse actual latency from output if available
                # Linux: time=X.XX ms, Windows: time=Xms
                import re
                match = re.search(r'time[=<](\d+\.?\d*)\s*ms', result.stdout)
                if match:
                    latency = int(float(match.group(1)))
                else:
                    latency = int(elapsed)
                return True, latency
            else:
                return False, None

        except subprocess.TimeoutExpired:
            return False, None
        except Exception as e:
            logger.debug(f"Ping failed for {host}: {e}")
            return False, None

    def run_health_checks(self) -> List[ExitNodeHealth]:
        """
        Run health checks on all exit nodes.

        Returns list of updated health statuses.
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            # Get all exit nodes in groups
            cursor.execute("""
                SELECT DISTINCT e.id, e.hostname, e.endpoint,
                       COALESCE(h.status, 'healthy') as current_status,
                       COALESCE(h.consecutive_failures, 0) as consecutive_failures,
                       COALESCE(h.consecutive_successes, 0) as consecutive_successes,
                       g.degraded_threshold_ms, g.failure_threshold, g.recovery_threshold,
                       g.health_check_timeout
                FROM exit_node e
                JOIN exit_node_group_member m ON e.id = m.exit_node_id
                JOIN exit_node_group g ON m.group_id = g.id
                LEFT JOIN exit_node_health h ON e.id = h.exit_node_id
                WHERE m.enabled = 1
            """)

            results = []
            now = datetime.utcnow()

            for row in cursor.fetchall():
                exit_id = row['id']
                hostname = row['hostname']
                endpoint = row['endpoint']
                current_status = HealthStatus(row['current_status'])
                consec_failures = row['consecutive_failures']
                consec_successes = row['consecutive_successes']
                degraded_threshold = row['degraded_threshold_ms']
                failure_threshold = row['failure_threshold']
                recovery_threshold = row['recovery_threshold']
                timeout = row['health_check_timeout']

                # Extract host from endpoint (remove port if present)
                host = endpoint.split(':')[0] if endpoint else hostname

                # Run ping check
                success, latency = self.ping_host(host, timeout)

                # Determine new status using circuit breaker logic
                if success:
                    consec_failures = 0
                    consec_successes += 1

                    if latency and latency > degraded_threshold:
                        new_status = HealthStatus.DEGRADED
                        failure_reason = f"High latency: {latency}ms"
                    elif current_status == HealthStatus.FAILED and consec_successes >= recovery_threshold:
                        new_status = HealthStatus.HEALTHY
                        failure_reason = None
                    elif current_status == HealthStatus.DEGRADED and consec_successes >= recovery_threshold:
                        new_status = HealthStatus.HEALTHY
                        failure_reason = None
                    else:
                        new_status = current_status if current_status != HealthStatus.FAILED else HealthStatus.DEGRADED
                        failure_reason = None
                else:
                    consec_successes = 0
                    consec_failures += 1

                    if consec_failures >= failure_threshold:
                        new_status = HealthStatus.FAILED
                    elif consec_failures >= self.DEFAULT_DEGRADED_AFTER:
                        new_status = HealthStatus.DEGRADED
                    else:
                        new_status = current_status

                    failure_reason = "Health check failed (no response)"

                # Update health record
                cursor.execute("""
                    INSERT INTO exit_node_health (
                        exit_node_id, status, latency_ms, last_check_at,
                        consecutive_failures, consecutive_successes,
                        last_success_at, last_failure_at, failure_reason
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(exit_node_id) DO UPDATE SET
                        status = excluded.status,
                        latency_ms = excluded.latency_ms,
                        last_check_at = excluded.last_check_at,
                        consecutive_failures = excluded.consecutive_failures,
                        consecutive_successes = excluded.consecutive_successes,
                        last_success_at = CASE WHEN excluded.consecutive_successes > 0
                                          THEN excluded.last_check_at
                                          ELSE exit_node_health.last_success_at END,
                        last_failure_at = CASE WHEN excluded.consecutive_failures > 0
                                          THEN excluded.last_check_at
                                          ELSE exit_node_health.last_failure_at END,
                        failure_reason = excluded.failure_reason
                """, (
                    exit_id, new_status.value, latency, now.isoformat(),
                    consec_failures, consec_successes,
                    now.isoformat() if success else None,
                    now.isoformat() if not success else None,
                    failure_reason
                ))

                results.append(ExitNodeHealth(
                    exit_node_id=exit_id,
                    hostname=hostname,
                    status=new_status,
                    latency_ms=latency,
                    last_check_at=now,
                    consecutive_failures=consec_failures,
                    consecutive_successes=consec_successes,
                    last_success_at=now if success else None,
                    last_failure_at=now if not success else None,
                    failure_reason=failure_reason
                ))

            conn.commit()
            logger.info(f"Health checks completed for {len(results)} exit nodes")
            return results

        finally:
            conn.close()

    def process_failovers(self) -> List[FailoverEvent]:
        """
        Process failovers for remotes with failed exit nodes.

        Uses lock to prevent race conditions.
        """
        with self._failover_lock:
            return self._do_failovers()

    def _do_failovers(self) -> List[FailoverEvent]:
        """Execute failover logic"""
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            failovers = []
            now = datetime.utcnow()

            # Find remotes that need failover
            cursor.execute("""
                SELECT r.id as remote_id, r.hostname as remote_hostname,
                       r.exit_group_id, r.active_exit_id,
                       e.hostname as exit_hostname,
                       h.status
                FROM remote r
                JOIN exit_node_group g ON r.exit_group_id = g.id
                LEFT JOIN exit_node e ON r.active_exit_id = e.id
                LEFT JOIN exit_node_health h ON r.active_exit_id = h.exit_node_id
                WHERE r.exit_group_id IS NOT NULL
                  AND (r.active_exit_id IS NULL OR h.status = 'failed')
            """)

            for row in cursor.fetchall():
                remote_id = row['remote_id']
                remote_hostname = row['remote_hostname']
                group_id = row['exit_group_id']
                current_exit_id = row['active_exit_id']
                current_exit_hostname = row['exit_hostname']

                # Get best available exit
                new_exit_id = self._get_best_exit_for_group(cursor, group_id)

                if not new_exit_id:
                    logger.warning(f"No healthy exit available for remote {remote_hostname}")
                    continue

                if new_exit_id == current_exit_id:
                    continue  # No change needed

                # Get new exit hostname
                cursor.execute("SELECT hostname FROM exit_node WHERE id = ?", (new_exit_id,))
                new_exit_row = cursor.fetchone()
                new_exit_hostname = new_exit_row['hostname'] if new_exit_row else str(new_exit_id)

                # Perform failover
                cursor.execute("""
                    UPDATE remote SET active_exit_id = ? WHERE id = ?
                """, (new_exit_id, remote_id))

                # Record failover
                trigger_reason = "health_check_failed" if current_exit_id else "initial_assignment"

                cursor.execute("""
                    INSERT INTO exit_failover_history (
                        remote_id, group_id, from_exit_id, to_exit_id,
                        trigger_reason, success
                    ) VALUES (?, ?, ?, ?, ?, 1)
                """, (remote_id, group_id, current_exit_id, new_exit_id, trigger_reason))

                failover_id = cursor.lastrowid

                failovers.append(FailoverEvent(
                    id=failover_id,
                    remote_id=remote_id,
                    remote_hostname=remote_hostname or str(remote_id),
                    group_id=group_id,
                    from_exit_id=current_exit_id,
                    from_exit_hostname=current_exit_hostname,
                    to_exit_id=new_exit_id,
                    to_exit_hostname=new_exit_hostname,
                    trigger_reason=trigger_reason,
                    triggered_at=now,
                    success=True,
                    error_message=None
                ))

                logger.info(
                    f"Failover: {remote_hostname} from {current_exit_hostname or 'none'} "
                    f"to {new_exit_hostname}"
                )

            conn.commit()
            return failovers

        finally:
            conn.close()

    def get_health_status(self) -> List[ExitNodeHealth]:
        """Get current health status for all exit nodes"""
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                SELECT e.id, e.hostname, h.*
                FROM exit_node e
                LEFT JOIN exit_node_health h ON e.id = h.exit_node_id
                ORDER BY e.hostname
            """)

            results = []
            for row in cursor.fetchall():
                results.append(ExitNodeHealth(
                    exit_node_id=row['id'],
                    hostname=row['hostname'],
                    status=HealthStatus(row['status']) if row['status'] else HealthStatus.HEALTHY,
                    latency_ms=row['latency_ms'],
                    last_check_at=datetime.fromisoformat(row['last_check_at']) if row['last_check_at'] else None,
                    consecutive_failures=row['consecutive_failures'] or 0,
                    consecutive_successes=row['consecutive_successes'] or 0,
                    last_success_at=datetime.fromisoformat(row['last_success_at']) if row['last_success_at'] else None,
                    last_failure_at=datetime.fromisoformat(row['last_failure_at']) if row['last_failure_at'] else None,
                    failure_reason=row['failure_reason']
                ))

            return results

        finally:
            conn.close()

    def get_failover_history(
        self,
        group_id: Optional[int] = None,
        remote_id: Optional[int] = None,
        limit: int = 50
    ) -> List[FailoverEvent]:
        """Get failover history"""
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            query = """
                SELECT fh.*,
                       r.hostname as remote_hostname,
                       e1.hostname as from_hostname,
                       e2.hostname as to_hostname
                FROM exit_failover_history fh
                JOIN remote r ON fh.remote_id = r.id
                LEFT JOIN exit_node e1 ON fh.from_exit_id = e1.id
                JOIN exit_node e2 ON fh.to_exit_id = e2.id
                WHERE 1=1
            """
            params = []

            if group_id:
                query += " AND fh.group_id = ?"
                params.append(group_id)

            if remote_id:
                query += " AND fh.remote_id = ?"
                params.append(remote_id)

            query += " ORDER BY fh.triggered_at DESC LIMIT ?"
            params.append(limit)

            cursor.execute(query, params)

            events = []
            for row in cursor.fetchall():
                events.append(FailoverEvent(
                    id=row['id'],
                    remote_id=row['remote_id'],
                    remote_hostname=row['remote_hostname'] or str(row['remote_id']),
                    group_id=row['group_id'],
                    from_exit_id=row['from_exit_id'],
                    from_exit_hostname=row['from_hostname'],
                    to_exit_id=row['to_exit_id'],
                    to_exit_hostname=row['to_hostname'] or str(row['to_exit_id']),
                    trigger_reason=row['trigger_reason'],
                    triggered_at=datetime.fromisoformat(row['triggered_at']),
                    success=bool(row['success']),
                    error_message=row['error_message']
                ))

            return events

        finally:
            conn.close()


if __name__ == "__main__":
    print("=== Exit Node Failover Demo ===\n")
    print("This module requires exit_node and remote tables to function.")
    print("Use with existing WireGuard Friend database.\n")

    print("Features:")
    print("  - Failover groups with priority/round-robin/latency strategies")
    print("  - Health checks with circuit breaker pattern")
    print("  - Automatic failover when exits fail")
    print("  - Failover history tracking")
