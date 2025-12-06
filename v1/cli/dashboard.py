"""
Enhanced Dashboard Module

Provides advanced TUI features:
- Network topology visualization
- Bandwidth monitoring display
- Alert and notification system
- Real-time status dashboard

Follows ui-ux-design-specifications.md guidelines.
"""

import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Optional, Tuple

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.tree import Tree
    from rich.layout import Layout
    from rich.live import Live
    from rich.text import Text
    from rich import box
    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False
    console = None


# =============================================================================
# ALERT SYSTEM
# =============================================================================

class AlertSeverity:
    CRITICAL = "critical"
    WARNING = "warning"
    INFO = "info"


class Alert:
    """Single alert/notification."""

    def __init__(self, severity: str, title: str, message: str,
                 entity_type: str = None, entity_name: str = None,
                 timestamp: datetime = None, action_hint: str = None):
        self.severity = severity
        self.title = title
        self.message = message
        self.entity_type = entity_type
        self.entity_name = entity_name
        self.timestamp = timestamp or datetime.now()
        self.action_hint = action_hint

    @property
    def severity_icon(self) -> str:
        icons = {
            AlertSeverity.CRITICAL: "[red]![/red]",
            AlertSeverity.WARNING: "[yellow]![/yellow]",
            AlertSeverity.INFO: "[blue]i[/blue]",
        }
        return icons.get(self.severity, "?")

    @property
    def severity_color(self) -> str:
        colors = {
            AlertSeverity.CRITICAL: "red",
            AlertSeverity.WARNING: "yellow",
            AlertSeverity.INFO: "blue",
        }
        return colors.get(self.severity, "white")


class AlertManager:
    """Manages alerts and notifications."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init_tables()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_tables(self):
        """Create alert tables if needed."""
        conn = self._get_conn()
        try:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS tui_alert (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    severity TEXT NOT NULL,
                    title TEXT NOT NULL,
                    message TEXT NOT NULL,
                    entity_type TEXT,
                    entity_name TEXT,
                    action_hint TEXT,
                    created_at TEXT NOT NULL,
                    acknowledged_at TEXT,
                    dismissed INTEGER NOT NULL DEFAULT 0
                );

                CREATE INDEX IF NOT EXISTS idx_alert_dismissed
                    ON tui_alert(dismissed);
                CREATE INDEX IF NOT EXISTS idx_alert_created
                    ON tui_alert(created_at);
            """)
            conn.commit()
        finally:
            conn.close()

    def add_alert(self, alert: Alert) -> int:
        """Add a new alert."""
        conn = self._get_conn()
        try:
            cursor = conn.execute("""
                INSERT INTO tui_alert
                (severity, title, message, entity_type, entity_name,
                 action_hint, created_at, dismissed)
                VALUES (?, ?, ?, ?, ?, ?, ?, 0)
            """, (
                alert.severity, alert.title, alert.message,
                alert.entity_type, alert.entity_name,
                alert.action_hint, alert.timestamp.isoformat()
            ))
            conn.commit()
            return cursor.lastrowid
        finally:
            conn.close()

    def get_active_alerts(self, limit: int = 10) -> List[Alert]:
        """Get active (non-dismissed) alerts."""
        conn = self._get_conn()
        try:
            rows = conn.execute("""
                SELECT * FROM tui_alert
                WHERE dismissed = 0
                ORDER BY
                    CASE severity
                        WHEN 'critical' THEN 1
                        WHEN 'warning' THEN 2
                        WHEN 'info' THEN 3
                    END,
                    created_at DESC
                LIMIT ?
            """, (limit,)).fetchall()

            alerts = []
            for row in rows:
                alerts.append(Alert(
                    severity=row['severity'],
                    title=row['title'],
                    message=row['message'],
                    entity_type=row['entity_type'],
                    entity_name=row['entity_name'],
                    timestamp=datetime.fromisoformat(row['created_at']),
                    action_hint=row['action_hint']
                ))
            return alerts
        finally:
            conn.close()

    def dismiss_alert(self, alert_id: int):
        """Dismiss an alert."""
        conn = self._get_conn()
        try:
            conn.execute("""
                UPDATE tui_alert SET dismissed = 1
                WHERE id = ?
            """, (alert_id,))
            conn.commit()
        finally:
            conn.close()

    def dismiss_all(self):
        """Dismiss all alerts."""
        conn = self._get_conn()
        try:
            conn.execute("UPDATE tui_alert SET dismissed = 1")
            conn.commit()
        finally:
            conn.close()

    def check_and_generate_alerts(self):
        """Check system state and generate alerts."""
        alerts = []

        conn = self._get_conn()
        try:
            # Check for pending key rotations (old keys)
            thirty_days_ago = (datetime.now() - timedelta(days=30)).isoformat()

            # Check remotes without recent rotation
            try:
                rows = conn.execute("""
                    SELECT r.hostname, r.id,
                           COALESCE(MAX(krh.rotated_at), r.created_at) as last_rotation
                    FROM remote r
                    LEFT JOIN key_rotation_history krh
                        ON krh.entity_type = 'remote' AND krh.entity_permanent_guid = r.permanent_guid
                    GROUP BY r.id
                    HAVING last_rotation < ?
                """, (thirty_days_ago,)).fetchall()
            except sqlite3.OperationalError:
                # key_rotation_history table may not exist
                rows = []

            for row in rows:
                alerts.append(Alert(
                    severity=AlertSeverity.WARNING,
                    title="Key Rotation Due",
                    message=f"Remote '{row['hostname']}' hasn't had key rotation in 30+ days",
                    entity_type="remote",
                    entity_name=row['hostname'],
                    action_hint="Use Rotate Keys to update"
                ))

            # Check for drift detection issues
            try:
                drift_rows = conn.execute("""
                    SELECT entity_type, entity_name, critical_count, warning_count
                    FROM drift_scan
                    WHERE is_drifted = 1
                    AND scan_time > datetime('now', '-1 day')
                """).fetchall()

                for row in drift_rows:
                    if row['critical_count'] > 0:
                        alerts.append(Alert(
                            severity=AlertSeverity.CRITICAL,
                            title="Configuration Drift Detected",
                            message=f"{row['critical_count']} critical drift(s) on {row['entity_name']}",
                            entity_type=row['entity_type'],
                            entity_name=row['entity_name'],
                            action_hint="Check drift detection report"
                        ))
            except sqlite3.OperationalError:
                pass  # drift_scan table doesn't exist yet

            # Check exit node health
            try:
                health_rows = conn.execute("""
                    SELECT en.hostname, enh.status, enh.consecutive_failures
                    FROM exit_node_health enh
                    JOIN exit_node en ON en.id = enh.exit_node_id
                    WHERE enh.status IN ('degraded', 'failed')
                """).fetchall()

                for row in health_rows:
                    severity = AlertSeverity.CRITICAL if row['status'] == 'failed' else AlertSeverity.WARNING
                    alerts.append(Alert(
                        severity=severity,
                        title=f"Exit Node {row['status'].upper()}",
                        message=f"{row['hostname']} has {row['consecutive_failures']} failures",
                        entity_type="exit_node",
                        entity_name=row['hostname'],
                        action_hint="Check exit node health"
                    ))
            except sqlite3.OperationalError:
                pass  # exit_node_health table doesn't exist yet

            # Check backup age
            try:
                backup_row = conn.execute("""
                    SELECT MAX(created_at) as last_backup FROM backup_history
                """).fetchone()

                if backup_row and backup_row['last_backup']:
                    last_backup = datetime.fromisoformat(backup_row['last_backup'])
                    if datetime.now() - last_backup > timedelta(days=7):
                        alerts.append(Alert(
                            severity=AlertSeverity.WARNING,
                            title="Backup Overdue",
                            message=f"Last backup was {(datetime.now() - last_backup).days} days ago",
                            action_hint="Create a new backup"
                        ))
                else:
                    alerts.append(Alert(
                        severity=AlertSeverity.INFO,
                        title="No Backups Found",
                        message="Consider creating a database backup",
                        action_hint="Use disaster recovery to create backup"
                    ))
            except sqlite3.OperationalError:
                pass  # backup_history table doesn't exist yet

            # Add alerts to database (avoid duplicates)
            for alert in alerts:
                # Check if similar alert exists
                existing = conn.execute("""
                    SELECT id FROM tui_alert
                    WHERE title = ? AND entity_name = ?
                    AND dismissed = 0
                    AND created_at > datetime('now', '-1 day')
                """, (alert.title, alert.entity_name)).fetchone()

                if not existing:
                    self.add_alert(alert)

        finally:
            conn.close()

        return alerts


# =============================================================================
# NETWORK TOPOLOGY
# =============================================================================

def render_topology_tree(db_path: str) -> str:
    """Render network topology as an ASCII tree."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    try:
        # Get coordination server
        cs = conn.execute("""
            SELECT hostname, vpn_ip, endpoint FROM coordination_server LIMIT 1
        """).fetchone()

        if not cs:
            return "No coordination server found."

        if not RICH_AVAILABLE:
            return _render_topology_plain(conn, cs)

        # Build Rich tree
        tree = Tree(
            f"[bold cyan]{cs['hostname']}[/bold cyan] [dim]({cs['endpoint']})[/dim]",
            guide_style="cyan"
        )

        # Add subnet routers
        routers = conn.execute("""
            SELECT id, hostname, vpn_ip, endpoint FROM subnet_router ORDER BY hostname
        """).fetchall()

        for router in routers:
            router_node = tree.add(
                f"[green]{router['hostname']}[/green] [dim]{router['vpn_ip']}[/dim]"
            )

            # Get remotes for this router
            remotes = conn.execute("""
                SELECT hostname, vpn_ip, access_level, exit_node_id
                FROM remote
                WHERE sponsor_type = 'sr' AND sponsor_id = ?
                ORDER BY hostname
            """, (router['id'],)).fetchall()

            for remote in remotes:
                access_icon = _get_access_icon(remote['access_level'])
                exit_indicator = " [yellow]->[/yellow]exit" if remote['exit_node_id'] else ""
                router_node.add(
                    f"{access_icon} {remote['hostname']} [dim]{remote['vpn_ip']}{exit_indicator}[/dim]"
                )

            # Get advertised networks
            networks = conn.execute("""
                SELECT network FROM advertised_network WHERE sr_id = ?
            """, (router['id'],)).fetchall()

            if networks:
                for net in networks:
                    router_node.add(f"[dim]LAN: {net['network']}[/dim]")

        # Add remotes directly under CS
        cs_remotes = conn.execute("""
            SELECT hostname, vpn_ip, access_level, exit_node_id
            FROM remote
            WHERE sponsor_type = 'cs'
            ORDER BY hostname
        """).fetchall()

        for remote in cs_remotes:
            access_icon = _get_access_icon(remote['access_level'])
            exit_indicator = " [yellow]->[/yellow]exit" if remote['exit_node_id'] else ""
            tree.add(
                f"{access_icon} {remote['hostname']} [dim]{remote['vpn_ip']}{exit_indicator}[/dim]"
            )

        # Add exit nodes
        exit_nodes = conn.execute("""
            SELECT id, hostname, ipv4_address FROM exit_node ORDER BY hostname
        """).fetchall()

        if exit_nodes:
            exit_branch = tree.add("[bold yellow]Exit Nodes[/bold yellow]")
            for en in exit_nodes:
                # Count clients
                client_count = conn.execute("""
                    SELECT COUNT(*) FROM remote WHERE exit_node_id = ?
                """, (en['id'],)).fetchone()[0]

                exit_branch.add(
                    f"[yellow]{en['hostname']}[/yellow] [dim]{en['ipv4_address']} ({client_count} clients)[/dim]"
                )

        # Render to string
        with console.capture() as capture:
            console.print(tree)
        return capture.get()

    finally:
        conn.close()


def _get_access_icon(access_level: str) -> str:
    """Get icon for access level."""
    icons = {
        'full': '[green]F[/green]',
        'vpn': '[blue]V[/blue]',
        'lan': '[cyan]L[/cyan]',
        'exit_only': '[yellow]E[/yellow]',
        'custom': '[magenta]C[/magenta]',
    }
    return icons.get(access_level, '[white]?[/white]')


def _render_topology_plain(conn, cs) -> str:
    """Plain text topology for non-Rich environments."""
    lines = []
    lines.append(f"{cs['hostname']} ({cs['endpoint']})")
    lines.append("|")

    routers = conn.execute("""
        SELECT id, hostname, vpn_ip FROM subnet_router ORDER BY hostname
    """).fetchall()

    for i, router in enumerate(routers):
        is_last_router = (i == len(routers) - 1)
        prefix = "\\--" if is_last_router else "+--"
        lines.append(f"{prefix} {router['hostname']} ({router['vpn_ip']})")

        remotes = conn.execute("""
            SELECT hostname, vpn_ip FROM remote
            WHERE sponsor_type = 'sr' AND sponsor_id = ?
        """, (router['id'],)).fetchall()

        for j, remote in enumerate(remotes):
            child_prefix = "   " if is_last_router else "|  "
            is_last = (j == len(remotes) - 1)
            remote_prefix = "\\--" if is_last else "+--"
            lines.append(f"{child_prefix}{remote_prefix} {remote['hostname']} ({remote['vpn_ip']})")

    return "\n".join(lines)


# =============================================================================
# BANDWIDTH VISUALIZATION
# =============================================================================

def render_bandwidth_table(db_path: str, hours: int = 24) -> str:
    """Render bandwidth usage table."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    try:
        # Try to get bandwidth data
        try:
            rows = conn.execute("""
                SELECT
                    ba.entity_type,
                    ba.entity_id,
                    ba.period_type,
                    SUM(ba.bytes_received) as total_rx,
                    SUM(ba.bytes_sent) as total_tx
                FROM bandwidth_aggregate ba
                WHERE ba.period_type = 'hourly'
                AND ba.period_start > datetime('now', ?)
                GROUP BY ba.entity_type, ba.entity_id
                ORDER BY (total_rx + total_tx) DESC
                LIMIT 10
            """, (f'-{hours} hours',)).fetchall()
        except sqlite3.OperationalError:
            return "Bandwidth tracking not yet configured."

        if not rows:
            return "No bandwidth data available yet."

        if not RICH_AVAILABLE:
            return _render_bandwidth_plain(conn, rows)

        table = Table(title=f"Bandwidth Usage (Last {hours}h)", box=box.ROUNDED)
        table.add_column("Entity", style="cyan")
        table.add_column("Type", style="dim")
        table.add_column("Received", justify="right", style="green")
        table.add_column("Sent", justify="right", style="yellow")
        table.add_column("Total", justify="right", style="bold")

        for row in rows:
            # Get entity name
            entity_name = _get_entity_name(conn, row['entity_type'], row['entity_id'])

            table.add_row(
                entity_name,
                row['entity_type'],
                _format_bytes(row['total_rx']),
                _format_bytes(row['total_tx']),
                _format_bytes(row['total_rx'] + row['total_tx'])
            )

        with console.capture() as capture:
            console.print(table)
        return capture.get()

    finally:
        conn.close()


def _get_entity_name(conn, entity_type: str, entity_id: int) -> str:
    """Get entity hostname from type and ID."""
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


def _format_bytes(num_bytes: int) -> str:
    """Format bytes as human-readable."""
    if num_bytes is None:
        return "0 B"

    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if abs(num_bytes) < 1024.0:
            return f"{num_bytes:.1f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.1f} PB"


def _render_bandwidth_plain(conn, rows) -> str:
    """Plain text bandwidth table."""
    lines = ["Entity               Type      Received    Sent       Total"]
    lines.append("-" * 65)

    for row in rows:
        entity_name = _get_entity_name(conn, row['entity_type'], row['entity_id'])
        lines.append(
            f"{entity_name:20} {row['entity_type']:8} "
            f"{_format_bytes(row['total_rx']):>10} "
            f"{_format_bytes(row['total_tx']):>10} "
            f"{_format_bytes(row['total_rx'] + row['total_tx']):>10}"
        )

    return "\n".join(lines)


def render_bandwidth_sparkline(db_path: str, entity_type: str,
                                entity_id: int, hours: int = 24) -> str:
    """Render simple sparkline for entity bandwidth."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    try:
        rows = conn.execute("""
            SELECT
                strftime('%H', period_start) as hour,
                bytes_received + bytes_sent as total
            FROM bandwidth_aggregate
            WHERE entity_type = ? AND entity_id = ?
            AND period_type = 'hourly'
            AND period_start > datetime('now', ?)
            ORDER BY period_start
        """, (entity_type, entity_id, f'-{hours} hours')).fetchall()

        if not rows:
            return "[dim]No data[/dim]"

        # Build sparkline
        values = [row['total'] for row in rows]
        max_val = max(values) if values else 1
        chars = " _.-~^"

        sparkline = ""
        for val in values:
            idx = int((val / max_val) * (len(chars) - 1)) if max_val > 0 else 0
            sparkline += chars[idx]

        return f"[cyan]{sparkline}[/cyan] ({_format_bytes(sum(values))})"

    except sqlite3.OperationalError:
        return "[dim]N/A[/dim]"
    finally:
        conn.close()


# =============================================================================
# ENHANCED DASHBOARD
# =============================================================================

def render_dashboard(db_path: str) -> str:
    """Render full dashboard with all components."""
    if not RICH_AVAILABLE:
        return "Rich library required for dashboard display."

    parts = []

    # Header
    parts.append("[bold cyan]WIREGUARD FRIEND - DASHBOARD[/bold cyan]")
    parts.append("")

    # Network summary
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        cs_count = conn.execute("SELECT COUNT(*) FROM coordination_server").fetchone()[0]
        sr_count = conn.execute("SELECT COUNT(*) FROM subnet_router").fetchone()[0]
        remote_count = conn.execute("SELECT COUNT(*) FROM remote").fetchone()[0]

        try:
            exit_count = conn.execute("SELECT COUNT(*) FROM exit_node").fetchone()[0]
        except:
            exit_count = 0

        parts.append(f"[bold]Network:[/bold] {cs_count} CS, {sr_count} routers, {remote_count} remotes, {exit_count} exit nodes")
        parts.append("")
    finally:
        conn.close()

    # Alerts section
    alert_mgr = AlertManager(db_path)
    alert_mgr.check_and_generate_alerts()
    alerts = alert_mgr.get_active_alerts(limit=5)

    if alerts:
        parts.append("[bold]Active Alerts:[/bold]")
        for alert in alerts:
            parts.append(f"  {alert.severity_icon} [{alert.severity_color}]{alert.title}[/{alert.severity_color}]: {alert.message}")
        parts.append("")
    else:
        parts.append("[bold]Alerts:[/bold] [green]All clear[/green]")
        parts.append("")

    # Topology preview (compact)
    parts.append("[bold]Network Topology:[/bold]")
    topology = render_topology_tree(db_path)
    # Limit topology lines for dashboard
    topo_lines = topology.strip().split('\n')[:10]
    parts.extend(topo_lines)
    if len(topology.strip().split('\n')) > 10:
        parts.append("[dim]  ... (use Topology View for full tree)[/dim]")
    parts.append("")

    # Bandwidth summary
    parts.append("[bold]Bandwidth (24h):[/bold]")
    bw = render_bandwidth_table(db_path, hours=24)
    bw_lines = bw.strip().split('\n')[:7]
    parts.extend(bw_lines)

    return "\n".join(parts)


def render_status_bar(db_path: str) -> str:
    """Render compact status bar for bottom of screen."""
    if not RICH_AVAILABLE:
        return ""

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    try:
        # Count entities
        remote_count = conn.execute("SELECT COUNT(*) FROM remote").fetchone()[0]

        # Check for alerts
        try:
            alert_count = conn.execute("""
                SELECT COUNT(*) FROM tui_alert WHERE dismissed = 0
            """).fetchone()[0]
        except:
            alert_count = 0

        # Last backup
        try:
            backup_row = conn.execute("""
                SELECT MAX(created_at) FROM backup_history
            """).fetchone()
            last_backup = backup_row[0][:10] if backup_row and backup_row[0] else "Never"
        except:
            last_backup = "N/A"

        parts = []
        parts.append(f"Peers: {remote_count}")

        if alert_count > 0:
            parts.append(f"[yellow]Alerts: {alert_count}[/yellow]")
        else:
            parts.append("[green]Alerts: 0[/green]")

        parts.append(f"Backup: {last_backup}")
        parts.append(f"[dim]{datetime.now().strftime('%H:%M')}[/dim]")

        return " | ".join(parts)

    finally:
        conn.close()


# =============================================================================
# TUI MENU INTEGRATION
# =============================================================================

def show_dashboard_menu(db_path: str):
    """Show dashboard menu with all monitoring options."""
    from v1.cli.tui import clear_screen, print_menu, get_keypress_choice, getch

    while True:
        clear_screen()

        # Show dashboard
        if RICH_AVAILABLE:
            console.print(Panel(
                render_dashboard(db_path),
                title="[bold]DASHBOARD[/bold]",
                border_style="cyan",
                padding=(1, 2)
            ))

        print_menu(
            "",
            [
                "Full Network Topology",
                "Bandwidth Details",
                "View All Alerts",
                "Dismiss All Alerts",
                "Back to Main Menu",
            ],
            include_quit=False
        )

        choice = get_keypress_choice(5, allow_quit=False)

        if choice is None or choice == 5:
            return

        if choice == -1:
            continue

        if choice == 1:
            # Full topology
            clear_screen()
            if RICH_AVAILABLE:
                console.print(Panel(
                    render_topology_tree(db_path),
                    title="[bold]NETWORK TOPOLOGY[/bold]",
                    border_style="cyan",
                    padding=(1, 2)
                ))
            else:
                print(render_topology_tree(db_path))
            print("\nPress any key..."); getch()

        elif choice == 2:
            # Bandwidth details
            clear_screen()
            if RICH_AVAILABLE:
                console.print(Panel(
                    render_bandwidth_table(db_path, hours=24),
                    title="[bold]BANDWIDTH USAGE[/bold]",
                    border_style="cyan",
                    padding=(1, 2)
                ))
            else:
                print(render_bandwidth_table(db_path, hours=24))
            print("\nPress any key..."); getch()

        elif choice == 3:
            # View all alerts
            show_alerts_menu(db_path)

        elif choice == 4:
            # Dismiss all alerts
            alert_mgr = AlertManager(db_path)
            alert_mgr.dismiss_all()
            print("\n[green]All alerts dismissed.[/green]" if RICH_AVAILABLE else "\nAll alerts dismissed.")
            getch()


def show_alerts_menu(db_path: str):
    """Show alerts list with management options."""
    from v1.cli.tui import clear_screen, getch

    alert_mgr = AlertManager(db_path)

    clear_screen()
    alerts = alert_mgr.get_active_alerts(limit=20)

    if not alerts:
        print("\nNo active alerts.")
        print("\nPress any key..."); getch()
        return

    if RICH_AVAILABLE:
        table = Table(title="Active Alerts", box=box.ROUNDED)
        table.add_column("#", style="dim", width=3)
        table.add_column("Sev", width=4)
        table.add_column("Title", style="bold")
        table.add_column("Message")
        table.add_column("Entity", style="dim")
        table.add_column("Action", style="cyan")

        for i, alert in enumerate(alerts, 1):
            table.add_row(
                str(i),
                f"[{alert.severity_color}]{alert.severity[0].upper()}[/{alert.severity_color}]",
                alert.title,
                alert.message,
                alert.entity_name or "",
                alert.action_hint or ""
            )

        console.print()
        console.print(table)
        console.print()
    else:
        print("\nActive Alerts:")
        print("-" * 70)
        for i, alert in enumerate(alerts, 1):
            print(f"{i}. [{alert.severity}] {alert.title}")
            print(f"   {alert.message}")
            if alert.action_hint:
                print(f"   -> {alert.action_hint}")

    print("\nPress any key..."); getch()
