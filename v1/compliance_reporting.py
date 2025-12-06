"""
Compliance Reporting Module

Generates compliance reports for audits (SOC2, ISO27001, etc.).

Report Types:
1. Access Control Report - Who has access to what
2. Key Rotation Report - Rotation history and compliance
3. Configuration Change Report - All changes with timestamps
4. Network Inventory Report - Complete asset list
5. Executive Summary - High-level compliance overview

Output Formats: Markdown, JSON, CSV
"""

import json
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import List, Dict, Optional, Any


class ReportType(Enum):
    """Types of compliance reports."""
    ACCESS_CONTROL = "access_control"
    KEY_ROTATION = "key_rotation"
    CONFIGURATION_CHANGES = "configuration_changes"
    NETWORK_INVENTORY = "network_inventory"
    EXECUTIVE_SUMMARY = "executive_summary"
    FULL_COMPLIANCE = "full_compliance"


class OutputFormat(Enum):
    """Report output formats."""
    MARKDOWN = "markdown"
    JSON = "json"
    CSV = "csv"


@dataclass
class AccessControlEntry:
    """Single access control entry."""
    entity_type: str
    hostname: str
    access_level: str
    vpn_ip: str
    created_at: str
    last_rotation: Optional[str]
    networks_accessible: List[str] = field(default_factory=list)


@dataclass
class KeyRotationEntry:
    """Key rotation history entry."""
    entity_type: str
    hostname: str
    rotated_at: str
    days_since_rotation: int
    policy_name: Optional[str]
    compliant: bool


@dataclass
class ConfigChangeEntry:
    """Configuration change entry."""
    timestamp: str
    event_type: str
    entity_type: Optional[str]
    entity_name: Optional[str]
    operator: str
    details: str


@dataclass
class ComplianceReport:
    """Complete compliance report."""
    report_type: ReportType
    generated_at: datetime
    period_start: datetime
    period_end: datetime
    organization: str
    data: Dict[str, Any]
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "report_type": self.report_type.value,
            "generated_at": self.generated_at.isoformat(),
            "period_start": self.period_start.isoformat(),
            "period_end": self.period_end.isoformat(),
            "organization": self.organization,
            "data": self.data,
            "warnings": self.warnings,
        }


class ComplianceReporter:
    """
    Generates compliance reports for enterprise audits.

    Usage:
        reporter = ComplianceReporter(db_path)
        report = reporter.generate_report(
            ReportType.FULL_COMPLIANCE,
            days=90,
            organization="Acme Corp"
        )

        # Export to file
        reporter.export_report(report, "compliance-q4.md", OutputFormat.MARKDOWN)
    """

    def __init__(self, db_path: str):
        self.db_path = db_path

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def generate_report(self, report_type: ReportType,
                       days: int = 90,
                       organization: str = "WireGuard Network") -> ComplianceReport:
        """Generate a compliance report."""
        period_end = datetime.now()
        period_start = period_end - timedelta(days=days)

        if report_type == ReportType.ACCESS_CONTROL:
            data = self._generate_access_control()
        elif report_type == ReportType.KEY_ROTATION:
            data = self._generate_key_rotation(days)
        elif report_type == ReportType.CONFIGURATION_CHANGES:
            data = self._generate_config_changes(period_start)
        elif report_type == ReportType.NETWORK_INVENTORY:
            data = self._generate_network_inventory()
        elif report_type == ReportType.EXECUTIVE_SUMMARY:
            data = self._generate_executive_summary(days)
        elif report_type == ReportType.FULL_COMPLIANCE:
            data = self._generate_full_compliance(days, period_start)
        else:
            data = {}

        warnings = self._check_compliance_warnings(days)

        return ComplianceReport(
            report_type=report_type,
            generated_at=datetime.now(),
            period_start=period_start,
            period_end=period_end,
            organization=organization,
            data=data,
            warnings=warnings
        )

    def _generate_access_control(self) -> dict:
        """Generate access control report data."""
        conn = self._get_conn()
        try:
            entries = []

            # Get all remotes with access levels
            # Try with key_rotation_history first, fall back without
            try:
                rows = conn.execute("""
                    SELECT
                        'remote' as entity_type,
                        r.hostname,
                        r.access_level,
                        r.ipv4_address as vpn_ip,
                        r.created_at,
                        (SELECT MAX(rotated_at) FROM key_rotation_history
                         WHERE entity_type = 'remote' AND entity_id = r.id) as last_rotation
                    FROM remote r
                    ORDER BY r.access_level, r.hostname
                """).fetchall()
            except sqlite3.OperationalError:
                # key_rotation_history table doesn't exist
                rows = conn.execute("""
                    SELECT
                        'remote' as entity_type,
                        r.hostname,
                        r.access_level,
                        r.ipv4_address as vpn_ip,
                        r.created_at,
                        NULL as last_rotation
                    FROM remote r
                    ORDER BY r.access_level, r.hostname
                """).fetchall()

            for row in rows:
                entries.append({
                    "entity_type": row['entity_type'],
                    "hostname": row['hostname'],
                    "access_level": row['access_level'],
                    "vpn_ip": row['vpn_ip'],
                    "created_at": row['created_at'],
                    "last_rotation": row['last_rotation'],
                })

            # Group by access level
            by_level = {}
            for entry in entries:
                level = entry['access_level']
                if level not in by_level:
                    by_level[level] = []
                by_level[level].append(entry)

            return {
                "total_peers": len(entries),
                "by_access_level": by_level,
                "entries": entries,
            }

        finally:
            conn.close()

    def _generate_key_rotation(self, days: int) -> dict:
        """Generate key rotation compliance report."""
        conn = self._get_conn()
        try:
            entries = []
            compliant_count = 0
            non_compliant_count = 0

            # Get all entities and their rotation status
            for table, entity_type in [
                ('coordination_server', 'cs'),
                ('subnet_router', 'sr'),
                ('remote', 'remote')
            ]:
                try:
                    rows = conn.execute(f"""
                        SELECT
                            t.id,
                            t.hostname,
                            t.created_at,
                            (SELECT MAX(rotated_at) FROM key_rotation_history
                             WHERE entity_type = ? AND entity_id = t.id) as last_rotation
                        FROM {table} t
                        ORDER BY t.hostname
                    """, (entity_type,)).fetchall()
                except sqlite3.OperationalError:
                    # key_rotation_history doesn't exist
                    rows = conn.execute(f"""
                        SELECT
                            t.id,
                            t.hostname,
                            t.created_at,
                            NULL as last_rotation
                        FROM {table} t
                        ORDER BY t.hostname
                    """).fetchall()

                for row in rows:
                    last_rotation = row['last_rotation'] or row['created_at']
                    if last_rotation:
                        try:
                            rotation_date = datetime.fromisoformat(last_rotation.replace('Z', '+00:00'))
                            days_since = (datetime.now() - rotation_date.replace(tzinfo=None)).days
                        except:
                            days_since = 999
                    else:
                        days_since = 999

                    compliant = days_since <= days
                    if compliant:
                        compliant_count += 1
                    else:
                        non_compliant_count += 1

                    entries.append({
                        "entity_type": entity_type,
                        "hostname": row['hostname'],
                        "last_rotation": last_rotation,
                        "days_since_rotation": days_since,
                        "compliant": compliant,
                    })

            # Get rotation history
            try:
                history = conn.execute("""
                    SELECT
                        entity_type,
                        entity_id,
                        old_public_key,
                        new_public_key,
                        rotated_at,
                        rotation_reason
                    FROM key_rotation_history
                    WHERE rotated_at > datetime('now', ?)
                    ORDER BY rotated_at DESC
                """, (f'-{days} days',)).fetchall()
                history_list = [dict(h) for h in history]
            except sqlite3.OperationalError:
                history_list = []

            return {
                "policy_days": days,
                "total_entities": len(entries),
                "compliant_count": compliant_count,
                "non_compliant_count": non_compliant_count,
                "compliance_rate": f"{(compliant_count / len(entries) * 100):.1f}%" if entries else "N/A",
                "entities": entries,
                "rotation_history": history_list,
            }

        finally:
            conn.close()

    def _generate_config_changes(self, period_start: datetime) -> dict:
        """Generate configuration changes report."""
        conn = self._get_conn()
        try:
            changes = []

            # Try to get from audit_log if available
            try:
                rows = conn.execute("""
                    SELECT
                        event_type,
                        entity_type,
                        entity_id,
                        operator,
                        details,
                        timestamp
                    FROM audit_log
                    WHERE timestamp > ?
                    ORDER BY timestamp DESC
                """, (period_start.isoformat(),)).fetchall()

                for row in rows:
                    changes.append({
                        "timestamp": row['timestamp'],
                        "event_type": row['event_type'],
                        "entity_type": row['entity_type'],
                        "operator": row['operator'],
                        "details": row['details'],
                    })
            except sqlite3.OperationalError:
                # Audit log not available, try key rotation history
                try:
                    rows = conn.execute("""
                        SELECT
                            'key_rotation' as event_type,
                            entity_type,
                            entity_id,
                            rotated_at as timestamp,
                            rotation_reason as details
                        FROM key_rotation_history
                        WHERE rotated_at > ?
                        ORDER BY rotated_at DESC
                    """, (period_start.isoformat(),)).fetchall()

                    for row in rows:
                        changes.append({
                            "timestamp": row['timestamp'],
                            "event_type": row['event_type'],
                            "entity_type": row['entity_type'],
                            "operator": "system",
                            "details": row['details'] or "Scheduled rotation",
                        })
                except sqlite3.OperationalError:
                    pass  # No change history available

            # Categorize by event type
            by_type = {}
            for change in changes:
                event_type = change['event_type']
                if event_type not in by_type:
                    by_type[event_type] = []
                by_type[event_type].append(change)

            return {
                "total_changes": len(changes),
                "by_event_type": {k: len(v) for k, v in by_type.items()},
                "changes": changes,
            }

        finally:
            conn.close()

    def _generate_network_inventory(self) -> dict:
        """Generate complete network inventory."""
        conn = self._get_conn()
        try:
            inventory = {
                "coordination_servers": [],
                "subnet_routers": [],
                "remotes": [],
                "exit_nodes": [],
            }

            # Coordination servers
            rows = conn.execute("""
                SELECT hostname, endpoint, ipv4_address, ipv6_address,
                       listen_port, created_at
                FROM coordination_server
            """).fetchall()
            inventory["coordination_servers"] = [dict(r) for r in rows]

            # Subnet routers
            rows = conn.execute("""
                SELECT sr.hostname, sr.endpoint, sr.ipv4_address, sr.ipv6_address,
                       sr.created_at, cs.hostname as cs_hostname
                FROM subnet_router sr
                LEFT JOIN coordination_server cs ON sr.cs_id = cs.id
            """).fetchall()

            for row in rows:
                router_data = dict(row)
                # Get advertised networks
                networks = conn.execute("""
                    SELECT network FROM advertised_network WHERE sr_id = ?
                """, (row['hostname'],)).fetchall()  # Note: may need to fix this query
                router_data["advertised_networks"] = [n['network'] for n in networks]
                inventory["subnet_routers"].append(router_data)

            # Remotes
            rows = conn.execute("""
                SELECT hostname, ipv4_address, ipv6_address, access_level,
                       exit_node_id, created_at
                FROM remote
                ORDER BY hostname
            """).fetchall()
            inventory["remotes"] = [dict(r) for r in rows]

            # Exit nodes
            try:
                rows = conn.execute("""
                    SELECT hostname, endpoint, ipv4_address, ipv6_address,
                           listen_port, created_at
                    FROM exit_node
                """).fetchall()
                inventory["exit_nodes"] = [dict(r) for r in rows]
            except sqlite3.OperationalError:
                inventory["exit_nodes"] = []

            # Summary counts
            inventory["summary"] = {
                "coordination_servers": len(inventory["coordination_servers"]),
                "subnet_routers": len(inventory["subnet_routers"]),
                "remotes": len(inventory["remotes"]),
                "exit_nodes": len(inventory["exit_nodes"]),
                "total_entities": (
                    len(inventory["coordination_servers"]) +
                    len(inventory["subnet_routers"]) +
                    len(inventory["remotes"]) +
                    len(inventory["exit_nodes"])
                ),
            }

            return inventory

        finally:
            conn.close()

    def _generate_executive_summary(self, days: int) -> dict:
        """Generate executive summary."""
        inventory = self._generate_network_inventory()
        rotation = self._generate_key_rotation(days)
        access = self._generate_access_control()

        return {
            "network_size": inventory["summary"],
            "key_rotation_compliance": {
                "policy_days": days,
                "compliance_rate": rotation["compliance_rate"],
                "compliant": rotation["compliant_count"],
                "non_compliant": rotation["non_compliant_count"],
            },
            "access_levels": {
                level: len(peers)
                for level, peers in access["by_access_level"].items()
            },
            "last_security_incident": "None recorded",
        }

    def _generate_full_compliance(self, days: int, period_start: datetime) -> dict:
        """Generate full compliance report with all sections."""
        return {
            "executive_summary": self._generate_executive_summary(days),
            "network_inventory": self._generate_network_inventory(),
            "access_control": self._generate_access_control(),
            "key_rotation": self._generate_key_rotation(days),
            "configuration_changes": self._generate_config_changes(period_start),
        }

    def _check_compliance_warnings(self, days: int) -> List[str]:
        """Check for compliance warnings."""
        warnings = []
        conn = self._get_conn()

        try:
            # Check for keys not rotated within policy period
            for table, entity_type, label in [
                ('coordination_server', 'cs', 'Coordination server'),
                ('subnet_router', 'sr', 'Subnet router'),
                ('remote', 'remote', 'Remote'),
            ]:
                try:
                    rows = conn.execute(f"""
                        SELECT t.hostname,
                               COALESCE(
                                   (SELECT MAX(rotated_at) FROM key_rotation_history
                                    WHERE entity_type = ? AND entity_id = t.id),
                                   t.created_at
                               ) as last_rotation
                        FROM {table} t
                    """, (entity_type,)).fetchall()
                except sqlite3.OperationalError:
                    # key_rotation_history doesn't exist
                    rows = conn.execute(f"""
                        SELECT t.hostname, t.created_at as last_rotation
                        FROM {table} t
                    """).fetchall()

                for row in rows:
                    if row['last_rotation']:
                        try:
                            rotation_date = datetime.fromisoformat(
                                row['last_rotation'].replace('Z', '+00:00')
                            )
                            days_since = (datetime.now() - rotation_date.replace(tzinfo=None)).days
                            if days_since > days:
                                warnings.append(
                                    f"{label} '{row['hostname']}' key not rotated in {days_since} days"
                                )
                        except:
                            pass

            # Check for missing SSH configuration on servers
            try:
                rows = conn.execute("""
                    SELECT hostname FROM coordination_server
                    WHERE ssh_host IS NULL OR ssh_host = ''
                """).fetchall()
                for row in rows:
                    warnings.append(f"No SSH access configured for '{row['hostname']}'")
            except sqlite3.OperationalError:
                pass  # ssh_host column doesn't exist

        finally:
            conn.close()

        return warnings

    def export_report(self, report: ComplianceReport,
                     output_path: str,
                     format: OutputFormat = OutputFormat.MARKDOWN) -> str:
        """Export report to file."""
        if format == OutputFormat.JSON:
            content = self._to_json(report)
        elif format == OutputFormat.CSV:
            content = self._to_csv(report)
        else:
            content = self._to_markdown(report)

        with open(output_path, 'w') as f:
            f.write(content)

        return output_path

    def _to_markdown(self, report: ComplianceReport) -> str:
        """Convert report to Markdown format."""
        lines = []

        # Header
        lines.append("=" * 75)
        lines.append(f"{'WIREGUARD NETWORK COMPLIANCE REPORT':^75}")
        lines.append(f"{'Generated: ' + report.generated_at.strftime('%Y-%m-%d %H:%M UTC'):^75}")
        lines.append("=" * 75)
        lines.append("")

        lines.append(f"**Organization**: {report.organization}")
        lines.append(f"**Report Period**: {report.period_start.strftime('%Y-%m-%d')} to {report.period_end.strftime('%Y-%m-%d')}")
        lines.append(f"**Report Type**: {report.report_type.value.replace('_', ' ').title()}")
        lines.append("")

        # Warnings
        if report.warnings:
            lines.append("## Compliance Warnings")
            lines.append("")
            for warning in report.warnings:
                lines.append(f"- {warning}")
            lines.append("")

        data = report.data

        # Executive Summary
        if "executive_summary" in data:
            summary = data["executive_summary"]
            lines.append("## Executive Summary")
            lines.append("")

            if "network_size" in summary:
                ns = summary["network_size"]
                lines.append(f"**Total Peers**: {ns.get('total_entities', 'N/A')}")
                lines.append(f"- Coordination Servers: {ns.get('coordination_servers', 0)}")
                lines.append(f"- Subnet Routers: {ns.get('subnet_routers', 0)}")
                lines.append(f"- Remotes: {ns.get('remotes', 0)}")
                lines.append(f"- Exit Nodes: {ns.get('exit_nodes', 0)}")
                lines.append("")

            if "key_rotation_compliance" in summary:
                krc = summary["key_rotation_compliance"]
                lines.append(f"**Key Rotation Compliance** ({krc.get('policy_days', 90)}-day policy)")
                lines.append(f"- Compliance Rate: {krc.get('compliance_rate', 'N/A')}")
                lines.append(f"- Compliant: {krc.get('compliant', 0)}")
                lines.append(f"- Non-Compliant: {krc.get('non_compliant', 0)}")
                lines.append("")

            if "access_levels" in summary:
                lines.append("**Access Levels**")
                for level, count in summary["access_levels"].items():
                    lines.append(f"- {level}: {count}")
                lines.append("")

            lines.append(f"**Last Security Incident**: {summary.get('last_security_incident', 'None recorded')}")
            lines.append("")

        # Network Inventory
        if "network_inventory" in data:
            inv = data["network_inventory"]
            lines.append("## Network Inventory")
            lines.append("")

            if inv.get("coordination_servers"):
                lines.append("### Coordination Servers")
                lines.append("")
                lines.append("| Hostname | Endpoint | VPN IP | Port |")
                lines.append("|----------|----------|--------|------|")
                for cs in inv["coordination_servers"]:
                    lines.append(f"| {cs.get('hostname', '-')} | {cs.get('endpoint', '-')} | {cs.get('ipv4_address', '-')} | {cs.get('listen_port', '-')} |")
                lines.append("")

            if inv.get("subnet_routers"):
                lines.append("### Subnet Routers")
                lines.append("")
                lines.append("| Hostname | VPN IP | Advertised Networks |")
                lines.append("|----------|--------|---------------------|")
                for sr in inv["subnet_routers"]:
                    networks = ', '.join(sr.get('advertised_networks', [])) or '-'
                    lines.append(f"| {sr.get('hostname', '-')} | {sr.get('ipv4_address', '-')} | {networks} |")
                lines.append("")

            if inv.get("remotes"):
                lines.append("### Remote Clients")
                lines.append("")
                lines.append("| Hostname | VPN IP | Access Level |")
                lines.append("|----------|--------|--------------|")
                for r in inv["remotes"]:
                    lines.append(f"| {r.get('hostname', '-')} | {r.get('ipv4_address', '-')} | {r.get('access_level', '-')} |")
                lines.append("")

            if inv.get("exit_nodes"):
                lines.append("### Exit Nodes")
                lines.append("")
                lines.append("| Hostname | Endpoint | VPN IP |")
                lines.append("|----------|----------|--------|")
                for en in inv["exit_nodes"]:
                    lines.append(f"| {en.get('hostname', '-')} | {en.get('endpoint', '-')} | {en.get('ipv4_address', '-')} |")
                lines.append("")

        # Key Rotation
        if "key_rotation" in data:
            kr = data["key_rotation"]
            lines.append("## Key Rotation Compliance")
            lines.append("")
            lines.append(f"**Policy**: {kr.get('policy_days', 90)}-day rotation requirement")
            lines.append(f"**Compliance Rate**: {kr.get('compliance_rate', 'N/A')}")
            lines.append("")

            if kr.get("entities"):
                lines.append("### Entity Status")
                lines.append("")
                lines.append("| Entity | Type | Last Rotation | Days | Status |")
                lines.append("|--------|------|---------------|------|--------|")
                for e in kr["entities"]:
                    status = "OK" if e.get('compliant') else "OVERDUE"
                    lines.append(f"| {e.get('hostname', '-')} | {e.get('entity_type', '-')} | {e.get('last_rotation', '-')[:10] if e.get('last_rotation') else '-'} | {e.get('days_since_rotation', '-')} | {status} |")
                lines.append("")

            if kr.get("rotation_history"):
                lines.append("### Recent Rotations")
                lines.append("")
                lines.append("| Date | Entity Type | Reason |")
                lines.append("|------|-------------|--------|")
                for h in kr["rotation_history"][:10]:  # Last 10
                    date = h.get('rotated_at', '-')[:10] if h.get('rotated_at') else '-'
                    lines.append(f"| {date} | {h.get('entity_type', '-')} | {h.get('rotation_reason', 'Scheduled')} |")
                lines.append("")

        # Configuration Changes
        if "configuration_changes" in data:
            cc = data["configuration_changes"]
            lines.append("## Configuration Changes")
            lines.append("")
            lines.append(f"**Total Changes**: {cc.get('total_changes', 0)}")
            lines.append("")

            if cc.get("by_event_type"):
                lines.append("### By Event Type")
                lines.append("")
                for event_type, count in cc["by_event_type"].items():
                    lines.append(f"- {event_type}: {count}")
                lines.append("")

            if cc.get("changes"):
                lines.append("### Recent Changes")
                lines.append("")
                lines.append("| Timestamp | Event | Entity | Operator |")
                lines.append("|-----------|-------|--------|----------|")
                for c in cc["changes"][:20]:  # Last 20
                    ts = c.get('timestamp', '-')[:19] if c.get('timestamp') else '-'
                    lines.append(f"| {ts} | {c.get('event_type', '-')} | {c.get('entity_type', '-')} | {c.get('operator', '-')} |")
                lines.append("")

        # Access Control
        if "access_control" in data and "access_control" not in str(data.get("executive_summary", {})):
            ac = data["access_control"]
            lines.append("## Access Control")
            lines.append("")
            lines.append(f"**Total Peers**: {ac.get('total_peers', 0)}")
            lines.append("")

            if ac.get("by_access_level"):
                for level, peers in ac["by_access_level"].items():
                    lines.append(f"### {level.replace('_', ' ').title()} ({len(peers)} peers)")
                    lines.append("")
                    lines.append("| Hostname | VPN IP | Created |")
                    lines.append("|----------|--------|---------|")
                    for p in peers:
                        created = p.get('created_at', '-')[:10] if p.get('created_at') else '-'
                        lines.append(f"| {p.get('hostname', '-')} | {p.get('vpn_ip', '-')} | {created} |")
                    lines.append("")

        # Footer
        lines.append("---")
        lines.append("")
        lines.append(f"*Report generated by WireGuard Friend v1.2.0*")

        return '\n'.join(lines)

    def _to_json(self, report: ComplianceReport) -> str:
        """Convert report to JSON format."""
        return json.dumps(report.to_dict(), indent=2, default=str)

    def _to_csv(self, report: ComplianceReport) -> str:
        """Convert report to CSV format (inventory only)."""
        lines = []

        data = report.data
        inv = data.get("network_inventory", data)

        # Header
        lines.append("entity_type,hostname,vpn_ip,access_level,endpoint,created_at")

        # Coordination servers
        for cs in inv.get("coordination_servers", []):
            lines.append(f"coordination_server,{cs.get('hostname', '')},{cs.get('ipv4_address', '')},,{cs.get('endpoint', '')},{cs.get('created_at', '')}")

        # Subnet routers
        for sr in inv.get("subnet_routers", []):
            lines.append(f"subnet_router,{sr.get('hostname', '')},{sr.get('ipv4_address', '')},,{sr.get('endpoint', '')},{sr.get('created_at', '')}")

        # Remotes
        for r in inv.get("remotes", []):
            lines.append(f"remote,{r.get('hostname', '')},{r.get('ipv4_address', '')},{r.get('access_level', '')},,{r.get('created_at', '')}")

        # Exit nodes
        for en in inv.get("exit_nodes", []):
            lines.append(f"exit_node,{en.get('hostname', '')},{en.get('ipv4_address', '')},,{en.get('endpoint', '')},{en.get('created_at', '')}")

        return '\n'.join(lines)


def generate_compliance_report(db_path: str, output_path: str = None,
                               days: int = 90,
                               report_type: str = "full_compliance",
                               format: str = "markdown",
                               organization: str = "WireGuard Network") -> str:
    """
    Convenience function to generate and optionally export a compliance report.

    Args:
        db_path: Path to WireGuard Friend database
        output_path: Optional path to save report (if None, returns content)
        days: Compliance period in days
        report_type: Type of report (full_compliance, access_control, etc.)
        format: Output format (markdown, json, csv)
        organization: Organization name for report header

    Returns:
        Report content as string (or path if output_path provided)
    """
    reporter = ComplianceReporter(db_path)

    # Parse report type
    try:
        rt = ReportType(report_type)
    except ValueError:
        rt = ReportType.FULL_COMPLIANCE

    # Parse output format
    try:
        fmt = OutputFormat(format)
    except ValueError:
        fmt = OutputFormat.MARKDOWN

    report = reporter.generate_report(rt, days, organization)

    if output_path:
        return reporter.export_report(report, output_path, fmt)
    else:
        if fmt == OutputFormat.JSON:
            return reporter._to_json(report)
        elif fmt == OutputFormat.CSV:
            return reporter._to_csv(report)
        else:
            return reporter._to_markdown(report)
