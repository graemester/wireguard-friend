"""
Guided Troubleshooting Wizard for WireGuard Friend.

Interactive diagnostic system that guides users through
troubleshooting common WireGuard connectivity and configuration issues.

Features:
- Step-by-step diagnostic workflows
- Automated connectivity tests
- Configuration validation
- Common issue detection and remediation suggestions
- Diagnostic report generation
"""

import sqlite3
import subprocess
import socket
import time
import re
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any, Callable
from dataclasses import dataclass, field
from enum import Enum


class DiagnosticResult(Enum):
    """Result of a diagnostic check."""
    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"
    SKIP = "skip"
    UNKNOWN = "unknown"


class IssueCategory(Enum):
    """Categories of issues."""
    CONNECTIVITY = "connectivity"
    CONFIGURATION = "configuration"
    HANDSHAKE = "handshake"
    ROUTING = "routing"
    DNS = "dns"
    FIREWALL = "firewall"
    KEYS = "keys"
    PERFORMANCE = "performance"


@dataclass
class DiagnosticCheck:
    """A single diagnostic check."""
    id: str
    name: str
    description: str
    category: IssueCategory
    check_func: Optional[Callable] = None
    result: DiagnosticResult = DiagnosticResult.UNKNOWN
    message: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    remediation: List[str] = field(default_factory=list)


@dataclass
class TroubleshootingSession:
    """A troubleshooting session with all results."""
    id: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    target_entity_type: str = ""
    target_entity_id: Optional[int] = None
    checks: List[DiagnosticCheck] = field(default_factory=list)
    summary: str = ""


class TroubleshootingWizard:
    """Guided troubleshooting for WireGuard issues."""

    def __init__(self, db_path: str):
        """Initialize the troubleshooting wizard.

        Args:
            db_path: Path to the database
        """
        self.db_path = db_path
        self._session: Optional[TroubleshootingSession] = None

    def _get_connection(self) -> sqlite3.Connection:
        """Get a database connection."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def start_session(self, entity_type: str = None,
                      entity_id: int = None) -> TroubleshootingSession:
        """Start a new troubleshooting session.

        Args:
            entity_type: Optional entity type to focus on
            entity_id: Optional entity ID to focus on

        Returns:
            New TroubleshootingSession
        """
        session_id = f"ts_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self._session = TroubleshootingSession(
            id=session_id,
            started_at=datetime.now(),
            target_entity_type=entity_type or "",
            target_entity_id=entity_id
        )
        return self._session

    def run_full_diagnostic(self, entity_type: str = None,
                            entity_id: int = None) -> TroubleshootingSession:
        """Run a full diagnostic on the WireGuard setup.

        Args:
            entity_type: Optional entity type to focus on
            entity_id: Optional entity ID to focus on

        Returns:
            TroubleshootingSession with all results
        """
        session = self.start_session(entity_type, entity_id)

        # Run all diagnostic checks
        checks = [
            self._check_wireguard_installed(),
            self._check_wireguard_interface(),
            self._check_coordination_server(),
            self._check_peer_handshakes(),
            self._check_allowed_ips(),
            self._check_endpoint_reachability(),
            self._check_dns_resolution(),
            self._check_key_validity(),
            self._check_firewall_rules(),
            self._check_routing_table(),
            self._check_mtu_settings(),
            self._check_persistent_keepalive(),
        ]

        session.checks = checks
        session.completed_at = datetime.now()
        session.summary = self._generate_summary(checks)

        return session

    def _check_wireguard_installed(self) -> DiagnosticCheck:
        """Check if WireGuard tools are installed."""
        check = DiagnosticCheck(
            id="wg_installed",
            name="WireGuard Installation",
            description="Verify WireGuard tools are installed",
            category=IssueCategory.CONFIGURATION
        )

        try:
            result = subprocess.run(
                ["wg", "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                check.result = DiagnosticResult.PASS
                check.message = f"WireGuard installed: {result.stdout.strip()}"
                check.details["version"] = result.stdout.strip()
            else:
                check.result = DiagnosticResult.FAIL
                check.message = "WireGuard tools not found"
                check.remediation = [
                    "Install WireGuard: apt install wireguard (Debian/Ubuntu)",
                    "Or: dnf install wireguard-tools (Fedora/RHEL)"
                ]
        except FileNotFoundError:
            check.result = DiagnosticResult.FAIL
            check.message = "WireGuard command not found in PATH"
            check.remediation = [
                "Install WireGuard tools for your distribution",
                "Ensure 'wg' command is in your PATH"
            ]
        except subprocess.TimeoutExpired:
            check.result = DiagnosticResult.WARN
            check.message = "WireGuard check timed out"

        return check

    def _check_wireguard_interface(self) -> DiagnosticCheck:
        """Check WireGuard interfaces are up."""
        check = DiagnosticCheck(
            id="wg_interface",
            name="WireGuard Interface",
            description="Verify WireGuard interface is active",
            category=IssueCategory.CONNECTIVITY
        )

        try:
            result = subprocess.run(
                ["wg", "show", "interfaces"],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0 and result.stdout.strip():
                interfaces = result.stdout.strip().split()
                check.result = DiagnosticResult.PASS
                check.message = f"Active interfaces: {', '.join(interfaces)}"
                check.details["interfaces"] = interfaces
            else:
                check.result = DiagnosticResult.FAIL
                check.message = "No WireGuard interfaces found"
                check.remediation = [
                    "Start WireGuard: wg-quick up <interface>",
                    "Check config file exists in /etc/wireguard/",
                    "Verify permissions on config files"
                ]
        except (subprocess.TimeoutExpired, PermissionError) as e:
            check.result = DiagnosticResult.WARN
            check.message = f"Could not check interfaces: {e}"
            check.remediation = ["Run with sudo for full diagnostics"]

        return check

    def _check_coordination_server(self) -> DiagnosticCheck:
        """Check coordination server connectivity."""
        check = DiagnosticCheck(
            id="cs_connectivity",
            name="Coordination Server",
            description="Verify coordination server is reachable",
            category=IssueCategory.CONNECTIVITY
        )

        conn = self._get_connection()

        try:
            cs = conn.execute("""
                SELECT id, name, endpoint, listen_port
                FROM coordination_server
                LIMIT 1
            """).fetchone()

            if not cs:
                check.result = DiagnosticResult.SKIP
                check.message = "No coordination server configured"
                conn.close()
                return check

            endpoint = cs['endpoint']
            port = cs['listen_port'] or 51820

            check.details["endpoint"] = endpoint
            check.details["port"] = port

            # Try to resolve and ping
            try:
                ip = socket.gethostbyname(endpoint)
                check.details["resolved_ip"] = ip

                # Try UDP connectivity (WireGuard is UDP)
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(5)

                # Try ICMP ping
                ping_result = subprocess.run(
                    ["ping", "-c", "1", "-W", "3", ip],
                    capture_output=True,
                    timeout=5
                )

                if ping_result.returncode == 0:
                    check.result = DiagnosticResult.PASS
                    check.message = f"Coordination server {endpoint} ({ip}) is reachable"
                else:
                    check.result = DiagnosticResult.WARN
                    check.message = f"ICMP blocked to {endpoint}, but UDP may work"
                    check.remediation = [
                        "ICMP ping is blocked but WireGuard uses UDP",
                        "Check firewall allows UDP port " + str(port)
                    ]

            except socket.gaierror:
                check.result = DiagnosticResult.FAIL
                check.message = f"Cannot resolve {endpoint}"
                check.remediation = [
                    "Check DNS configuration",
                    "Verify endpoint hostname is correct",
                    "Try using IP address directly"
                ]
            except socket.timeout:
                check.result = DiagnosticResult.FAIL
                check.message = f"Connection to {endpoint} timed out"
                check.remediation = [
                    "Check network connectivity",
                    "Verify firewall allows outbound UDP",
                    f"Ensure port {port} is open on server"
                ]

        except sqlite3.OperationalError:
            check.result = DiagnosticResult.SKIP
            check.message = "Coordination server table not found"

        conn.close()
        return check

    def _check_peer_handshakes(self) -> DiagnosticCheck:
        """Check peer handshake status."""
        check = DiagnosticCheck(
            id="peer_handshakes",
            name="Peer Handshakes",
            description="Verify recent handshakes with peers",
            category=IssueCategory.HANDSHAKE
        )

        try:
            result = subprocess.run(
                ["wg", "show", "all", "dump"],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode != 0:
                check.result = DiagnosticResult.SKIP
                check.message = "Could not get WireGuard status"
                return check

            now = time.time()
            stale_peers = []
            healthy_peers = []
            never_connected = []

            for line in result.stdout.strip().split('\n'):
                parts = line.split('\t')
                if len(parts) >= 6:
                    public_key = parts[1][:8] + "..."
                    last_handshake = int(parts[5]) if parts[5] != '0' else 0

                    if last_handshake == 0:
                        never_connected.append(public_key)
                    elif now - last_handshake > 180:  # 3 minutes
                        stale_peers.append({
                            "key": public_key,
                            "age_seconds": int(now - last_handshake)
                        })
                    else:
                        healthy_peers.append(public_key)

            check.details["healthy_peers"] = len(healthy_peers)
            check.details["stale_peers"] = len(stale_peers)
            check.details["never_connected"] = len(never_connected)

            if stale_peers or never_connected:
                check.result = DiagnosticResult.WARN
                issues = []
                if stale_peers:
                    issues.append(f"{len(stale_peers)} peers with stale handshakes")
                if never_connected:
                    issues.append(f"{len(never_connected)} peers never connected")
                check.message = "; ".join(issues)
                check.remediation = [
                    "Check peer endpoint addresses are correct",
                    "Verify firewall allows WireGuard traffic",
                    "Ensure peer public keys match",
                    "Try restarting WireGuard on both ends"
                ]
            elif healthy_peers:
                check.result = DiagnosticResult.PASS
                check.message = f"All {len(healthy_peers)} peers have recent handshakes"
            else:
                check.result = DiagnosticResult.WARN
                check.message = "No peers configured"

        except Exception as e:
            check.result = DiagnosticResult.WARN
            check.message = f"Could not check handshakes: {e}"

        return check

    def _check_allowed_ips(self) -> DiagnosticCheck:
        """Check allowed IPs configuration."""
        check = DiagnosticCheck(
            id="allowed_ips",
            name="Allowed IPs Configuration",
            description="Verify allowed IPs are properly configured",
            category=IssueCategory.ROUTING
        )

        try:
            result = subprocess.run(
                ["wg", "show", "all", "allowed-ips"],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode != 0:
                check.result = DiagnosticResult.SKIP
                check.message = "Could not get allowed IPs"
                return check

            issues = []
            overlaps = []

            # Parse allowed IPs
            all_ranges = []
            for line in result.stdout.strip().split('\n'):
                if '\t' in line:
                    parts = line.split('\t')
                    if len(parts) >= 2:
                        peer = parts[0][:8] + "..."
                        ips = parts[1].split() if len(parts) > 1 else []
                        for ip in ips:
                            all_ranges.append({"peer": peer, "range": ip})

            # Check for common issues
            has_default = any(r['range'] in ['0.0.0.0/0', '::/0'] for r in all_ranges)
            has_vpn_only = not has_default and all_ranges

            check.details["total_ranges"] = len(all_ranges)
            check.details["has_default_route"] = has_default

            if not all_ranges:
                check.result = DiagnosticResult.WARN
                check.message = "No allowed IPs configured"
                check.remediation = ["Add allowed IPs to peer configurations"]
            else:
                check.result = DiagnosticResult.PASS
                check.message = f"{len(all_ranges)} allowed IP ranges configured"
                if has_default:
                    check.message += " (includes default route)"

        except Exception as e:
            check.result = DiagnosticResult.WARN
            check.message = f"Could not check allowed IPs: {e}"

        return check

    def _check_endpoint_reachability(self) -> DiagnosticCheck:
        """Check if peer endpoints are reachable."""
        check = DiagnosticCheck(
            id="endpoint_reach",
            name="Endpoint Reachability",
            description="Test connectivity to peer endpoints",
            category=IssueCategory.CONNECTIVITY
        )

        try:
            result = subprocess.run(
                ["wg", "show", "all", "endpoints"],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode != 0:
                check.result = DiagnosticResult.SKIP
                check.message = "Could not get endpoints"
                return check

            reachable = 0
            unreachable = 0
            no_endpoint = 0

            for line in result.stdout.strip().split('\n'):
                if '\t' in line:
                    parts = line.split('\t')
                    if len(parts) >= 2:
                        endpoint = parts[1]
                        if endpoint == '(none)':
                            no_endpoint += 1
                        else:
                            # Extract host from endpoint
                            host = endpoint.rsplit(':', 1)[0]
                            if host.startswith('['):
                                host = host[1:-1]  # IPv6

                            # Quick connectivity test
                            try:
                                socket.gethostbyname(host)
                                reachable += 1
                            except socket.gaierror:
                                unreachable += 1

            check.details["reachable"] = reachable
            check.details["unreachable"] = unreachable
            check.details["no_endpoint"] = no_endpoint

            if unreachable > 0:
                check.result = DiagnosticResult.WARN
                check.message = f"{unreachable} endpoint(s) unreachable"
                check.remediation = [
                    "Check endpoint hostnames are correct",
                    "Verify DNS resolution",
                    "Check network connectivity"
                ]
            elif reachable > 0:
                check.result = DiagnosticResult.PASS
                check.message = f"All {reachable} endpoints resolvable"
            else:
                check.result = DiagnosticResult.PASS
                check.message = "No dynamic endpoints configured"

        except Exception as e:
            check.result = DiagnosticResult.WARN
            check.message = f"Could not check endpoints: {e}"

        return check

    def _check_dns_resolution(self) -> DiagnosticCheck:
        """Check DNS resolution through tunnel."""
        check = DiagnosticCheck(
            id="dns_resolution",
            name="DNS Resolution",
            description="Test DNS resolution",
            category=IssueCategory.DNS
        )

        test_domains = ["cloudflare.com", "google.com", "github.com"]
        resolved = 0
        failed = 0

        for domain in test_domains:
            try:
                socket.gethostbyname(domain)
                resolved += 1
            except socket.gaierror:
                failed += 1

        check.details["resolved"] = resolved
        check.details["failed"] = failed

        if failed > 0:
            check.result = DiagnosticResult.WARN
            check.message = f"DNS resolution issues: {failed}/{len(test_domains)} failed"
            check.remediation = [
                "Check DNS server configuration",
                "Verify DNS traffic routing through tunnel",
                "Try alternative DNS servers (8.8.8.8, 1.1.1.1)"
            ]
        else:
            check.result = DiagnosticResult.PASS
            check.message = "DNS resolution working"

        return check

    def _check_key_validity(self) -> DiagnosticCheck:
        """Check key configuration validity."""
        check = DiagnosticCheck(
            id="key_validity",
            name="Key Validity",
            description="Verify WireGuard key configuration",
            category=IssueCategory.KEYS
        )

        conn = self._get_connection()
        issues = []

        try:
            # Check for remotes with missing or invalid keys
            remotes = conn.execute("""
                SELECT id, name, current_public_key, key_created_at
                FROM remote
            """).fetchall()

            for remote in remotes:
                key = remote['current_public_key']
                if not key:
                    issues.append(f"Remote {remote['name'] or remote['id']}: missing public key")
                elif len(key) != 44 or not key.endswith('='):
                    issues.append(f"Remote {remote['name'] or remote['id']}: invalid key format")

                # Check key age
                if remote['key_created_at']:
                    created = datetime.fromisoformat(remote['key_created_at'])
                    age_days = (datetime.now() - created).days
                    if age_days > 365:
                        issues.append(f"Remote {remote['name'] or remote['id']}: key is {age_days} days old")

            check.details["total_remotes"] = len(remotes)
            check.details["issues"] = len(issues)

        except sqlite3.OperationalError:
            pass

        conn.close()

        if issues:
            check.result = DiagnosticResult.WARN
            check.message = f"{len(issues)} key issue(s) found"
            check.details["issue_list"] = issues
            check.remediation = [
                "Rotate old keys using key rotation feature",
                "Ensure keys are 44 characters and base64 encoded",
                "Regenerate invalid keys"
            ]
        else:
            check.result = DiagnosticResult.PASS
            check.message = "All keys valid"

        return check

    def _check_firewall_rules(self) -> DiagnosticCheck:
        """Check firewall configuration."""
        check = DiagnosticCheck(
            id="firewall",
            name="Firewall Rules",
            description="Check firewall allows WireGuard traffic",
            category=IssueCategory.FIREWALL
        )

        issues = []

        # Check iptables (if available)
        try:
            result = subprocess.run(
                ["iptables", "-L", "-n"],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                # Look for DROP rules that might affect WireGuard
                if "DROP" in result.stdout and "51820" in result.stdout:
                    issues.append("Possible DROP rule for WireGuard port")

                check.details["iptables_available"] = True
            else:
                check.details["iptables_available"] = False

        except (FileNotFoundError, PermissionError):
            check.details["iptables_available"] = False

        # Check ufw (if available)
        try:
            result = subprocess.run(
                ["ufw", "status"],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0 and "active" in result.stdout.lower():
                check.details["ufw_active"] = True
                if "51820" not in result.stdout:
                    issues.append("UFW active but 51820/udp may not be allowed")
            else:
                check.details["ufw_active"] = False

        except (FileNotFoundError, PermissionError):
            check.details["ufw_active"] = False

        if issues:
            check.result = DiagnosticResult.WARN
            check.message = "; ".join(issues)
            check.remediation = [
                "Allow UDP port 51820: ufw allow 51820/udp",
                "Or: iptables -A INPUT -p udp --dport 51820 -j ACCEPT",
                "Ensure forwarding enabled: sysctl net.ipv4.ip_forward=1"
            ]
        else:
            check.result = DiagnosticResult.PASS
            check.message = "No obvious firewall issues detected"

        return check

    def _check_routing_table(self) -> DiagnosticCheck:
        """Check routing table configuration."""
        check = DiagnosticCheck(
            id="routing",
            name="Routing Table",
            description="Verify routing table entries for WireGuard",
            category=IssueCategory.ROUTING
        )

        try:
            result = subprocess.run(
                ["ip", "route", "show"],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode != 0:
                check.result = DiagnosticResult.SKIP
                check.message = "Could not check routing table"
                return check

            wg_routes = []
            for line in result.stdout.split('\n'):
                if 'wg' in line.lower() or '10.0.0' in line or '10.10.' in line:
                    wg_routes.append(line.strip())

            check.details["wg_routes"] = wg_routes

            if wg_routes:
                check.result = DiagnosticResult.PASS
                check.message = f"Found {len(wg_routes)} WireGuard-related route(s)"
            else:
                check.result = DiagnosticResult.WARN
                check.message = "No WireGuard routes found"
                check.remediation = [
                    "Ensure WireGuard interface is up",
                    "Check AllowedIPs configuration adds routes",
                    "Verify ip route for VPN subnet exists"
                ]

        except Exception as e:
            check.result = DiagnosticResult.WARN
            check.message = f"Could not check routing: {e}"

        return check

    def _check_mtu_settings(self) -> DiagnosticCheck:
        """Check MTU configuration."""
        check = DiagnosticCheck(
            id="mtu",
            name="MTU Settings",
            description="Verify MTU is appropriately configured",
            category=IssueCategory.PERFORMANCE
        )

        try:
            result = subprocess.run(
                ["ip", "link", "show"],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode != 0:
                check.result = DiagnosticResult.SKIP
                check.message = "Could not check MTU"
                return check

            wg_mtus = {}
            current_interface = None

            for line in result.stdout.split('\n'):
                # Match interface name
                match = re.match(r'^\d+:\s+(\S+):', line)
                if match:
                    current_interface = match.group(1)

                # Match MTU
                mtu_match = re.search(r'mtu\s+(\d+)', line)
                if mtu_match and current_interface and 'wg' in current_interface:
                    wg_mtus[current_interface] = int(mtu_match.group(1))

            check.details["interface_mtus"] = wg_mtus

            issues = []
            for iface, mtu in wg_mtus.items():
                if mtu > 1420:
                    issues.append(f"{iface}: MTU {mtu} may cause fragmentation")
                elif mtu < 1280:
                    issues.append(f"{iface}: MTU {mtu} very low, may impact performance")

            if issues:
                check.result = DiagnosticResult.WARN
                check.message = "; ".join(issues)
                check.remediation = [
                    "Recommended MTU for WireGuard: 1420",
                    "Lower if experiencing packet loss (try 1400, 1380)",
                    "Set MTU in config: MTU = 1420"
                ]
            elif wg_mtus:
                check.result = DiagnosticResult.PASS
                check.message = f"MTU settings look good: {wg_mtus}"
            else:
                check.result = DiagnosticResult.SKIP
                check.message = "No WireGuard interfaces found for MTU check"

        except Exception as e:
            check.result = DiagnosticResult.WARN
            check.message = f"Could not check MTU: {e}"

        return check

    def _check_persistent_keepalive(self) -> DiagnosticCheck:
        """Check persistent keepalive settings."""
        check = DiagnosticCheck(
            id="keepalive",
            name="Persistent Keepalive",
            description="Check keepalive configuration for NAT traversal",
            category=IssueCategory.CONNECTIVITY
        )

        conn = self._get_connection()
        issues = []

        try:
            # Check remotes
            remotes = conn.execute("""
                SELECT id, name, persistent_keepalive
                FROM remote
            """).fetchall()

            no_keepalive = []
            for remote in remotes:
                if not remote['persistent_keepalive'] or remote['persistent_keepalive'] == 0:
                    no_keepalive.append(remote['name'] or str(remote['id']))

            check.details["total_remotes"] = len(remotes)
            check.details["without_keepalive"] = len(no_keepalive)

            if no_keepalive and len(no_keepalive) == len(remotes):
                check.result = DiagnosticResult.WARN
                check.message = "No peers have persistent keepalive configured"
                check.remediation = [
                    "Add PersistentKeepalive = 25 for peers behind NAT",
                    "Helps maintain connections through firewalls",
                    "Not needed if both endpoints have public IPs"
                ]
            elif no_keepalive:
                check.result = DiagnosticResult.PASS
                check.message = f"{len(remotes) - len(no_keepalive)}/{len(remotes)} peers have keepalive"
            else:
                check.result = DiagnosticResult.PASS
                check.message = "All peers have persistent keepalive configured"

        except sqlite3.OperationalError:
            check.result = DiagnosticResult.SKIP
            check.message = "Could not check keepalive settings"

        conn.close()
        return check

    def _generate_summary(self, checks: List[DiagnosticCheck]) -> str:
        """Generate a summary of diagnostic results."""
        passed = sum(1 for c in checks if c.result == DiagnosticResult.PASS)
        failed = sum(1 for c in checks if c.result == DiagnosticResult.FAIL)
        warned = sum(1 for c in checks if c.result == DiagnosticResult.WARN)
        skipped = sum(1 for c in checks if c.result == DiagnosticResult.SKIP)

        total = len(checks)

        if failed > 0:
            status = "ISSUES FOUND"
        elif warned > 0:
            status = "WARNINGS"
        else:
            status = "HEALTHY"

        return f"{status}: {passed}/{total} passed, {failed} failed, {warned} warnings, {skipped} skipped"

    def get_remediation_steps(self, session: TroubleshootingSession) -> List[str]:
        """Get all remediation steps from a session.

        Args:
            session: Troubleshooting session

        Returns:
            List of unique remediation steps
        """
        steps = []
        seen = set()

        for check in session.checks:
            if check.result in [DiagnosticResult.FAIL, DiagnosticResult.WARN]:
                for step in check.remediation:
                    if step not in seen:
                        steps.append(step)
                        seen.add(step)

        return steps

    def export_report(self, session: TroubleshootingSession,
                      format: str = "text") -> str:
        """Export diagnostic report.

        Args:
            session: Troubleshooting session
            format: Output format ('text' or 'json')

        Returns:
            Formatted report
        """
        if format == "json":
            import json
            data = {
                "session_id": session.id,
                "started_at": session.started_at.isoformat(),
                "completed_at": session.completed_at.isoformat() if session.completed_at else None,
                "summary": session.summary,
                "checks": [
                    {
                        "id": c.id,
                        "name": c.name,
                        "result": c.result.value,
                        "message": c.message,
                        "details": c.details,
                        "remediation": c.remediation
                    }
                    for c in session.checks
                ]
            }
            return json.dumps(data, indent=2)

        # Text format
        lines = [
            "=" * 60,
            "WIREGUARD FRIEND DIAGNOSTIC REPORT",
            "=" * 60,
            f"Session: {session.id}",
            f"Started: {session.started_at.strftime('%Y-%m-%d %H:%M:%S')}",
            f"Summary: {session.summary}",
            "",
            "-" * 60,
            "DIAGNOSTIC CHECKS",
            "-" * 60,
        ]

        result_symbols = {
            DiagnosticResult.PASS: "[OK]",
            DiagnosticResult.FAIL: "[FAIL]",
            DiagnosticResult.WARN: "[WARN]",
            DiagnosticResult.SKIP: "[SKIP]",
            DiagnosticResult.UNKNOWN: "[?]"
        }

        for check in session.checks:
            symbol = result_symbols.get(check.result, "[?]")
            lines.append(f"\n{symbol} {check.name}")
            lines.append(f"    {check.message}")

            if check.remediation:
                lines.append("    Remediation:")
                for step in check.remediation:
                    lines.append(f"      - {step}")

        lines.extend([
            "",
            "-" * 60,
            "RECOMMENDED ACTIONS",
            "-" * 60,
        ])

        remediation = self.get_remediation_steps(session)
        if remediation:
            for i, step in enumerate(remediation, 1):
                lines.append(f"{i}. {step}")
        else:
            lines.append("No immediate actions required.")

        lines.append("")
        lines.append("=" * 60)

        return "\n".join(lines)


def quick_diagnostic(db_path: str) -> Dict[str, Any]:
    """Run a quick diagnostic and return results.

    Args:
        db_path: Path to database

    Returns:
        Dict with diagnostic summary
    """
    wizard = TroubleshootingWizard(db_path)
    session = wizard.run_full_diagnostic()

    return {
        "summary": session.summary,
        "passed": sum(1 for c in session.checks if c.result == DiagnosticResult.PASS),
        "failed": sum(1 for c in session.checks if c.result == DiagnosticResult.FAIL),
        "warnings": sum(1 for c in session.checks if c.result == DiagnosticResult.WARN),
        "remediation_steps": wizard.get_remediation_steps(session)
    }
