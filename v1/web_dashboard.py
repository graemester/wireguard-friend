"""
WireGuard Friend Web Dashboard

Provides a web-based dashboard for monitoring WireGuard networks.

Features:
- Real-time network status
- Peer list with search/filter
- Interactive topology visualization
- Alert management
- Configuration templates

Usage:
  wg-friend dashboard --port 8080
"""

import json
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from dataclasses import dataclass
from typing import Optional, Dict, List
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import threading
import time


@dataclass
class DashboardConfig:
    """Dashboard configuration."""
    host: str = "127.0.0.1"
    port: int = 8080
    db_path: str = "wireguard.db"
    refresh_interval: int = 30  # seconds
    enable_auth: bool = False
    username: str = "admin"
    password_hash: Optional[str] = None


class DashboardData:
    """Collect and cache dashboard data."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._cache = {}
        self._cache_time = {}
        self._cache_ttl = 10  # seconds

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _is_cache_valid(self, key: str) -> bool:
        if key not in self._cache_time:
            return False
        return time.time() - self._cache_time[key] < self._cache_ttl

    def get_network_summary(self) -> Dict:
        """Get network summary data."""
        if self._is_cache_valid('network_summary'):
            return self._cache['network_summary']

        conn = self._get_conn()
        try:
            cs_count = conn.execute("SELECT COUNT(*) FROM coordination_server").fetchone()[0]
            sr_count = conn.execute("SELECT COUNT(*) FROM subnet_router").fetchone()[0]
            remote_count = conn.execute("SELECT COUNT(*) FROM remote").fetchone()[0]

            try:
                exit_count = conn.execute("SELECT COUNT(*) FROM exit_node").fetchone()[0]
            except:
                exit_count = 0

            # Get CS info
            cs = conn.execute("""
                SELECT hostname, endpoint, vpn_ip FROM coordination_server LIMIT 1
            """).fetchone()

            result = {
                "coordination_servers": cs_count,
                "subnet_routers": sr_count,
                "remotes": remote_count,
                "exit_nodes": exit_count,
                "total_peers": sr_count + remote_count + exit_count,
                "cs_info": dict(cs) if cs else None,
            }

            self._cache['network_summary'] = result
            self._cache_time['network_summary'] = time.time()
            return result
        finally:
            conn.close()

    def get_all_peers(self) -> List[Dict]:
        """Get all peers."""
        if self._is_cache_valid('all_peers'):
            return self._cache['all_peers']

        conn = self._get_conn()
        try:
            peers = []

            # Routers
            rows = conn.execute("""
                SELECT id, hostname, vpn_ip, endpoint, created_at
                FROM subnet_router ORDER BY hostname
            """).fetchall()
            for row in rows:
                peers.append({
                    "id": row['id'],
                    "type": "router",
                    "hostname": row['hostname'],
                    "vpn_ip": row['vpn_ip'],
                    "endpoint": row['endpoint'],
                })

            # Remotes
            rows = conn.execute("""
                SELECT id, hostname, vpn_ip, access_level, sponsor_type, created_at, exit_node_id
                FROM remote ORDER BY hostname
            """).fetchall()
            for row in rows:
                peers.append({
                    "id": row['id'],
                    "type": "remote",
                    "hostname": row['hostname'],
                    "vpn_ip": row['vpn_ip'],
                    "access_level": row['access_level'],
                    "has_exit": bool(row['exit_node_id']),
                })

            # Exit nodes
            try:
                rows = conn.execute("""
                    SELECT id, hostname, ipv4_address as vpn_ip, endpoint
                    FROM exit_node ORDER BY hostname
                """).fetchall()
                for row in rows:
                    peers.append({
                        "id": row['id'],
                        "type": "exit_node",
                        "hostname": row['hostname'],
                        "vpn_ip": row['vpn_ip'],
                        "endpoint": row['endpoint'],
                    })
            except:
                pass

            self._cache['all_peers'] = peers
            self._cache_time['all_peers'] = time.time()
            return peers
        finally:
            conn.close()

    def get_alerts(self) -> List[Dict]:
        """Get active alerts."""
        conn = self._get_conn()
        try:
            try:
                rows = conn.execute("""
                    SELECT id, severity, title, message, created_at
                    FROM tui_alert
                    WHERE dismissed = 0
                    ORDER BY
                        CASE severity
                            WHEN 'critical' THEN 1
                            WHEN 'warning' THEN 2
                            ELSE 3
                        END,
                        created_at DESC
                    LIMIT 10
                """).fetchall()
                return [dict(row) for row in rows]
            except:
                return []
        finally:
            conn.close()

    def get_topology(self) -> Dict:
        """Get network topology for visualization."""
        conn = self._get_conn()
        try:
            nodes = []
            edges = []

            # CS node
            cs = conn.execute("""
                SELECT id, hostname, vpn_ip FROM coordination_server LIMIT 1
            """).fetchone()
            if cs:
                nodes.append({
                    "id": "cs",
                    "label": cs['hostname'],
                    "ip": cs['vpn_ip'],
                    "type": "cs",
                    "color": "#4299e1",
                })

            # Router nodes
            routers = conn.execute("""
                SELECT id, hostname, vpn_ip FROM subnet_router ORDER BY hostname
            """).fetchall()
            for r in routers:
                nodes.append({
                    "id": f"sr_{r['id']}",
                    "label": r['hostname'],
                    "ip": r['vpn_ip'],
                    "type": "router",
                    "color": "#48bb78",
                })
                edges.append({"from": "cs", "to": f"sr_{r['id']}"})

                # Remotes under this router
                remotes = conn.execute("""
                    SELECT id, hostname, vpn_ip FROM remote
                    WHERE sponsor_type = 'sr' AND sponsor_id = ?
                """, (r['id'],)).fetchall()
                for rm in remotes:
                    nodes.append({
                        "id": f"rm_{rm['id']}",
                        "label": rm['hostname'],
                        "ip": rm['vpn_ip'],
                        "type": "remote",
                        "color": "#ecc94b",
                    })
                    edges.append({"from": f"sr_{r['id']}", "to": f"rm_{rm['id']}"})

            # Remotes directly under CS
            cs_remotes = conn.execute("""
                SELECT id, hostname, vpn_ip FROM remote
                WHERE sponsor_type = 'cs'
            """).fetchall()
            for rm in cs_remotes:
                nodes.append({
                    "id": f"rm_{rm['id']}",
                    "label": rm['hostname'],
                    "ip": rm['vpn_ip'],
                    "type": "remote",
                    "color": "#ecc94b",
                })
                edges.append({"from": "cs", "to": f"rm_{rm['id']}"})

            return {"nodes": nodes, "edges": edges}
        finally:
            conn.close()

    def get_recent_activity(self) -> List[Dict]:
        """Get recent activity from audit log."""
        conn = self._get_conn()
        try:
            try:
                rows = conn.execute("""
                    SELECT event_type, entity_type, entity_id, details, timestamp
                    FROM audit_event
                    ORDER BY timestamp DESC
                    LIMIT 10
                """).fetchall()
                return [dict(row) for row in rows]
            except:
                return []
        finally:
            conn.close()


# HTML template for the dashboard
DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WireGuard Friend Dashboard</title>
    <style>
        :root {
            --bg-primary: #1a202c;
            --bg-secondary: #2d3748;
            --bg-tertiary: #4a5568;
            --text-primary: #f7fafc;
            --text-secondary: #a0aec0;
            --accent-blue: #4299e1;
            --accent-green: #48bb78;
            --accent-yellow: #ecc94b;
            --accent-red: #fc8181;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 1rem;
        }

        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 1rem 0;
            border-bottom: 1px solid var(--bg-tertiary);
            margin-bottom: 1.5rem;
        }

        header h1 {
            font-size: 1.5rem;
            color: var(--accent-blue);
        }

        .status-badge {
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .status-dot {
            width: 10px;
            height: 10px;
            border-radius: 50%;
            background: var(--accent-green);
        }

        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 1rem;
        }

        .card {
            background: var(--bg-secondary);
            border-radius: 8px;
            padding: 1.25rem;
            border: 1px solid var(--bg-tertiary);
        }

        .card h2 {
            font-size: 0.875rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-secondary);
            margin-bottom: 1rem;
        }

        .stat-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 1rem;
        }

        .stat {
            text-align: center;
        }

        .stat-value {
            font-size: 2rem;
            font-weight: bold;
            color: var(--accent-blue);
        }

        .stat-label {
            font-size: 0.75rem;
            color: var(--text-secondary);
        }

        .peer-list {
            max-height: 400px;
            overflow-y: auto;
        }

        .peer-item {
            display: flex;
            align-items: center;
            padding: 0.75rem;
            border-bottom: 1px solid var(--bg-tertiary);
            gap: 1rem;
        }

        .peer-item:last-child { border-bottom: none; }

        .peer-icon {
            width: 32px;
            height: 32px;
            border-radius: 4px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: bold;
            font-size: 0.75rem;
        }

        .peer-icon.router { background: var(--accent-green); color: #000; }
        .peer-icon.remote { background: var(--accent-yellow); color: #000; }
        .peer-icon.exit { background: var(--accent-blue); color: #fff; }

        .peer-info { flex: 1; }
        .peer-name { font-weight: 500; }
        .peer-ip { font-size: 0.875rem; color: var(--text-secondary); font-family: monospace; }

        .alert-item {
            padding: 0.75rem;
            border-radius: 4px;
            margin-bottom: 0.5rem;
            border-left: 3px solid;
        }

        .alert-item.critical { background: rgba(252, 129, 129, 0.1); border-color: var(--accent-red); }
        .alert-item.warning { background: rgba(236, 201, 75, 0.1); border-color: var(--accent-yellow); }
        .alert-item.info { background: rgba(66, 153, 225, 0.1); border-color: var(--accent-blue); }

        .alert-title { font-weight: 500; }
        .alert-message { font-size: 0.875rem; color: var(--text-secondary); }

        #topology {
            height: 300px;
            background: var(--bg-primary);
            border-radius: 4px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: var(--text-secondary);
        }

        .topology-node {
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            padding: 0.5rem 1rem;
            background: var(--bg-tertiary);
            border-radius: 4px;
            margin: 0.25rem;
        }

        .last-update {
            font-size: 0.75rem;
            color: var(--text-secondary);
            text-align: right;
            margin-top: 1rem;
        }

        @media (max-width: 768px) {
            .grid { grid-template-columns: 1fr; }
            .stat-grid { grid-template-columns: 1fr; }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>WireGuard Friend</h1>
            <div class="status-badge">
                <span class="status-dot"></span>
                <span>Connected</span>
            </div>
        </header>

        <div class="grid">
            <!-- Network Summary -->
            <div class="card">
                <h2>Network Overview</h2>
                <div class="stat-grid" id="network-stats">
                    <div class="stat">
                        <div class="stat-value" id="total-peers">-</div>
                        <div class="stat-label">Total Peers</div>
                    </div>
                    <div class="stat">
                        <div class="stat-value" id="routers">-</div>
                        <div class="stat-label">Routers</div>
                    </div>
                    <div class="stat">
                        <div class="stat-value" id="remotes">-</div>
                        <div class="stat-label">Remotes</div>
                    </div>
                    <div class="stat">
                        <div class="stat-value" id="exits">-</div>
                        <div class="stat-label">Exit Nodes</div>
                    </div>
                </div>
            </div>

            <!-- Alerts -->
            <div class="card">
                <h2>Active Alerts</h2>
                <div id="alerts">
                    <div style="color: var(--accent-green);">All clear</div>
                </div>
            </div>

            <!-- Peers -->
            <div class="card" style="grid-column: span 2;">
                <h2>Peers</h2>
                <div class="peer-list" id="peer-list">
                    Loading...
                </div>
            </div>

            <!-- Topology -->
            <div class="card" style="grid-column: span 2;">
                <h2>Network Topology</h2>
                <div id="topology">
                    Loading topology...
                </div>
            </div>
        </div>

        <div class="last-update">
            Last updated: <span id="last-update">-</span>
        </div>
    </div>

    <script>
        const API_BASE = '';

        async function fetchData(endpoint) {
            const resp = await fetch(API_BASE + endpoint);
            return resp.json();
        }

        function updateDashboard() {
            // Update network summary
            fetchData('/api/summary').then(data => {
                document.getElementById('total-peers').textContent = data.total_peers || 0;
                document.getElementById('routers').textContent = data.subnet_routers || 0;
                document.getElementById('remotes').textContent = data.remotes || 0;
                document.getElementById('exits').textContent = data.exit_nodes || 0;
            });

            // Update peers
            fetchData('/api/peers').then(data => {
                const list = document.getElementById('peer-list');
                if (!data.length) {
                    list.innerHTML = '<div style="color: var(--text-secondary);">No peers found</div>';
                    return;
                }
                list.innerHTML = data.map(peer => `
                    <div class="peer-item">
                        <div class="peer-icon ${peer.type}">${peer.type[0].toUpperCase()}</div>
                        <div class="peer-info">
                            <div class="peer-name">${peer.hostname}</div>
                            <div class="peer-ip">${peer.vpn_ip || '-'}</div>
                        </div>
                    </div>
                `).join('');
            });

            // Update alerts
            fetchData('/api/alerts').then(data => {
                const container = document.getElementById('alerts');
                if (!data.length) {
                    container.innerHTML = '<div style="color: var(--accent-green);">All clear</div>';
                    return;
                }
                container.innerHTML = data.map(alert => `
                    <div class="alert-item ${alert.severity}">
                        <div class="alert-title">${alert.title}</div>
                        <div class="alert-message">${alert.message}</div>
                    </div>
                `).join('');
            });

            // Update topology
            fetchData('/api/topology').then(data => {
                const container = document.getElementById('topology');
                const nodes = data.nodes || [];
                if (!nodes.length) {
                    container.innerHTML = '<div>No topology data</div>';
                    return;
                }
                container.innerHTML = nodes.map(node => `
                    <div class="topology-node" style="background: ${node.color}">
                        <strong>${node.label}</strong>
                        <span>${node.ip || ''}</span>
                    </div>
                `).join('');
            });

            document.getElementById('last-update').textContent = new Date().toLocaleTimeString();
        }

        // Initial load and refresh
        updateDashboard();
        setInterval(updateDashboard, 30000);
    </script>
</body>
</html>
"""


class DashboardRequestHandler(BaseHTTPRequestHandler):
    """HTTP request handler for dashboard."""

    data: DashboardData = None
    config: DashboardConfig = None

    def log_message(self, format, *args):
        pass  # Suppress logging

    def _send_json(self, data):
        body = json.dumps(data).encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', len(body))
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, html):
        body = html.encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', len(body))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        try:
            if path == '/' or path == '/index.html':
                self._send_html(DASHBOARD_HTML)

            elif path == '/api/summary':
                self._send_json(self.data.get_network_summary())

            elif path == '/api/peers':
                self._send_json(self.data.get_all_peers())

            elif path == '/api/alerts':
                self._send_json(self.data.get_alerts())

            elif path == '/api/topology':
                self._send_json(self.data.get_topology())

            elif path == '/api/activity':
                self._send_json(self.data.get_recent_activity())

            else:
                self.send_response(404)
                self.end_headers()

        except Exception as e:
            self.send_response(500)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"error": str(e)}).encode())


def run_dashboard_server(config: DashboardConfig) -> None:
    """Run the dashboard server."""
    data = DashboardData(config.db_path)

    handler = type('Handler', (DashboardRequestHandler,), {
        'data': data,
        'config': config
    })

    server = HTTPServer((config.host, config.port), handler)

    print(f"WireGuard Friend Dashboard starting...")
    print(f"  URL: http://{config.host}:{config.port}")
    print(f"  Database: {config.db_path}")
    print(f"  Refresh: {config.refresh_interval}s")
    print()
    print("Press Ctrl+C to stop")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
        server.shutdown()


def main():
    """CLI entry point for dashboard."""
    import argparse

    parser = argparse.ArgumentParser(description='WireGuard Friend Web Dashboard')
    parser.add_argument('--host', default='127.0.0.1', help='Host to bind to')
    parser.add_argument('--port', type=int, default=8080, help='Port to listen on')
    parser.add_argument('--db', default='wireguard.db', help='Database path')
    parser.add_argument('--refresh', type=int, default=30, help='Refresh interval (seconds)')

    args = parser.parse_args()

    config = DashboardConfig(
        host=args.host,
        port=args.port,
        db_path=args.db,
        refresh_interval=args.refresh,
    )

    run_dashboard_server(config)


if __name__ == '__main__':
    main()
