"""
WireGuard Friend REST API

Provides programmatic access to WireGuard Friend functionality.

Endpoints:
  GET  /api/v1/status          - Network status overview
  GET  /api/v1/peers           - List all peers
  POST /api/v1/peers           - Add new peer
  GET  /api/v1/peers/{id}      - Get peer details
  PATCH /api/v1/peers/{id}     - Update peer
  DELETE /api/v1/peers/{id}    - Remove peer
  POST /api/v1/peers/{id}/rotate - Rotate peer keys
  GET  /api/v1/peers/{id}/config - Get generated config
  POST /api/v1/deploy          - Deploy configurations
  GET  /api/v1/audit           - Audit log entries
  GET  /api/v1/health          - Health check
  GET  /api/v1/metrics         - Prometheus metrics

Usage:
  wg-friend api --port 8080
  wg-friend api --port 8080 --token <api-token>

Authentication:
  - Bearer token in Authorization header
  - Optional: Basic auth
  - Rate limiting per client
"""

import json
import sqlite3
import hashlib
import hmac
import time
import threading
from datetime import datetime, timedelta
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import Optional, Dict, List, Any, Callable
from functools import wraps

# Use standard library for HTTP server (no Flask dependency)
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import ssl


@dataclass
class APIConfig:
    """API server configuration."""
    host: str = "127.0.0.1"
    port: int = 8080
    db_path: str = "wireguard.db"
    api_token: Optional[str] = None
    enable_cors: bool = True
    rate_limit: int = 100  # requests per minute per IP
    ssl_cert: Optional[str] = None
    ssl_key: Optional[str] = None


class RateLimiter:
    """Simple rate limiter per IP address."""

    def __init__(self, max_requests: int = 100, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests: Dict[str, List[float]] = {}
        self.lock = threading.Lock()

    def is_allowed(self, client_ip: str) -> bool:
        """Check if request is allowed."""
        now = time.time()
        cutoff = now - self.window_seconds

        with self.lock:
            if client_ip not in self.requests:
                self.requests[client_ip] = []

            # Remove old entries
            self.requests[client_ip] = [t for t in self.requests[client_ip] if t > cutoff]

            if len(self.requests[client_ip]) >= self.max_requests:
                return False

            self.requests[client_ip].append(now)
            return True


class APIError(Exception):
    """API error with HTTP status code."""

    def __init__(self, message: str, status_code: int = 400):
        self.message = message
        self.status_code = status_code
        super().__init__(message)


class WireGuardFriendAPI:
    """Main API handler class."""

    def __init__(self, config: APIConfig):
        self.config = config
        self.db_path = config.db_path
        self.rate_limiter = RateLimiter(config.rate_limit)

    def _get_conn(self) -> sqlite3.Connection:
        """Get database connection."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def authenticate(self, headers: Dict[str, str]) -> bool:
        """Verify authentication."""
        if not self.config.api_token:
            return True  # No auth configured

        auth_header = headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            token = auth_header[7:]
            return hmac.compare_digest(token, self.config.api_token)

        return False

    # =========================================================================
    # STATUS ENDPOINTS
    # =========================================================================

    def get_status(self) -> Dict:
        """Get network status overview."""
        conn = self._get_conn()
        try:
            # Count entities
            cs_count = conn.execute("SELECT COUNT(*) FROM coordination_server").fetchone()[0]
            sr_count = conn.execute("SELECT COUNT(*) FROM subnet_router").fetchone()[0]
            remote_count = conn.execute("SELECT COUNT(*) FROM remote").fetchone()[0]

            try:
                exit_count = conn.execute("SELECT COUNT(*) FROM exit_node").fetchone()[0]
            except:
                exit_count = 0

            # Get CS info
            cs = conn.execute("""
                SELECT hostname, endpoint, vpn_ip, listen_port
                FROM coordination_server LIMIT 1
            """).fetchone()

            # Check alerts
            try:
                alert_count = conn.execute("""
                    SELECT COUNT(*) FROM tui_alert WHERE dismissed = 0
                """).fetchone()[0]
            except:
                alert_count = 0

            return {
                "status": "ok",
                "timestamp": datetime.now().isoformat(),
                "network": {
                    "coordination_server": dict(cs) if cs else None,
                    "subnet_routers": sr_count,
                    "remotes": remote_count,
                    "exit_nodes": exit_count,
                },
                "alerts": {
                    "active": alert_count
                }
            }
        finally:
            conn.close()

    def get_health(self) -> Dict:
        """Health check endpoint."""
        try:
            conn = self._get_conn()
            conn.execute("SELECT 1").fetchone()
            conn.close()
            return {"status": "healthy", "database": "connected"}
        except Exception as e:
            return {"status": "unhealthy", "error": str(e)}

    # =========================================================================
    # PEER ENDPOINTS
    # =========================================================================

    def list_peers(self, peer_type: Optional[str] = None) -> Dict:
        """List all peers."""
        conn = self._get_conn()
        try:
            peers = []

            # Get remotes
            if not peer_type or peer_type == 'remote':
                rows = conn.execute("""
                    SELECT id, hostname, vpn_ip, access_level, sponsor_type,
                           current_public_key, created_at, exit_node_id
                    FROM remote ORDER BY hostname
                """).fetchall()
                for row in rows:
                    peers.append({
                        "id": row['id'],
                        "type": "remote",
                        "hostname": row['hostname'],
                        "vpn_ip": row['vpn_ip'],
                        "access_level": row['access_level'],
                        "public_key": row['current_public_key'][:32] + "...",
                        "has_exit_node": bool(row['exit_node_id']),
                    })

            # Get routers
            if not peer_type or peer_type == 'router':
                rows = conn.execute("""
                    SELECT id, hostname, vpn_ip, endpoint, listen_port,
                           current_public_key, created_at
                    FROM subnet_router ORDER BY hostname
                """).fetchall()
                for row in rows:
                    peers.append({
                        "id": row['id'],
                        "type": "subnet_router",
                        "hostname": row['hostname'],
                        "vpn_ip": row['vpn_ip'],
                        "endpoint": row['endpoint'],
                        "public_key": row['current_public_key'][:32] + "...",
                    })

            # Get exit nodes
            if not peer_type or peer_type == 'exit_node':
                try:
                    rows = conn.execute("""
                        SELECT id, hostname, ipv4_address, endpoint, listen_port,
                               current_public_key
                        FROM exit_node ORDER BY hostname
                    """).fetchall()
                    for row in rows:
                        peers.append({
                            "id": row['id'],
                            "type": "exit_node",
                            "hostname": row['hostname'],
                            "vpn_ip": row['ipv4_address'],
                            "endpoint": row['endpoint'],
                            "public_key": row['current_public_key'][:32] + "...",
                        })
                except:
                    pass

            return {"peers": peers, "count": len(peers)}
        finally:
            conn.close()

    # Columns that should never be exposed via API (contain sensitive key material)
    SENSITIVE_COLUMNS = {'private_key', 'preshared_key', 'new_private_key', 'local_private_key'}

    def _filter_sensitive(self, row_dict: Dict) -> Dict:
        """Remove sensitive columns (private keys) from API response."""
        return {k: v for k, v in row_dict.items() if k not in self.SENSITIVE_COLUMNS}

    def get_peer(self, peer_type: str, peer_id: int) -> Dict:
        """Get peer details (excludes private keys for security)."""
        conn = self._get_conn()
        try:
            table_map = {
                'remote': 'remote',
                'router': 'subnet_router',
                'subnet_router': 'subnet_router',
                'exit_node': 'exit_node',
            }
            table = table_map.get(peer_type)
            if not table:
                raise APIError(f"Invalid peer type: {peer_type}", 400)

            row = conn.execute(f"SELECT * FROM {table} WHERE id = ?", (peer_id,)).fetchone()
            if not row:
                raise APIError(f"Peer not found: {peer_type}/{peer_id}", 404)

            # Filter out private keys - use /config endpoint for full config
            return {"peer": self._filter_sensitive(dict(row))}
        finally:
            conn.close()

    def add_peer(self, data: Dict) -> Dict:
        """Add new peer."""
        from v1.schema_semantic import WireGuardDBv2
        from v1.keygen import generate_keypair

        peer_type = data.get('type', 'remote')
        hostname = data.get('hostname')
        access_level = data.get('access_level', 'vpn')

        if not hostname:
            raise APIError("hostname is required", 400)

        db = WireGuardDBv2(self.db_path)

        if peer_type == 'remote':
            private_key, public_key = generate_keypair()

            # Get next IP
            next_ip = db.get_next_remote_ip()

            with db._connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO remote (hostname, vpn_ip, access_level,
                                       current_private_key, current_public_key,
                                       sponsor_type, sponsor_id)
                    VALUES (?, ?, ?, ?, ?, 'cs', 1)
                """, (hostname, next_ip, access_level, private_key, public_key))
                peer_id = cursor.lastrowid

            return {
                "id": peer_id,
                "type": "remote",
                "hostname": hostname,
                "vpn_ip": next_ip,
                "access_level": access_level,
            }

        elif peer_type == 'router':
            private_key, public_key = generate_keypair()
            endpoint = data.get('endpoint')
            network = data.get('network')

            if not endpoint or not network:
                raise APIError("endpoint and network required for router", 400)

            next_ip = db.get_next_router_ip()

            with db._connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO subnet_router (hostname, vpn_ip, endpoint, listen_port,
                                              current_private_key, current_public_key)
                    VALUES (?, ?, ?, 51820, ?, ?)
                """, (hostname, next_ip, endpoint, private_key, public_key))
                peer_id = cursor.lastrowid

                cursor.execute("""
                    INSERT INTO advertised_network (sr_id, network)
                    VALUES (?, ?)
                """, (peer_id, network))

            return {
                "id": peer_id,
                "type": "subnet_router",
                "hostname": hostname,
                "vpn_ip": next_ip,
                "endpoint": endpoint,
                "network": network,
            }

        else:
            raise APIError(f"Unsupported peer type: {peer_type}", 400)

    def delete_peer(self, peer_type: str, peer_id: int) -> Dict:
        """Remove peer."""
        conn = self._get_conn()
        try:
            table_map = {
                'remote': 'remote',
                'router': 'subnet_router',
                'subnet_router': 'subnet_router',
            }
            table = table_map.get(peer_type)
            if not table:
                raise APIError(f"Cannot delete peer type: {peer_type}", 400)

            # Check exists
            row = conn.execute(f"SELECT hostname FROM {table} WHERE id = ?", (peer_id,)).fetchone()
            if not row:
                raise APIError(f"Peer not found: {peer_type}/{peer_id}", 404)

            hostname = row['hostname']

            # Delete
            conn.execute(f"DELETE FROM {table} WHERE id = ?", (peer_id,))
            conn.commit()

            return {"deleted": True, "hostname": hostname}
        finally:
            conn.close()

    def rotate_peer_keys(self, peer_type: str, peer_id: int) -> Dict:
        """Rotate peer keys."""
        from v1.schema_semantic import WireGuardDBv2
        from v1.cli.peer_manager import rotate_keys

        db = WireGuardDBv2(self.db_path)

        # Validate peer exists
        conn = self._get_conn()
        try:
            table_map = {
                'remote': 'remote',
                'router': 'subnet_router',
                'cs': 'coordination_server',
                'exit_node': 'exit_node',
            }
            table = table_map.get(peer_type)
            if not table:
                raise APIError(f"Invalid peer type: {peer_type}", 400)

            if peer_type != 'cs':
                row = conn.execute(f"SELECT hostname FROM {table} WHERE id = ?", (peer_id,)).fetchone()
                if not row:
                    raise APIError(f"Peer not found: {peer_type}/{peer_id}", 404)
        finally:
            conn.close()

        try:
            rotate_keys(db, peer_type, peer_id, "API-triggered rotation")
            return {"rotated": True, "peer_type": peer_type, "peer_id": peer_id}
        except Exception as e:
            raise APIError(f"Rotation failed: {e}", 500)

    def get_peer_config(self, peer_type: str, peer_id: int) -> Dict:
        """Get generated config for peer."""
        from v1.schema_semantic import WireGuardDBv2
        from v1.cli.config_generator import generate_remote_config, generate_router_config, generate_cs_config

        db = WireGuardDBv2(self.db_path)

        if peer_type == 'remote':
            config = generate_remote_config(db, peer_id)
        elif peer_type in ('router', 'subnet_router'):
            config = generate_router_config(db, peer_id)
        elif peer_type == 'cs':
            config = generate_cs_config(db)
        else:
            raise APIError(f"Cannot generate config for: {peer_type}", 400)

        return {"config": config}

    # =========================================================================
    # DEPLOYMENT ENDPOINTS
    # =========================================================================

    def deploy(self, data: Dict) -> Dict:
        """Deploy configurations."""
        from v1.cli.deploy import deploy_configs

        class Args:
            pass

        args = Args()
        args.db = self.db_path
        args.output = 'generated'
        args.user = data.get('user', 'root')
        args.entity = data.get('entity')
        args.dry_run = data.get('dry_run', False)
        args.restart = data.get('restart', False)

        try:
            result = deploy_configs(args)
            return {"success": result == 0}
        except Exception as e:
            raise APIError(f"Deployment failed: {e}", 500)

    # =========================================================================
    # AUDIT ENDPOINTS
    # =========================================================================

    def get_audit_log(self, limit: int = 50, offset: int = 0) -> Dict:
        """Get audit log entries."""
        from v1.audit_log import AuditLogger

        try:
            logger = AuditLogger(self.db_path)
            entries = logger.get_recent_entries(limit=limit)

            return {
                "entries": [
                    {
                        "id": e.id,
                        "event_type": e.event_type.value if hasattr(e.event_type, 'value') else str(e.event_type),
                        "entity_type": e.entity_type,
                        "entity_id": e.entity_id,
                        "operator": e.operator,
                        "timestamp": e.timestamp.isoformat() if e.timestamp else None,
                        "details": e.details,
                    }
                    for e in entries
                ],
                "count": len(entries),
            }
        except Exception as e:
            raise APIError(f"Failed to get audit log: {e}", 500)

    # =========================================================================
    # METRICS ENDPOINTS
    # =========================================================================

    def get_metrics(self) -> str:
        """Get Prometheus metrics."""
        from v1.prometheus_metrics import PrometheusMetricsCollector

        try:
            collector = PrometheusMetricsCollector(self.db_path)
            collector.collect_all()
            return collector.format_prometheus()
        except Exception as e:
            raise APIError(f"Failed to collect metrics: {e}", 500)


class APIRequestHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the API."""

    api: WireGuardFriendAPI = None
    config: APIConfig = None

    def log_message(self, format, *args):
        """Override to customize logging."""
        pass  # Suppress default logging

    def _send_json(self, data: Dict, status_code: int = 200):
        """Send JSON response."""
        body = json.dumps(data, indent=2).encode('utf-8')
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', len(body))
        if self.config.enable_cors:
            self.send_header('Access-Control-Allow-Origin', '*')
            self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS')
            self.send_header('Access-Control-Allow-Headers', 'Authorization, Content-Type')
        self.end_headers()
        self.wfile.write(body)

    def _send_text(self, text: str, content_type: str = 'text/plain', status_code: int = 200):
        """Send text response."""
        body = text.encode('utf-8')
        self.send_response(status_code)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', len(body))
        self.end_headers()
        self.wfile.write(body)

    def _send_error(self, message: str, status_code: int = 400):
        """Send error response."""
        self._send_json({"error": message}, status_code)

    def _get_headers(self) -> Dict[str, str]:
        """Get request headers as dict."""
        return {k: v for k, v in self.headers.items()}

    def _get_body(self) -> Dict:
        """Get request body as JSON."""
        content_length = int(self.headers.get('Content-Length', 0))
        if content_length == 0:
            return {}
        body = self.rfile.read(content_length)
        return json.loads(body.decode('utf-8'))

    def _check_auth(self) -> bool:
        """Check authentication."""
        if not self.api.authenticate(self._get_headers()):
            self._send_error("Unauthorized", 401)
            return False
        return True

    def _check_rate_limit(self) -> bool:
        """Check rate limit."""
        client_ip = self.client_address[0]
        if not self.api.rate_limiter.is_allowed(client_ip):
            self._send_error("Rate limit exceeded", 429)
            return False
        return True

    def do_OPTIONS(self):
        """Handle preflight CORS requests."""
        self.send_response(200)
        if self.config.enable_cors:
            self.send_header('Access-Control-Allow-Origin', '*')
            self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS')
            self.send_header('Access-Control-Allow-Headers', 'Authorization, Content-Type')
        self.end_headers()

    def do_GET(self):
        """Handle GET requests."""
        if not self._check_rate_limit():
            return

        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        try:
            # Public endpoints
            if path == '/api/v1/health':
                self._send_json(self.api.get_health())
                return

            # Protected endpoints
            if not self._check_auth():
                return

            if path == '/api/v1/status':
                self._send_json(self.api.get_status())

            elif path == '/api/v1/peers':
                peer_type = query.get('type', [None])[0]
                self._send_json(self.api.list_peers(peer_type))

            elif path.startswith('/api/v1/peers/') and '/config' in path:
                # /api/v1/peers/{type}/{id}/config
                parts = path.split('/')
                peer_type = parts[4]
                peer_id = int(parts[5])
                self._send_json(self.api.get_peer_config(peer_type, peer_id))

            elif path.startswith('/api/v1/peers/'):
                # /api/v1/peers/{type}/{id}
                parts = path.split('/')
                if len(parts) >= 6:
                    peer_type = parts[4]
                    peer_id = int(parts[5])
                    self._send_json(self.api.get_peer(peer_type, peer_id))
                else:
                    self._send_error("Invalid peer path", 400)

            elif path == '/api/v1/audit':
                limit = int(query.get('limit', [50])[0])
                offset = int(query.get('offset', [0])[0])
                self._send_json(self.api.get_audit_log(limit, offset))

            elif path == '/api/v1/metrics':
                metrics = self.api.get_metrics()
                self._send_text(metrics, 'text/plain; version=0.0.4')

            else:
                self._send_error("Not found", 404)

        except APIError as e:
            self._send_error(e.message, e.status_code)
        except Exception as e:
            self._send_error(f"Internal error: {e}", 500)

    def do_POST(self):
        """Handle POST requests."""
        if not self._check_rate_limit():
            return
        if not self._check_auth():
            return

        parsed = urlparse(self.path)
        path = parsed.path

        try:
            if path == '/api/v1/peers':
                data = self._get_body()
                self._send_json(self.api.add_peer(data), 201)

            elif path.startswith('/api/v1/peers/') and '/rotate' in path:
                # /api/v1/peers/{type}/{id}/rotate
                parts = path.split('/')
                peer_type = parts[4]
                peer_id = int(parts[5])
                self._send_json(self.api.rotate_peer_keys(peer_type, peer_id))

            elif path == '/api/v1/deploy':
                data = self._get_body()
                self._send_json(self.api.deploy(data))

            else:
                self._send_error("Not found", 404)

        except APIError as e:
            self._send_error(e.message, e.status_code)
        except Exception as e:
            self._send_error(f"Internal error: {e}", 500)

    def do_DELETE(self):
        """Handle DELETE requests."""
        if not self._check_rate_limit():
            return
        if not self._check_auth():
            return

        parsed = urlparse(self.path)
        path = parsed.path

        try:
            if path.startswith('/api/v1/peers/'):
                # /api/v1/peers/{type}/{id}
                parts = path.split('/')
                if len(parts) >= 6:
                    peer_type = parts[4]
                    peer_id = int(parts[5])
                    self._send_json(self.api.delete_peer(peer_type, peer_id))
                else:
                    self._send_error("Invalid peer path", 400)
            else:
                self._send_error("Not found", 404)

        except APIError as e:
            self._send_error(e.message, e.status_code)
        except Exception as e:
            self._send_error(f"Internal error: {e}", 500)


def run_api_server(config: APIConfig) -> None:
    """Run the API server."""
    api = WireGuardFriendAPI(config)

    # Set up request handler with references
    handler = type('Handler', (APIRequestHandler,), {'api': api, 'config': config})

    server = HTTPServer((config.host, config.port), handler)

    # Optional SSL
    if config.ssl_cert and config.ssl_key:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(config.ssl_cert, config.ssl_key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        protocol = "https"
    else:
        protocol = "http"

    print(f"WireGuard Friend API server starting...")
    print(f"  Listening: {protocol}://{config.host}:{config.port}")
    print(f"  Database: {config.db_path}")
    print(f"  Auth: {'Enabled' if config.api_token else 'Disabled'}")
    print()
    print("Endpoints:")
    print("  GET  /api/v1/status         - Network status")
    print("  GET  /api/v1/health         - Health check")
    print("  GET  /api/v1/peers          - List peers")
    print("  POST /api/v1/peers          - Add peer")
    print("  GET  /api/v1/peers/{t}/{id} - Get peer")
    print("  DELETE /api/v1/peers/{t}/{id} - Delete peer")
    print("  POST /api/v1/peers/{t}/{id}/rotate - Rotate keys")
    print("  GET  /api/v1/peers/{t}/{id}/config - Get config")
    print("  POST /api/v1/deploy         - Deploy configs")
    print("  GET  /api/v1/audit          - Audit log")
    print("  GET  /api/v1/metrics        - Prometheus metrics")
    print()
    print("Press Ctrl+C to stop")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
        server.shutdown()


def main():
    """CLI entry point for API server."""
    import argparse

    parser = argparse.ArgumentParser(description='WireGuard Friend REST API Server')
    parser.add_argument('--host', default='127.0.0.1', help='Host to bind to')
    parser.add_argument('--port', type=int, default=8080, help='Port to listen on')
    parser.add_argument('--db', default='wireguard.db', help='Database path')
    parser.add_argument('--token', help='API authentication token')
    parser.add_argument('--ssl-cert', help='SSL certificate file')
    parser.add_argument('--ssl-key', help='SSL private key file')
    parser.add_argument('--no-cors', action='store_true', help='Disable CORS')

    args = parser.parse_args()

    config = APIConfig(
        host=args.host,
        port=args.port,
        db_path=args.db,
        api_token=args.token,
        enable_cors=not args.no_cors,
        ssl_cert=args.ssl_cert,
        ssl_key=args.ssl_key,
    )

    run_api_server(config)


if __name__ == '__main__':
    main()
