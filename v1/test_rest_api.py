"""
Tests for WireGuard Friend REST API

Tests the API endpoints and functionality.
"""

import unittest
import json
import tempfile
import sqlite3
from pathlib import Path

from v1.rest_api import WireGuardFriendAPI, APIConfig, APIError


class TestRESTAPI(unittest.TestCase):
    """Test REST API functionality."""

    def setUp(self):
        """Set up test database."""
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = Path(self.temp_dir) / "test.db"

        # Create schema
        conn = sqlite3.connect(str(self.db_path))
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS coordination_server (
                id INTEGER PRIMARY KEY,
                hostname TEXT NOT NULL,
                endpoint TEXT,
                vpn_ip TEXT,
                listen_port INTEGER DEFAULT 51820,
                current_private_key TEXT,
                current_public_key TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS subnet_router (
                id INTEGER PRIMARY KEY,
                hostname TEXT NOT NULL,
                vpn_ip TEXT,
                endpoint TEXT,
                listen_port INTEGER DEFAULT 51820,
                current_private_key TEXT,
                current_public_key TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS remote (
                id INTEGER PRIMARY KEY,
                hostname TEXT NOT NULL,
                vpn_ip TEXT,
                access_level TEXT DEFAULT 'vpn',
                sponsor_type TEXT DEFAULT 'cs',
                sponsor_id INTEGER DEFAULT 1,
                current_private_key TEXT,
                current_public_key TEXT,
                exit_node_id INTEGER,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS advertised_network (
                id INTEGER PRIMARY KEY,
                sr_id INTEGER,
                network TEXT
            );

            CREATE TABLE IF NOT EXISTS tui_alert (
                id INTEGER PRIMARY KEY,
                severity TEXT,
                title TEXT,
                message TEXT,
                dismissed INTEGER DEFAULT 0
            );
        """)

        # Insert test data
        conn.execute("""
            INSERT INTO coordination_server (hostname, endpoint, vpn_ip, listen_port,
                                            current_private_key, current_public_key)
            VALUES ('test-cs', 'cs.example.com:51820', '10.0.0.1', 51820,
                    'cHJpdmF0ZS1rZXktY3M=', 'cHVibGljLWtleS1jcw==')
        """)

        conn.execute("""
            INSERT INTO subnet_router (hostname, vpn_ip, endpoint, listen_port,
                                       current_private_key, current_public_key)
            VALUES ('test-router', '10.0.0.2', 'router.example.com:51820', 51820,
                    'cHJpdmF0ZS1rZXktcm91dGVy', 'cHVibGljLWtleS1yb3V0ZXI=')
        """)

        conn.execute("""
            INSERT INTO remote (hostname, vpn_ip, access_level, sponsor_type, sponsor_id,
                               current_private_key, current_public_key)
            VALUES ('test-phone', '10.0.0.10', 'vpn', 'cs', 1,
                    'cHJpdmF0ZS1rZXktcGhvbmU=', 'cHVibGljLWtleS1waG9uZQ==')
        """)

        conn.commit()
        conn.close()

        # Create API instance
        config = APIConfig(db_path=str(self.db_path))
        self.api = WireGuardFriendAPI(config)

    def tearDown(self):
        """Clean up test files."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_get_health(self):
        """Test health check endpoint."""
        result = self.api.get_health()
        self.assertEqual(result['status'], 'healthy')
        self.assertEqual(result['database'], 'connected')

    def test_get_status(self):
        """Test status endpoint."""
        result = self.api.get_status()
        self.assertEqual(result['status'], 'ok')
        self.assertIn('network', result)
        self.assertEqual(result['network']['subnet_routers'], 1)
        self.assertEqual(result['network']['remotes'], 1)

    def test_list_peers(self):
        """Test peer listing."""
        result = self.api.list_peers()
        self.assertIn('peers', result)
        self.assertIn('count', result)
        self.assertGreaterEqual(result['count'], 2)  # router + remote

        # Filter by type
        remotes = self.api.list_peers(peer_type='remote')
        self.assertEqual(remotes['count'], 1)

    def test_get_peer(self):
        """Test getting a specific peer."""
        result = self.api.get_peer('remote', 1)
        self.assertIn('peer', result)
        self.assertEqual(result['peer']['hostname'], 'test-phone')

    def test_get_peer_not_found(self):
        """Test getting non-existent peer."""
        with self.assertRaises(APIError) as ctx:
            self.api.get_peer('remote', 999)
        self.assertEqual(ctx.exception.status_code, 404)

    def test_authentication_no_token(self):
        """Test authentication without token."""
        config = APIConfig(db_path=str(self.db_path), api_token=None)
        api = WireGuardFriendAPI(config)

        # No token required
        self.assertTrue(api.authenticate({}))

    def test_authentication_with_token(self):
        """Test authentication with token."""
        config = APIConfig(db_path=str(self.db_path), api_token='secret123')
        api = WireGuardFriendAPI(config)

        # Without auth header
        self.assertFalse(api.authenticate({}))

        # Wrong token
        self.assertFalse(api.authenticate({'Authorization': 'Bearer wrong'}))

        # Correct token
        self.assertTrue(api.authenticate({'Authorization': 'Bearer secret123'}))

    def test_rate_limiter(self):
        """Test rate limiting."""
        from v1.rest_api import RateLimiter

        limiter = RateLimiter(max_requests=3, window_seconds=60)

        # First 3 requests should pass
        self.assertTrue(limiter.is_allowed('127.0.0.1'))
        self.assertTrue(limiter.is_allowed('127.0.0.1'))
        self.assertTrue(limiter.is_allowed('127.0.0.1'))

        # Fourth should be blocked
        self.assertFalse(limiter.is_allowed('127.0.0.1'))

        # Different IP should pass
        self.assertTrue(limiter.is_allowed('192.168.1.1'))


class TestAPIConfig(unittest.TestCase):
    """Test API configuration."""

    def test_default_config(self):
        """Test default configuration values."""
        config = APIConfig()
        self.assertEqual(config.host, '127.0.0.1')
        self.assertEqual(config.port, 8080)
        self.assertEqual(config.db_path, 'wireguard.db')
        self.assertIsNone(config.api_token)
        self.assertTrue(config.enable_cors)
        self.assertEqual(config.rate_limit, 100)

    def test_custom_config(self):
        """Test custom configuration."""
        config = APIConfig(
            host='0.0.0.0',
            port=443,
            db_path='/var/lib/wireguard.db',
            api_token='mysecret',
            enable_cors=False,
            rate_limit=50
        )
        self.assertEqual(config.host, '0.0.0.0')
        self.assertEqual(config.port, 443)
        self.assertEqual(config.api_token, 'mysecret')
        self.assertFalse(config.enable_cors)


if __name__ == '__main__':
    unittest.main()
