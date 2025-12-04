"""
Exit Node Feature Tests

Comprehensive test coverage for exit node functionality:
1. Schema - exit_node table and remote.exit_node_id column
2. CRUD - Add, list, get, remove exit nodes
3. Assignment - Assign/clear exit nodes from remotes
4. Config Generation - Remote configs with exit node peers
5. Access Levels - exit_only access level behavior

Run with: python3 v1/test_exit_nodes.py
"""

import tempfile
from pathlib import Path

# Optional pytest support
try:
    import pytest
    PYTEST_AVAILABLE = True
except ImportError:
    PYTEST_AVAILABLE = False
    # Mock pytest.fixture for standalone execution
    class pytest:
        @staticmethod
        def fixture(func):
            return func
        @staticmethod
        def raises(exception, match=None):
            class RaisesContext:
                def __init__(self, exc, match):
                    self.exc = exc
                    self.match = match
                def __enter__(self):
                    return self
                def __exit__(self, exc_type, exc_val, exc_tb):
                    if exc_type is None:
                        raise AssertionError(f"Expected {self.exc.__name__} was not raised")
                    if not issubclass(exc_type, self.exc):
                        return False
                    if self.match and self.match not in str(exc_val):
                        raise AssertionError(f"Expected match '{self.match}' not in '{exc_val}'")
                    return True
            return RaisesContext(exception, match)

from v1.schema_semantic import WireGuardDBv2
from v1.exit_node_ops import ExitNodeOps
from v1.cli.config_generator import (
    generate_cs_config,
    generate_remote_config,
    generate_exit_node_config
)
from v1.keygen import generate_keypair


# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture
def temp_db():
    """Create a temporary database with test data"""
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
        db_path = Path(f.name)

    db = WireGuardDBv2(db_path)

    # Create coordination server
    with db._connection() as conn:
        cursor = conn.cursor()

        # Insert CS
        privkey, pubkey = generate_keypair()
        cursor.execute("""
            INSERT INTO coordination_server (
                permanent_guid, current_public_key, hostname,
                endpoint, listen_port, network_ipv4, network_ipv6,
                ipv4_address, ipv6_address, private_key
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            pubkey, pubkey, 'test-cs',
            'cs.example.com', 51820, '10.66.0.0/24', 'fd66::/64',
            '10.66.0.1/32', 'fd66::1/128', privkey
        ))

        # Insert a few test remotes
        for i, name in enumerate(['alice-laptop', 'bob-phone', 'carol-tablet'], start=30):
            privkey, pubkey = generate_keypair()
            cursor.execute("""
                INSERT INTO remote (
                    cs_id, permanent_guid, current_public_key, hostname,
                    ipv4_address, ipv6_address, private_key, access_level
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                1, pubkey, pubkey, name,
                f'10.66.0.{i}/32', f'fd66::{i:x}/128', privkey, 'full_access'
            ))

    yield db, db_path

    # Cleanup
    try:
        db_path.unlink()
    except:
        pass


# =============================================================================
# SCHEMA TESTS
# =============================================================================

class TestExitNodeSchema:
    """Test database schema for exit nodes"""

    def test_exit_node_table_exists(self, temp_db):
        """exit_node table should exist after schema init"""
        db, db_path = temp_db

        with db._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT name FROM sqlite_master
                WHERE type='table' AND name='exit_node'
            """)
            result = cursor.fetchone()

        assert result is not None, "exit_node table should exist"

    def test_exit_node_table_columns(self, temp_db):
        """exit_node table should have all required columns"""
        db, db_path = temp_db

        with db._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("PRAGMA table_info(exit_node)")
            columns = {row[1] for row in cursor.fetchall()}

        expected = {
            'id', 'cs_id', 'permanent_guid', 'current_public_key', 'hostname',
            'endpoint', 'listen_port', 'ipv4_address', 'ipv6_address',
            'private_key', 'wan_interface', 'ssh_host', 'ssh_user', 'ssh_port',
            'created_at', 'updated_at'
        }
        assert expected.issubset(columns), f"Missing columns: {expected - columns}"

    def test_remote_has_exit_node_id(self, temp_db):
        """remote table should have exit_node_id column"""
        db, db_path = temp_db

        with db._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("PRAGMA table_info(remote)")
            columns = {row[1] for row in cursor.fetchall()}

        assert 'exit_node_id' in columns, "remote table should have exit_node_id column"


# =============================================================================
# CRUD TESTS
# =============================================================================

class TestExitNodeCRUD:
    """Test CRUD operations for exit nodes"""

    def test_add_exit_node(self, temp_db):
        """Should add exit node successfully"""
        db, db_path = temp_db
        ops = ExitNodeOps(db)

        exit_id = ops.add_exit_node(
            hostname='exit-us-west',
            endpoint='us-west.example.com',
            ipv4_address='10.66.0.100/32',
            ipv6_address='fd66::64/128',
            listen_port=51820,
            wan_interface='eth0'
        )

        assert exit_id is not None
        assert exit_id > 0

    def test_list_exit_nodes(self, temp_db):
        """Should list all exit nodes"""
        db, db_path = temp_db
        ops = ExitNodeOps(db)

        # Add two exit nodes
        ops.add_exit_node(
            hostname='exit-us-west',
            endpoint='us-west.example.com',
            ipv4_address='10.66.0.100/32',
            ipv6_address='fd66::64/128'
        )
        ops.add_exit_node(
            hostname='exit-eu-central',
            endpoint='eu.example.com',
            ipv4_address='10.66.0.101/32',
            ipv6_address='fd66::65/128'
        )

        exit_nodes = ops.list_exit_nodes()

        assert len(exit_nodes) == 2
        hostnames = {e.hostname for e in exit_nodes}
        assert hostnames == {'exit-us-west', 'exit-eu-central'}

    def test_get_exit_node(self, temp_db):
        """Should get exit node by ID"""
        db, db_path = temp_db
        ops = ExitNodeOps(db)

        exit_id = ops.add_exit_node(
            hostname='exit-test',
            endpoint='test.example.com',
            ipv4_address='10.66.0.100/32',
            ipv6_address='fd66::64/128',
            listen_port=51821,
            wan_interface='ens18'
        )

        exit_node = ops.get_exit_node(exit_id)

        assert exit_node is not None
        assert exit_node.hostname == 'exit-test'
        assert exit_node.endpoint == 'test.example.com'
        assert exit_node.listen_port == 51821
        assert exit_node.wan_interface == 'ens18'

    def test_get_exit_node_by_hostname(self, temp_db):
        """Should get exit node by hostname"""
        db, db_path = temp_db
        ops = ExitNodeOps(db)

        ops.add_exit_node(
            hostname='exit-unique',
            endpoint='unique.example.com',
            ipv4_address='10.66.0.100/32',
            ipv6_address='fd66::64/128'
        )

        exit_node = ops.get_exit_node_by_hostname('exit-unique')

        assert exit_node is not None
        assert exit_node.hostname == 'exit-unique'

    def test_remove_exit_node(self, temp_db):
        """Should remove exit node"""
        db, db_path = temp_db
        ops = ExitNodeOps(db)

        exit_id = ops.add_exit_node(
            hostname='exit-to-remove',
            endpoint='remove.example.com',
            ipv4_address='10.66.0.100/32',
            ipv6_address='fd66::64/128'
        )

        hostname, affected = ops.remove_exit_node(exit_id)

        assert hostname == 'exit-to-remove'
        assert affected == 0
        assert ops.get_exit_node(exit_id) is None

    def test_remove_exit_node_clears_remotes(self, temp_db):
        """Removing exit node should clear exit_node_id from remotes"""
        db, db_path = temp_db
        ops = ExitNodeOps(db)

        exit_id = ops.add_exit_node(
            hostname='exit-to-remove',
            endpoint='remove.example.com',
            ipv4_address='10.66.0.100/32',
            ipv6_address='fd66::64/128'
        )

        # Assign to two remotes
        ops.assign_exit_to_remote(1, exit_id)  # alice-laptop
        ops.assign_exit_to_remote(2, exit_id)  # bob-phone

        hostname, affected = ops.remove_exit_node(exit_id)

        assert affected == 2

        # Verify remotes no longer have exit_node_id
        assert ops.get_exit_node_for_remote(1) is None
        assert ops.get_exit_node_for_remote(2) is None

    def test_duplicate_hostname_rejected(self, temp_db):
        """Should reject duplicate exit node hostname"""
        db, db_path = temp_db
        ops = ExitNodeOps(db)

        ops.add_exit_node(
            hostname='exit-unique',
            endpoint='first.example.com',
            ipv4_address='10.66.0.100/32',
            ipv6_address='fd66::64/128'
        )

        with pytest.raises(ValueError, match="already exists"):
            ops.add_exit_node(
                hostname='exit-unique',  # Same hostname
                endpoint='second.example.com',
                ipv4_address='10.66.0.101/32',
                ipv6_address='fd66::65/128'
            )


# =============================================================================
# ASSIGNMENT TESTS
# =============================================================================

class TestExitNodeAssignment:
    """Test exit node assignment to remotes"""

    def test_assign_exit_to_remote(self, temp_db):
        """Should assign exit node to remote"""
        db, db_path = temp_db
        ops = ExitNodeOps(db)

        exit_id = ops.add_exit_node(
            hostname='exit-test',
            endpoint='test.example.com',
            ipv4_address='10.66.0.100/32',
            ipv6_address='fd66::64/128'
        )

        result = ops.assign_exit_to_remote(1, exit_id)  # alice-laptop

        assert result is True
        assigned = ops.get_exit_node_for_remote(1)
        assert assigned is not None
        assert assigned.hostname == 'exit-test'

    def test_clear_exit_from_remote(self, temp_db):
        """Should clear exit node from remote"""
        db, db_path = temp_db
        ops = ExitNodeOps(db)

        exit_id = ops.add_exit_node(
            hostname='exit-test',
            endpoint='test.example.com',
            ipv4_address='10.66.0.100/32',
            ipv6_address='fd66::64/128'
        )

        ops.assign_exit_to_remote(1, exit_id)
        result = ops.clear_exit_from_remote(1)

        assert result is True
        assert ops.get_exit_node_for_remote(1) is None

    def test_clear_exit_only_remote_rejected(self, temp_db):
        """Should reject clearing exit from exit_only remote"""
        db, db_path = temp_db
        ops = ExitNodeOps(db)

        exit_id = ops.add_exit_node(
            hostname='exit-test',
            endpoint='test.example.com',
            ipv4_address='10.66.0.100/32',
            ipv6_address='fd66::64/128'
        )

        # Set remote to exit_only with exit node
        ops.set_remote_access_level(1, 'exit_only', exit_id)

        with pytest.raises(ValueError, match="exit_only"):
            ops.clear_exit_from_remote(1)

    def test_list_remotes_using_exit_node(self, temp_db):
        """Should list all remotes using an exit node"""
        db, db_path = temp_db
        ops = ExitNodeOps(db)

        exit_id = ops.add_exit_node(
            hostname='exit-test',
            endpoint='test.example.com',
            ipv4_address='10.66.0.100/32',
            ipv6_address='fd66::64/128'
        )

        ops.assign_exit_to_remote(1, exit_id)  # alice
        ops.assign_exit_to_remote(2, exit_id)  # bob

        remotes = ops.list_remotes_using_exit_node(exit_id)

        assert len(remotes) == 2
        hostnames = {r['hostname'] for r in remotes}
        assert hostnames == {'alice-laptop', 'bob-phone'}


# =============================================================================
# ACCESS LEVEL TESTS
# =============================================================================

class TestExitOnlyAccessLevel:
    """Test exit_only access level behavior"""

    def test_set_exit_only_requires_exit_node(self, temp_db):
        """exit_only access level requires an exit node"""
        db, db_path = temp_db
        ops = ExitNodeOps(db)

        with pytest.raises(ValueError, match="requires an exit_node_id"):
            ops.set_remote_access_level(1, 'exit_only', exit_node_id=None)

    def test_set_exit_only_with_exit_node(self, temp_db):
        """exit_only with exit node should succeed"""
        db, db_path = temp_db
        ops = ExitNodeOps(db)

        exit_id = ops.add_exit_node(
            hostname='exit-test',
            endpoint='test.example.com',
            ipv4_address='10.66.0.100/32',
            ipv6_address='fd66::64/128'
        )

        result = ops.set_remote_access_level(1, 'exit_only', exit_id)

        assert result is True

        # Verify in database
        with db._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT access_level, exit_node_id FROM remote WHERE id = 1")
            row = cursor.fetchone()

        assert row[0] == 'exit_only'
        assert row[1] == exit_id


# =============================================================================
# CONFIG GENERATION TESTS
# =============================================================================

class TestExitNodeConfigGeneration:
    """Test config generation with exit nodes"""

    def test_remote_config_without_exit_node(self, temp_db):
        """Remote config without exit node should be standard split tunnel"""
        db, db_path = temp_db

        config = generate_remote_config(db, 1)  # alice-laptop

        assert '[Interface]' in config
        assert '[Peer]' in config
        assert '# coordination-server' in config
        assert '0.0.0.0/0' not in config  # No default route

    def test_remote_config_with_exit_node(self, temp_db):
        """Remote config with exit node should include exit peer"""
        db, db_path = temp_db
        ops = ExitNodeOps(db)

        exit_id = ops.add_exit_node(
            hostname='exit-test',
            endpoint='exit.example.com',
            ipv4_address='10.66.0.100/32',
            ipv6_address='fd66::64/128'
        )

        ops.assign_exit_to_remote(1, exit_id)  # alice-laptop

        config = generate_remote_config(db, 1)

        # Should have both CS and exit node peers
        assert '# coordination-server' in config
        assert '# exit-node: exit-test' in config
        assert 'exit.example.com' in config
        assert '0.0.0.0/0, ::/0' in config  # Default route through exit

    def test_exit_only_remote_config(self, temp_db):
        """exit_only remote should only have exit peer, no CS"""
        db, db_path = temp_db
        ops = ExitNodeOps(db)

        exit_id = ops.add_exit_node(
            hostname='exit-test',
            endpoint='exit.example.com',
            ipv4_address='10.66.0.100/32',
            ipv6_address='fd66::64/128'
        )

        ops.set_remote_access_level(1, 'exit_only', exit_id)

        config = generate_remote_config(db, 1)

        # Should NOT have CS peer
        assert '# coordination-server' not in config

        # Should have exit peer with default route
        assert '# exit-node: exit-test' in config
        assert '0.0.0.0/0, ::/0' in config

    def test_exit_node_config_generation(self, temp_db):
        """Exit node config should have NAT rules and client peers"""
        db, db_path = temp_db
        ops = ExitNodeOps(db)

        exit_id = ops.add_exit_node(
            hostname='exit-test',
            endpoint='exit.example.com',
            ipv4_address='10.66.0.100/32',
            ipv6_address='fd66::64/128',
            wan_interface='ens18'
        )

        ops.assign_exit_to_remote(1, exit_id)  # alice-laptop
        ops.assign_exit_to_remote(2, exit_id)  # bob-phone

        config = generate_exit_node_config(db, exit_id)

        # Interface section
        assert '[Interface]' in config
        assert 'ListenPort = 51820' in config

        # NAT rules
        assert 'PostUp = sysctl -w net.ipv4.ip_forward=1' in config
        assert 'MASQUERADE' in config
        assert 'ens18' in config  # WAN interface

        # Client peers
        assert '# alice-laptop' in config
        assert '# bob-phone' in config

    def test_cs_config_includes_exit_nodes(self, temp_db):
        """CS config should include exit nodes as peers"""
        db, db_path = temp_db
        ops = ExitNodeOps(db)

        ops.add_exit_node(
            hostname='exit-us',
            endpoint='us.example.com',
            ipv4_address='10.66.0.100/32',
            ipv6_address='fd66::64/128'
        )

        config = generate_cs_config(db)

        assert '# exit-node: exit-us' in config
        assert 'us.example.com' in config


# =============================================================================
# IP ALLOCATION TESTS
# =============================================================================

class TestExitNodeIPAllocation:
    """Test automatic IP allocation for exit nodes"""

    def test_get_next_exit_node_ip(self, temp_db):
        """Should allocate IPs in 100-119 range"""
        db, db_path = temp_db
        ops = ExitNodeOps(db)

        ipv4, ipv6 = ops.get_next_exit_node_ip()

        assert ipv4 == '10.66.0.100/32'
        assert ipv6 == 'fd66::64/128'

    def test_ip_allocation_increments(self, temp_db):
        """Should increment IP for each exit node"""
        db, db_path = temp_db
        ops = ExitNodeOps(db)

        # Add first exit node
        ops.add_exit_node(
            hostname='exit-1',
            endpoint='1.example.com',
            ipv4_address='10.66.0.100/32',
            ipv6_address='fd66::64/128'
        )

        # Next IP should be .101
        ipv4, ipv6 = ops.get_next_exit_node_ip()
        assert ipv4 == '10.66.0.101/32'


# =============================================================================
# VALIDATION TESTS
# =============================================================================

class TestExitNodeValidation:
    """Test validation logic for exit nodes"""

    def test_validate_exit_only_with_exit_node(self, temp_db):
        """exit_only remote with exit node should be valid"""
        db, db_path = temp_db
        ops = ExitNodeOps(db)

        exit_id = ops.add_exit_node(
            hostname='exit-test',
            endpoint='test.example.com',
            ipv4_address='10.66.0.100/32',
            ipv6_address='fd66::64/128'
        )

        ops.set_remote_access_level(1, 'exit_only', exit_id)

        result = ops.validate_exit_only_remote(1)
        assert result is True

    def test_validate_exit_only_without_exit_node(self, temp_db):
        """exit_only remote without exit node should fail validation"""
        db, db_path = temp_db
        ops = ExitNodeOps(db)

        # Manually set access_level to exit_only without exit_node_id
        with db._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE remote SET access_level = 'exit_only', exit_node_id = NULL
                WHERE id = 1
            """)

        with pytest.raises(ValueError, match="must have an exit node"):
            ops.validate_exit_only_remote(1)


def create_temp_db():
    """Create a temporary database with test data (standalone version of fixture)"""
    db_path = Path(tempfile.mktemp(suffix='.db'))
    db = WireGuardDBv2(db_path)

    # Create coordination server
    with db._connection() as conn:
        cursor = conn.cursor()

        # Insert CS
        privkey, pubkey = generate_keypair()
        cursor.execute("""
            INSERT INTO coordination_server (
                permanent_guid, current_public_key, hostname,
                endpoint, listen_port, network_ipv4, network_ipv6,
                ipv4_address, ipv6_address, private_key
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            pubkey, pubkey, 'test-cs',
            'cs.example.com', 51820, '10.66.0.0/24', 'fd66::/64',
            '10.66.0.1/32', 'fd66::1/128', privkey
        ))

        # Insert a few test remotes
        for i, name in enumerate(['alice-laptop', 'bob-phone', 'carol-tablet'], start=30):
            privkey, pubkey = generate_keypair()
            cursor.execute("""
                INSERT INTO remote (
                    cs_id, permanent_guid, current_public_key, hostname,
                    ipv4_address, ipv6_address, private_key, access_level
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                1, pubkey, pubkey, name,
                f'10.66.0.{i}/32', f'fd66::{i:x}/128', privkey, 'full_access'
            ))

    return db, db_path


if __name__ == '__main__':
    if PYTEST_AVAILABLE:
        pytest.main([__file__, '-v'])
    else:
        # Run tests manually when pytest is not installed
        print("Running exit node tests (standalone mode)...")
        import traceback
        import inspect

        # Get all test classes
        test_classes = [
            TestExitNodeSchema,
            TestExitNodeCRUD,
            TestExitNodeAssignment,
            TestExitOnlyAccessLevel,
            TestExitNodeConfigGeneration,
            TestExitNodeIPAllocation,
            TestExitNodeValidation,
        ]

        passed = 0
        failed = 0

        for test_class in test_classes:
            print(f"\n{test_class.__name__}:")
            test_instance = test_class()

            for attr in dir(test_instance):
                if attr.startswith('test_'):
                    try:
                        # Create fresh db with test data for each test
                        db, db_path = create_temp_db()

                        # Check if the method needs temp_db argument
                        method = getattr(test_instance, attr)
                        sig = inspect.signature(method)
                        if 'temp_db' in sig.parameters:
                            # Fixture returns tuple of (db, db_path)
                            method((db, db_path))
                        else:
                            method()

                        print(f"  PASS: {attr}")
                        passed += 1

                        # Cleanup
                        if db_path.exists():
                            db_path.unlink()
                    except Exception as e:
                        print(f"  FAIL: {attr}")
                        traceback.print_exc()
                        failed += 1

        print(f"\n{'='*50}")
        print(f"Results: {passed} passed, {failed} failed")
        if failed == 0:
            print("All tests passed!")
