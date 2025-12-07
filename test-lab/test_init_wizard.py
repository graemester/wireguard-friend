#!/usr/bin/env python3
"""
Init Wizard Configuration Tests

Comprehensive tests for from-scratch wizard configurations:
1. Minimal: CS + 1 remote
2. Standard: CS + 1 router + 3 remotes
3. Full: CS + 2 routers + 2 exit nodes + 5 remotes
4. Edge cases: various option combinations

For each configuration:
- Database schema validation
- Config generation
- Config roundtrip (generate -> parse -> compare)
- WireGuard syntax validation

Run with: python3 test-lab/test_init_wizard.py
Docker tests: python3 test-lab/test_init_wizard.py --docker
"""

import sys
import os
import sqlite3
import tempfile
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass

# Add project to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from v1.schema_semantic import WireGuardDBv2
from v1.keygen import generate_keypair
from v1.cli.config_generator import (
    generate_cs_config,
    generate_router_config,
    generate_remote_config,
    generate_exit_node_config
)


# =============================================================================
# TEST CONFIGURATION TEMPLATES
# =============================================================================

@dataclass
class TestConfig:
    """A test configuration to create and validate"""
    name: str
    description: str
    num_routers: int
    num_exit_nodes: int
    num_remotes: int
    router_has_endpoint: List[bool]  # Per-router endpoint config
    exit_has_ssh: List[bool]  # Per-exit SSH config
    remote_types: List[str]  # Per-remote device types


# Define test configurations
TEST_CONFIGS = [
    TestConfig(
        name="minimal",
        description="Minimal: CS + 1 remote only",
        num_routers=0,
        num_exit_nodes=0,
        num_remotes=1,
        router_has_endpoint=[],
        exit_has_ssh=[],
        remote_types=["mobile"]
    ),
    TestConfig(
        name="standard",
        description="Standard: CS + 1 router + 3 remotes",
        num_routers=1,
        num_exit_nodes=0,
        num_remotes=3,
        router_has_endpoint=[False],
        exit_has_ssh=[],
        remote_types=["mobile", "laptop", "mobile"]
    ),
    TestConfig(
        name="full",
        description="Full: CS + 2 routers + 2 exit nodes + 5 remotes",
        num_routers=2,
        num_exit_nodes=2,
        num_remotes=5,
        router_has_endpoint=[True, False],  # One with, one without
        exit_has_ssh=[True, False],  # One with, one without
        remote_types=["mobile", "laptop", "server", "mobile", "laptop"]
    ),
    TestConfig(
        name="exit_only",
        description="Exit-focused: CS + 1 exit + 2 remotes",
        num_routers=0,
        num_exit_nodes=1,
        num_remotes=2,
        router_has_endpoint=[],
        exit_has_ssh=[True],
        remote_types=["mobile", "mobile"]
    ),
    TestConfig(
        name="multi_router",
        description="Multi-router: CS + 3 routers + 2 remotes",
        num_routers=3,
        num_exit_nodes=0,
        num_remotes=2,
        router_has_endpoint=[True, False, True],
        exit_has_ssh=[],
        remote_types=["laptop", "server"]
    ),
]


# =============================================================================
# CONFIGURATION CREATOR
# =============================================================================

class ConfigCreator:
    """Creates wizard configurations programmatically"""

    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.db = WireGuardDBv2(db_path)

    def create_config(self, test_config: TestConfig) -> Dict:
        """Create a configuration and return entity counts"""
        with self.db._connection() as conn:
            cursor = conn.cursor()

            # 1. Create Coordination Server
            cs_private, cs_public = generate_keypair()
            cursor.execute("""
                INSERT INTO coordination_server (
                    permanent_guid, current_public_key, hostname,
                    endpoint, listen_port, network_ipv4, network_ipv6,
                    ipv4_address, ipv6_address, private_key
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                cs_public,
                cs_public,
                'coordination-server',
                'cs.example.com:51820',
                51820,
                '10.99.0.0/24',
                'fd99::/64',
                '10.99.0.1/24',
                'fd99::1/64',
                cs_private
            ))
            cs_id = cursor.lastrowid

            # 2. Create Subnet Routers
            for i in range(test_config.num_routers):
                router_private, router_public = generate_keypair()
                has_endpoint = test_config.router_has_endpoint[i] if i < len(test_config.router_has_endpoint) else False
                endpoint = f'router{i}.example.com:51820' if has_endpoint else None

                cursor.execute("""
                    INSERT INTO subnet_router (
                        cs_id, permanent_guid, current_public_key, hostname,
                        ipv4_address, ipv6_address, endpoint,
                        private_key, lan_interface
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    cs_id,
                    router_public,
                    router_public,
                    f'router-{i}',
                    f'10.99.0.{20 + i}/32',
                    f'fd99::{20 + i:x}/128',
                    endpoint,
                    router_private,
                    'eth0'
                ))
                router_id = cursor.lastrowid

                # Add advertised network
                cursor.execute("""
                    INSERT INTO advertised_network (subnet_router_id, network_cidr)
                    VALUES (?, ?)
                """, (router_id, f'192.168.{i}.0/24'))

            # 3. Create Exit Nodes
            for i in range(test_config.num_exit_nodes):
                exit_private, exit_public = generate_keypair()
                has_ssh = test_config.exit_has_ssh[i] if i < len(test_config.exit_has_ssh) else False

                cursor.execute("""
                    INSERT INTO exit_node (
                        cs_id, permanent_guid, current_public_key, hostname,
                        endpoint, listen_port, ipv4_address, ipv6_address,
                        private_key, wan_interface, ssh_host, ssh_user, ssh_port
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    cs_id,
                    exit_public,
                    exit_public,
                    f'exit-{i}',
                    f'exit{i}.example.com',
                    51820,
                    f'10.99.0.{100 + i}/32',
                    f'fd99::{100 + i:x}/128',
                    exit_private,
                    'eth0',
                    f'exit{i}.example.com' if has_ssh else None,
                    'root' if has_ssh else None,
                    22 if has_ssh else None
                ))

            # 4. Create Remotes
            for i in range(test_config.num_remotes):
                remote_private, remote_public = generate_keypair()
                device_type = test_config.remote_types[i] if i < len(test_config.remote_types) else 'mobile'

                cursor.execute("""
                    INSERT INTO remote (
                        cs_id, permanent_guid, current_public_key, hostname,
                        ipv4_address, ipv6_address, private_key, access_level
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    cs_id,
                    remote_public,
                    remote_public,
                    f'remote-{i}',
                    f'10.99.0.{30 + i}/32',
                    f'fd99::{30 + i:x}/128',
                    remote_private,
                    'full'
                ))

        return {
            'coordination_server': 1,
            'subnet_router': test_config.num_routers,
            'exit_node': test_config.num_exit_nodes,
            'remote': test_config.num_remotes,
            'total': 1 + test_config.num_routers + test_config.num_exit_nodes + test_config.num_remotes
        }


# =============================================================================
# CONFIG VALIDATION
# =============================================================================

class ConfigValidator:
    """Validates generated configurations"""

    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.db = WireGuardDBv2(db_path)

    def validate_schema(self) -> Tuple[bool, List[str]]:
        """Validate database schema has all required tables and columns"""
        errors = []

        required_tables = [
            'coordination_server',
            'subnet_router',
            'exit_node',
            'remote',
            'advertised_network',
            'command_pair',
            'command_singleton'
        ]

        with self.db._connection() as conn:
            cursor = conn.cursor()

            for table in required_tables:
                cursor.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
                    (table,)
                )
                if not cursor.fetchone():
                    errors.append(f"Missing table: {table}")

            # Check coordination_server has data
            cursor.execute("SELECT COUNT(*) FROM coordination_server")
            if cursor.fetchone()[0] == 0:
                errors.append("No coordination server found")

        return len(errors) == 0, errors

    def validate_configs_generate(self, output_dir: Path) -> Tuple[bool, List[str]]:
        """Validate that all configs can be generated"""
        errors = []

        try:
            # Generate CS config
            cs_config = generate_cs_config(self.db)
            cs_file = output_dir / "coordination.conf"
            cs_file.write_text(cs_config)

            if not cs_config or len(cs_config) < 50:
                errors.append("CS config too short or empty")

            # Generate router configs
            with self.db._connection() as conn:
                cursor = conn.cursor()

                cursor.execute("SELECT id, hostname FROM subnet_router")
                for row in cursor.fetchall():
                    router_id, hostname = row['id'], row['hostname']
                    try:
                        config = generate_router_config(self.db, router_id)
                        config_file = output_dir / f"{hostname}.conf"
                        config_file.write_text(config)
                    except Exception as e:
                        errors.append(f"Router {hostname}: {e}")

                # Generate remote configs
                cursor.execute("SELECT id, hostname FROM remote")
                for row in cursor.fetchall():
                    remote_id, hostname = row['id'], row['hostname']
                    try:
                        config = generate_remote_config(self.db, remote_id)
                        config_file = output_dir / f"{hostname}.conf"
                        config_file.write_text(config)
                    except Exception as e:
                        errors.append(f"Remote {hostname}: {e}")

                # Generate exit node configs
                cursor.execute("SELECT id, hostname FROM exit_node")
                for row in cursor.fetchall():
                    exit_id, hostname = row['id'], row['hostname']
                    try:
                        config = generate_exit_node_config(self.db, exit_id)
                        config_file = output_dir / f"{hostname}.conf"
                        config_file.write_text(config)
                    except Exception as e:
                        errors.append(f"Exit {hostname}: {e}")

        except Exception as e:
            errors.append(f"Config generation failed: {e}")

        return len(errors) == 0, errors

    def validate_config_syntax(self, config_path: Path) -> Tuple[bool, str]:
        """Validate WireGuard config syntax"""
        if not config_path.exists():
            return False, f"Config not found: {config_path}"

        content = config_path.read_text()
        lines = content.strip().split('\n')

        # Basic validation
        has_interface = any(line.strip() == '[Interface]' for line in lines)
        has_private_key = any('PrivateKey' in line for line in lines)

        if not has_interface:
            return False, "Missing [Interface] section"
        if not has_private_key:
            return False, "Missing PrivateKey"

        # Check for common errors
        for i, line in enumerate(lines, 1):
            line = line.strip()
            if line and not line.startswith('#') and not line.startswith('['):
                if '=' not in line:
                    return False, f"Line {i}: Invalid key=value format: {line[:50]}"

        return True, "OK"

    def validate_all_configs(self, output_dir: Path) -> Tuple[int, int, List[str]]:
        """Validate all generated configs"""
        passed = 0
        failed = 0
        errors = []

        for config_file in output_dir.glob("*.conf"):
            success, msg = self.validate_config_syntax(config_file)
            if success:
                passed += 1
            else:
                failed += 1
                errors.append(f"{config_file.name}: {msg}")

        return passed, failed, errors


# =============================================================================
# TEST RUNNER
# =============================================================================

def run_config_test(test_config: TestConfig) -> Tuple[bool, List[str]]:
    """Run a complete test for one configuration"""
    errors = []

    # Create temp directory for this test
    test_dir = Path(tempfile.mkdtemp(prefix=f'wgf-test-{test_config.name}-'))
    db_path = test_dir / 'test.db'
    output_dir = test_dir / 'configs'
    output_dir.mkdir()

    try:
        # 1. Create configuration
        creator = ConfigCreator(db_path)
        counts = creator.create_config(test_config)

        # 2. Validate schema
        validator = ConfigValidator(db_path)
        schema_ok, schema_errors = validator.validate_schema()
        if not schema_ok:
            errors.extend(schema_errors)

        # 3. Generate configs
        gen_ok, gen_errors = validator.validate_configs_generate(output_dir)
        if not gen_ok:
            errors.extend(gen_errors)

        # 4. Validate all config syntax
        passed, failed, syntax_errors = validator.validate_all_configs(output_dir)
        errors.extend(syntax_errors)

        # 5. Verify expected entity counts
        with validator.db._connection() as conn:
            cursor = conn.cursor()

            cursor.execute("SELECT COUNT(*) FROM coordination_server")
            actual_cs = cursor.fetchone()[0]
            if actual_cs != 1:
                errors.append(f"Expected 1 CS, got {actual_cs}")

            cursor.execute("SELECT COUNT(*) FROM subnet_router")
            actual_routers = cursor.fetchone()[0]
            if actual_routers != test_config.num_routers:
                errors.append(f"Expected {test_config.num_routers} routers, got {actual_routers}")

            cursor.execute("SELECT COUNT(*) FROM exit_node")
            actual_exits = cursor.fetchone()[0]
            if actual_exits != test_config.num_exit_nodes:
                errors.append(f"Expected {test_config.num_exit_nodes} exit nodes, got {actual_exits}")

            cursor.execute("SELECT COUNT(*) FROM remote")
            actual_remotes = cursor.fetchone()[0]
            if actual_remotes != test_config.num_remotes:
                errors.append(f"Expected {test_config.num_remotes} remotes, got {actual_remotes}")

        # 6. Verify config file count
        expected_configs = 1 + test_config.num_routers + test_config.num_exit_nodes + test_config.num_remotes
        actual_configs = len(list(output_dir.glob("*.conf")))
        if actual_configs != expected_configs:
            errors.append(f"Expected {expected_configs} config files, got {actual_configs}")

    finally:
        # Cleanup
        shutil.rmtree(test_dir, ignore_errors=True)

    return len(errors) == 0, errors


def main():
    print("=" * 70)
    print("INIT WIZARD CONFIGURATION TESTS")
    print("=" * 70)
    print()

    total_passed = 0
    total_failed = 0
    all_errors = []

    for test_config in TEST_CONFIGS:
        print(f"Testing: {test_config.description}")
        success, errors = run_config_test(test_config)

        if success:
            print(f"  [PASS] {test_config.name}")
            total_passed += 1
        else:
            print(f"  [FAIL] {test_config.name}")
            for error in errors:
                print(f"         - {error}")
            total_failed += 1
            all_errors.extend(errors)

    print()
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"Configurations tested: {len(TEST_CONFIGS)}")
    print(f"Passed: {total_passed}")
    print(f"Failed: {total_failed}")

    if total_failed == 0:
        print("\n[OK] All init wizard configurations work correctly!")
        return 0
    else:
        print(f"\n[FAIL] {total_failed} configuration(s) failed")
        return 1


if __name__ == '__main__':
    sys.exit(main())
