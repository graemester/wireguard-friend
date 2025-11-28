# WireGuard Friend - Test Suite

## Quick Test

Run the comprehensive test suite:

```bash
python3 tests/test-suite.py
```

## What It Tests

### 1. Database & Schema (2 tests)
- Table creation
- Foreign key constraints enabled

### 2. Coordination Server (2 tests)
- Save/retrieve operations
- PostUp/PostDown rule storage

### 3. Subnet Router (4 tests)
- Save/retrieve operations
- LAN network management
- Firewall rule storage
- Config reconstruction

### 4. Peers - All Access Levels (5 tests)
- `full_access` - VPN + all LANs
- `vpn_only` - VPN network only
- `restricted_ip` (all ports) - One IP, all ports
- `restricted_ip` (specific ports) - One IP, specific ports
- Peer order tracking

### 5. Config Reconstruction (3 tests)
- Coordination server config rebuilding
- Subnet router config with peer-specific rules
- Peer client config rebuilding

### 6. Foreign Key CASCADE (2 tests)
- Peer deletion removes IP restrictions
- Peer deletion removes firewall rules

### 7. Key Generation (2 tests)
- WireGuard keypair generation
- Key uniqueness

### 8. Edge Cases (2 tests)
- Empty port list handling
- Multiple LAN networks

## Test Output

```
======================================================================
WireGuard Friend - Comprehensive Test Suite
======================================================================

[1/8] Database & Schema Tests
✓ Database initialization
✓ Foreign keys enabled

[2/8] Coordination Server Tests
✓ CS: Save and retrieve
✓ CS: PostUp/PostDown rules

... (22 tests total)

======================================================================
Tests Run:    22
Tests Passed: 22 (100%)
Tests Failed: 0
======================================================================

✓ All tests passed!
```

## Test Database

The test suite creates a temporary SQLite database that is automatically cleaned up after tests complete. It does not affect your production `wg-friend.db`.

## Adding New Tests

Use the `@test("Test name")` decorator:

```python
@test("New feature test")
def test_new_feature(self):
    """Test description"""
    # Setup
    data = create_test_data()

    # Execute
    result = self.db.some_operation(data)

    # Assert
    assert result is not None
    assert result['field'] == expected_value
```

## Other Test Scripts

- `demo-new-peer.py` - Demonstrates programmatic peer creation
- `test-maintain.py` - Tests database queries and entity listing
- `test-restricted-ip.py` - Tests restricted IP functionality with ports
- `migrate-*.py` - Database migration scripts
