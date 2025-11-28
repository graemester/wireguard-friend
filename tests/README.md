# WireGuard Friend - Test Suite

## Quick Test

Run the comprehensive test suite:

```bash
python3 tests/test-suite.py
```

## What It Tests

### 1. Database Schema & Integrity (3 tests)
- All required tables exist
- Foreign key constraints enforced
- UNIQUE constraints prevent duplicates

### 2. Coordination Server - Deep Validation (2 tests)
- Complete CRUD cycle
- PostUp/PostDown rule order preserved

### 3. Subnet Router - Multiple SNs, Config Fidelity (3 tests)
- Multiple subnet routers in same network
- Config reconstruction byte-for-byte
- Peer-specific rules labeled correctly

### 4. Peers - All Access Levels + Edge Cases (7 tests)
- `full_access` - VPN + all LANs with keepalive
- `vpn_only` - VPN network isolation
- `restricted_ip` (all ports) - One IP, all ports
- `restricted_ip` (single port) - SSH only
- `restricted_ip` (multiple ports) - SSH, HTTPS, Jellyfin
- `restricted_ip` (port range) - Port range 8000-8999
- Server-only peer (no client config)

### 5. IP Allocation Logic (2 tests)
- Find next available IPv4 address
- Find next available IPv6 address

### 6. Key Generation & Cryptography (3 tests)
- WireGuard keypair validity
- Public key derivation from private key
- Key uniqueness

### 7. Peer Order & CS Config Reconstruction (2 tests)
- Peer order preserved in CS config
- CS config includes all peers and SNs

### 8. Foreign Key CASCADE - Data Integrity (3 tests)
- Peer deletion removes IP restrictions
- Peer deletion removes firewall rules
- Peer order cleanup (manual - no FK CASCADE)

### 9. Real-World Scenarios (3 tests)
- Multiple restricted peers on same subnet router
- Firewall rule ordering (ACCEPT before DROP)
- Config export file permissions (600)

### 10. Edge Cases & Error Handling (4 tests)
- Empty string vs None for optional fields
- Large config handling (50+ peers)
- Special characters in peer names
- IPv6 address validation

## Test Output

```
================================================================================
WireGuard Friend - Ultra-Refined Test Suite
================================================================================

[1/10] Database Schema & Integrity
✓ Schema: All required tables exist
✓ Schema: Foreign keys enforced
✓ Schema: UNIQUE constraints work

[2/10] Coordination Server - Deep Validation
✓ CS: Complete CRUD cycle
✓ CS: PostUp/PostDown rule order preserved

... (32 tests across 10 categories)

================================================================================
Tests Run:    32
Tests Passed: 32 (100%)
Tests Failed: 0
================================================================================

✓ All tests passed! System is stable and reliable.
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
- `demo-remote-assistance.py` - Demonstrates remote assistance peer creation with instructions
- `test-maintain.py` - Tests database queries and entity listing
- `test-restricted-ip.py` - Tests restricted IP functionality with ports
- `migrate-*.py` - Database migration scripts

## Remote Assistance Feature

The `remote_assistance` access level creates peers with:
- Full network access (VPN + all LANs)
- Config exported as `RemoteAssist.conf`
- User-friendly setup instructions in `remote-assist.txt`
- Includes macOS and Windows installation guides
- Documents SSH (port 22), RDP (port 3389), and VNC (port 5900) access

To use:
1. In maintenance mode, select option [5] when creating a new peer
2. Config and instructions are exported to `output/` directory
3. Share both files with the user needing assistance

## Database Migrations

### Add Remote Assistance Access Level
```bash
python3 tests/migrate-add-remote-assistance.py
```

This migration updates the `peer` table CHECK constraint to allow the new `remote_assistance` access level. Required for existing databases before using this feature.
