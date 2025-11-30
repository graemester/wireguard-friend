# Permanent GUID System

## The Problem

In v1, comments were associated with peers by **position** in the config file. This created a critical bug:
- If peer order changed, comments got mismatched
- 'alice-laptop' comment could end up associated with 'bob-phone' peer
- No way to track entities across key rotations

## The Solution: Triple-Purpose Public Key

The first public key ever seen for an entity serves **three purposes**:

### 1. Permanent GUID (Immutable Identifier)
```sql
permanent_guid TEXT NOT NULL UNIQUE
```
- Set to the first public key when entity is created
- **NEVER changes**, even when key is rotated
- Used to link comments and track entity across time
- Survives key rotations, config regenerations, etc.

### 2. Current Public Key (Active WireGuard Key)
```sql
current_public_key TEXT NOT NULL
```
- The active WireGuard cryptographic key
- **Changes** when key is rotated
- Used for actual WireGuard operations
- Stored in generated configs as `PublicKey = <current_public_key>`

### 3. Default Hostname
```sql
hostname TEXT NULL  -- defaults to permanent_guid
```
- If user doesn't provide a hostname comment, use permanent_guid
- Ensures every entity has a human-readable identifier
- No need to generate arbitrary names like "peer1", "peer2"
- The GUID itself serves as the name

## Database Schema

### Entity Tables
All three entity types (coordination_server, subnet_router, remote) have:

```sql
CREATE TABLE remote (
    id INTEGER PRIMARY KEY,

    -- Identity (triple-purpose public key)
    permanent_guid TEXT NOT NULL UNIQUE,      -- Immutable
    current_public_key TEXT NOT NULL,         -- Active key
    hostname TEXT,                             -- Defaults to permanent_guid

    -- ... other fields
)
```

### Comment Linking
Comments link to entities via `permanent_guid`, not `entity_id`:

```sql
CREATE TABLE comment (
    id INTEGER PRIMARY KEY,

    -- Links to permanent GUID (survives key rotations)
    entity_permanent_guid TEXT NOT NULL,
    entity_type TEXT NOT NULL,

    category TEXT NOT NULL,  -- 'hostname', 'role', 'permanent_guid', 'custom'
    text TEXT NOT NULL,
    -- ...
)
```

This ensures comments **always** stay with the correct entity, even after:
- Key rotations
- Peer reordering
- Config regeneration

### Key Rotation History
Track all key changes over time:

```sql
CREATE TABLE key_rotation_history (
    id INTEGER PRIMARY KEY,

    entity_permanent_guid TEXT NOT NULL,  -- Which entity
    entity_type TEXT NOT NULL,

    old_public_key TEXT NOT NULL,
    new_public_key TEXT NOT NULL,

    rotated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    reason TEXT,  -- 'security_incident', 'routine_rotation', 'device_compromise'

    new_private_key TEXT NOT NULL
)
```

## Key Rotation Workflow

### Before Rotation
```
[Peer]
# alice-phone
# no endpoint == behind CGNAT
PublicKey = ABC123xyz...  ← Original key

Database:
  permanent_guid: ABC123xyz...
  current_public_key: ABC123xyz...
  hostname: alice-phone
```

### After Rotation
```
[Peer]
# alice-phone
# no endpoint == behind CGNAT
# permanent_guid: ABC123xyz...  ← Optional reference comment
PublicKey = XYZ789abc...  ← New rotated key

Database:
  permanent_guid: ABC123xyz...        ← UNCHANGED
  current_public_key: XYZ789abc...    ← UPDATED
  hostname: alice-phone               ← UNCHANGED

Comments still linked via permanent_guid ABC123xyz...
```

### History Table Entry
```sql
INSERT INTO key_rotation_history VALUES (
    entity_permanent_guid: 'ABC123xyz...',
    entity_type: 'remote',
    old_public_key: 'ABC123xyz...',
    new_public_key: 'XYZ789abc...',
    rotated_at: '2025-11-29 14:30:00',
    reason: 'routine_rotation',
    new_private_key: 'NEW_PRIVATE_KEY...'
)
```

## Comment Categories

After key rotation, can add a `permanent_guid` comment to maintain the explicit link:

```ini
[Peer]
# alice-phone                              ← category: hostname (order=1)
# no endpoint == behind CGNAT              ← category: role (order=2)
# permanent_guid: ABC123xyz...             ← category: permanent_guid (order=3)
PublicKey = XYZ789abc...                   ← New rotated key
AllowedIPs = 10.66.0.30/32
```

Comment categories and display order:
1. `hostname` (order=1) - Human-readable identifier
2. `role` (order=2) - Function/characteristics
3. `permanent_guid` (order=3) - GUID reference (after rotation)
4. `custom` (order=999) - Personal admin notes

## Benefits

### 1. Solves v1 Bug
- Comments linked by GUID, not position
- Peer order can change freely
- Comments **always** stay with correct peer

### 2. Tracks Entities Across Time
- Same entity before and after key rotation
- Can query: "Show me all configs where alice-phone appeared"
- Complete history of key changes

### 3. Automatic Default Hostname
- Don't need to invent names for unnamed peers
- permanent_guid serves as both:
  - Immutable identifier
  - Default human-readable name

### 4. Future-Proof
- Can implement additional features:
  - Timeline: "Show network topology at any point in time"
  - Audit: "Which entities have never rotated keys?"
  - Recovery: "Restore alice-phone to state before rotation"

## Implementation Notes

### On Import
```python
# First time seeing this peer
public_key = extract_public_key(entity)

# Set permanent GUID = first public key
permanent_guid = public_key
current_public_key = public_key

# Hostname defaults to GUID if not provided
hostname = extract_hostname(entity) or permanent_guid

# Store in database
INSERT INTO remote (
    permanent_guid,
    current_public_key,
    hostname,
    ...
) VALUES (?, ?, ?, ...)
```

### On Key Rotation
```python
# Lookup entity by current key or hostname
entity = find_entity(identifier)

# Generate new keypair
new_private, new_public = generate_keypair()

# Record rotation
INSERT INTO key_rotation_history (
    entity_permanent_guid,
    old_public_key,
    new_public_key,
    reason
) VALUES (
    entity.permanent_guid,
    entity.current_public_key,
    new_public,
    reason
)

# Update entity
UPDATE remote
SET
    current_public_key = new_public,
    private_key = new_private,
    updated_at = CURRENT_TIMESTAMP
WHERE permanent_guid = entity.permanent_guid

# Comments remain linked via permanent_guid (automatic!)
```

### On Config Generation
```python
# Retrieve entity
entity = get_remote(permanent_guid)

# Retrieve comments linked to permanent_guid
comments = get_comments(entity.permanent_guid)

# Generate config
[Peer]
{for comment in comments}
# {comment.text}
{endfor}
PublicKey = {entity.current_public_key}  ← Active key, not GUID
AllowedIPs = {entity.allowed_ips}
```

## Testing

See `v2/test_permanent_guid.py` for detailed tests:
- ✓ Assignment on import
- ✓ Hostname defaulting
- ✓ Comment linking
- ✓ Key rotation scenario
- ✓ Database storage

Run: `PYTHONPATH=/home/ged/wireguard-friend python3 v2/test_permanent_guid.py`

## Summary

The permanent_guid system provides:
- **Immutable identity**: Track entities across time
- **Flexible keys**: Rotate without losing history
- **Reliable comments**: Always linked correctly
- **Automatic naming**: GUID serves as default hostname
- **Complete history**: All changes tracked

All this from a single insight: **The first public key is special**.
