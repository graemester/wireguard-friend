# WireGuard Friend Architecture Review
**Innovation Roadmap 2025 Analysis**

**Date**: 2025-12-04
**Reviewer**: Architecture Agent
**Version**: v1.1.0 (merlin)
**Context**: SQLite-based VPN config management, permanent GUID system, exit nodes, extramural configs

---

## Executive Summary

WireGuard Friend has a solid architectural foundation with clean separation of concerns, semantic database modeling, and robust identity management. The roadmap proposes ambitious features that require careful architectural planning to maintain system coherence. This review identifies critical architectural decisions, dependencies, and risks.

**Key Findings**:
- Current architecture supports roadmap well with minor adjustments
- Database encryption is critical path item requiring immediate decision
- API layer will become architectural keystone - design carefully
- Exit node failover needs schema refinement for reliability
- Feature dependency chains create 3 critical path bottlenecks

---

## 1. Database Architecture (Priority Features)

### 1.1 Database Encryption: **RECOMMENDATION = Column-Level AES-256-GCM**

**Decision Rationale**:

| Approach | Pros | Cons | Verdict |
|----------|------|------|---------|
| **SQLCipher** | Transparent, strong, battle-tested | External dependency, backup complexity, all-or-nothing | ❌ Too heavyweight |
| **Column-Level** | Surgical control, standard library, incremental adoption | Manual key management, query limitations | ✅ **RECOMMENDED** |
| **Hybrid** | Layered defense | Complexity overhead | ⚠️ Overkill for use case |

**Architecture Decision**:

```python
# Use Python's cryptography library (already standard)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

class SecureColumn:
    """Encrypt sensitive columns with authenticated encryption"""

    def __init__(self, passphrase: str, salt: bytes):
        # Scrypt for key derivation (memory-hard, ASIC-resistant)
        kdf = Scrypt(salt=salt, length=32, n=2**20, r=8, p=1)
        self.key = kdf.derive(passphrase.encode())
        self.cipher = AESGCM(self.key)

    def encrypt(self, plaintext: str) -> str:
        """Returns base64(nonce + ciphertext + tag)"""
        nonce = os.urandom(12)  # 96-bit nonce for AES-GCM
        ciphertext = self.cipher.encrypt(nonce, plaintext.encode(), None)
        return base64.b64encode(nonce + ciphertext).decode()

    def decrypt(self, encrypted: str) -> str:
        """Decrypts and verifies authentication tag"""
        data = base64.b64decode(encrypted)
        nonce, ciphertext = data[:12], data[12:]
        plaintext = self.cipher.decrypt(nonce, ciphertext, None)
        return plaintext.decode()
```

**Schema Impact** - Add encryption metadata table:

```sql
CREATE TABLE encryption_metadata (
    id INTEGER PRIMARY KEY CHECK (id = 1),  -- Singleton table
    salt BLOB NOT NULL,                      -- 32 bytes for Scrypt
    key_check TEXT NOT NULL,                 -- Encrypted "canary" for verification
    algorithm TEXT DEFAULT 'AES-256-GCM',
    kdf TEXT DEFAULT 'Scrypt-1048576-8-1',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

**Encrypted Columns** (add `_encrypted` suffix convention):
- `coordination_server.private_key` → encrypted
- `subnet_router.private_key` → encrypted
- `exit_node.private_key` → encrypted
- `remote.private_key` → encrypted (nullable - provisional peers)
- `*.preshared_key` → encrypted

**Migration Strategy**:
1. Generate salt, derive key from passphrase
2. Encrypt existing keys in transaction
3. Add encryption metadata row
4. Set application flag for encrypted mode

**Performance**: Negligible (< 1ms per encrypt/decrypt operation)

---

### 1.2 Exit Node Failover Schema: **NEEDS REFINEMENT**

**Current Roadmap Proposal**:
```sql
CREATE TABLE exit_node_group (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    failover_strategy TEXT DEFAULT 'priority',
    health_check_interval INTEGER DEFAULT 30,
    health_check_timeout INTEGER DEFAULT 5
);

CREATE TABLE exit_node_group_member (
    group_id INTEGER REFERENCES exit_node_group(id),
    exit_node_id INTEGER REFERENCES exit_node(id),
    priority INTEGER DEFAULT 0,
    PRIMARY KEY (group_id, exit_node_id)
);
```

**Architectural Issues**:
1. ❌ No health state storage - checks run but state is ephemeral
2. ❌ Missing failover history - can't audit switches
3. ❌ No active exit tracking per remote

**Improved Schema** (see Section 5):
```sql
-- Add health state table
CREATE TABLE exit_node_health (
    exit_node_id INTEGER PRIMARY KEY,
    status TEXT NOT NULL,              -- 'healthy', 'degraded', 'failed'
    last_check_at TIMESTAMP NOT NULL,
    latency_ms INTEGER,                -- NULL if unreachable
    consecutive_failures INTEGER DEFAULT 0,
    last_success_at TIMESTAMP,
    FOREIGN KEY (exit_node_id) REFERENCES exit_node(id) ON DELETE CASCADE
);

-- Track failover events
CREATE TABLE exit_failover_history (
    id INTEGER PRIMARY KEY,
    remote_id INTEGER NOT NULL,
    group_id INTEGER NOT NULL,
    from_exit_id INTEGER,             -- NULL for initial assignment
    to_exit_id INTEGER NOT NULL,
    triggered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    trigger_reason TEXT NOT NULL,     -- 'health_check_failed', 'manual', 'latency_threshold'
    FOREIGN KEY (remote_id) REFERENCES remote(id) ON DELETE CASCADE,
    FOREIGN KEY (group_id) REFERENCES exit_node_group(id) ON DELETE CASCADE,
    FOREIGN KEY (from_exit_id) REFERENCES exit_node(id),
    FOREIGN KEY (to_exit_id) REFERENCES exit_node(id)
);

-- Track active exit per remote (denormalized for performance)
ALTER TABLE remote ADD COLUMN active_exit_id INTEGER REFERENCES exit_node(id);
ALTER TABLE remote ADD COLUMN exit_group_id INTEGER REFERENCES exit_node_group(id);
-- Constraint: exit_node_id is deprecated, use active_exit_id
```

**Design Pattern**: **Circuit Breaker Pattern**
- Healthy → Degraded (3 consecutive failures)
- Degraded → Failed (5 consecutive failures)
- Failed → Healthy (1 success)
- Prevents flapping with hysteresis

---

### 1.3 Audit Log Schema: **APPROVE WITH MODIFICATIONS**

**Roadmap Proposal**:
```sql
CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY,
    event_type TEXT NOT NULL,
    entity_type TEXT,
    entity_id INTEGER,
    operator TEXT,
    details TEXT NOT NULL,           -- JSON
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    previous_hash TEXT,              -- Hash chain
    entry_hash TEXT NOT NULL
);
```

**Assessment**: ✅ Good foundation, ⚠️ needs integrity improvements

**Recommended Changes**:
1. **Hash Chain Enhancement** - Add Merkle tree for efficient verification
2. **Immutability Enforcement** - Use append-only mode at application level
3. **Tamper Detection** - Add periodic checkpoints

**Revised Schema** (see Section 5 for full implementation)

---

## 2. API Architecture

### 2.1 REST API Authentication Strategy

**RECOMMENDATION**: **JWT with API Key Fallback**

```
┌─────────────────────────────────────────────────────────┐
│                    API Gateway Layer                     │
│  ┌──────────────────────────────────────────────────┐  │
│  │  1. Authentication Middleware                     │  │
│  │     • JWT Bearer Token (Web UI, Mobile)          │  │
│  │     • API Key Header (Automation, Scripts)       │  │
│  │  2. Rate Limiting (Token Bucket)                 │  │
│  │  3. Audit Logging (All authenticated requests)   │  │
│  └──────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────┐
│                  Route Handlers                          │
│  /api/v1/status      [GET]    - Read-only, no auth     │
│  /api/v1/peers       [GET]    - Requires: read scope    │
│  /api/v1/peers       [POST]   - Requires: write scope   │
│  /api/v1/peers/{id}  [DELETE] - Requires: admin scope   │
│  /api/v1/rotate      [POST]   - Requires: admin + 2FA   │
└─────────────────────────────────────────────────────────┘
```

**Authentication Schema**:

```sql
CREATE TABLE api_token (
    id INTEGER PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,      -- SHA-256 of actual token
    token_prefix TEXT NOT NULL,            -- First 8 chars for identification
    name TEXT NOT NULL,                    -- "CI/CD Pipeline", "Mobile App"
    scopes TEXT NOT NULL,                  -- JSON: ["read", "write", "admin"]
    rate_limit INTEGER DEFAULT 1000,      -- Requests per hour
    expires_at TIMESTAMP,                  -- NULL = never expires
    last_used_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by TEXT                        -- User/system that created it
);

CREATE TABLE api_request_log (
    id INTEGER PRIMARY KEY,
    token_id INTEGER,
    endpoint TEXT NOT NULL,
    method TEXT NOT NULL,
    status_code INTEGER NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    requested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (token_id) REFERENCES api_token(id) ON DELETE SET NULL
);
```

**Security Model**:
- **No passwords** - Token-based only (generate with `wg-friend api create-token`)
- **Scopes**: `read` (status, list), `write` (add, update), `admin` (delete, rotate)
- **Rate limiting**: Per-token, using token bucket algorithm
- **TLS required** for non-localhost connections

---

### 2.2 WebSocket Design for Live Updates

**Architecture**:

```python
# Server-Sent Events (SSE) - simpler than WebSocket, sufficient for unidirectional
# Client: EventSource API (native browser support)
# Server: Flask with generator function

@app.route('/api/v1/stream/status')
def stream_status():
    """Server-sent events for live status updates"""
    def generate():
        while True:
            # Poll wg show every 5 seconds
            status = get_network_status()
            yield f"data: {json.dumps(status)}\n\n"
            time.sleep(5)

    return Response(generate(), mimetype='text/event-stream')
```

**Alternative**: WebSocket for bidirectional (if needed for interactive troubleshooting)

```python
# Using python-socketio
@socketio.on('subscribe')
def handle_subscribe(data):
    """Client subscribes to specific peer updates"""
    room = f"peer:{data['peer_id']}"
    join_room(room)
    emit('subscribed', {'peer_id': data['peer_id']})

# Broadcast updates when config changes
def on_peer_updated(peer_id):
    socketio.emit('peer_update', get_peer_status(peer_id),
                  room=f"peer:{peer_id}")
```

**Recommendation**: **Start with SSE, add WebSocket only if bidirectional needed**

---

### 2.3 Rate Limiting Approach

**Algorithm**: **Token Bucket** (standard, proven, simple)

```python
class TokenBucket:
    """Token bucket rate limiter"""

    def __init__(self, capacity: int, refill_rate: int):
        self.capacity = capacity        # Max requests
        self.refill_rate = refill_rate  # Tokens per second
        self.tokens = capacity
        self.last_refill = time.time()

    def consume(self, tokens: int = 1) -> bool:
        """Returns True if request allowed"""
        now = time.time()
        elapsed = now - self.last_refill

        # Refill tokens
        self.tokens = min(
            self.capacity,
            self.tokens + elapsed * self.refill_rate
        )
        self.last_refill = now

        if self.tokens >= tokens:
            self.tokens -= tokens
            return True
        return False
```

**Rate Limits** (per API token):
- **Read endpoints**: 1000/hour (16.7/minute)
- **Write endpoints**: 100/hour (1.7/minute)
- **Admin endpoints**: 10/hour (0.17/minute)

**Storage**: In-memory (Redis-like dict) with periodic persistence

---

## 3. Critical Dependencies (Feature Dependency Graph)

```
                    ┌─────────────────────────┐
                    │  Database Encryption    │ ◄── CRITICAL PATH 1
                    │  (Phase 1, Week 1-2)    │
                    └────────────┬────────────┘
                                 │
                ┌────────────────┼────────────────┐
                │                │                │
                ▼                ▼                ▼
    ┌───────────────────┐ ┌──────────────┐ ┌──────────────┐
    │ Audit Logging     │ │ Key Rotation │ │ Disaster     │
    │ (Phase 1)         │ │ Policies     │ │ Recovery     │
    └───────────────────┘ └──────────────┘ └──────────────┘
                │
                ▼
    ┌─────────────────────────┐
    │  REST API               │ ◄── CRITICAL PATH 2
    │  (Phase 3, Week 1-3)    │
    └────────────┬────────────┘
                 │
        ┌────────┼────────┐
        │        │        │
        ▼        ▼        ▼
    ┌──────┐ ┌──────┐ ┌──────────┐
    │ Web  │ │Prom  │ │ Webhooks │
    │ UI   │ │Metrics│ │          │
    └──────┘ └──────┘ └──────────┘
        │
        ▼
    ┌─────────────────────────┐
    │  Exit Node Failover     │ ◄── CRITICAL PATH 3
    │  (Phase 2, Week 2)      │
    └────────────┬────────────┘
                 │
                 ▼
    ┌─────────────────────────┐
    │  Bandwidth Tracking     │
    │  (Phase 2, Week 1)      │
    └─────────────────────────┘
                 │
                 ▼
    ┌─────────────────────────┐
    │  Alerting System        │
    │  (Phase 2, Week 3)      │
    └─────────────────────────┘
```

### 3.1 Critical Path Blockers

**BLOCKER 1: Database Encryption**
- **Blocks**: Disaster Recovery, Compliance Reporting, 2FA setup
- **Risk**: If delayed, entire Phase 1 slips
- **Mitigation**: Implement first, parallel development after

**BLOCKER 2: REST API**
- **Blocks**: Web Dashboard, Mobile App, Terraform/Ansible integrations
- **Risk**: Phase 3+ completely blocked without this
- **Mitigation**: Design API contract early (OpenAPI spec), mock endpoints

**BLOCKER 3: Bandwidth Tracking**
- **Blocks**: Alerting System, Anomaly Detection, Prometheus Metrics
- **Risk**: Operational features delayed
- **Mitigation**: Simple MVP (poll `wg show`, store samples) unblocks downstream

---

## 4. Top 5 Architectural Risks & Mitigations

### Risk 1: **API Becomes Monolithic God Object** ⚠️ HIGH

**Scenario**: REST API grows to 50+ endpoints, becomes unmaintainable

**Mitigation**:
- **Bounded Contexts**: Separate API into logical modules
  - `/api/v1/network/*` - Network topology
  - `/api/v1/peers/*` - Peer management
  - `/api/v1/deploy/*` - Deployment operations
  - `/api/v1/audit/*` - Audit/compliance
- **Vertical Slice Architecture**: Each endpoint owns its data access
- **API Gateway Pattern**: Use Flask Blueprints for modularity

```python
# v1/api/peers.py
peers_bp = Blueprint('peers', __name__)

@peers_bp.route('/api/v1/peers', methods=['GET'])
def list_peers():
    """Peers module owns peer data access"""
    pass

# v1/api/network.py
network_bp = Blueprint('network', __name__)

@network_bp.route('/api/v1/network/status', methods=['GET'])
def network_status():
    """Network module owns status aggregation"""
    pass
```

---

### Risk 2: **Schema Creep - Uncontrolled Table Growth** ⚠️ MEDIUM

**Scenario**: Roadmap adds 20+ tables, database becomes unwieldy

**Current State**: 15 tables (good)
**Roadmap Adds**: 12+ new tables
**Projected**: 27 tables (⚠️ approaching complexity threshold)

**Mitigation**:
- **Consolidate Related Data**: Use JSON columns for flexibility
  ```sql
  -- Instead of separate tables for alert channels
  CREATE TABLE notification_channel (
      config TEXT NOT NULL  -- JSON: type-specific config
  );
  ```
- **Periodic Schema Review**: Quarterly review to identify merge opportunities
- **Namespace Tables**: Prefix by feature (`exit_*`, `audit_*`)

---

### Risk 3: **Exit Node Failover Race Conditions** ⚠️ HIGH

**Scenario**: Two health checks fail simultaneously, both trigger failover

**Race Condition**:
```
Thread A: Check exit-1 → FAIL → Switch remote-1 to exit-2
Thread B: Check exit-1 → FAIL → Switch remote-2 to exit-2
                                  ↓
                          exit-2 now has 2x expected load
```

**Mitigation**:
- **Pessimistic Locking**: Use SQLite row locks
  ```sql
  BEGIN IMMEDIATE;  -- Acquire write lock immediately
  SELECT status FROM exit_node_health WHERE exit_node_id = ? FOR UPDATE;
  -- Perform failover
  COMMIT;
  ```
- **Idempotent Operations**: Failover logic checks current state first
- **Health Check Coordination**: Single-threaded health checker with batch updates

---

### Risk 4: **Audit Log Grows Unbounded** ⚠️ MEDIUM

**Scenario**: After 1 year, audit_log has 10M rows (100MB+), queries slow

**Mitigation**:
- **Log Rotation Policy**: Archive old logs
  ```sql
  -- Archive logs older than 1 year
  CREATE TABLE audit_log_archive_2024 AS
  SELECT * FROM audit_log
  WHERE timestamp < '2024-01-01';

  DELETE FROM audit_log WHERE timestamp < '2024-01-01';
  ```
- **Partitioning**: Use yearly/monthly archive tables
- **Retention Policy**: Configurable retention (default: 1 year)
- **Index Optimization**:
  ```sql
  CREATE INDEX idx_audit_timestamp ON audit_log(timestamp DESC);
  ```

---

### Risk 5: **Passphrase Management Nightmare** ⚠️ HIGH

**Scenario**: Users lose encryption passphrase, data unrecoverable

**Impact**: Total data loss for that deployment

**Mitigation**:
- **Passphrase Recovery Mechanism**: Split-key escrow
  ```
  User Passphrase → Derive Key A
  Random Key B (stored in secure location)
  Actual Encryption Key = HKDF(Key A || Key B)
  ```
- **Clear Warnings**: Prominent UI warnings about irrecoverability
- **Backup Verification**: Force user to decrypt backup during setup
- **Optional**: Hardware security module (HSM) integration for enterprise

---

## 5. Schema Improvements (Top 3 Tables)

### 5.1 Exit Node Health & Failover (Complete Implementation)

```sql
-- Health state with circuit breaker pattern
CREATE TABLE exit_node_health (
    exit_node_id INTEGER PRIMARY KEY,

    -- Current state
    status TEXT NOT NULL CHECK(status IN ('healthy', 'degraded', 'failed')),
    last_check_at TIMESTAMP NOT NULL,
    latency_ms INTEGER,                 -- NULL if unreachable

    -- Circuit breaker counters
    consecutive_failures INTEGER DEFAULT 0,
    consecutive_successes INTEGER DEFAULT 0,

    -- History
    last_success_at TIMESTAMP,
    last_failure_at TIMESTAMP,
    failure_reason TEXT,                -- "timeout", "unreachable", etc.

    -- Health check config (can override group defaults)
    check_interval_override INTEGER,    -- NULL = use group default
    check_timeout_override INTEGER,

    FOREIGN KEY (exit_node_id) REFERENCES exit_node(id) ON DELETE CASCADE
);

-- Refined group membership with dynamic priority
CREATE TABLE exit_node_group_member (
    group_id INTEGER NOT NULL,
    exit_node_id INTEGER NOT NULL,

    -- Static priority (lower = preferred)
    static_priority INTEGER DEFAULT 100,

    -- Dynamic priority adjustment based on health
    priority_adjustment INTEGER DEFAULT 0,  -- Added/subtracted from static

    -- Effective priority = static_priority + priority_adjustment
    -- Recalculated after each health check

    -- Weights for load balancing strategy
    weight INTEGER DEFAULT 1,            -- For round-robin weighting

    -- Metadata
    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    enabled BOOLEAN DEFAULT 1,           -- Can disable without removing

    PRIMARY KEY (group_id, exit_node_id),
    FOREIGN KEY (group_id) REFERENCES exit_node_group(id) ON DELETE CASCADE,
    FOREIGN KEY (exit_node_id) REFERENCES exit_node(id) ON DELETE CASCADE
);

-- Failover history with rich context
CREATE TABLE exit_failover_history (
    id INTEGER PRIMARY KEY,

    -- What failed over
    remote_id INTEGER NOT NULL,
    group_id INTEGER NOT NULL,

    -- Failover transition
    from_exit_id INTEGER,               -- NULL for initial assignment
    to_exit_id INTEGER NOT NULL,

    -- Why it happened
    trigger_reason TEXT NOT NULL,       -- 'health_check_failed', 'latency_threshold', 'manual', 'load_balancing'
    trigger_details TEXT,               -- JSON: {"latency_ms": 450, "threshold": 200}

    -- When
    triggered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    -- Outcome
    success BOOLEAN NOT NULL DEFAULT 1,
    error_message TEXT,                 -- If success=0

    FOREIGN KEY (remote_id) REFERENCES remote(id) ON DELETE CASCADE,
    FOREIGN KEY (group_id) REFERENCES exit_node_group(id) ON DELETE CASCADE,
    FOREIGN KEY (from_exit_id) REFERENCES exit_node(id) ON DELETE SET NULL,
    FOREIGN KEY (to_exit_id) REFERENCES exit_node(id) ON DELETE CASCADE
);

-- Indexes for performance
CREATE INDEX idx_exit_health_status ON exit_node_health(status, last_check_at);
CREATE INDEX idx_failover_remote ON exit_failover_history(remote_id, triggered_at DESC);
CREATE INDEX idx_failover_group ON exit_failover_history(group_id, triggered_at DESC);
```

**Key Improvements**:
1. ✅ **Circuit Breaker Pattern**: Prevents flapping with state transitions
2. ✅ **Dynamic Priority**: Health influences routing decisions
3. ✅ **Rich History**: Audit trail for failovers with context
4. ✅ **Flexible Overrides**: Per-exit health check tuning

---

### 5.2 Audit Log with Merkle Tree Integrity

```sql
-- Enhanced audit log with cryptographic integrity
CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY,

    -- What happened
    event_type TEXT NOT NULL,           -- 'key_rotation', 'peer_added', 'config_deployed', etc.
    event_category TEXT NOT NULL,       -- 'security', 'configuration', 'access', 'system'
    severity TEXT NOT NULL,             -- 'info', 'warning', 'critical'

    -- Who/what it affected
    entity_type TEXT,                   -- 'remote', 'subnet_router', 'exit_node'
    entity_id INTEGER,
    entity_permanent_guid TEXT,         -- For long-term tracking across ID changes

    -- Who did it
    operator TEXT NOT NULL,             -- 'root', 'system', 'api_token:abc123'
    operator_ip TEXT,
    operator_source TEXT,               -- 'cli', 'api', 'web_ui'

    -- Details
    details TEXT NOT NULL,              -- JSON with event-specific data

    -- When
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    -- Cryptographic integrity (hash chain)
    entry_hash TEXT NOT NULL,           -- SHA-256(id||event_type||timestamp||details||previous_hash)
    previous_hash TEXT,                 -- Hash of previous entry (NULL for first entry)

    -- Merkle tree (for efficient verification)
    merkle_root TEXT,                   -- Updated every 1000 entries
    merkle_tree_index INTEGER,          -- Position in current tree

    -- Metadata
    client_version TEXT,                -- wg-friend version that logged this
    schema_version INTEGER DEFAULT 1    -- For future evolution
);

-- Merkle tree checkpoints (for efficient verification)
CREATE TABLE audit_checkpoint (
    id INTEGER PRIMARY KEY,

    -- Range covered
    start_entry_id INTEGER NOT NULL,
    end_entry_id INTEGER NOT NULL,
    entry_count INTEGER NOT NULL,

    -- Merkle root for this range
    merkle_root TEXT NOT NULL,

    -- Timestamp
    checkpoint_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (start_entry_id) REFERENCES audit_log(id),
    FOREIGN KEY (end_entry_id) REFERENCES audit_log(id)
);

-- Indexes
CREATE INDEX idx_audit_timestamp ON audit_log(timestamp DESC);
CREATE INDEX idx_audit_entity ON audit_log(entity_type, entity_id, timestamp DESC);
CREATE INDEX idx_audit_operator ON audit_log(operator, timestamp DESC);
CREATE INDEX idx_audit_category ON audit_log(event_category, severity, timestamp DESC);
CREATE INDEX idx_audit_guid ON audit_log(entity_permanent_guid, timestamp DESC);
```

**Key Improvements**:
1. ✅ **Hash Chain**: Tamper-evident append-only log
2. ✅ **Merkle Checkpoints**: Efficient verification without scanning entire log
3. ✅ **Rich Metadata**: Category, severity, source tracking
4. ✅ **GUID Tracking**: Links to entities across key rotations

**Verification Algorithm**:
```python
def verify_audit_log_integrity():
    """Verify complete audit log integrity"""
    with db._connection() as conn:
        entries = conn.execute(
            "SELECT id, entry_hash, previous_hash FROM audit_log ORDER BY id"
        ).fetchall()

        prev_hash = None
        for entry in entries:
            # Verify hash chain
            if entry['previous_hash'] != prev_hash:
                return False, f"Hash chain broken at entry {entry['id']}"

            # Verify entry hash (would need full row data)
            # ...

            prev_hash = entry['entry_hash']

        return True, "Audit log integrity verified"
```

---

### 5.3 Bandwidth Tracking with Aggregation

```sql
-- Raw bandwidth samples (retained for 7 days)
CREATE TABLE bandwidth_sample (
    id INTEGER PRIMARY KEY,

    -- What entity
    entity_type TEXT NOT NULL,          -- 'remote', 'subnet_router', 'exit_node'
    entity_id INTEGER NOT NULL,

    -- Sample data (from wg show)
    sampled_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    rx_bytes INTEGER NOT NULL,          -- Cumulative received
    tx_bytes INTEGER NOT NULL,          -- Cumulative transmitted
    latest_handshake TIMESTAMP,         -- From wg show

    -- Connection state
    endpoint TEXT,                      -- Current endpoint
    connected BOOLEAN NOT NULL,         -- Has recent handshake

    FOREIGN KEY (entity_id) REFERENCES remote(id) ON DELETE CASCADE  -- Polymorphic
);

-- Aggregated bandwidth (retained long-term)
CREATE TABLE bandwidth_aggregate (
    id INTEGER PRIMARY KEY,

    -- What entity
    entity_type TEXT NOT NULL,
    entity_id INTEGER NOT NULL,

    -- Time period
    period_type TEXT NOT NULL,          -- 'hourly', 'daily', 'weekly', 'monthly'
    period_start TIMESTAMP NOT NULL,
    period_end TIMESTAMP NOT NULL,

    -- Aggregated metrics
    total_rx_bytes INTEGER NOT NULL,
    total_tx_bytes INTEGER NOT NULL,
    total_bytes INTEGER NOT NULL,       -- rx + tx
    peak_rx_rate INTEGER,               -- Bytes per second
    peak_tx_rate INTEGER,
    avg_rx_rate INTEGER,
    avg_tx_rate INTEGER,

    -- Connection quality
    uptime_seconds INTEGER NOT NULL,    -- Time connected during period
    downtime_seconds INTEGER NOT NULL,
    availability_percent REAL NOT NULL,

    -- Computed at
    computed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    UNIQUE(entity_type, entity_id, period_type, period_start)
);

-- Baseline statistics (for anomaly detection)
CREATE TABLE bandwidth_baseline (
    entity_type TEXT NOT NULL,
    entity_id INTEGER NOT NULL,

    -- Rolling baseline (last 30 days)
    avg_daily_bytes INTEGER NOT NULL,
    stddev_daily_bytes INTEGER NOT NULL,
    p95_daily_bytes INTEGER NOT NULL,

    -- Baseline updated at
    computed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    samples_count INTEGER NOT NULL,     -- Number of days in baseline

    PRIMARY KEY (entity_type, entity_id)
);

-- Indexes
CREATE INDEX idx_bandwidth_sample_entity ON bandwidth_sample(entity_type, entity_id, sampled_at DESC);
CREATE INDEX idx_bandwidth_aggregate_entity ON bandwidth_aggregate(entity_type, entity_id, period_type, period_start DESC);
CREATE INDEX idx_bandwidth_sample_time ON bandwidth_sample(sampled_at);  -- For cleanup
```

**Key Improvements**:
1. ✅ **Two-Tier Storage**: Raw samples (short-term) + aggregates (long-term)
2. ✅ **Statistical Baseline**: Enables anomaly detection
3. ✅ **Connection Quality**: Track uptime/downtime
4. ✅ **Cleanup Strategy**: Delete raw samples > 7 days, keep aggregates

**Data Lifecycle**:
```
Raw Samples (7 days) → Hourly Aggregates (30 days) → Daily Aggregates (1 year) → Monthly Aggregates (forever)
```

---

## 6. Additional Architectural Recommendations

### 6.1 Service Layer Pattern

**Current**: Direct database access from CLI/TUI
**Proposed**: Service layer for business logic encapsulation

```python
# v1/services/peer_service.py
class PeerService:
    """Business logic for peer management (separate from DB access)"""

    def __init__(self, db: WireGuardDBv2):
        self.db = db

    def add_remote(self, hostname: str, access_level: str) -> Remote:
        """Add remote with business logic"""
        # Validation
        if not hostname:
            raise ValueError("Hostname required")

        # Check duplicates
        if self.db.get_remote_by_hostname(hostname):
            raise ValueError(f"Remote {hostname} already exists")

        # Allocate IP
        ip = self._allocate_next_ip()

        # Create entity
        remote = self.db.create_remote(hostname, ip, access_level)

        # Audit log
        self._log_audit('peer_added', remote)

        return remote
```

**Benefits**:
- ✅ Single place for business logic
- ✅ Easier testing (mock database)
- ✅ Consistent behavior across CLI/API/TUI

---

### 6.2 Event System for Cross-Cutting Concerns

**Pattern**: Observer/Event Bus

```python
# v1/events.py
class Event:
    """Base event"""
    pass

class PeerAddedEvent(Event):
    def __init__(self, peer_id: int, peer_type: str):
        self.peer_id = peer_id
        self.peer_type = peer_type

class EventBus:
    """Simple event bus for decoupling"""

    def __init__(self):
        self.handlers = {}

    def subscribe(self, event_type: type, handler: callable):
        """Subscribe handler to event type"""
        if event_type not in self.handlers:
            self.handlers[event_type] = []
        self.handlers[event_type].append(handler)

    def publish(self, event: Event):
        """Publish event to all subscribers"""
        for handler in self.handlers.get(type(event), []):
            handler(event)

# Usage
event_bus = EventBus()

# Subscribe handlers
event_bus.subscribe(PeerAddedEvent, audit_logger.log)
event_bus.subscribe(PeerAddedEvent, webhook_notifier.send)
event_bus.subscribe(PeerAddedEvent, metrics_collector.record)

# Publish when peer added
event_bus.publish(PeerAddedEvent(peer_id=5, peer_type='remote'))
```

**Benefits**:
- ✅ Decouples audit logging, webhooks, metrics
- ✅ Easy to add new cross-cutting concerns
- ✅ Supports async event processing

---

### 6.3 Configuration Validation Layer

**Current**: Implicit validation in CLI prompts
**Proposed**: Explicit validation schema

```python
# v1/validation/schemas.py
from pydantic import BaseModel, validator, IPvAnyAddress

class RemoteConfig(BaseModel):
    """Validation schema for remote config"""
    hostname: str
    ipv4_address: IPvAnyAddress
    access_level: str

    @validator('hostname')
    def hostname_valid(cls, v):
        if not v or len(v) > 63:
            raise ValueError("Invalid hostname")
        if not re.match(r'^[a-z0-9-]+$', v):
            raise ValueError("Hostname must be lowercase alphanumeric")
        return v

    @validator('access_level')
    def access_level_valid(cls, v):
        valid = ['full_access', 'vpn_only', 'lan_only', 'exit_only', 'custom']
        if v not in valid:
            raise ValueError(f"Access level must be one of {valid}")
        return v
```

**Benefits**:
- ✅ Centralized validation rules
- ✅ Consistent across CLI/API/TUI
- ✅ Auto-generated API documentation

---

## 7. Migration Path & Backward Compatibility

### 7.1 Schema Versioning Strategy

```sql
-- Add schema version tracking
CREATE TABLE schema_metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO schema_metadata (key, value) VALUES ('schema_version', '2');
INSERT INTO schema_metadata (key, value) VALUES ('wgf_version', '1.1.0');
```

**Migration Scripts**:
```bash
v1/migrations/
├── 001_add_exit_nodes.sql
├── 002_add_encryption_metadata.sql
├── 003_add_audit_log.sql
└── ...
```

### 7.2 Backward Compatibility Guarantees

**Database**:
- ✅ Always additive (new tables/columns)
- ✅ Never remove columns (deprecate, then remove in major version)
- ✅ Use `ALTER TABLE ADD COLUMN` with defaults

**API**:
- ✅ Versioned endpoints (`/api/v1/`, `/api/v2/`)
- ✅ Maintain v1 for 1 year after v2 release
- ✅ Deprecation warnings in response headers

---

## 8. Performance Considerations

### 8.1 Database Query Optimization

**Current**: Single-threaded, synchronous queries (fine for current scale)
**Future**: Connection pooling for API workload

```python
# v1/database/pool.py
from contextlib import contextmanager
import sqlite3
import queue

class ConnectionPool:
    """Simple SQLite connection pool"""

    def __init__(self, db_path: str, size: int = 5):
        self.db_path = db_path
        self.pool = queue.Queue(maxsize=size)
        for _ in range(size):
            conn = sqlite3.connect(db_path, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            self.pool.put(conn)

    @contextmanager
    def connection(self):
        conn = self.pool.get()
        try:
            yield conn
            conn.commit()
        except:
            conn.rollback()
            raise
        finally:
            self.pool.put(conn)
```

**Recommendation**: Implement when API is added (Phase 3)

---

### 8.2 Caching Strategy

**Read-Heavy Queries**: Cache in memory with TTL

```python
from functools import lru_cache
from datetime import datetime, timedelta

class CachedQueries:
    """Cache expensive queries"""

    def __init__(self, db: WireGuardDBv2):
        self.db = db
        self.cache = {}
        self.cache_ttl = timedelta(minutes=5)

    def get_network_status(self) -> dict:
        """Get cached network status"""
        cache_key = 'network_status'
        if cache_key in self.cache:
            cached_at, data = self.cache[cache_key]
            if datetime.now() - cached_at < self.cache_ttl:
                return data

        # Cache miss - query database
        data = self._compute_network_status()
        self.cache[cache_key] = (datetime.now(), data)
        return data
```

**Recommendation**: Add caching for:
- Network status (5 min TTL)
- Peer lists (1 min TTL)
- Bandwidth aggregates (1 hour TTL)

---

## 9. Testing Strategy for New Features

### 9.1 Test Pyramid

```
         /\
        /  \  E2E Tests (5%)
       /────\  - Full workflow tests
      /      \  - Browser automation (Playwright)
     /────────\
    / Integration Tests (20%)
   /   - API endpoint tests
  /    - Database + service tests
 /──────────────\
/ Unit Tests (75%)
  - Service layer
  - Validation logic
  - Utility functions
```

### 9.2 Critical Test Coverage

**Must Test**:
1. ✅ Exit node failover race conditions
2. ✅ Audit log integrity verification
3. ✅ Database encryption/decryption
4. ✅ API authentication & authorization
5. ✅ Bandwidth calculation accuracy

**Example Test**:
```python
def test_exit_failover_prevents_race_condition():
    """Test concurrent failover attempts are serialized"""
    db = WireGuardDBv2(':memory:')

    # Setup: 2 remotes using same exit group
    group = db.create_exit_group('test-group')
    exit1 = db.create_exit_node('exit-1')
    exit2 = db.create_exit_node('exit-2')
    db.add_to_exit_group(group.id, exit1.id, priority=1)
    db.add_to_exit_group(group.id, exit2.id, priority=2)

    remote1 = db.create_remote('remote-1', group_id=group.id)
    remote2 = db.create_remote('remote-2', group_id=group.id)

    # Simulate concurrent failover
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=2) as executor:
        future1 = executor.submit(failover_service.handle_exit_failure, exit1.id)
        future2 = executor.submit(failover_service.handle_exit_failure, exit1.id)

        future1.result()
        future2.result()

    # Verify both remotes switched to exit2
    assert db.get_remote(remote1.id).active_exit_id == exit2.id
    assert db.get_remote(remote2.id).active_exit_id == exit2.id

    # Verify exactly 2 failover history entries
    history = db.get_failover_history(group_id=group.id)
    assert len(history) == 2
```

---

## 10. Security Hardening Checklist

### 10.1 OWASP Top 10 Mitigations

| Risk | Mitigation | Status |
|------|------------|--------|
| **Injection** | Parameterized queries (SQLite) | ✅ Already done |
| **Broken Auth** | JWT + API keys, no passwords | ⚠️ Implement in Phase 3 |
| **Sensitive Data** | Database encryption | ⚠️ Phase 1 critical |
| **XML External Entities** | N/A (no XML parsing) | ✅ N/A |
| **Broken Access Control** | Role-based scopes | ⚠️ Implement with API |
| **Security Misconfiguration** | Secure defaults, audit logs | ⚠️ Ongoing |
| **XSS** | CSP headers in web UI | ⚠️ Phase 4 |
| **Insecure Deserialization** | JSON only (built-in) | ✅ Already done |
| **Using Components with Known Vulnerabilities** | Dependabot, regular updates | ⚠️ Setup CI |
| **Insufficient Logging** | Audit log system | ⚠️ Phase 1 |

### 10.2 Additional Security Measures

1. **Rate Limiting**: ✅ Designed (Section 2.3)
2. **TLS for API**: ⚠️ Document self-signed cert setup
3. **Least Privilege**: ✅ Already follows (SSH key auth, minimal perms)
4. **Input Validation**: ⚠️ Add Pydantic schemas (Section 6.3)
5. **Audit Everything**: ⚠️ Phase 1 priority

---

## Summary & Action Items

### Immediate Actions (Week 1)

1. ✅ **Approve database encryption approach** (Column-level AES-256-GCM)
2. ✅ **Refine exit node failover schema** (Use improved schema from Section 5.1)
3. ✅ **Approve audit log design** (Hash chain + Merkle checkpoints)
4. ⚠️ **Create OpenAPI spec for REST API** (Design before implementation)
5. ⚠️ **Set up schema migration framework** (Track version, write migrations)

### Short-Term (Phase 1: Q1 2025)

- Implement database encryption (2 weeks)
- Implement audit logging (1 week)
- Add key rotation policies (1 week)
- Build disaster recovery system (2 weeks)

### Medium-Term (Phase 2-3: Q2-Q3 2025)

- Build REST API with authentication (3 weeks)
- Implement exit node failover (2 weeks)
- Add bandwidth tracking & alerting (3 weeks)
- Create web dashboard MVP (4 weeks)

### Long-Term (Phase 4+: Q4 2025+)

- Mobile app specification
- Terraform/Ansible integrations
- Advanced networking features

---

## Conclusion

WireGuard Friend's architecture is solid and well-positioned for the ambitious roadmap. The permanent GUID system, semantic schema, and clean separation of concerns provide a strong foundation. Key recommendations:

1. **Prioritize database encryption** - Critical path blocker, moderate complexity
2. **Design API carefully** - Will become architectural keystone
3. **Use improved schemas** - Especially exit node failover and audit logging
4. **Add service layer** - Encapsulate business logic before API phase
5. **Implement event bus** - Decouple cross-cutting concerns early

The roadmap is achievable with disciplined execution and attention to the architectural risks identified in this review.

---

**Generated**: 2025-12-04
**Review by**: Architecture Agent
**Files Analyzed**: 46 Python files, schema_semantic.py, innovation-roadmap-2025.md
**Total Lines Reviewed**: ~8,500 LOC
