# WireGuard Friend Innovation Roadmap 2025

## Executive Summary

This document proposes a comprehensive set of innovative features, enhancements, and refinements for WireGuard Friend. The proposals are organized into seven strategic pillars, each addressing distinct user needs and market opportunities.

**Current State**: WireGuard Friend v1.1.0 ("merlin") is a production-ready, menu-driven management tool with semantic database storage, exit node support, extramural config management, and comprehensive deployment automation.

**Vision**: Transform WireGuard Friend from a configuration management tool into an intelligent VPN operations platform with autonomous monitoring, predictive maintenance, and enterprise-grade security.

---

## Strategic Pillars

| Pillar | Focus | Impact |
|--------|-------|--------|
| 1. Network Intelligence | Failover, load balancing, health monitoring | High availability |
| 2. Security Hardening | Encryption, scheduled rotation, audit logging | Enterprise compliance |
| 3. User Experience | Web dashboard, mobile companion, visual topology | Accessibility |
| 4. Operational Excellence | Compliance reporting, disaster recovery | Enterprise readiness |
| 5. Advanced Networking | Multi-hop, traffic splitting, split DNS | Power user features |
| 6. Integration Ecosystem | API, webhooks, metrics, IaC modules | DevOps adoption |
| 7. Intelligent Operations | Anomaly detection, predictive maintenance | Autonomous management |

---

## Pillar 1: Network Intelligence & Automation

### 1.1 Automatic Exit Node Failover

**Problem**: If an exit node becomes unreachable, remotes using it lose internet connectivity with no automatic recovery.

**Solution**: Implement health-check-driven failover between exit nodes.

**Design**:
```
Primary Exit (us-west) ──── FAIL ────> Failover Exit (us-east)
        │                                      │
        └──── RECOVER ─────────────────────────┘
```

**Implementation**:
```sql
CREATE TABLE exit_node_group (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,                    -- "US Exits", "EU Exits"
    failover_strategy TEXT DEFAULT 'priority',  -- 'priority', 'round_robin', 'latency'
    health_check_interval INTEGER DEFAULT 30,   -- seconds
    health_check_timeout INTEGER DEFAULT 5
);

CREATE TABLE exit_node_group_member (
    group_id INTEGER REFERENCES exit_node_group(id),
    exit_node_id INTEGER REFERENCES exit_node(id),
    priority INTEGER DEFAULT 0,            -- Lower = higher priority
    PRIMARY KEY (group_id, exit_node_id)
);

ALTER TABLE remote ADD COLUMN exit_group_id INTEGER REFERENCES exit_node_group(id);
```

**Failover Strategies**:
- **Priority**: Always use highest-priority available exit
- **Round Robin**: Distribute load across healthy exits
- **Latency**: Use exit with lowest measured latency

**Health Checks**:
- ICMP ping to exit node endpoint
- WireGuard handshake verification
- Optional: HTTP health endpoint on exit

**User Experience**:
```
=== EXIT NODE GROUPS ===

1. US Exits (3 nodes, all healthy)
   Priority 1: us-west     [HEALTHY]  23ms
   Priority 2: us-east     [HEALTHY]  45ms
   Priority 3: us-central  [HEALTHY]  38ms

2. EU Exits (2 nodes, 1 degraded)
   Priority 1: frankfurt   [HEALTHY]  120ms
   Priority 2: amsterdam   [DEGRADED] 450ms
```

**Priority**: HIGH
**Complexity**: MEDIUM
**Dependencies**: Exit node feature (complete)

---

### 1.2 Bandwidth & Usage Tracking

**Problem**: No visibility into peer bandwidth consumption, limiting capacity planning and anomaly detection.

**Solution**: Periodic polling of `wg show` data with historical storage.

**Implementation**:
```sql
CREATE TABLE bandwidth_sample (
    id INTEGER PRIMARY KEY,
    entity_type TEXT NOT NULL,      -- 'remote', 'subnet_router', 'exit_node'
    entity_id INTEGER NOT NULL,
    sampled_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    rx_bytes INTEGER,               -- Total received
    tx_bytes INTEGER,               -- Total transmitted
    latest_handshake TIMESTAMP      -- From wg show
);

CREATE INDEX idx_bandwidth_entity ON bandwidth_sample(entity_type, entity_id, sampled_at);
```

**Collection Modes**:
1. **Manual**: Run `wg-friend bandwidth collect` to sample now
2. **Scheduled**: Cron job or systemd timer for periodic collection
3. **Live**: Background process with configurable interval

**User Experience**:
```
=== BANDWIDTH REPORT (Last 24h) ===

Peer               Received      Sent        Last Seen
────────────────────────────────────────────────────────
alice-laptop       2.4 GB        156 MB      2m ago
bob-phone          890 MB        45 MB       5m ago
home-router        12.1 GB       8.7 GB      30s ago
exit-us-west       45.2 GB       3.1 GB      1m ago

Top Consumers (7 days):
  1. exit-us-west     312 GB total
  2. home-router       89 GB total
  3. alice-laptop      24 GB total
```

**Priority**: MEDIUM
**Complexity**: LOW
**Dependencies**: SSH access to CS for remote `wg show`

---

### 1.3 Intelligent Alerting System

**Problem**: Network issues go unnoticed until users report problems.

**Solution**: Configurable alerts based on health metrics.

**Alert Types**:
| Alert | Trigger | Default Threshold |
|-------|---------|-------------------|
| Peer Offline | No handshake in N minutes | 10 minutes |
| High Latency | Latency exceeds N ms | 200ms |
| Bandwidth Spike | Usage exceeds N% of baseline | 300% |
| Key Expiry | Key not rotated in N days | 90 days |
| Exit Failover | Exit node group switched | Immediate |
| Connection Storm | N+ new connections in M seconds | 10 in 60s |

**Notification Channels**:
- **Local**: Log file, desktop notification
- **Email**: SMTP configuration
- **Webhook**: HTTP POST to arbitrary endpoint
- **Slack/Discord**: Native integrations

**Implementation**:
```sql
CREATE TABLE alert_rule (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    alert_type TEXT NOT NULL,
    threshold_value INTEGER,
    threshold_unit TEXT,
    enabled BOOLEAN DEFAULT 1,
    cooldown_minutes INTEGER DEFAULT 60
);

CREATE TABLE notification_channel (
    id INTEGER PRIMARY KEY,
    channel_type TEXT NOT NULL,     -- 'webhook', 'email', 'slack'
    config TEXT NOT NULL            -- JSON configuration
);

CREATE TABLE alert_history (
    id INTEGER PRIMARY KEY,
    rule_id INTEGER REFERENCES alert_rule(id),
    triggered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    entity_type TEXT,
    entity_id INTEGER,
    message TEXT,
    resolved_at TIMESTAMP
);
```

**Priority**: MEDIUM
**Complexity**: MEDIUM
**Dependencies**: Bandwidth tracking, health monitoring

---

### 1.4 Geographic Routing Intelligence

**Problem**: Users must manually select exit nodes without visibility into optimal choices.

**Solution**: Automatic exit selection based on geographic and latency data.

**Features**:
- **GeoIP Integration**: Map peer IPs to approximate locations
- **Latency Matrix**: Periodic measurement between all node pairs
- **Routing Recommendations**: Suggest optimal exit for each peer
- **Auto-Selection Mode**: Automatically assign best exit

**User Experience**:
```
=== ROUTING INTELLIGENCE ===

alice-laptop (San Francisco, CA)
  Current exit: us-west (Los Angeles)     32ms
  Recommended:  us-west (Los Angeles)     32ms  [OPTIMAL]

bob-phone (London, UK)
  Current exit: us-east (New York)        89ms
  Recommended:  eu-west (London)          12ms  [SUBOPTIMAL]

  Actions:
    1. Switch bob-phone to eu-west
    2. Auto-optimize all peers
```

**Priority**: LOW
**Complexity**: HIGH
**Dependencies**: Exit node groups, GeoIP database

---

## Pillar 2: Security Hardening

### 2.1 Database Encryption at Rest

**Problem**: SQLite database contains private keys in plaintext, vulnerable if disk is compromised.

**Solution**: Encrypt sensitive columns or entire database.

**Options**:
1. **Column-Level Encryption**: Encrypt only private keys using AES-256-GCM
2. **Full Database Encryption**: Use SQLCipher for transparent encryption
3. **Hybrid**: Column encryption + file permissions

**Recommended Approach**: Column-level encryption with key derivation from passphrase.

**Implementation**:
```python
# Key derivation
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.fernet import Fernet

def derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=2**20, r=8, p=1)
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))

# Encryption wrapper
class SecureColumn:
    def encrypt(self, value: str) -> str: ...
    def decrypt(self, encrypted: str) -> str: ...
```

**Schema Addition**:
```sql
CREATE TABLE encryption_metadata (
    id INTEGER PRIMARY KEY,
    salt BLOB NOT NULL,
    key_check TEXT NOT NULL,        -- Encrypted known value for verification
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

**User Experience**:
```
=== DATABASE ENCRYPTION ===

Database encryption protects private keys at rest.
If you forget the passphrase, data cannot be recovered.

Enter encryption passphrase: ********
Confirm passphrase: ********

Encrypting 12 private keys...
  Coordination server: encrypted
  3 subnet routers: encrypted
  8 remotes: encrypted

Database encryption enabled.
You will be prompted for passphrase when launching wg-friend.
```

**Priority**: HIGH (enterprise requirement)
**Complexity**: MEDIUM
**Dependencies**: None

---

### 2.2 Scheduled Key Rotation Policies

**Problem**: Manual key rotation is often forgotten, increasing exposure window if a key is compromised.

**Solution**: Configurable automatic key rotation schedules.

**Policy Options**:
- **Time-Based**: Rotate every N days (30, 60, 90)
- **Usage-Based**: Rotate after N GB transferred
- **Event-Based**: Rotate on specific triggers (new device, security incident)

**Implementation**:
```sql
CREATE TABLE rotation_policy (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    policy_type TEXT NOT NULL,       -- 'time', 'usage', 'event'
    threshold_value INTEGER,         -- days, GB, or event count
    applies_to TEXT,                 -- 'all', 'remotes', 'routers', specific entity
    enabled BOOLEAN DEFAULT 1,
    last_applied_at TIMESTAMP
);

CREATE TABLE rotation_schedule (
    id INTEGER PRIMARY KEY,
    policy_id INTEGER REFERENCES rotation_policy(id),
    entity_type TEXT NOT NULL,
    entity_id INTEGER NOT NULL,
    next_rotation_at TIMESTAMP,
    last_rotation_at TIMESTAMP
);
```

**User Experience**:
```
=== ROTATION POLICIES ===

1. Standard (90-day rotation)
   Applies to: All remotes
   Status: 3 remotes due in next 7 days

2. High Security (30-day rotation)
   Applies to: admin-laptop, server-access
   Status: All current

Upcoming Rotations:
  Dec 10: alice-phone (Standard policy)
  Dec 12: bob-laptop (Standard policy)
  Dec 15: guest-access (Standard policy)

  Actions:
    1. Run pending rotations now
    2. Create new policy
    3. Edit policies
```

**Automation Mode**:
```bash
# Add to cron or systemd timer
wg-friend rotation apply --auto --deploy
```

**Priority**: HIGH
**Complexity**: LOW
**Dependencies**: Key rotation (complete)

---

### 2.3 Security Audit Logging

**Problem**: No tamper-evident audit trail for security-sensitive operations.

**Solution**: Append-only audit log with cryptographic integrity.

**Logged Events**:
| Event | Data Captured |
|-------|---------------|
| Key Rotation | Entity, old key hash, new key hash, operator |
| Access Level Change | Entity, old level, new level, operator |
| Peer Added/Removed | Entity details, operator |
| Config Deployed | Target, config hash, operator |
| Login Attempt | Success/failure, timestamp |
| Policy Change | Old value, new value, operator |

**Implementation**:
```sql
CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY,
    event_type TEXT NOT NULL,
    entity_type TEXT,
    entity_id INTEGER,
    operator TEXT,                   -- User or "system"
    details TEXT NOT NULL,           -- JSON
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    previous_hash TEXT,              -- Hash of previous entry (chain)
    entry_hash TEXT NOT NULL         -- SHA-256 of this entry
);

CREATE INDEX idx_audit_timestamp ON audit_log(timestamp);
CREATE INDEX idx_audit_entity ON audit_log(entity_type, entity_id);
```

**Integrity Verification**:
```bash
wg-friend audit verify
# Verifies hash chain, reports any tampering
```

**Export for Compliance**:
```bash
wg-friend audit export --format json --from 2024-01-01 --to 2024-12-31 > audit-2024.json
```

**Priority**: HIGH (compliance requirement)
**Complexity**: LOW
**Dependencies**: None

---

### 2.4 Two-Factor Authentication for Sensitive Operations

**Problem**: Anyone with file access can perform destructive operations.

**Solution**: Optional 2FA for sensitive operations.

**Protected Operations**:
- Key rotation
- Peer removal
- Access level changes
- Config deployment
- Database decryption

**2FA Options**:
1. **TOTP**: Time-based one-time passwords (Google Authenticator, Authy)
2. **Hardware Keys**: FIDO2/WebAuthn support
3. **Passphrase Confirmation**: Re-enter encryption passphrase

**Implementation**:
```sql
CREATE TABLE auth_config (
    id INTEGER PRIMARY KEY,
    totp_secret TEXT,               -- Encrypted TOTP seed
    totp_enabled BOOLEAN DEFAULT 0,
    protected_operations TEXT,       -- JSON array of operation names
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

**User Experience**:
```
Rotating key for: alice-laptop

This operation requires 2FA verification.
Enter TOTP code: 123456

Key rotation confirmed.
```

**Priority**: MEDIUM
**Complexity**: MEDIUM
**Dependencies**: Database encryption

---

### 2.5 Preshared Key Management Automation

**Problem**: PSK management is manual and inconsistent across peers.

**Solution**: Automated PSK generation, rotation, and deployment.

**Features**:
- **Auto-Generate**: Create unique PSK for each peer relationship
- **Batch Rotation**: Rotate all PSKs with single command
- **Sync Validation**: Verify PSKs match across config pairs

**User Experience**:
```
=== PRESHARED KEY STATUS ===

Peer               PSK Status      Age        Next Rotation
────────────────────────────────────────────────────────────
alice-laptop       [ENABLED]       45 days    Jan 15 (policy)
bob-phone          [ENABLED]       45 days    Jan 15 (policy)
home-router        [DISABLED]      -          -
exit-us-west       [ENABLED]       12 days    Feb 20 (policy)

Actions:
  1. Enable PSK for home-router
  2. Rotate all PSKs now
  3. Configure PSK policy
```

**Priority**: MEDIUM
**Complexity**: LOW
**Dependencies**: Rotation policies

---

## Pillar 3: User Experience Enhancements

### 3.1 Web-Based Dashboard

**Problem**: TUI requires terminal access; not accessible from mobile or for quick glances.

**Solution**: Optional web dashboard for monitoring and basic operations.

**Architecture**:
```
wg-friend web --port 8080
       │
       ├── Static UI (HTML/JS/CSS)
       │
       ├── REST API
       │     ├── GET /api/status
       │     ├── GET /api/peers
       │     ├── POST /api/peers/{id}/rotate
       │     └── ...
       │
       └── WebSocket (live updates)
             └── /ws/status
```

**Technology Stack**:
- **Backend**: Built-in Python HTTP server or Flask
- **Frontend**: Vanilla JS or lightweight framework (Alpine.js)
- **Authentication**: Basic auth or token-based

**Dashboard Views**:
1. **Overview**: Network health at a glance
2. **Peers**: List with status indicators
3. **Bandwidth**: Usage graphs
4. **Alerts**: Active and recent alerts
5. **History**: Timeline of changes

**Security Considerations**:
- Listen on localhost by default
- Optional TLS with self-signed or provided cert
- Rate limiting on authentication
- CSRF protection

**Priority**: MEDIUM
**Complexity**: HIGH
**Dependencies**: REST API (new)

---

### 3.2 Visual Network Topology

**Problem**: Text-based status doesn't convey network structure intuitively.

**Solution**: ASCII and graphical topology visualization.

**ASCII Topology** (TUI):
```
                    ┌─────────────────────────────────────┐
                    │      cs.example.com (10.66.0.1)     │
                    │          Coordination Server         │
                    └──────────────────┬──────────────────┘
                                       │
           ┌───────────────────────────┼───────────────────────────┐
           │                           │                           │
    ┌──────┴──────┐             ┌──────┴──────┐             ┌──────┴──────┐
    │ home-router │             │ alice-laptop│             │ exit-us-west│
    │  10.66.0.20 │             │  10.66.0.30 │             │  10.66.0.100│
    │   [ONLINE]  │             │   [ONLINE]  │             │   [ONLINE]  │
    └──────┬──────┘             └─────────────┘             └─────────────┘
           │
    ┌──────┴──────┐
    │192.168.1.0/24│
    │   Home LAN   │
    └─────────────┘
```

**Web Topology** (Dashboard):
- Interactive SVG/Canvas visualization
- Drag to rearrange nodes
- Click for peer details
- Color-coded health status
- Bandwidth flow indicators

**Implementation**:
```python
def generate_topology_ascii(db: WireGuardDBv2) -> str:
    """Generate ASCII art network topology."""
    cs = db.get_coordination_server()
    routers = db.get_all_subnet_routers()
    remotes = db.get_all_remotes()
    exits = db.get_all_exit_nodes()

    # Build tree structure
    # Render with box-drawing characters
    ...
```

**Priority**: MEDIUM
**Complexity**: MEDIUM (ASCII), HIGH (web)
**Dependencies**: None (ASCII), Web dashboard (web)

---

### 3.3 Configuration Templates

**Problem**: Users often set up similar network patterns repeatedly.

**Solution**: Pre-built templates for common use cases.

**Built-in Templates**:
1. **Personal VPN**: CS + 3 remotes, basic access
2. **Home Access**: CS + home router + remotes, full LAN access
3. **Multi-Site Office**: CS + 2 site routers + remotes
4. **Privacy Exit**: CS + exit nodes + remotes
5. **Family Network**: CS + multiple routers + many remotes

**Template Format**:
```yaml
# templates/home-access.yaml
name: Home Access
description: Access your home network from anywhere
version: 1

entities:
  coordination_server:
    prompt: "Coordination server public IP or hostname"

  subnet_routers:
    - name_prompt: "Home router hostname"
      network_prompt: "Home LAN network (e.g., 192.168.1.0/24)"

  remotes:
    count_prompt: "How many remote devices?"
    access_level: full_access

post_setup:
  - "Deploy configs to coordination server"
  - "Deploy config to home router"
  - "Use QR codes or manual config for remote devices"
```

**User Experience**:
```
=== SETUP FROM TEMPLATE ===

Choose a template:
  1. Personal VPN - Basic cloud VPN for personal devices
  2. Home Access - Access your home LAN from anywhere
  3. Multi-Site - Connect multiple office locations
  4. Privacy Exit - Route internet through exit nodes
  5. Custom - Start from scratch

Choice: 2

=== HOME ACCESS SETUP ===

Step 1/4: Coordination Server
  Public IP or hostname: vps.example.com

Step 2/4: Home Router
  Hostname [home-router]:
  LAN network: 192.168.1.0/24

Step 3/4: Remote Devices
  How many devices? 3

  Device 1 hostname: laptop
  Device 2 hostname: phone
  Device 3 hostname: tablet

Step 4/4: Review

  Coordination Server: vps.example.com (10.66.0.1)
  Home Router: home-router (10.66.0.20) -> 192.168.1.0/24
  Remotes:
    - laptop (10.66.0.30) [full_access]
    - phone (10.66.0.31) [full_access]
    - tablet (10.66.0.32) [full_access]

Create this network? [Y/n]:
```

**Priority**: LOW
**Complexity**: LOW
**Dependencies**: None

---

### 3.4 Mobile Companion App Specification

**Problem**: Mobile device management requires desktop access for QR codes.

**Solution**: Specification for companion app (native or PWA).

**Core Features**:
- View network status
- See own device's config and QR code
- Request key rotation
- View connection health

**Architecture**:
```
Mobile App <─── HTTPS ───> wg-friend web API
                               │
                          wireguard.db
```

**API Endpoints for Mobile**:
```
GET  /api/mobile/status          # Overall network health
GET  /api/mobile/me              # Current device info
GET  /api/mobile/me/config       # My WireGuard config
GET  /api/mobile/me/qr           # QR code for my config
POST /api/mobile/me/rotate       # Request key rotation
GET  /api/mobile/peers           # List peer names/status (limited)
```

**Security for Mobile**:
- Device-specific API tokens
- Token tied to peer permanent_guid
- Limited scope (can only see/modify own data)
- Expiring tokens with refresh

**Note**: This is a specification for future development, not immediate implementation.

**Priority**: LOW
**Complexity**: HIGH
**Dependencies**: Web dashboard, REST API

---

### 3.5 Guided Troubleshooting Wizard

**Problem**: Users struggle to diagnose connectivity issues.

**Solution**: Interactive troubleshooting flow with automated checks.

**Diagnostic Steps**:
```
=== TROUBLESHOOTING: alice-laptop ===

Running diagnostics...

[PASS] WireGuard interface exists
[PASS] Private key configured
[PASS] Coordination server endpoint reachable (32ms)
[FAIL] No recent handshake (last: 2 hours ago)
[PASS] DNS resolution working

Likely Issue: Handshake not completing

Possible Causes:
  1. Firewall blocking UDP 51820 (most common)
  2. NAT traversal issue
  3. Key mismatch between peers

Suggested Actions:
  1. Check firewall on alice-laptop
  2. Verify CS has latest public key for alice-laptop
  3. Try manual ping: ping -c 3 10.66.0.1

Run automated fix attempts? [y/N]:
```

**Automated Checks**:
- Interface existence and configuration
- Key verification (pubkey matches DB)
- Endpoint reachability (ICMP, UDP)
- Handshake recency
- DNS resolution through tunnel
- Route table verification
- MTU issues (MSS clamping)

**Priority**: MEDIUM
**Complexity**: MEDIUM
**Dependencies**: SSH access for remote diagnostics

---

## Pillar 4: Operational Excellence

### 4.1 Compliance Reporting

**Problem**: Enterprises need documentation for audits (SOC2, ISO27001, etc.).

**Solution**: Automated compliance report generation.

**Report Types**:
1. **Access Control Report**: Who has access to what
2. **Key Rotation Report**: Rotation history and compliance
3. **Configuration Change Report**: All changes with timestamps
4. **Network Inventory Report**: Complete asset list

**Sample Report**:
```
═══════════════════════════════════════════════════════════════════════
                    WIREGUARD NETWORK COMPLIANCE REPORT
                         Generated: 2024-12-04 14:30 UTC
═══════════════════════════════════════════════════════════════════════

EXECUTIVE SUMMARY
─────────────────
Total Peers:              12
Key Rotation Compliance:  100% (all within 90-day policy)
Access Levels Documented: 100%
Last Security Incident:   None recorded

NETWORK INVENTORY
─────────────────
Coordination Server: cs.example.com (10.66.0.1)
  - Keys last rotated: 2024-10-15
  - SSH deployment: Enabled

Subnet Routers: 2
  - home-router (10.66.0.20) -> 192.168.1.0/24
  - office-router (10.66.0.21) -> 10.0.0.0/24

Remote Clients: 8
  - full_access: 3 (alice-laptop, bob-laptop, admin-workstation)
  - vpn_only: 4 (guest-1, guest-2, contractor-1, contractor-2)
  - lan_only: 1 (media-server)

Exit Nodes: 2
  - exit-us-west (us-west.example.com)
  - exit-eu-central (eu.example.com)

KEY ROTATION HISTORY (Last 90 days)
───────────────────────────────────
2024-11-15  alice-laptop    Scheduled rotation
2024-11-15  bob-laptop      Scheduled rotation
2024-10-20  guest-1         Access revocation (key invalidated)
2024-10-15  cs.example.com  Scheduled rotation

ACCESS LEVEL CHANGES (Last 90 days)
───────────────────────────────────
2024-11-01  contractor-2    full_access -> vpn_only (contract ended)
2024-10-15  media-server    vpn_only -> lan_only (restricted access)

CONFIGURATION DEPLOYMENTS (Last 90 days)
────────────────────────────────────────
2024-11-15  cs.example.com  Config deployed (12 peers)
2024-11-15  home-router     Config deployed (1 peer)
2024-11-01  cs.example.com  Config deployed (access level change)
```

**Export Formats**: Markdown, PDF, JSON, CSV

**Priority**: MEDIUM (enterprise)
**Complexity**: LOW
**Dependencies**: Audit logging

---

### 4.2 Disaster Recovery Automation

**Problem**: No automated way to restore network from backup.

**Solution**: Comprehensive backup and restore system.

**Backup Contents**:
- SQLite database (encrypted if configured)
- Generated configurations
- SSH host keys (optional)
- Encryption metadata

**Backup Commands**:
```bash
# Create encrypted backup
wg-friend backup create --encrypt --output backup-2024-12-04.wgfb

# List contents of backup
wg-friend backup list backup-2024-12-04.wgfb

# Restore from backup
wg-friend backup restore backup-2024-12-04.wgfb

# Scheduled backup to S3/GCS/local
wg-friend backup schedule --destination s3://mybucket/wgf-backups/
```

**Backup Format** (.wgfb):
```
wireguard-friend-backup-v1/
├── manifest.json           # Backup metadata, checksums
├── database.db.enc         # Encrypted SQLite database
├── configs/                # Generated .conf files
│   ├── cs.conf
│   ├── home-router.conf
│   └── ...
└── metadata/
    ├── encryption.json     # Encryption metadata (salt, etc.)
    └── version.json        # WG Friend version info
```

**Priority**: HIGH
**Complexity**: MEDIUM
**Dependencies**: Database encryption (for secure backup)

---

### 4.3 Multi-Tenancy Support

**Problem**: MSPs and enterprises need to manage multiple isolated networks.

**Solution**: Tenant isolation with centralized management.

**Architecture**:
```
wg-friend
├── tenant: personal
│   └── wireguard.db
├── tenant: client-acme
│   └── wireguard.db
└── tenant: client-globex
    └── wireguard.db
```

**Implementation**:
```bash
# Create new tenant
wg-friend tenant create client-acme

# Switch tenant
wg-friend tenant use client-acme

# List tenants
wg-friend tenant list

# Current tenant shown in prompt
wg-friend [client-acme]>
```

**User Experience**:
```
=== TENANT MANAGEMENT ===

Current tenant: personal

Available tenants:
  1. personal (12 peers, last active: today)
  2. client-acme (8 peers, last active: yesterday)
  3. client-globex (24 peers, last active: 3 days ago)

Actions:
  1. Switch tenant
  2. Create new tenant
  3. Delete tenant
  4. Export tenant
```

**Priority**: LOW (enterprise)
**Complexity**: LOW
**Dependencies**: None

---

### 4.4 Configuration Drift Detection

**Problem**: Manual changes to deployed configs go undetected.

**Solution**: Compare deployed configs against database state.

**Detection Process**:
1. SSH to each host
2. Read current `/etc/wireguard/*.conf`
3. Compare against generated config from database
4. Report differences

**User Experience**:
```
=== CONFIGURATION DRIFT REPORT ===

Checking 4 hosts...

cs.example.com:
  [OK] wg0.conf matches database

home-router:
  [DRIFT] wg0.conf differs from database
    Line 12: DNS = 1.1.1.1
    Expected: DNS = 8.8.8.8

office-router:
  [OK] wg0.conf matches database

alice-laptop:
  [SKIP] No SSH access configured

Summary: 1 drift detected, 2 OK, 1 skipped

Actions:
  1. View detailed diff for home-router
  2. Redeploy to fix drift
  3. Update database to match deployed
```

**Priority**: MEDIUM
**Complexity**: LOW
**Dependencies**: SSH deployment

---

## Pillar 5: Advanced Networking

### 5.1 Multi-Hop Routing

**Problem**: Cannot route traffic through multiple WireGuard hops (e.g., remote -> CS -> exit).

**Solution**: Support for chained peer relationships.

**Use Cases**:
- Force all traffic through CS before exiting
- Route through specific geographic paths
- Add defense-in-depth layers

**Current Flow** (single hop):
```
Remote ──WG──> CS ──WG──> Other Peers
       ──WG──> Exit ───> Internet
```

**Multi-Hop Flow**:
```
Remote ──WG──> CS ──WG──> Exit ───> Internet
                    │
                    └──WG──> Other Peers
```

**Implementation Considerations**:
- Requires CS to forward traffic to exit
- Adds latency (double encryption/decryption)
- CS sees all traffic (privacy consideration)
- More complex AllowedIPs configuration

**Config Generation**:
```ini
# Remote config (multi-hop through CS)
[Interface]
PrivateKey = ...
Address = 10.66.0.30/32

# CS handles all routing
[Peer]
PublicKey = <cs-pubkey>
Endpoint = cs.example.com:51820
AllowedIPs = 0.0.0.0/0, ::/0    # Everything through CS
PersistentKeepalive = 25
```

```ini
# CS config (forwards to exit)
[Interface]
PrivateKey = ...
Address = 10.66.0.1/32
PostUp = ip route add default via <exit-vpn-ip> table 100
PostUp = ip rule add from 10.66.0.30/32 lookup 100

# Exit node peer
[Peer]
PublicKey = <exit-pubkey>
Endpoint = exit.example.com:51820
AllowedIPs = 0.0.0.0/0, ::/0
```

**Priority**: LOW
**Complexity**: HIGH
**Dependencies**: Exit nodes, advanced routing

---

### 5.2 Traffic Splitting Rules

**Problem**: All-or-nothing routing; can't route specific traffic through exit.

**Solution**: Policy-based routing rules per peer.

**Rule Types**:
```yaml
# Route specific destinations through exit
rules:
  - name: "Streaming services through exit"
    match:
      destinations:
        - netflix.com
        - hulu.com
    action: route_through_exit
    exit: us-west

  - name: "Work traffic direct"
    match:
      destinations:
        - 10.0.0.0/8
        - company.com
    action: direct

  - name: "Default"
    action: split_tunnel  # Internet direct, VPN through CS
```

**Implementation**:
- Generate complex AllowedIPs based on rules
- Use `nftables` or `iptables` marks for advanced routing
- Provide rule templates for common scenarios

**Priority**: LOW
**Complexity**: HIGH
**Dependencies**: Exit nodes, policy routing

---

### 5.3 Split DNS with Fallback

**Problem**: DNS configuration is static; no fallback for failure.

**Solution**: Intelligent DNS configuration with fallback chains.

**Configuration**:
```sql
CREATE TABLE dns_config (
    id INTEGER PRIMARY KEY,
    entity_type TEXT,
    entity_id INTEGER,
    primary_dns TEXT,         -- 10.66.0.1 (CS as DNS)
    secondary_dns TEXT,       -- 1.1.1.1 (public fallback)
    domain_overrides TEXT     -- JSON: {"home.lan": "192.168.1.1"}
);
```

**Generated Config**:
```ini
[Interface]
DNS = 10.66.0.1, 1.1.1.1
PostUp = resolvectl domain %i ~home.lan
PostUp = resolvectl dns %i 10.66.0.1 1.1.1.1
```

**Priority**: MEDIUM
**Complexity**: MEDIUM
**Dependencies**: None

---

### 5.4 IPv6-First Deployment Mode

**Problem**: IPv6 is second-class; ULAs are optional afterthought.

**Solution**: First-class IPv6 support with optional IPv4.

**Changes**:
- IPv6 as default address family
- Auto-generate ULA prefix (fd00::/8)
- IPv4 becomes optional overlay
- Dual-stack by default, IPv6-only option

**User Experience**:
```
=== NETWORK ADDRESSING ===

IPv6 ULA prefix [fd66::/64]:
IPv4 network [10.66.0.0/24]:
  (Press Enter for none to skip IPv4)

Address allocation:
  Coordination Server: fd66::1, 10.66.0.1
  Subnet Router range: fd66::14-fd66::1d, 10.66.0.20-29
  Remote range:        fd66::1e-fd66::63, 10.66.0.30-99
  Exit range:          fd66::64-fd66::77, 10.66.0.100-119
```

**Priority**: LOW
**Complexity**: MEDIUM
**Dependencies**: None

---

## Pillar 6: Integration & Ecosystem

### 6.1 REST API

**Problem**: No programmatic access for automation and integration.

**Solution**: Comprehensive REST API with OpenAPI specification.

**API Design**:
```yaml
openapi: 3.0.0
info:
  title: WireGuard Friend API
  version: 1.0.0

paths:
  /api/v1/status:
    get:
      summary: Network status overview
      responses:
        200:
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/NetworkStatus'

  /api/v1/peers:
    get:
      summary: List all peers
    post:
      summary: Add new peer

  /api/v1/peers/{id}:
    get:
      summary: Get peer details
    patch:
      summary: Update peer
    delete:
      summary: Remove peer

  /api/v1/peers/{id}/rotate:
    post:
      summary: Rotate peer keys

  /api/v1/peers/{id}/config:
    get:
      summary: Get generated config

  /api/v1/deploy:
    post:
      summary: Deploy configurations

  /api/v1/audit:
    get:
      summary: Audit log entries
```

**Authentication**:
- API tokens with scopes
- Optional mutual TLS
- Rate limiting

**Priority**: MEDIUM
**Complexity**: MEDIUM
**Dependencies**: None

---

### 6.2 Prometheus Metrics Export

**Problem**: No integration with existing monitoring infrastructure.

**Solution**: Prometheus-compatible metrics endpoint.

**Metrics**:
```
# HELP wgf_peer_total Total number of peers
# TYPE wgf_peer_total gauge
wgf_peer_total{type="remote"} 8
wgf_peer_total{type="subnet_router"} 2
wgf_peer_total{type="exit_node"} 2

# HELP wgf_peer_last_handshake_seconds Time since last handshake
# TYPE wgf_peer_last_handshake_seconds gauge
wgf_peer_last_handshake_seconds{peer="alice-laptop"} 45
wgf_peer_last_handshake_seconds{peer="bob-phone"} 120

# HELP wgf_peer_rx_bytes_total Total bytes received
# TYPE wgf_peer_rx_bytes_total counter
wgf_peer_rx_bytes_total{peer="alice-laptop"} 2457862144

# HELP wgf_key_age_days Days since last key rotation
# TYPE wgf_key_age_days gauge
wgf_key_age_days{peer="alice-laptop"} 45

# HELP wgf_exit_node_health Exit node health status
# TYPE wgf_exit_node_health gauge
wgf_exit_node_health{exit="us-west"} 1
wgf_exit_node_health{exit="eu-central"} 0.5
```

**Endpoint**: `wg-friend metrics serve --port 9100`

**Grafana Dashboard**: Provide pre-built dashboard JSON.

**Priority**: MEDIUM
**Complexity**: LOW
**Dependencies**: Bandwidth tracking

---

### 6.3 Webhook Notifications

**Problem**: No way to trigger external systems on events.

**Solution**: Configurable webhook delivery.

**Event Types**:
- `peer.added`
- `peer.removed`
- `peer.rotated`
- `peer.offline`
- `deployment.completed`
- `alert.triggered`

**Webhook Payload**:
```json
{
  "event": "peer.rotated",
  "timestamp": "2024-12-04T14:30:00Z",
  "data": {
    "peer_id": 5,
    "peer_name": "alice-laptop",
    "old_key_prefix": "abc123...",
    "new_key_prefix": "xyz789..."
  },
  "signature": "sha256=..."
}
```

**Configuration**:
```sql
CREATE TABLE webhook (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    url TEXT NOT NULL,
    secret TEXT,                  -- For HMAC signature
    events TEXT NOT NULL,         -- JSON array of event types
    enabled BOOLEAN DEFAULT 1
);
```

**Priority**: MEDIUM
**Complexity**: LOW
**Dependencies**: None

---

### 6.4 Ansible Collection

**Problem**: Infrastructure-as-code users can't integrate WireGuard Friend.

**Solution**: Ansible collection for declarative management.

**Collection Structure**:
```
ansible_collections/
└── wgfriend/
    └── network/
        ├── plugins/
        │   └── modules/
        │       ├── wgf_peer.py
        │       ├── wgf_router.py
        │       ├── wgf_exit.py
        │       └── wgf_deploy.py
        └── roles/
            └── setup/
```

**Playbook Example**:
```yaml
- name: Configure WireGuard network
  hosts: localhost
  collections:
    - wgfriend.network

  tasks:
    - name: Ensure peer exists
      wgf_peer:
        name: alice-laptop
        access_level: full_access
        state: present

    - name: Rotate old keys
      wgf_peer:
        name: "{{ item }}"
        rotate: yes
      loop: "{{ peers_needing_rotation }}"
      when: peer_age_days > 90

    - name: Deploy configurations
      wgf_deploy:
        targets: all
        restart: yes
```

**Priority**: LOW
**Complexity**: HIGH
**Dependencies**: REST API (preferred) or CLI wrapper

---

### 6.5 Terraform Provider

**Problem**: Terraform users can't manage WireGuard Friend resources.

**Solution**: Terraform provider for WireGuard Friend.

**Resources**:
```hcl
terraform {
  required_providers {
    wgfriend = {
      source = "graemester/wgfriend"
    }
  }
}

provider "wgfriend" {
  database = "/path/to/wireguard.db"
  # Or API endpoint if using REST API
  api_url = "http://localhost:8080"
  api_key = var.wgf_api_key
}

resource "wgfriend_peer" "alice" {
  hostname     = "alice-laptop"
  access_level = "full_access"

  lifecycle {
    prevent_destroy = true
  }
}

resource "wgfriend_exit_node" "us_west" {
  hostname    = "exit-us-west"
  endpoint    = "us-west.example.com"
  listen_port = 51820
}

data "wgfriend_peer_config" "alice" {
  peer_id = wgfriend_peer.alice.id
}

output "alice_config" {
  value     = data.wgfriend_peer_config.alice.content
  sensitive = true
}
```

**Priority**: LOW
**Complexity**: HIGH
**Dependencies**: REST API

---

## Pillar 7: Intelligent Operations

### 7.1 Anomaly Detection

**Problem**: Unusual network patterns go unnoticed.

**Solution**: ML-based anomaly detection for traffic patterns.

**Detection Categories**:
1. **Usage Anomalies**: Unusual bandwidth consumption
2. **Connection Anomalies**: Unexpected connection patterns
3. **Timing Anomalies**: Activity at unusual times
4. **Geographic Anomalies**: Connections from unexpected locations

**Implementation Approach**:
- Establish baseline from historical data
- Use statistical methods (z-score, IQR) for simple anomalies
- Optional: sklearn for more sophisticated detection

**Alert Example**:
```
[ANOMALY] alice-laptop bandwidth spike

Normal baseline: 2-5 GB/day
Current (24h):   45 GB

Possible causes:
  - Large file transfer
  - Backup running through VPN
  - Compromised device (data exfiltration)

Actions:
  1. View bandwidth timeline
  2. Check running processes (requires SSH)
  3. Temporarily restrict access
  4. Mark as expected (update baseline)
```

**Priority**: LOW
**Complexity**: HIGH
**Dependencies**: Bandwidth tracking, alerting system

---

### 7.2 Predictive Maintenance

**Problem**: Key rotations and maintenance are reactive.

**Solution**: Predict when maintenance will be needed.

**Predictions**:
- **Key Rotation**: "3 peers will need rotation in next 7 days"
- **Capacity**: "Exit node will reach 80% capacity in 2 weeks"
- **Health**: "home-router showing degraded handshake times"

**Implementation**:
- Track trends in bandwidth, latency, handshake frequency
- Linear regression for capacity predictions
- Threshold-based early warnings

**User Experience**:
```
=== PREDICTIVE INSIGHTS ===

Upcoming Maintenance:
  [Dec 10] Key rotation due: alice-phone, bob-laptop
  [Dec 15] Key rotation due: guest-access

Capacity Alerts:
  [Dec 20] exit-us-west projected 80% bandwidth capacity
           Recommendation: Add additional exit node

Health Trends:
  [WATCH] home-router: handshake latency trending up
          Current: 45ms (was 20ms last month)
          Possible cause: ISP issues or hardware degradation
```

**Priority**: LOW
**Complexity**: MEDIUM
**Dependencies**: Bandwidth tracking, historical data

---

### 7.3 Natural Language Interface (Experimental)

**Problem**: Complex operations require memorizing commands.

**Solution**: Natural language command interpretation.

**Examples**:
```
> add a new phone for alice with full access
Creating remote: alice-phone
Access level: full_access
IP assigned: 10.66.0.35

> rotate keys for all guests
Found 3 peers matching "guests": guest-1, guest-2, guest-3
Rotate all 3? [y/N]: y

> show who used the most bandwidth this week
Top bandwidth consumers (7 days):
  1. exit-us-west     312 GB
  2. home-router       89 GB
  3. alice-laptop      24 GB

> deploy everything
Deploying to 4 hosts...
  cs.example.com: OK
  home-router: OK
  office-router: OK
  exit-us-west: OK
```

**Implementation**:
- Pattern matching for common intents
- Optional: Local LLM integration (ollama) for complex queries
- Fallback to menu/command clarification

**Priority**: LOW (experimental)
**Complexity**: HIGH
**Dependencies**: None

---

## Implementation Priorities

### Phase 1: Foundation (Q1 2025)
High-impact, low-complexity features that strengthen the core.

| Feature | Priority | Complexity | Effort |
|---------|----------|------------|--------|
| Database Encryption | HIGH | MEDIUM | 2 weeks |
| Scheduled Key Rotation | HIGH | LOW | 1 week |
| Security Audit Logging | HIGH | LOW | 1 week |
| Disaster Recovery | HIGH | MEDIUM | 2 weeks |
| Configuration Drift Detection | MEDIUM | LOW | 1 week |

### Phase 2: Operations (Q2 2025)
Monitoring, alerting, and operational visibility.

| Feature | Priority | Complexity | Effort |
|---------|----------|------------|--------|
| Bandwidth Tracking | MEDIUM | LOW | 1 week |
| Exit Node Failover | HIGH | MEDIUM | 2 weeks |
| Alerting System | MEDIUM | MEDIUM | 2 weeks |
| Compliance Reporting | MEDIUM | LOW | 1 week |
| Visual Topology (ASCII) | MEDIUM | MEDIUM | 1 week |

### Phase 3: Integration (Q3 2025)
API and ecosystem connectivity.

| Feature | Priority | Complexity | Effort |
|---------|----------|------------|--------|
| REST API | MEDIUM | MEDIUM | 3 weeks |
| Prometheus Metrics | MEDIUM | LOW | 1 week |
| Webhook Notifications | MEDIUM | LOW | 1 week |
| PSK Management | MEDIUM | LOW | 1 week |
| Troubleshooting Wizard | MEDIUM | MEDIUM | 2 weeks |

### Phase 4: Experience (Q4 2025)
User experience and accessibility.

| Feature | Priority | Complexity | Effort |
|---------|----------|------------|--------|
| Web Dashboard | MEDIUM | HIGH | 4 weeks |
| Configuration Templates | LOW | LOW | 1 week |
| Split DNS | MEDIUM | MEDIUM | 1 week |
| 2FA for Operations | MEDIUM | MEDIUM | 2 weeks |
| Multi-Tenancy | LOW | LOW | 1 week |

### Phase 5: Advanced (2026+)
Power features and experimental capabilities.

| Feature | Priority | Complexity | Effort |
|---------|----------|------------|--------|
| Ansible Collection | LOW | HIGH | 4 weeks |
| Terraform Provider | LOW | HIGH | 4 weeks |
| Multi-Hop Routing | LOW | HIGH | 3 weeks |
| Traffic Splitting | LOW | HIGH | 3 weeks |
| Anomaly Detection | LOW | HIGH | 4 weeks |
| Natural Language | LOW | HIGH | Ongoing |
| Mobile App | LOW | HIGH | 8 weeks |
| Geographic Routing | LOW | HIGH | 3 weeks |

---

## Technical Debt & Refinements

### Comment Preservation (V2 Vision)
Current: ~22% comment preservation
Target: 100% preservation via full AST model

**Work Remaining**:
- Integrate shell_parser.py into production import
- Complete comment positioning system
- Remove raw block fallback
- Round-trip testing with edge cases

### Code Quality Improvements
- Add type hints throughout codebase
- Increase test coverage to 90%+
- Document all public APIs
- Standardize error handling

### Performance Optimization
- Index optimization for large deployments
- Lazy loading for peer lists
- Caching for repeated queries
- Batch operations for bulk changes

---

## Success Metrics

### Adoption Metrics
- GitHub stars and forks
- PyPI downloads
- Binary downloads
- Community contributions

### Quality Metrics
- Test coverage percentage
- Mean time to fix bugs
- User-reported issues per release
- Documentation completeness

### Feature Metrics
- Feature adoption rate
- User satisfaction surveys
- Performance benchmarks
- Security audit results

---

## Conclusion

This roadmap transforms WireGuard Friend from a capable configuration manager into a comprehensive VPN operations platform. The phased approach ensures continuous delivery of value while building toward ambitious long-term goals.

Key themes:
1. **Security First**: Encryption, auditing, and compliance
2. **Operational Excellence**: Monitoring, alerting, and automation
3. **User Accessibility**: Web interface, templates, and troubleshooting
4. **Ecosystem Integration**: APIs, metrics, and IaC support
5. **Intelligent Operations**: Predictions and anomaly detection

The foundation laid in v1.x provides a solid base. These enhancements will position WireGuard Friend as the definitive tool for WireGuard network management across personal, professional, and enterprise use cases.

---

*Document Version: 1.0*
*Created: December 2024*
*Author: Claude Code Analysis*
