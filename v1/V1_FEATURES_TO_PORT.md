# v1 Features Analysis - What to Port to v2

## Executive Summary

Comprehensive review of v1 codebase (3,598 lines) identified **12 major features** that should be ported to v2.

---

## ✅ Already Ported

1. **Config Type Detection** (`ConfigDetector`)
   - 3+ peers → coordination_server
   - FORWARD/POSTROUTING detection
   - Endpoint presence checking
   - **Status:** ✅ Ported to `v2/config_detector.py`

2. **Entity Parsing** (`RawBlockParser`)
   - Bracket delimiter rule
   - Raw block extraction
   - **Status:** ✅ v2 has `entity_parser.py`

3. **Basic CRUD** (Create/Read/Update/Delete peers)
   - Add peer
   - Remove peer
   - Rotate keys
   - **Status:** ✅ v2 has `peer_manager.py`

---

## 🚧 Missing from v2 (High Priority)

### 1. **Live Peer Status Monitoring** ⭐⭐⭐
**File:** `v1/src/peer_manager.py` (701 lines)

**What it does:**
- Runs `wg show` on coordination server via SSH
- Parses output to get peer status
- Shows which peers are online (handshake < 3 minutes)
- Shows transfer stats (RX/TX bytes)
- Shows last handshake time
- Flags old configs (> 6 months)

**Code example:**
```python
@property
def is_online(self) -> bool:
    """Check if peer is online (handshake within last 3 minutes)"""
    if not self.latest_handshake:
        return False
    return (datetime.now() - self.latest_handshake) < timedelta(minutes=3)
```

**Why important:**
- Users need to know who's connected
- Debugging connectivity issues
- Security monitoring (detect unexpected connections)

**Effort to port:** Medium (need SSH integration + parsing)

---

### 2. **Preshared Key (PSK) Support** ⭐⭐⭐
**File:** `v1/wg-friend-maintain.py:1348`

**What it does:**
- Generate preshared keys for additional security
- Add/update PSK for existing peers
- Updates both CS config and peer config
- Post-quantum resistance

**Code highlights:**
```python
def _add_preshared_key(self, peer: Dict):
    """Add or update preshared key for peer"""
    # Generate preshared key
    preshared_key = generate_preshared_key()

    # Update CS peer entry
    # Add PresharedKey line after PublicKey

    # Update client config
    # Add PresharedKey line after Endpoint
```

**Why important:**
- Security best practice
- Post-quantum resistance
- Many users request this

**Effort to port:** Low (just key generation + config updates)

---

### 3. **Port-Based Firewall Rules** ⭐⭐
**File:** `v1/wg-friend-maintain.py:103`

**What it does:**
- Restrict peer access to specific ports on target IPs
- Support for port ranges (e.g., "8000:8999")
- Support for comma-delimited ports (e.g., "22,443,8080")
- Generates iptables FORWARD rules
- Final DROP rule to block everything else

**Code example:**
```python
def _generate_port_firewall_rules(self, peer_ipv4: str, target_ip: str, allowed_ports: Optional[str]):
    """
    Generate firewall rules for port-restricted access

    Args:
        peer_ipv4: Peer's VPN IPv4 address
        target_ip: Target IP address on LAN
        allowed_ports: "22,443,8080" or "8000:8999" or None for all

    Returns:
        (postup_rules, postdown_rules)
    """
```

**Why important:**
- Fine-grained access control beyond "full/vpn/lan"
- Example: Give contractor access ONLY to port 22 on one server
- Security hardening

**Effort to port:** Low (just iptables rule generation)

---

### 4. **SSH Setup Wizard** ⭐⭐
**File:** `v1/wg-friend-maintain.py:353`

**What it does:**
- Interactive SSH key setup
- Generates SSH keypair if needed
- Installs public key to coordination server
- Installs public key to subnet routers
- Tests authentication
- Handles localhost detection (no SSH needed)

**Why important:**
- Many users struggle with SSH setup
- Automates tedious manual steps
- Tests before deployment

**Effort to port:** Medium (SSH interaction + key installation)

---

### 5. **Remote Assist Instructions Generator** ⭐
**File:** `v1/wg-friend-maintain.py:149`

**What it does:**
- Generates comprehensive setup guide for non-technical users
- Platform-specific instructions (Windows/macOS/Linux)
- Step-by-step with screenshots descriptions
- Troubleshooting section
- Saves as `remote-assist.txt`

**Why important:**
- Helping family members/non-tech users
- Remote support scenarios
- Professional client deliverable

**Effort to port:** Low (just templating)

---

### 6. **Individual Config View/Export** ⭐
**Files:** `v1/wg-friend-maintain.py:693, 702, 905, 924`

**What it does:**
- View single config without generating all
- Export single config to file
- View CS config separately
- View router config separately
- View peer config separately

**Why important:**
- Quick lookups (don't need to generate everything)
- Copy/paste specific configs
- Debugging individual entities

**Effort to port:** Low (just read from database + format)

---

### 7. **Per-Peer QR Code Generation** ⭐
**File:** `v1/wg-friend-maintain.py:1244`

**What it does:**
- Generate QR code for specific peer on demand
- Not just during full generation
- Useful for re-sending to user

**Why important:**
- Re-send QR after user loses it
- Don't need to regenerate everything

**Effort to port:** Very Low (just call QR generator)

---

### 8. **Localhost Detection for Deployment** ⭐
**File:** `v1/wg-friend-maintain.py:32`

**What it does:**
```python
def is_local_host(host: str) -> bool:
    """Check if hostname/IP refers to local machine"""
    # Check localhost variants
    # Check local hostname
    # Check local FQDN
    # Compare IP addresses
```

**Why important:**
- Skip SSH for local deployments
- Just copy files directly
- Faster and simpler

**Effort to port:** Low (standalone function)

---

## 🔍 Medium Priority Features

### 9. **Metadata Database** ⭐
**File:** `v1/src/metadata_db.py` (243 lines)

**What it does:**
- Separate metadata storage
- Track peer creation dates
- Track last config generation
- Track deployment history
- Track key rotation history

**Why important:**
- Audit trail
- Compliance reporting
- Historical tracking

**Effort to port:** Medium (database schema extension)

**Note:** v2 has `key_rotation_history` table but not full metadata tracking

---

### 10. **SSH Client Class** ⭐
**File:** `v1/src/ssh_client.py` (227 lines)

**What it does:**
- Robust SSH connection handling
- Context manager support
- Command execution with timeout
- File upload/download
- Connection pooling
- Error handling

**Current v2 status:** v2 uses subprocess.run(['ssh', ...])

**Why important:**
- More robust than subprocess
- Better error messages
- Connection reuse

**Effort to port:** Low (copy class over)

---

### 11. **TUI with Rich Library**
**File:** `v1/src/tui.py` (381 lines)

**What it does:**
- Colored output with Rich
- Tables with borders
- Panels and boxes
- Syntax highlighting
- Progress bars

**Current v2 status:** v2 uses plain text

**Why important:**
- Professional appearance
- Better readability
- Industry standard (Rich library)

**Effort to port:** Low (add rich dependency, update output)

---

### 12. **Config Builder with Templates**
**File:** `v1/src/config_builder.py` (170 lines)

**What it does:**
- Template-based config generation
- Handles edge cases
- Consistent formatting
- Comment preservation

**Current v2 status:** v2 generates directly

**Why important:**
- Proven templates from v1
- Handles edge cases
- Consistent output

**Effort to port:** Low (copy templates)

---

## 📊 Feature Matrix

| Feature | v1 | v2 | Priority | Effort |
|---------|----|----|----------|--------|
| Config detection | ✅ | ✅ | - | - |
| Basic CRUD | ✅ | ✅ | - | - |
| Key rotation | ✅ | ✅ | - | - |
| SSH deployment | ✅ | ✅ | - | - |
| Live peer status | ✅ | ❌ | ⭐⭐⭐ | Medium |
| Preshared keys | ✅ | ❌ | ⭐⭐⭐ | Low |
| Port firewall rules | ✅ | ❌ | ⭐⭐ | Low |
| SSH setup wizard | ✅ | ❌ | ⭐⭐ | Medium |
| Remote assist guide | ✅ | ❌ | ⭐ | Low |
| Individual view/export | ✅ | ❌ | ⭐ | Low |
| Per-peer QR codes | ✅ | ❌ | ⭐ | Very Low |
| Localhost detection | ✅ | ❌ | ⭐ | Low |
| Metadata tracking | ✅ | Partial | ⭐ | Medium |
| SSH client class | ✅ | Partial | ⭐ | Low |
| Rich TUI | ✅ | ❌ | ⭐ | Low |
| Template system | ✅ | ❌ | ⭐ | Low |

---

## 🎯 Recommended Porting Priority

### Phase 1 (Before v1.0.0 Release)
1. **Preshared key support** (Low effort, high value)
2. **Localhost detection** (Low effort, improves UX)
3. **Per-peer QR codes** (Very low effort)

### Phase 2 (v1.1.0)
4. **Live peer status** (Medium effort, killer feature)
5. **SSH setup wizard** (Medium effort, helps onboarding)
6. **Port-based firewall rules** (Low effort, security feature)

### Phase 3 (v1.2.0)
7. **Individual config view/export** (Low effort, convenience)
8. **Remote assist guide generator** (Low effort, nice-to-have)
9. **SSH client class** (Low effort, robustness)
10. **Rich library TUI** (Low effort, polish)

### Future
11. **Metadata database** (Medium effort, enterprise feature)
12. **Template system** (Low effort, refactoring)

---

## 💡 Questions for User

1. **Live peer status**: Do you want this for v1.0.0? It's a killer feature but requires SSH integration.

2. **Preshared keys**: This is security best practice. Include in v1.0.0?

3. **Port firewall rules**: Is this commonly used? Or edge case?

4. **Rich library**: Worth adding the dependency for prettier output? Or keep it lightweight?

5. **SSH class vs subprocess**: Current v2 uses subprocess which works. Upgrade to dedicated SSH class?

---

## 📝 Notes

- v1 had 3,598 lines of well-tested code
- v2 currently has ~2,500 lines
- Many v1 features can be ported quickly (1-2 hours each for low-effort items)
- High-priority features would bring v2 to feature superiority over v1
- Some features (like metadata db) are nice-to-have but not critical

**Total effort estimate for all features:** ~3-4 days of focused work

**Recommendation:** Cherry-pick the high-value, low-effort features for v1.0.0, save the rest for v1.x releases.
