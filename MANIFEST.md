# 📦 WireGuard Friend - File Manifest

**Critical files needed to run WireGuard Friend on your system.**

---

## ✅ Required Files (Must Have)

### Core Scripts

```
wg-friend-onboard.py        ← Import existing WireGuard configs
wg-friend-maintain.py       ← Interactive maintenance and management
requirements.txt            ← Python dependencies
```

### Source Code

```
src/database.py             ← Database operations and schema
src/raw_parser.py           ← Config file parsing
src/keygen.py               ← WireGuard key generation
src/ssh_client.py           ← SSH deployment functionality
src/qr_generator.py         ← QR code generation for mobile devices
```

### Documentation (Recommended)

```
README.md                   ← Project overview and quick start
DOCUMENTATION.md            ← Complete documentation index
WHERE_TO_RUN.md             ← Installation location guide
QUICK_START.md              ← Step-by-step tutorial
```

**Minimum to run:** 2 scripts + 5 source files + 1 requirements file = **8 files**

---

## 📖 Documentation Files (Highly Recommended)

### User Guides

```
README.md                   ← Start here! (~400 lines)
WHERE_TO_RUN.md             ← Where to install (~500 lines)
QUICK_START.md              ← Complete tutorial (~450 lines)
DOCUMENTATION.md            ← Documentation index (~300 lines)
```

### Technical Documentation

```
ARCHITECTURE.md             ← Design and internals (~650 lines)
BACKUP_RESTORE.md           ← Database backup guide (~350 lines)
RESTRICTED_IP_ACCESS.md     ← IP/port access control (~200 lines)
```

### Support Files

```
MANIFEST.md                 ← This file (critical files list)
tests/README.md             ← Testing documentation (~150 lines)
```

**Total documentation:** 9 markdown files, ~3,000 lines

---

## 🔧 Optional But Useful

### Utility Scripts

```
backup-database.sh          ← Automated database backup (highly recommended!)
```

### Test & Demo Scripts

```
tests/test-suite.py         ← Comprehensive test suite (32 tests)
tests/demo-new-peer.py      ← Demo: Create new peer programmatically
tests/demo-remote-assistance.py ← Demo: Remote assistance peer
tests/test-maintain.py      ← Demo: Database queries and listing
```

### Migration Scripts

```
tests/migrate-add-allowed-ports.py        ← Add port restrictions (if upgrading)
tests/migrate-add-remote-assistance.py    ← Add remote_assistance access level
tests/migrate-restricted-ip.py            ← Add restricted IP support
```

---

## 💾 Generated/Runtime Files

### Created on First Run

```
wg-friend.db                ← SQLite database (created automatically)
import/                     ← Directory for configs to import (create manually)
output/                     ← Directory for generated configs (created automatically)
```

### Created by Backup Script

```
backups/                    ← Database backups (created by backup-database.sh)
```

### SSH Keys (Optional)

```
~/.ssh/wg-friend-*          ← SSH keys for deployment (created by setup wizard)
```

---

## 📂 Complete Directory Structure

```
wireguard-friend/
│
├── 🎯 MUST HAVE (Core Functionality)
│   ├── wg-friend-onboard.py          ✅ Required
│   ├── wg-friend-maintain.py         ✅ Required
│   ├── requirements.txt              ✅ Required
│   └── src/
│       ├── database.py               ✅ Required
│       ├── raw_parser.py             ✅ Required
│       ├── keygen.py                 ✅ Required
│       ├── ssh_client.py             ✅ Required
│       └── qr_generator.py           ✅ Required
│
├── 📖 SHOULD HAVE (Documentation)
│   ├── README.md                     ⭐ Highly recommended
│   ├── DOCUMENTATION.md              ⭐ Highly recommended
│   ├── WHERE_TO_RUN.md               ⭐ Highly recommended
│   ├── QUICK_START.md                ⭐ Highly recommended
│   ├── ARCHITECTURE.md               🔧 For power users
│   ├── BACKUP_RESTORE.md             🔧 For backup/restore
│   ├── RESTRICTED_IP_ACCESS.md       🔧 For advanced access control
│   └── MANIFEST.md                   📋 This file
│
├── 🔧 NICE TO HAVE (Utilities)
│   ├── backup-database.sh            💾 Automated backups
│   └── tests/
│       ├── README.md                 📖 Testing guide
│       ├── test-suite.py             🧪 Test suite
│       ├── demo-new-peer.py          🎮 Demo script
│       ├── demo-remote-assistance.py 🎮 Demo script
│       ├── test-maintain.py          🎮 Demo script
│       └── migrate-*.py              🔄 Migration scripts
│
└── 💾 RUNTIME (Generated)
    ├── wg-friend.db                  📊 Created on first run
    ├── import/                       📥 Create manually, place configs here
    ├── output/                       📤 Created automatically
    └── backups/                      💾 Created by backup script
```

---

## 🚀 Quick Setup Checklist

### 1. Copy Required Files

```bash
# Minimum files needed:
wg-friend-onboard.py
wg-friend-maintain.py
requirements.txt
src/database.py
src/raw_parser.py
src/keygen.py
src/ssh_client.py
src/qr_generator.py
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

Dependencies:
- `rich` - Beautiful terminal UI
- `qrcode` - QR code generation
- `pillow` - Image processing for QR codes
- `paramiko` - SSH connectivity

### 3. Copy Documentation (Recommended)

```bash
README.md
DOCUMENTATION.md
WHERE_TO_RUN.md
QUICK_START.md
```

### 4. Copy Utilities (Optional)

```bash
backup-database.sh
tests/test-suite.py
tests/demo-*.py
```

### 5. Create Runtime Directories

```bash
mkdir -p import output
```

### 6. You're Ready!

```bash
# Place configs in import/
cp /path/to/configs/*.conf import/

# Import
./wg-friend-onboard.py

# Manage
./wg-friend-maintain.py
```

---

## 📦 Distribution Packages

### Minimal Package (Core Only)

**Size:** ~50 KB (code only)

```
wg-friend-core/
├── wg-friend-onboard.py
├── wg-friend-maintain.py
├── requirements.txt
└── src/
    ├── database.py
    ├── raw_parser.py
    ├── keygen.py
    ├── ssh_client.py
    └── qr_generator.py
```

**Usage:** For users who just want the tool, no docs.

---

### Standard Package (Core + Docs)

**Size:** ~150 KB (code + documentation)

```
wireguard-friend/
├── wg-friend-onboard.py
├── wg-friend-maintain.py
├── requirements.txt
├── README.md
├── DOCUMENTATION.md
├── WHERE_TO_RUN.md
├── QUICK_START.md
├── MANIFEST.md
└── src/
    ├── database.py
    ├── raw_parser.py
    ├── keygen.py
    ├── ssh_client.py
    └── qr_generator.py
```

**Usage:** Recommended for most users.

---

### Complete Package (Everything)

**Size:** ~250 KB (code + docs + tests + utilities)

```
wireguard-friend/
├── All core files
├── All documentation
├── backup-database.sh
├── tests/
│   ├── test-suite.py
│   ├── demo-*.py
│   ├── migrate-*.py
│   └── README.md
├── ARCHITECTURE.md
├── BACKUP_RESTORE.md
└── RESTRICTED_IP_ACCESS.md
```

**Usage:** For power users, developers, contributors.

---

## 🔍 File Details

### wg-friend-onboard.py (~1,100 lines)

**Purpose:** Import existing WireGuard configs into database

**Functions:**
- Parse WireGuard config files
- Extract raw blocks and structured data
- Store in SQLite database
- Verify perfect fidelity reconstruction
- Interactive wizard for new networks

**Dependencies:**
- src/database.py
- src/raw_parser.py
- src/keygen.py
- rich (for UI)

---

### wg-friend-maintain.py (~1,800 lines)

**Purpose:** Interactive maintenance and management

**Functions:**
- Create new peers
- Rotate keys
- Deploy configs via SSH
- Generate QR codes
- Manage access levels
- List and query entities
- Remote assistance peer creation

**Dependencies:**
- src/database.py
- src/keygen.py
- src/qr_generator.py
- src/ssh_client.py
- rich (for UI)

---

### src/database.py (~750 lines)

**Purpose:** SQLite database operations

**Functions:**
- Schema initialization (12 tables)
- CRUD operations for all entities
- Config reconstruction from database
- Query and filter entities
- Foreign key management

**Dependencies:**
- SQLite3 (built-in)

---

### src/raw_parser.py (~400 lines)

**Purpose:** Parse WireGuard config files

**Functions:**
- Extract raw blocks (Interface, Peer, PostUp/PostDown)
- Parse structured data from blocks
- Preserve exact formatting
- Handle comments and whitespace
- Detect config type (CS, SN, peer)

**Dependencies:**
- None (pure Python)

---

### src/keygen.py (~50 lines)

**Purpose:** WireGuard key generation

**Functions:**
- Generate WireGuard keypairs
- Derive public keys from private keys
- Generate preshared keys

**Dependencies:**
- subprocess (calls `wg` command)

---

### src/ssh_client.py (~200 lines)

**Purpose:** SSH deployment

**Functions:**
- Connect to remote servers
- Upload config files
- Execute remote commands
- Handle authentication
- Error handling and retries

**Dependencies:**
- paramiko (SSH library)

---

### src/qr_generator.py (~100 lines)

**Purpose:** Generate QR codes

**Functions:**
- Generate QR code from config text
- Save as PNG image
- ASCII terminal display
- Error correction

**Dependencies:**
- qrcode (QR code generation)
- pillow (image processing)

---

## 📊 File Size Summary

| Category | Files | Lines | Size |
|----------|-------|-------|------|
| Core Scripts | 2 | ~2,900 | ~90 KB |
| Source Code | 5 | ~1,500 | ~50 KB |
| Documentation | 9 | ~3,000 | ~150 KB |
| Tests & Utilities | 10+ | ~1,500 | ~50 KB |
| **Total** | **26+** | **~8,900** | **~340 KB** |

**Runtime database:** Varies (typically 50-500 KB depending on network size)

---

## 🔐 Files Containing Sensitive Data

### Generated at Runtime (DO NOT COMMIT TO GIT)

```
wg-friend.db                ← Contains private keys! (.gitignore ✅)
import/*.conf               ← Original configs with keys (.gitignore ✅)
output/*.conf               ← Generated configs with keys (.gitignore ✅)
~/.ssh/wg-friend-*          ← SSH keys for deployment (user directory)
backups/*.tar.gz            ← Backup archives (.gitignore ✅)
```

### Safe to Version Control

```
All *.py files               ← Source code only
All *.md files               ← Documentation only
requirements.txt             ← Dependencies only
backup-database.sh           ← Script only, no data
```

---

## ✅ Verification Checklist

After copying files, verify you have:

```bash
# Core files exist
[ -f wg-friend-onboard.py ] && echo "✓ Onboard script"
[ -f wg-friend-maintain.py ] && echo "✓ Maintain script"
[ -f requirements.txt ] && echo "✓ Requirements"

# Source directory exists
[ -d src ] && echo "✓ Source directory"
[ -f src/database.py ] && echo "✓ Database module"
[ -f src/raw_parser.py ] && echo "✓ Parser module"
[ -f src/keygen.py ] && echo "✓ Keygen module"
[ -f src/ssh_client.py ] && echo "✓ SSH module"
[ -f src/qr_generator.py ] && echo "✓ QR module"

# Documentation exists
[ -f README.md ] && echo "✓ README"
[ -f DOCUMENTATION.md ] && echo "✓ Documentation index"

# Scripts are executable
[ -x wg-friend-onboard.py ] && echo "✓ Onboard executable"
[ -x wg-friend-maintain.py ] && echo "✓ Maintain executable"

# Dependencies installed
python3 -c "import rich" 2>/dev/null && echo "✓ rich installed"
python3 -c "import qrcode" 2>/dev/null && echo "✓ qrcode installed"
python3 -c "import paramiko" 2>/dev/null && echo "✓ paramiko installed"
```

---

## 🎯 What You Can Safely Delete

### If You're Tight on Space

**Can delete:**
- `tests/` directory (unless you need testing)
- `ARCHITECTURE.md` (unless you need internals)
- `archive/` directory (legacy files)
- `docs/` directory (legacy setup notes)

**Keep:**
- Core scripts (wg-friend-*.py)
- Source code (src/)
- README.md and DOCUMENTATION.md
- requirements.txt

**Minimal viable install:** ~140 KB (core + basic docs)

---

## 📝 Summary

**To run WireGuard Friend, you need:**

1. ✅ **8 core files** (2 scripts + 5 source modules + 1 requirements)
2. ⭐ **4 documentation files** (highly recommended)
3. 🔧 **1 backup script** (optional but smart)
4. 🧪 **Test suite** (optional, for verification)

**Total essential:** ~12 files, ~200 KB

**Everything works from these files.** The rest is extras, examples, and deep-dive documentation.

---

**💡 Pro tip:** Keep the entire repo intact for updates and upgrades. Disk space is cheap, and having all documentation available is valuable!

**📦 See [DOCUMENTATION.md](DOCUMENTATION.md) for a complete guide to all files and their purposes.**
