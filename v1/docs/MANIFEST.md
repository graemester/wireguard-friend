# WireGuard Friend - File Manifest

Files needed to run WireGuard Friend.

---

## Required Files

### Core Scripts

```
v1/wg-friend                ← Main CLI entry point
requirements.txt            ← Python dependencies
```

### CLI Modules

```
v1/cli/init_wizard.py       ← First-run setup wizard
v1/cli/import_configs.py    ← Import existing configs
v1/cli/peer_manager.py      ← Add/remove peers
v1/cli/config_generator.py  ← Generate WireGuard configs
v1/cli/deploy.py            ← SSH deployment
v1/cli/status.py            ← Network status
v1/cli/tui.py               ← Interactive TUI
v1/cli/ssh_setup.py         ← SSH key setup wizard
```

### Core Modules

```
v1/schema_semantic.py       ← Database schema
v1/parser.py                ← Config parser
v1/generator.py             ← Config generator
v1/keygen.py                ← Key generation
v1/network_utils.py         ← Network utilities
v1/config_detector.py       ← Config type detection
v1/comment_system.py        ← Comment handling
v1/formatting.py            ← Formatting preservation
v1/shell_parser.py          ← Shell command parsing
v1/unknown_fields.py        ← Unknown field handling
```

Minimum to run: 1 main script + 8 CLI modules + 10 core modules + requirements = **20 files**

---

## Documentation Files

### User Guides

```
README.md                   ← Project overview
v1/docs/WHERE_TO_RUN.md     ← Installation location guide
v1/quick-start.md           ← Tutorial
v1/COMMAND_REFERENCE.md     ← Command reference
v1/docs/DOCUMENTATION.md    ← Documentation index
```

### Technical Documentation

```
v1/docs/ARCHITECTURE.md     ← Design and internals
v1/docs/BACKUP_RESTORE.md   ← Database backup guide
v1/docs/MANIFEST.md         ← This file
```

Total documentation: 8 markdown files

---

## Optional Files

### Test Scripts

```
v1/test_permanent_guid.py
v1/test_key_validation.py
v1/test_roundtrip.py
v1/integration-tests/
```

### Demo Scripts

```
v1/demo.py
```

### Archive

```
v-alpha/                    ← Original version (archived)
```

---

## Runtime Generated Files

Not included in repository:

```
wireguard.db                ← SQLite database (created by wg-friend)
generated/*.conf            ← WireGuard configs (generated from database)
generated/*.png             ← QR codes (generated with --qr flag)
```

These are created when you run `wg-friend`.

---

## Installation Size

**Minimal install** (required files only): ~200 KB
**With documentation**: ~300 KB
**With tests**: ~400 KB

Python dependencies (requirements.txt) download separately via pip.

---

## Dependencies

See `requirements.txt`:
```
qrcode[pil]                 ← QR code generation
PyNaCl                      ← Curve25519 key operations
```

Install with:
```bash
pip install -r requirements.txt
```

---

## File Locations

### Development (from git)

```
wireguard-friend/
├── README.md
├── requirements.txt
├── v1/                     ← Main codebase
│   ├── wg-friend
│   ├── cli/
│   ├── *.py
│   ├── docs/
│   └── quick-start.md
└── v-alpha/                ← Archived version
```

### Installed (to PATH)

```
/usr/local/bin/wg-friend    ← Symlink to v1/wg-friend
```

Or run directly:
```bash
./v1/wg-friend
```

---

## What You Need to Run

Minimum:
1. Python 3.7+
2. WireGuard tools (`wg`, `wg-quick`)
3. Files listed in "Required Files" section
4. Dependencies from `requirements.txt`

Recommended:
5. Documentation files
6. SSH client (for remote deployments)

That's it. No compilation, no build process.
