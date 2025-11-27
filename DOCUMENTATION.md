# WireGuard Friend - Documentation Index

## Available Documentation

### 1. [README.md](README.md) - Project Overview
**Start here!**

- Quick start guide
- Feature overview  
- Command reference
- Examples
- Troubleshooting

**Best for**: Getting started, understanding what the tool does

---

### 2. [QUICK_START.md](QUICK_START.md) - Detailed Walkthrough
**Step-by-step guide**

- Complete import workflow
- Maintenance mode guide
- Access level explanations
- Database queries
- Common operations
- Safety features

**Best for**: Learning how to use all features

---

### 3. [ARCHITECTURE.md](ARCHITECTURE.md) - Design & Internals
**Deep dive into design**

- Design philosophy (perfect fidelity)
- Dual storage model (raw blocks + structured data)
- Sacred rules (PostUp/PostDown, peer order, etc.)
- Database schema
- Import workflow
- Reconstruction algorithm
- Key rotation
- Testing strategy

**Best for**: Understanding how it works, contributing code

---

## Quick Reference

### Import Configs
```bash
./wg-friend-onboard-v2.py --import-dir import/ --yes
```

### Maintenance Mode
```bash
./wg-friend-maintain.py
```

### View Network
```bash
python3 test-maintain.py
```

### Create New Peer
```bash
python3 demo-new-peer.py
```

### Verify Fidelity
```bash
diff import/coordination.conf output/coordination.conf
```

---

## Documentation by Task

### I want to...

**Import existing configs**
→ [QUICK_START.md](QUICK_START.md) - Section: Import Workflow

**Create a new peer**
→ [QUICK_START.md](QUICK_START.md) - Section: Create New Peer
→ [README.md](README.md) - Examples: Create New Mobile Client

**Rotate keys**
→ [QUICK_START.md](QUICK_START.md) - Section: Key Rotation
→ [README.md](README.md) - Examples: Rotate Compromised Key

**Deploy to server**
→ [QUICK_START.md](QUICK_START.md) - Section: SSH Deployment
→ [README.md](README.md) - Examples: Deploy to Server

**Query the database**
→ [README.md](README.md) - Section: Database Queries
→ [QUICK_START.md](QUICK_START.md) - Section: Database Queries

**Understand access levels**
→ [QUICK_START.md](QUICK_START.md) - Section: Access Levels
→ [ARCHITECTURE.md](ARCHITECTURE.md) - Section: Access Levels

**Troubleshoot issues**
→ [README.md](README.md) - Section: Troubleshooting
→ [QUICK_START.md](QUICK_START.md) - Section: Troubleshooting

**Understand the design**
→ [ARCHITECTURE.md](ARCHITECTURE.md) - Entire document

**Contribute code**
→ [ARCHITECTURE.md](ARCHITECTURE.md) - Design decisions
→ [README.md](README.md) - Development section

---

## Code Documentation

### Source Files

All source files have comprehensive docstrings:

**src/database.py** (442 lines)
- Database operations
- CRUD for all entities
- Reconstruction functions
- Schema initialization

**src/raw_parser.py** (358 lines)
- Raw block extraction
- Structured data parsing
- Config type detection
- Public key derivation

**src/keygen.py**
- Keypair generation
- Public key derivation

**src/ssh_client.py**
- SSH connection handling
- File upload
- Command execution

**src/qr_generator.py**
- QR code generation
- PNG output

### Scripts

**wg-friend-onboard-v2.py**
- 5-phase import workflow
- Raw block + structured data storage
- Perfect fidelity verification

**wg-friend-maintain.py**
- Interactive maintenance menu
- Entity management
- Key rotation
- SSH deployment
- QR code generation

---

## Testing & Examples

### Test Scripts

**test-maintain.py**
- List all entities
- Database query examples
- Verification

**demo-new-peer.py**
- Automated peer creation
- IP allocation demo
- Config generation

### Example Configs

**import/coordination.conf** - Sample CS config (11 peers)
**import/wg0.conf** - Sample subnet router
**import/iphone16.conf** - Sample client

---

## File Structure

```
wireguard-friend/
├── README.md              ← Start here
├── QUICK_START.md         ← Detailed guide
├── ARCHITECTURE.md        ← Design deep-dive
├── DOCUMENTATION.md       ← This file
├── requirements.txt       ← Python deps
│
├── wg-friend-onboard-v2.py    ← Import script
├── wg-friend-maintain.py      ← Maintenance script
├── wg-friend.db              ← SQLite database
│
├── src/                   ← Source modules
│   ├── database.py
│   ├── raw_parser.py
│   ├── keygen.py
│   ├── ssh_client.py
│   └── qr_generator.py
│
├── import/                ← Place configs here
├── output/                ← Generated configs
│
└── tests/
    ├── test-maintain.py
    └── demo-new-peer.py
```

---

## Getting Help

1. **Check documentation** (this index)
2. **Read error messages** (usually helpful)
3. **Try `--help`** on scripts
4. **Check database** with queries
5. **Verify config files** in output/

---

## Key Concepts

### Perfect Fidelity
Reconstructed configs must be byte-for-byte identical to originals.
See: [ARCHITECTURE.md](ARCHITECTURE.md) - Design Philosophy

### Raw Blocks
Exact text from config files, never parsed or modified.
See: [ARCHITECTURE.md](ARCHITECTURE.md) - Dual Storage Model

### Structured Data
Queryable fields extracted from raw blocks.
See: [ARCHITECTURE.md](ARCHITECTURE.md) - Structured Data

### PostUp/PostDown Sacred
These rules are stored as monolithic text blocks, never parsed.
See: [ARCHITECTURE.md](ARCHITECTURE.md) - Sacred Rules

### Access Levels
Control what peers can access: full_access, vpn_only, lan_only, custom.
See: [QUICK_START.md](QUICK_START.md) - Access Levels

---

**All documentation maintained with the same care as the code: accurate, complete, and trustworthy.**
