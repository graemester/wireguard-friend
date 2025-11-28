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
- Wizard mode for new setups
- Maintenance mode guide
- Access level explanations
- Database queries
- Common operations
- Safety features

**Best for**: Learning how to use all features

---

### 3. [ARCHITECTURE.md](ARCHITECTURE.md) - Design & Internals
**Deep dive into design**

- Dual storage model (text blocks + structured data)
- Design rules (PostUp/PostDown, peer order, etc.)
- Database schema
- Import workflow
- Key rotation
- Access levels

**Best for**: Understanding how it works, contributing code

---

## Quick Reference

### Import Configs
```bash
./wg-friend-onboard.py --import-dir import/
```

### Create from Scratch
```bash
mkdir -p import
./wg-friend-onboard.py --import-dir import/
# Wizard mode activates when no configs found
```

### Maintenance Mode
```bash
./wg-friend-maintain.py
```

---

## Documentation by Task

### I want to...

**Import existing configs**
→ [QUICK_START.md](QUICK_START.md) - Section: Choose Your Setup Path

**Create a new network from scratch**
→ [QUICK_START.md](QUICK_START.md) - Section: Option B (Wizard)

**Create a new peer**
→ [QUICK_START.md](QUICK_START.md) - Section: Create New Peer

**Rotate keys**
→ [QUICK_START.md](QUICK_START.md) - Section: Rotate Peer Keys

**Deploy to server**
→ [QUICK_START.md](QUICK_START.md) - Section: Deploy Configuration

**Query the database**
→ [QUICK_START.md](QUICK_START.md) - Section: Database Queries

**Understand access levels**
→ [QUICK_START.md](QUICK_START.md) - Section: Access Levels

**Troubleshoot issues**
→ [QUICK_START.md](QUICK_START.md) - Section: Troubleshooting

**Understand the design**
→ [ARCHITECTURE.md](ARCHITECTURE.md)

---

## Code Documentation

### Source Files

**src/database.py**
- Database operations
- CRUD for all entities
- Config generation
- Schema initialization

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

**wg-friend-onboard.py**
- Import workflow
- Wizard mode for new setups
- Database storage

**wg-friend-maintain.py**
- Interactive maintenance menu
- Entity management
- Key rotation
- SSH deployment
- QR code generation

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
├── wg-friend-onboard.py   ← Import/wizard script
├── wg-friend-maintain.py  ← Maintenance script
├── wg-friend.db           ← SQLite database
│
├── src/                   ← Source modules
│   ├── database.py
│   ├── keygen.py
│   ├── ssh_client.py
│   └── qr_generator.py
│
├── import/                ← Place configs here
├── output/                ← Generated configs
│
└── tests/
```

---

## Key Concepts

### Access Levels
Control what peers can access: full_access, vpn_only, lan_only, restricted_ip.
See: [QUICK_START.md](QUICK_START.md) - Access Levels

### Restricted IP Access
Limit specific peers to access only certain IPs and ports.
See: [QUICK_START.md](QUICK_START.md) - Access Levels

### PostUp/PostDown Rules
These rules are stored as text blocks, preserving your iptables configuration.
See: [ARCHITECTURE.md](ARCHITECTURE.md) - Design Rules

---

## Getting Help

1. **Check documentation** (this index)
2. **Read error messages** (usually helpful)
3. **Try `--help`** on scripts
4. **Check database** with queries
5. **Verify config files** in output/
