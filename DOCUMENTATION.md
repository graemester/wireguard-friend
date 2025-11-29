# WireGuard Friend - Documentation Index

> **Note for Users**: WireGuard Friend is distributed as a single compiled binary.
> Just download it, run it, and follow the prompts. See [QUICK_START.md](QUICK_START.md).
>
> **This document** is for developers contributing to the project, or users who want
> to understand how things work under the hood.

---

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

### Running (Binary Distribution)
```bash
# Download wg-friend binary, then:
mkdir ~/wireguard-friend && cd ~/wireguard-friend
wg-friend
# Follow the interactive prompts
```

### Running (From Source)
```bash
# Clone repo and install dependencies
pip install -r requirements.txt
./wg-friend              # Unified entry point
# Or use individual scripts:
./wg-friend-onboard.py   # Import/wizard mode
./wg-friend-maintain.py  # Maintenance mode
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

### Entry Points

**wg-friend** (wrapper script)
- Unified entry point for binary distribution
- Calls `src/app.py`

**src/app.py**
- Main application logic
- State detection (has database → maintenance, else → onboard)
- Self-update mechanism
- First-run setup flow
- Location checking and home directory management

### Source Modules

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

### Legacy Scripts (still functional)

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

### For Users (Binary Distribution)
```
~/wireguard-friend/        ← Your working directory
├── wg-friend.db           ← SQLite database (created on first run)
├── import/                ← Place configs here for import
└── output/                ← Generated configs
```

### Source Repository (For Developers)
```
wireguard-friend/
├── README.md              ← Start here
├── QUICK_START.md         ← User guide
├── ARCHITECTURE.md        ← Design deep-dive
├── DOCUMENTATION.md       ← This file (developer reference)
├── requirements.txt       ← Python dependencies
│
├── wg-friend              ← Unified entry point (wrapper)
├── wg-friend.spec         ← PyInstaller build config
├── wg-friend-onboard.py   ← Import/wizard script
├── wg-friend-maintain.py  ← Maintenance script
│
├── src/                   ← Source modules
│   ├── app.py             ← Main application logic
│   ├── database.py
│   ├── keygen.py
│   ├── ssh_client.py
│   └── qr_generator.py
│
├── docs/
│   ├── BUILDING.md        ← How to build releases
│   └── SETUP.md
│
├── .github/workflows/
│   └── release.yml        ← Automated release builds
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
3. **Use the menu** - wg-friend is interactive and menu-driven
4. **Check database** with queries (option in maintenance menu)
5. **Verify config files** in output/
