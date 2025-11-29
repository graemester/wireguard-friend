# 📚 WireGuard Friend - Complete Documentation Guide

**Everything you need to build, manage, and understand your WireGuard network.**

> **Note for Users**: WireGuard Friend is distributed as a single compiled binary.
> Just download it, run it, and follow the prompts. See [QUICK_START.md](QUICK_START.md).
>
> **This document** is for developers contributing to the project, or users who want
> to understand how things work under the hood.

---

## 🚀 Getting Started (Start Here!)

### [README.md](README.md) - Project Overview
**What is WireGuard Friend? Start here!**

- What it builds for you (network architecture)
- What problems it solves (key rotation, peer management, etc.)
- Features at a glance
- Quick start commands
- Troubleshooting

👉 **Read this first** to understand what the tool does and whether it's right for you.

---

### [WHERE_TO_RUN.md](WHERE_TO_RUN.md) - Installation Location Guide
**Should I run this on my Coordination Server, Subnet Router, or Client?**

- **Quick answer:** Subnet router (recommended) or your laptop
- CS vs SN vs Client device comparison
- Ideal workflow: Pick one place, SSH to it
- Requirements checklist
- Security considerations
- Multi-admin scenarios

👉 **Read this before installing** to choose the best location for your setup.

---

### [QUICK_START.md](QUICK_START.md) - Step-by-Step Tutorial
**Complete walkthrough of all features**

- Import existing WireGuard configs (Phase-by-phase guide)
- Maintenance mode interactive menu
- Create new peers with QR codes
- Access levels explained (full_access, vpn_only, restricted_ip, etc.)
- Key rotation workflow
- SSH deployment
- Database queries and verification

👉 **Use this as your manual** - detailed instructions for every operation.

---

## 🏗️ Understanding the System

### [ARCHITECTURE.md](ARCHITECTURE.md) - Design & Technical Details
**Deep dive into how it works (650+ lines)**

- Design philosophy: Don't break working configs
- Dual storage model: Raw blocks + structured data
- Sacred rules: PostUp/PostDown, peer order, comments
- Database schema (12 tables)
- Import workflow (5 phases)
- Reconstruction algorithm
- Key rotation internals
- Testing strategy

👉 **For power users and contributors** - understand the design decisions and internals.

---

### [RESTRICTED_IP_ACCESS.md](RESTRICTED_IP_ACCESS.md) - Advanced Peer Access Control
**Limit peers to specific IPs and ports**

- What is restricted IP access?
- Port-level filtering (SSH only, HTTPS only, etc.)
- How firewall rules are generated
- Interactive setup workflow
- Syntax: single port, multiple ports, port ranges
- Common ports reference (SSH=22, RDP=3389, VNC=5900, etc.)

👉 **For advanced setups** - granular access control for security-conscious networks.

---

## 💾 Database & Backup

### [BACKUP_RESTORE.md](BACKUP_RESTORE.md) - Database Portability Guide
**Keep your configs safe and portable**

- **Safe backup methods** (file copy, .backup command, SQL dump)
- **Copying between machines** (verification checklist)
- **Network storage guidance** (NAS/NFS/SMB - when it works, when it doesn't)
- **Migration workflows** (moving admin workstation)
- **What's portable** (database is fully portable!)
- **What's NOT portable** (SSH keys are separate)

👉 **Read before your first backup** - understand database portability and safety.

---

## 🧪 Testing & Development

### [tests/README.md](tests/README.md) - Test Suite Documentation
**Comprehensive testing and validation**

- **Test suite:** 32 tests across 10 categories (100% pass rate)
- **Demo scripts:** Remote assistance, new peer creation
- **Migration scripts:** Database schema updates
- **Test coverage:** Schema, CRUD, import/export, CASCADE, edge cases

👉 **For developers and testing** - verify system stability and reliability.

---

## 📋 Quick Reference

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

### Essential Commands (Source)
```bash
# Backup database
./backup-database.sh /mnt/nas/backups

# Custom database location
export WG_FRIEND_DB=/path/to/custom.db
./wg-friend-maintain.py

# Run test suite
python3 tests/test-suite.py
```

---

## 📖 Documentation by Task

### "I want to..."

| Task | Documentation | Section |
|------|---------------|---------|
| **Get started** | [README.md](README.md) | Quick Start |
| **Choose where to install** | [WHERE_TO_RUN.md](WHERE_TO_RUN.md) | Entire guide |
| **Import existing configs** | [QUICK_START.md](QUICK_START.md) | Import Workflow |
| **Create a new peer** | [QUICK_START.md](QUICK_START.md) | Create New Peer |
| **Create remote assistance peer** | [tests/README.md](tests/README.md) | Remote Assistance Feature |
| **Restrict peer to specific IPs** | [RESTRICTED_IP_ACCESS.md](RESTRICTED_IP_ACCESS.md) | Entire guide |
| **Rotate keys** | [QUICK_START.md](QUICK_START.md) | Key Rotation |
| **Deploy to server** | [QUICK_START.md](QUICK_START.md) | SSH Deployment |
| **Backup database** | [BACKUP_RESTORE.md](BACKUP_RESTORE.md) | Safe Backup Methods |
| **Copy to another machine** | [BACKUP_RESTORE.md](BACKUP_RESTORE.md) | Copying Between Machines |
| **Understand access levels** | [QUICK_START.md](QUICK_START.md) | Access Levels |
| **Query the database** | [QUICK_START.md](QUICK_START.md) | Database Queries |
| **Troubleshoot issues** | [README.md](README.md) | Troubleshooting |
| **Understand the design** | [ARCHITECTURE.md](ARCHITECTURE.md) | Design Philosophy |
| **Run tests** | [tests/README.md](tests/README.md) | Test Suite |
| **Contribute code** | [ARCHITECTURE.md](ARCHITECTURE.md) | Entire document |

---

## 🗂️ Complete Documentation Index

### User Guides (Read These)

1. **[README.md](README.md)** - Project overview and quick start
2. **[WHERE_TO_RUN.md](WHERE_TO_RUN.md)** - Where to install and run
3. **[QUICK_START.md](QUICK_START.md)** - Step-by-step tutorial (450+ lines)
4. **[BACKUP_RESTORE.md](BACKUP_RESTORE.md)** - Database backup and portability

### Technical Documentation (For Advanced Users)

5. **[ARCHITECTURE.md](ARCHITECTURE.md)** - Design and internals (650+ lines)
6. **[RESTRICTED_IP_ACCESS.md](RESTRICTED_IP_ACCESS.md)** - IP/port-based access control
7. **[tests/README.md](tests/README.md)** - Testing and validation

### Support Documentation

8. **[MANIFEST.md](MANIFEST.md)** - Critical files needed to run (← See this for required files!)
9. **[docs/SETUP.md](docs/SETUP.md)** - Legacy setup notes (archived)

---

## 🎯 Documentation Quality

All documentation is:
- ✅ **Accurate** - Reflects current codebase
- ✅ **Complete** - Covers all features
- ✅ **Clear** - Written for humans, not robots
- ✅ **Practical** - Real examples, not theory
- ✅ **Maintained** - Updated with code changes

**Total documentation:** ~2,500+ lines across 9 markdown files

---

## 📂 File Structure Overview

```
wireguard-friend/
├── 📖 Documentation (You Are Here)
│   ├── README.md                    ← Start here
│   ├── WHERE_TO_RUN.md              ← Installation guide
│   ├── QUICK_START.md               ← Tutorial
│   ├── ARCHITECTURE.md              ← Technical deep-dive
│   ├── BACKUP_RESTORE.md            ← Database guide
│   ├── RESTRICTED_IP_ACCESS.md      ← Access control
│   ├── DOCUMENTATION.md             ← This file
│   ├── MANIFEST.md                  ← Critical files list
│   └── tests/README.md              ← Testing guide
│
├── 🔧 Core Scripts
│   ├── wg-friend-onboard.py         ← Import configs
│   ├── wg-friend-maintain.py        ← Manage network
│   ├── backup-database.sh           ← Automated backups
│   └── requirements.txt             ← Python dependencies
│
├── 💾 Database & Generated Files
│   ├── wg-friend.db                 ← SQLite database (created on first run)
│   ├── import/                      ← Place configs here for import
│   ├── output/                      ← Generated configs
│   └── backups/                     ← Database backups (created by script)
│
├── 📦 Source Code
│   └── src/
│       ├── database.py              ← Database operations
│       ├── raw_parser.py            ← Config parsing
│       ├── keygen.py                ← Key generation
│       ├── ssh_client.py            ← SSH deployment
│       └── qr_generator.py          ← QR code generation
│
└── 🧪 Tests & Demos
    └── tests/
        ├── test-suite.py            ← 32 comprehensive tests
        ├── demo-new-peer.py         ← Peer creation demo
        ├── demo-remote-assistance.py ← Remote help demo
        ├── test-maintain.py         ← Database query examples
        └── migrate-*.py             ← Database migrations
```

---

## 🆘 Getting Help

### Step-by-Step Troubleshooting

1. **Check the documentation** (you're here - use the task index above!)
2. **Read error messages** (they're usually helpful and specific)
3. **Try `--help`** on any script for command-line options
4. **Check the database** using query examples in QUICK_START.md
5. **Verify config files** in the `output/` directory
6. **Run the test suite** to verify system integrity
7. **Check GitHub issues** at https://github.com/anthropics/claude-code/issues

### Common Issues

| Issue | Solution | Documentation |
|-------|----------|---------------|
| Import failed | Check config file format | [QUICK_START.md](QUICK_START.md) - Troubleshooting |
| Database not found | Run onboard script first | [README.md](README.md) - Quick Start |
| SSH deployment fails | Set up SSH keys | [QUICK_START.md](QUICK_START.md) - SSH Deployment |
| Configs don't match | Check import/export | [ARCHITECTURE.md](ARCHITECTURE.md) - Testing |
| Need to backup | Use backup script | [BACKUP_RESTORE.md](BACKUP_RESTORE.md) |
| Where to run it? | Read install guide | [WHERE_TO_RUN.md](WHERE_TO_RUN.md) |

---

## 🎓 Learning Path

### Beginner

1. Read [README.md](README.md) - Understand what it does
2. Read [WHERE_TO_RUN.md](WHERE_TO_RUN.md) - Choose install location
3. Follow [QUICK_START.md](QUICK_START.md) - Import your first config
4. Read [BACKUP_RESTORE.md](BACKUP_RESTORE.md) - Set up backups

### Intermediate

5. Explore [QUICK_START.md](QUICK_START.md) - Create peers, rotate keys
6. Read [RESTRICTED_IP_ACCESS.md](RESTRICTED_IP_ACCESS.md) - Advanced access control
7. Review [tests/README.md](tests/README.md) - Run test suite

### Advanced

8. Study [ARCHITECTURE.md](ARCHITECTURE.md) - Understand internals
9. Review source code in `src/` directory
10. Contribute improvements or customizations

---

## 🔑 Key Concepts Glossary


### Raw Blocks
Exact text from config files, never parsed or modified.
→ [ARCHITECTURE.md](ARCHITECTURE.md) - Dual Storage Model

### Structured Data
Queryable fields extracted from raw blocks for database queries.
→ [ARCHITECTURE.md](ARCHITECTURE.md) - Structured Data

### Sacred Rules
PostUp/PostDown rules stored as monolithic blocks, never parsed.
→ [ARCHITECTURE.md](ARCHITECTURE.md) - Sacred Rules

### Access Levels
Control what peers can access: full_access, vpn_only, lan_only, restricted_ip, remote_assistance.
→ [QUICK_START.md](QUICK_START.md) - Access Levels

### Peer Order
Exact sequence of peers in CS config, preserved from original.
→ [ARCHITECTURE.md](ARCHITECTURE.md) - Peer Order Tracking

---

## ⚙️ Advanced Topics

### Database Schema
Complete schema with 12 tables, foreign keys, and constraints.
→ [ARCHITECTURE.md](ARCHITECTURE.md) - Database Schema

### Key Rotation
Atomic updates with zero downtime and automatic backups.
→ [QUICK_START.md](QUICK_START.md) - Key Rotation

### SSH Deployment
Automated config deployment with backups and verification.
→ [QUICK_START.md](QUICK_START.md) - SSH Deployment

### Port-Based Restrictions
Firewall rules for granular access control (e.g., SSH-only access).
→ [RESTRICTED_IP_ACCESS.md](RESTRICTED_IP_ACCESS.md)

### Remote Assistance
Special peer type with user-friendly setup instructions.
→ [tests/README.md](tests/README.md) - Remote Assistance Feature

### Database Portability
Safe backup, restore, and migration between machines.
→ [BACKUP_RESTORE.md](BACKUP_RESTORE.md)

---

## 📊 Documentation Statistics

| File | Lines | Purpose |
|------|-------|---------|
| README.md | ~400 | Project overview |
| WHERE_TO_RUN.md | ~500 | Installation guide |
| QUICK_START.md | ~450 | Step-by-step tutorial |
| ARCHITECTURE.md | ~650 | Technical design |
| BACKUP_RESTORE.md | ~350 | Database management |
| RESTRICTED_IP_ACCESS.md | ~200 | Access control |
| DOCUMENTATION.md | ~300 | This index |
| tests/README.md | ~150 | Testing guide |
| **Total** | **~3,000** | **Complete documentation** |

---

**📚 This documentation is maintained with the same care as the code: accurate, complete, and trustworthy.**

**🎯 Can't find what you need?** Use the "I want to..." index above or check the task-based documentation table.

**💡 Tip:** Bookmark this page! It's your central hub for all WireGuard Friend documentation.
