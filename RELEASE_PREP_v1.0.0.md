# v1.0.0 Release Preparation Guide

This guide documents the clean slate release approach for WireGuard Friend v1.0.0.

---

## Background

**The situation:**
- Internal architecture is "v2" (complete rewrite with semantic schema)
- Old releases exist (v0.x) but were never really used (maybe 1 download)
- This is effectively the FIRST real release
- We want to call it v1.0.0 externally (clean slate)

**The solution:**
- ✅ Renamed folders: v1 → v-alpha, v2 → v1
- ✅ Updated all imports and documentation
- Release externally as v1.0.0
- Delete old tags and releases
- Archive old code in v-alpha/ branch for reference
- Start semantic versioning from v1.0.0 forward

---

## Pre-Release Checklist

### 1. Code Cleanup

- [x] Update version in CLI (`v1/wg-friend`) from "v2.0.0" to "v1.0.0"
- [ ] Update README.md with v1.0.0 features
- [ ] Update QUICK_START.md with new commands
- [ ] Update COMMAND_REFERENCE.md with psk, qr, ssh-setup, status --live
- [ ] Check requirements.txt has all dependencies
  - [ ] qrcode[pil]
  - [ ] PyNaCl
  - [ ] (others)

### 2. Feature Verification

All 5 v1.0.0 features implemented:

- [x] Localhost detection (Feature 1)
- [x] Preshared key support (Feature 2)
- [x] Per-peer QR codes (Feature 3)
- [x] Live peer status monitoring (Feature 4)
- [x] SSH setup wizard (Feature 5)

### 3. Testing

Manual testing with real database:

- [ ] Test import flow with real WireGuard configs
- [ ] Test generate configs
- [ ] Test deploy (with localhost detection)
- [ ] Test psk command
- [ ] Test qr command
- [ ] Test ssh-setup wizard
- [ ] Test status --live
- [ ] Test TUI (maintain mode)

### 4. Documentation

- [ ] Review README.md for accuracy
- [ ] Review QUICK_START.md for accuracy
- [ ] Review ARCHITECTURE.md for accuracy
- [ ] Create CHANGELOG.md for v1.0.0
- [ ] Ensure all new features documented

---

## Release Steps

### Step 1: Archive Old v1 Code

Create an archive branch for the old v1 codebase (for reference):

```bash
# Create archive branch from commit where v1 code still existed
git checkout <commit-before-v2-rewrite>
git checkout -b archive/v1-original
git push origin archive/v1-original

# Return to main
git checkout main
```

### Step 2: Delete Old Releases and Tags

**On GitHub:**

1. Go to https://github.com/graemester/wireguard-friend/releases
2. Delete all existing releases:
   - Click "Edit" on each release
   - Click "Delete this release"
   - Confirm deletion

**On local machine:**

```bash
# List all tags
git tag

# Delete old tags locally
git tag -d v0.1.0  # (or whatever old tags exist)
git tag -d v0.2.0
# ... repeat for all old tags

# Delete tags from remote
git push origin --delete v0.1.0
git push origin --delete v0.2.0
# ... repeat for all old tags
```

### Step 3: Create v1.0.0 Tag and Release

```bash
# Ensure you're on main branch and up to date
git checkout main
git pull origin main

# Create annotated tag for v1.0.0
git tag -a v1.0.0 -m "Release v1.0.0 - First stable release

Features:
- Complete WireGuard network management
- Import existing configs with type detection
- Smart routing (auto-detect import/init/maintain)
- Peer management (add/remove/modify)
- Key rotation with permanent GUID tracking
- Localhost detection for deployments
- Preshared key (PSK) support
- Per-peer QR code generation
- Live peer status monitoring (wg show)
- SSH setup wizard
- Interactive TUI mode
- Config generation from semantic database
- SSH deployment with automatic backup

Documentation:
- Comprehensive README
- Quick start guide
- Architecture documentation
- Command reference

This is the first stable release, representing a complete rewrite
with a semantic database schema and robust configuration management."

# Push tag to remote
git push origin v1.0.0
```

### Step 4: Create GitHub Release

**On GitHub:**

1. Go to https://github.com/graemester/wireguard-friend/releases
2. Click "Draft a new release"
3. Select tag: v1.0.0
4. Release title: "v1.0.0 - First Stable Release"
5. Description:

```markdown
# WireGuard Friend v1.0.0

First stable release! 🎉

This is a complete rewrite with a semantic database schema, robust configuration management, and a comprehensive set of features for managing WireGuard VPN networks.

## Highlights

- **Import existing configs** with automatic type detection (coordination server, subnet router, client)
- **Smart CLI routing** - just run `wg-friend` and it figures out what to do
- **Peer management** - add, remove, rotate keys with permanent GUID tracking
- **Preshared keys** - post-quantum resistance support
- **Live status monitoring** - see who's connected in real-time
- **SSH setup wizard** - one-time setup for passwordless deployments
- **QR codes** - generate on demand for mobile devices
- **Interactive TUI** - full-featured maintenance mode

## Installation

```bash
git clone https://github.com/graemester/wireguard-friend.git
cd wireguard-friend
pip install -r requirements.txt

# Add to PATH (optional)
sudo ln -s $(pwd)/v1/wg-friend /usr/local/bin/wg-friend
```

## Quick Start

```bash
# Import existing configs
wg-friend  # Just run it, it'll guide you

# Or start fresh
wg-friend init

# Then use
wg-friend add peer
wg-friend generate
wg-friend deploy
wg-friend status --live
```

## Documentation

- [README](README.md) - Overview and installation
- [Quick Start](v1/QUICK_START_V2.md) - Detailed walkthrough
- [Architecture](v1/ARCHITECTURE.md) - Design philosophy
- [Command Reference](v1/COMMAND_REFERENCE.md) - All commands

## What's New in v1.0.0

All features implemented:

### Core Features
- ✅ Import existing WireGuard configs
- ✅ Auto-detect config types (coordination server, subnet router, client)
- ✅ Smart CLI routing
- ✅ Peer management (add/remove/modify)
- ✅ Key rotation with permanent GUID tracking
- ✅ Config generation from database
- ✅ SSH deployment with backup

### New in v1.0.0
- ✅ **Localhost detection** - automatic detection of local deployments (skip SSH)
- ✅ **Preshared key support** - add/update PSK for post-quantum resistance
- ✅ **Per-peer QR codes** - generate QR for specific peer on demand
- ✅ **Live peer status** - real-time monitoring with `wg show` parsing
- ✅ **SSH setup wizard** - interactive setup for passwordless deployment

### Interactive Features
- ✅ Interactive TUI mode
- ✅ Full-featured maintenance mode
- ✅ Guided wizards for all operations

## Requirements

- Python 3.7+
- WireGuard tools (`wg`, `wg-quick`)
- SSH client (for remote deployments)
- qrcode library (for QR generation): `pip install qrcode[pil]`

## Known Limitations

- No port-based firewall rules yet (planned for v1.1.0)
- No remote assist guide generator (planned for v1.1.0)
- Plain text output (Rich library TUI planned for v1.2.0)

## Roadmap

**v1.1.0** (next minor release):
- Port-based firewall rules
- Individual config view/export
- Remote assist guide generator

**v1.2.0** (future):
- Enhanced metadata tracking
- Rich library TUI
- Template system

## Contributors

- Graeme (graemester)
- Claude Code (AI pair programmer)

## License

[Your license here]
```

6. Click "Publish release"

### Step 5: Update README Badge (Optional)

Add release badge to README.md:

```markdown
[![Release](https://img.shields.io/github/v/release/graemester/wireguard-friend)](https://github.com/graemester/wireguard-friend/releases)
```

---

## Post-Release

### Announce Release

- [ ] Create discussion post on GitHub
- [ ] Share on relevant forums/communities (if applicable)
- [ ] Update any external documentation

### Monitor

- [ ] Watch for issues
- [ ] Respond to questions
- [ ] Track feature requests for v1.1.0

### Plan Next Release

Start planning v1.1.0:
- Port-based firewall rules
- Individual config view/export
- Remote assist guide generator

---

## Version Numbering Strategy Going Forward

**Semantic Versioning (semver):**

- **Major (v2.0.0):** Breaking changes to database schema or CLI
- **Minor (v1.1.0):** New features, backward compatible
- **Patch (v1.0.1):** Bug fixes, backward compatible

**Example progression:**
```
v1.0.0 → v1.0.1 (bug fix)
v1.0.1 → v1.1.0 (new features)
v1.1.0 → v1.1.1 (bug fix)
v1.1.1 → v2.0.0 (breaking change)
```

---

## Notes

**Why "v2" folder but v1.0.0 release?**

- "v2" refers to internal architecture (rewrite with semantic schema)
- v1.0.0 is the FIRST real public release
- Folder name doesn't need to match release version
- Users see v1.0.0, developers see v2/ architecture

**Why delete old releases?**

- Nobody used them (maybe 1 download total)
- Clean slate is clearer for users
- Avoids confusion about version history
- This is effectively the first release

**What about old v1 code?**

- Archived in `archive/v1-original` branch
- Still accessible for reference
- Not deleted, just archived

---

## Checklist Summary

**Before Release:**
- [x] Update version to v1.0.0 in CLI
- [ ] Update documentation
- [ ] Test all features
- [ ] Create CHANGELOG.md

**Release:**
- [ ] Archive old v1 code
- [ ] Delete old tags and releases
- [ ] Create v1.0.0 tag
- [ ] Create GitHub release
- [ ] Update README badge

**After Release:**
- [ ] Announce release
- [ ] Monitor for issues
- [ ] Plan v1.1.0

---

## Ready to Release!

Once the checklist is complete, you're ready to tag and release v1.0.0.

The clean slate approach gives you a fresh start with semantic versioning
going forward, while keeping all the history and old code accessible.

🎉 First stable release of WireGuard Friend!
