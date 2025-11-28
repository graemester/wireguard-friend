# 📦 WireGuard Friend - Release Guide

**How to create and distribute releases for end users.**

---

## The Problem

**Development repo** contains everything:
- Source code ✅ (users need this)
- Documentation ✅ (users need this)
- Tests ❌ (developers need, users don't)
- Archive files ❌ (legacy, users don't need)
- Git metadata ❌ (users don't need)

**Users should get** only what they need to run the tool.

---

## GitHub's Built-in Mechanism

### `.gitattributes` with `export-ignore`

When you create a **GitHub Release**, the auto-generated "Source code" archives automatically exclude files marked with `export-ignore`:

```bash
# .gitattributes
tests/ export-ignore          # Exclude tests
archive/ export-ignore         # Exclude legacy files
.gitignore export-ignore       # Exclude git metadata
.gitattributes export-ignore   # Exclude this file
```

**This works for:** GitHub's auto-generated release archives

**This doesn't work for:** Custom distributions, PyPI packages, or `git clone`

---

## Our Three-Tier Distribution Strategy

### Package 1: Minimal (~50 KB)

**For:** Users who just want the tool, no documentation

**Includes:**
```
wg-friend-onboard.py
wg-friend-maintain.py
requirements.txt
src/database.py
src/raw_parser.py
src/keygen.py
src/ssh_client.py
src/qr_generator.py
README.md (basic info only)
MANIFEST.md
```

**Use case:** Embedded systems, minimal installs, advanced users

---

### Package 2: Standard (~150 KB) ⭐ Recommended

**For:** Most users

**Includes:**
```
All minimal files +
backup-database.sh
WHERE_TO_RUN.md
QUICK_START.md
BACKUP_RESTORE.md
RESTRICTED_IP_ACCESS.md
DOCUMENTATION.md
```

**Use case:** Normal deployment, recommended for everyone

---

### Package 3: Complete (~250 KB)

**For:** Power users, developers, contributors

**Includes:**
```
All standard files +
ARCHITECTURE.md
tests/test-suite.py
tests/demo-*.py
tests/migrate-*.py
tests/README.md
```

**Use case:** Development, testing, contributions

---

## Creating a Release

### Step 1: Prepare the Release

```bash
# Ensure everything is committed
git status

# Update version in files if needed
# (Currently no version file, but could add one)

# Run tests
python3 tests/test-suite.py

# Ensure all tests pass (100%)
```

---

### Step 2: Create Distribution Packages

```bash
# Create all three distribution packages
./create-distribution.sh v1.0.0

# This creates:
#   dist/wireguard-friend-minimal-v1.0.0.tar.gz
#   dist/wireguard-friend-v1.0.0.tar.gz          (standard)
#   dist/wireguard-friend-complete-v1.0.0.tar.gz
#   dist/SHA256SUMS
```

---

### Step 3: Test the Packages

```bash
# Extract and test the standard package
cd /tmp
tar xzf ~/wireguard-friend/dist/wireguard-friend-v1.0.0.tar.gz
cd wireguard-friend-v1.0.0

# Install dependencies
pip install -r requirements.txt

# Test basic functionality
./wg-friend-onboard.py --help
./wg-friend-maintain.py --help

# Verify files are present
ls -la
cat MANIFEST.md

# Clean up
cd ~
rm -rf /tmp/wireguard-friend-v1.0.0
```

---

### Step 4: Create GitHub Release

**Via GitHub Web Interface:**

1. Go to: https://github.com/YOUR_USERNAME/wireguard-friend/releases
2. Click "Draft a new release"
3. **Tag version:** v1.0.0 (must start with 'v')
4. **Release title:** WireGuard Friend v1.0.0
5. **Description:** Write release notes (see template below)
6. **Attach files:**
   - `wireguard-friend-minimal-v1.0.0.tar.gz`
   - `wireguard-friend-v1.0.0.tar.gz` ⭐ Mark as recommended
   - `wireguard-friend-complete-v1.0.0.tar.gz`
   - `SHA256SUMS`
7. Check "Set as the latest release"
8. Click "Publish release"

**Via GitHub CLI:**

```bash
# Create release
gh release create v1.0.0 \
  --title "WireGuard Friend v1.0.0" \
  --notes-file RELEASE_NOTES.md \
  dist/wireguard-friend-minimal-v1.0.0.tar.gz \
  dist/wireguard-friend-v1.0.0.tar.gz \
  dist/wireguard-friend-complete-v1.0.0.tar.gz \
  dist/SHA256SUMS
```

---

## Release Notes Template

````markdown
# WireGuard Friend v1.0.0

**Build and manage reliable WireGuard networks with perfect fidelity.**

## What's New in v1.0.0

### New Features
- Remote assistance peer type with user-friendly setup instructions
- Port-based IP restrictions (SSH-only, HTTPS-only, etc.)
- Automated database backup script
- Custom database location via environment variable
- Comprehensive documentation (3,000+ lines)

### Improvements
- Enhanced test suite (32 tests, 100% pass rate)
- Better error messages and validation
- Improved SSH deployment workflow

### Bug Fixes
- Fixed foreign key CASCADE for proper cleanup
- Fixed firewall rule generation for port restrictions

## Downloads

**Recommended for most users:**
- 📦 [wireguard-friend-v1.0.0.tar.gz](link) (~150 KB)
  - Core scripts + full documentation + backup utility

**Minimal install:**
- 📦 [wireguard-friend-minimal-v1.0.0.tar.gz](link) (~50 KB)
  - Core scripts only, minimal docs

**Complete package:**
- 📦 [wireguard-friend-complete-v1.0.0.tar.gz](link) (~250 KB)
  - Everything including tests and development tools

**Checksums:**
- [SHA256SUMS](link)

## Installation

```bash
# Download and extract (standard package)
wget https://github.com/USER/wireguard-friend/releases/download/v1.0.0/wireguard-friend-v1.0.0.tar.gz
tar xzf wireguard-friend-v1.0.0.tar.gz
cd wireguard-friend-v1.0.0

# Install dependencies
pip install -r requirements.txt

# Start using
./wg-friend-onboard.py
./wg-friend-maintain.py
```

## Documentation

- 📖 [README.md](link) - Quick start guide
- 📍 [WHERE_TO_RUN.md](link) - Installation location guide
- 📚 [QUICK_START.md](link) - Complete tutorial
- 💾 [BACKUP_RESTORE.md](link) - Database backup guide
- 📋 [MANIFEST.md](link) - File inventory

Full documentation: [DOCUMENTATION.md](link)

## Requirements

- Python 3.8+
- WireGuard installed on target systems
- SSH access to WireGuard hosts (for deployments)

## Changelog

See [CHANGELOG.md](link) for complete version history.

## Support

- 📖 Documentation: See DOCUMENTATION.md in the package
- 🐛 Issues: https://github.com/USER/wireguard-friend/issues
- 💬 Discussions: https://github.com/USER/wireguard-friend/discussions
````

---

## Verification After Release

### Users Should Be Able To:

```bash
# Download standard package
wget https://github.com/USER/wireguard-friend/releases/download/v1.0.0/wireguard-friend-v1.0.0.tar.gz

# Verify checksum
sha256sum wireguard-friend-v1.0.0.tar.gz
# Compare with SHA256SUMS file

# Extract
tar xzf wireguard-friend-v1.0.0.tar.gz
cd wireguard-friend-v1.0.0

# Install
pip install -r requirements.txt

# Run
./wg-friend-onboard.py --help

# No errors about missing files
# No test files cluttering the directory
# All documentation present and readable
```

---

## What Gets Excluded

### From GitHub Auto-Generated Archives (via .gitattributes)

```
tests/                  # Test suite and demos
archive/                # Legacy files
.gitignore              # Git metadata
.gitattributes          # Git metadata
```

### From Custom Distribution Packages (via create-distribution.sh)

**Minimal excludes:**
- All documentation except README.md and MANIFEST.md
- backup-database.sh
- All tests
- All advanced docs

**Standard excludes:**
- Tests
- ARCHITECTURE.md
- Archive files

**Complete excludes:**
- Archive files only
- Git metadata

---

## Git vs Distribution

### What's in Git (Development)

```
wireguard-friend/
├── Core scripts ✅
├── Source code ✅
├── All documentation ✅
├── Tests ✅
├── Archive (legacy) ✅
├── .git/ ✅
├── .gitignore ✅
├── .gitattributes ✅
└── This is for developers
```

### What Users Get (Standard Distribution)

```
wireguard-friend-v1.0.0/
├── Core scripts ✅
├── Source code ✅
├── User documentation ✅
├── backup-database.sh ✅
├── requirements.txt ✅
└── This is for end users
```

---

## Automation Opportunities

### Future Improvements

1. **GitHub Actions:** Auto-create distributions on git tag
2. **Version file:** Single source of truth for version number
3. **CHANGELOG.md:** Auto-generated from commit messages
4. **PyPI package:** `pip install wireguard-friend`
5. **Docker image:** Containerized version

### Example GitHub Action

```yaml
name: Create Release

on:
  push:
    tags:
      - 'v*'

jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Create distributions
        run: ./create-distribution.sh ${{ github.ref_name }}
      - name: Create release
        uses: softprops/action-gh-release@v1
        with:
          files: dist/*.tar.gz
```

---

## Best Practices

### Version Numbering

Use **Semantic Versioning** (semver.org):

```
v1.0.0 - Major.Minor.Patch

v1.0.0 - Initial release
v1.0.1 - Bug fix (backward compatible)
v1.1.0 - New feature (backward compatible)
v2.0.0 - Breaking change (not backward compatible)
```

### Release Checklist

- [ ] All tests pass (`python3 tests/test-suite.py`)
- [ ] Documentation is up to date
- [ ] CHANGELOG.md is updated
- [ ] Version number incremented
- [ ] Distribution packages created
- [ ] Packages tested on clean system
- [ ] Release notes written
- [ ] GitHub release created
- [ ] Checksums verified
- [ ] Announcement posted (if applicable)

---

## Summary

**For GitHub Releases:**
1. Use `.gitattributes` to exclude test/dev files from auto-generated archives
2. Create custom distribution packages with `create-distribution.sh`
3. Upload packages to GitHub Release
4. Include checksums and clear documentation

**Users get:**
- Only what they need (no tests/dev files)
- Clear package options (minimal/standard/complete)
- Verified checksums
- Complete documentation
- Easy installation

**Developers keep:**
- Complete repo with all history
- All tests and development tools
- Full documentation for contributions

**This solves the gap between development and distribution!**

---

**See also:**
- [MANIFEST.md](MANIFEST.md) - What files are needed
- [DOCUMENTATION.md](DOCUMENTATION.md) - Complete docs index
- [.gitattributes](.gitattributes) - What GitHub excludes from archives
