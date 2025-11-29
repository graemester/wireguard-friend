# WireGuard Friend - Release Guide

How to create releases.

---

## Release Process

### 1. Update Version

Update version in `v1/wg-friend`:
```python
parser.add_argument('--version', action='version', version='wg-friend v1.x.x')
```

### 2. Update Documentation

Review and update:
- README.md
- v1/quick-start.md
- v1/COMMAND_REFERENCE.md
- RELEASE_NOTES_vX.X.X.md (create new)

### 3. Test

Run tests:
```bash
cd v1
python3 test_permanent_guid.py
python3 test_roundtrip.py
# ... other tests
```

Manual testing:
- Import existing configs
- Generate configs
- Deploy (with localhost detection)
- Add peer
- Rotate keys
- QR code generation
- SSH setup wizard
- Live status

### 4. Commit Changes

```bash
git add -A
git commit -m "Release vX.X.X"
git push origin main
```

### 5. Create Tag

```bash
git tag -a vX.X.X -m "Release vX.X.X

Features:
- Feature 1
- Feature 2

Bug fixes:
- Fix 1
- Fix 2
"

git push origin vX.X.X
```

### 6. Create GitHub Release

Go to: https://github.com/graemester/wireguard-friend/releases/new

- Select tag: vX.X.X
- Title: `vX.X.X - Release Title`
- Description: Copy from RELEASE_NOTES_vX.X.X.md
- Publish release

---

## Semantic Versioning

**Major (v2.0.0):** Breaking changes to database schema or CLI
**Minor (v1.1.0):** New features, backward compatible
**Patch (v1.0.1):** Bug fixes, backward compatible

Examples:
```
v1.0.0 → v1.0.1 (bug fix)
v1.0.1 → v1.1.0 (new features)
v1.1.0 → v1.1.1 (bug fix)
v1.1.1 → v2.0.0 (breaking change)
```

---

## What to Include

### Source Code

GitHub automatically creates source archives for each release.

Users can install with:
```bash
git clone https://github.com/graemester/wireguard-friend.git
cd wireguard-friend
pip install -r requirements.txt
./v1/wg-friend
```

### Release Notes

Create `RELEASE_NOTES_vX.X.X.md` with:
- Features added
- Bug fixes
- Breaking changes (if any)
- Installation instructions
- Documentation links

---

## Pre-Release Checklist

- [ ] Version updated in CLI
- [ ] Documentation updated
- [ ] Tests pass
- [ ] Manual testing complete
- [ ] RELEASE_NOTES created
- [ ] Commit and push
- [ ] Tag created and pushed
- [ ] GitHub release published

---

## Post-Release

1. Announce release (if applicable)
2. Monitor for issues
3. Plan next version

---

## Release Artifacts

GitHub provides:
- Source code (zip)
- Source code (tar.gz)

Users need:
- Python 3.7+
- Dependencies via pip install -r requirements.txt
- WireGuard tools (wg, wg-quick)

No binary builds required - pure Python.

---

## Hotfix Process

For urgent bug fixes:

1. Create fix branch from tag:
   ```bash
   git checkout -b hotfix-v1.0.1 v1.0.0
   ```

2. Apply fix and test

3. Commit, tag, and release:
   ```bash
   git commit -m "Fix critical bug"
   git tag -a v1.0.1 -m "Hotfix: Fix critical bug"
   git push origin v1.0.1
   ```

4. Merge back to main:
   ```bash
   git checkout main
   git merge hotfix-v1.0.1
   git push origin main
   ```

---

## Version History

Maintained in git tags:
```bash
git tag -l
```

View specific version:
```bash
git show v1.0.0
```

Checkout specific version:
```bash
git checkout v1.0.0
```
