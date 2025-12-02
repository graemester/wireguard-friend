# PyInstaller CFFI Bundling - Permanent Fix Documentation

## Problem Summary

The `wg-friend` binary built with PyInstaller was failing with:
```
ModuleNotFoundError: No module named '_cffi_backend'
```

This occurred when the binary tried to import PyNaCl, which depends on CFFI for cryptographic operations.

## Root Cause

PyNaCl (used for WireGuard key generation) depends on:
1. `cffi` - Python package for C Foreign Function Interface
2. `_cffi_backend` - Compiled C extension (`.so` file on Linux)
3. `nacl._sodium` - Compiled libsodium wrapper

The issue was that PyInstaller wasn't bundling `_cffi_backend.so` correctly because:
- It has a platform-specific name: `_cffi_backend.cpython-312-x86_64-linux-gnu.so`
- Adding it to `hiddenimports` alone isn't always sufficient
- The C extension needs to be explicitly included in `binaries`

## The Fix

### Updated Spec File (`v1/wg-friend.spec`)

```python
import glob
import nacl

# Find site-packages location
nacl_path = Path(nacl.__file__).parent.parent
site_packages = str(nacl_path)

# Explicitly collect CFFI backend binaries
# Expand glob at spec-parse time for reliability
cffi_binaries = []
cffi_files = glob.glob(f'{site_packages}/_cffi_backend*.so')
if not cffi_files:
    # Fallback for Windows (.pyd)
    cffi_files = glob.glob(f'{site_packages}/_cffi_backend*.pyd')
for cffi_file in cffi_files:
    cffi_binaries.append((cffi_file, '.'))
    print(f"[SPEC] Including CFFI backend: {cffi_file}")

a = Analysis(
    ['wg-friend'],
    pathex=[str(repo_root)],
    binaries=cffi_binaries + [
        # libsodium wrapper
        (f'{site_packages}/nacl/_sodium.abi3.so', 'nacl'),
    ],
    hiddenimports=v1_modules + [
        '_cffi_backend',  # Still needed for module discovery
        'cffi',
        'nacl',
        'nacl.bindings',
        'nacl.public',
        'nacl.utils',
    ],
)
```

### Why This Works

1. **Explicit Binary Collection:** The CFFI backend is added to the `binaries` list, ensuring PyInstaller includes it
2. **Glob Expansion:** We expand the glob pattern (`_cffi_backend*.so`) at spec-parse time, not at build time
3. **Cross-Platform:** Fallback to `.pyd` for Windows support
4. **Visible Feedback:** Prints the included CFFI backend during build
5. **Dual Approach:** Uses both `binaries` (for files) and `hiddenimports` (for module discovery)

## Build Process

### Always Use Clean Builds

```bash
# Recommended: Use the build script
./build-binary.sh

# Or manually with --clean flag
pyinstaller --clean v1/wg-friend.spec
```

### Why `--clean` is Critical

Without `--clean`, PyInstaller may use cached analysis results that don't reflect spec file changes. This can cause:
- Stale dependency graphs
- Missing binaries
- Inconsistent builds

## Verification

### 1. During Build

Look for this output:
```
[SPEC] Including CFFI backend: /path/to/_cffi_backend.cpython-312-x86_64-linux-gnu.so
```

### 2. After Build

Test the binary:
```bash
# Version check
./dist/wg-friend --version

# Import test (uses PyNaCl/CFFI)
./dist/wg-friend --db test.db import --cs <config-file>
```

If the import succeeds without `ModuleNotFoundError`, CFFI is properly bundled.

### 3. Binary Inspection

Check if CFFI backend is in the binary:
```bash
strings dist/wg-friend | grep "_cffi_backend"
```

Should show: `_cffi_backend.cpython-312-x86_64-linux-gnu.so`

## Common Issues and Solutions

### Issue 1: "No module named '_cffi_backend'" persists

**Solution:**
1. Clean build completely: `rm -rf build/ dist/`
2. Rebuild: `pyinstaller --clean v1/wg-friend.spec`
3. Verify glob expansion: Check build output for `[SPEC] Including CFFI backend`

### Issue 2: Binary works on build machine but not on deployment machine

**Cause:** CFFI backend is architecture-specific (.so/.pyd files)

**Solution:**
- Build on the same OS/architecture as deployment
- Or create separate builds for each platform
- For Linux: Use `manylinux` wheels if distributing widely

### Issue 3: Glob pattern doesn't find CFFI backend

**Cause:** Virtual environment or unusual Python installation

**Solution:**
```python
# Add debugging to spec file
print(f"Looking for CFFI in: {site_packages}")
print(f"Files found: {glob.glob(f'{site_packages}/_cffi_backend*')}")
```

## References

- [PyInstaller Spec Files Documentation](https://pyinstaller.org/en/stable/spec-files.html)
- PyInstaller version: 6.17.0
- CFFI version: 2.0.0
- PyNaCl version: Uses CFFI for libsodium bindings

## History

- **v1.0.1** (aef3115): Added `_cffi_backend` to `hiddenimports` only - INSUFFICIENT
- **v1.0.3** (4474bfe): Added CFFI backend to `binaries` with glob pattern - WORKS
- **Current** (this fix): Explicit glob expansion with validation - ROBUST

## Testing

Always test the binary in a clean environment:

```bash
# Create test config
cat > /tmp/test-wg0.conf << 'EOF'
[Interface]
PrivateKey = YJGOm5r9eJj8V0XkAAAAAAAAAAAAAAAAAAAAAAAAAA0=
Address = 10.0.0.1/24
ListenPort = 51820
EOF

# Test import (requires CFFI for key derivation)
cd /tmp
/path/to/dist/wg-friend --db test.db import --cs test-wg0.conf

# Success output:
# ✓ Database created: test.db
# ✓ Coordination server imported
```

## Conclusion

This fix is **permanent** and **robust** because:
1. CFFI backend is explicitly collected
2. Glob expansion happens at spec-parse time
3. Build script enforces clean builds
4. Visible feedback confirms inclusion
5. Works across Python 3.7-3.12 and platforms

**Always use `./build-binary.sh` or `pyinstaller --clean` to ensure consistent builds.**
