# Building wg-friend

This guide covers how to build the `wg-friend` binary from source.

## Quick Version

```bash
# Install build dependencies
pip install pyinstaller
pip install -r requirements.txt

# Build
pyinstaller wg-friend.spec

# Binary is at dist/wg-friend
./dist/wg-friend --version
```

## Prerequisites

1. **Python 3.8+**
2. **PyInstaller** - bundles Python + dependencies into a single executable
3. **Project dependencies** - rich, paramiko, segno, etc.

```bash
pip install pyinstaller
pip install -r requirements.txt
```

## Building Locally

### Step 1: Build the binary

```bash
pyinstaller wg-friend.spec
```

This reads `wg-friend.spec` which tells PyInstaller:
- Entry point: `wg-friend` script
- Include all `src/*.py` modules
- Include `wg-friend-onboard.py` and `wg-friend-maintain.py`
- Bundle all dependencies (rich, paramiko, etc.)

### Step 2: Find the output

```bash
ls -la dist/
# dist/wg-friend    <- your binary
```

### Step 3: Test it

```bash
./dist/wg-friend --version
./dist/wg-friend --help
```

### Step 4: Install (optional)

```bash
sudo cp dist/wg-friend /usr/local/bin/
```

## What PyInstaller Does

PyInstaller analyzes the Python code, finds all imports, and bundles:
- Python interpreter
- All imported modules (standard library + third-party)
- Your source code
- Any data files specified in the spec

The result is a single executable that runs without Python installed.

## The Spec File

`wg-friend.spec` controls the build. Key parts:

```python
# Entry point script
Analysis(['wg-friend'], ...)

# Data files to include (source modules)
datas = [
    ('src/*.py', 'src'),
    ('wg-friend-onboard.py', '.'),
    ('wg-friend-maintain.py', '.'),
]

# Hidden imports PyInstaller might miss
hiddenimports = ['rich', 'paramiko', 'segno', ...]

# Output settings
EXE(..., name='wg-friend', console=True, ...)
```

## Automated Releases (GitHub Actions)

The repo includes `.github/workflows/release.yml` which automatically builds binaries when you create a git tag.

### Creating a Release

```bash
# 1. Update version in src/app.py (optional - workflow does this)
# 2. Commit any changes
git add -A && git commit -m "Prepare release v0.2.0"

# 3. Create and push a tag
git tag v0.2.0
git push origin v0.2.0
```

GitHub Actions will:
1. Build binaries for Linux x86_64, macOS Intel, macOS ARM
2. Create a GitHub Release
3. Upload binaries with checksums

### Manual Workflow Trigger

You can also trigger a build manually:
1. Go to Actions tab on GitHub
2. Select "Build and Release" workflow
3. Click "Run workflow"
4. Enter version (e.g., `v0.2.0`)

## Platform-Specific Notes

### Linux

Works out of the box. Binary is statically linked for portability.

```bash
pyinstaller wg-friend.spec
./dist/wg-friend --version
```

### macOS

Works on both Intel and Apple Silicon. Build on each architecture for native binaries.

```bash
# On Intel Mac -> produces x86_64 binary
# On M1/M2 Mac -> produces arm64 binary
pyinstaller wg-friend.spec
```

### Windows

Not supported. The tool assumes Unix paths, SSH, and `wg` command availability. Windows users can use WSL or manage their WireGuard network from a Linux/macOS machine.

## Troubleshooting

### "No module named X"

PyInstaller missed a dependency. Add it to `hiddenimports` in the spec:

```python
hiddenimports = [
    'missing_module',
    ...
]
```

### Binary is huge

Normal. It includes the Python interpreter (~15-30MB base). You can:
- Use UPX compression (already enabled in spec)
- Use `--exclude-module` for unused stdlib modules

### Import errors at runtime

The spec includes data files, but if imports fail:
1. Check the module is in `hiddenimports`
2. Check data files are in `datas` list
3. Run with `--debug` to see what's missing:
   ```bash
   pyinstaller --debug wg-friend.spec
   ```

## Development vs Production

| Mode | Command | Notes |
|------|---------|-------|
| Development | `./wg-friend` | Runs with system Python, uses local src/ |
| Production | `./dist/wg-friend` | Standalone binary, no Python needed |

Both work identically - the code detects which mode it's in and loads modules appropriately.

## Updating the Version

Version is in `src/app.py`:

```python
__version__ = "0.1.0"
__build_date__ = "dev"
```

The GitHub workflow updates these automatically during release builds. For local builds, edit manually if needed.
