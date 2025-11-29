# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec for wg-friend

Build commands:
    pyinstaller wg-friend.spec

This creates a single executable binary that includes:
- All Python dependencies (rich, paramiko, segno, etc.)
- All source files from src/
- The onboard and maintain scripts
"""

import sys
from pathlib import Path

block_cipher = None

# Collect all source files
src_dir = Path('src')
src_files = [
    (str(f), 'src') for f in src_dir.glob('*.py')
]

# Include the main scripts as data files (they get imported dynamically)
script_files = [
    ('wg-friend-onboard.py', '.'),
    ('wg-friend-maintain.py', '.'),
]

a = Analysis(
    ['wg-friend'],
    pathex=['.'],
    binaries=[],
    datas=src_files + script_files,
    hiddenimports=[
        # Rich console
        'rich',
        'rich.console',
        'rich.panel',
        'rich.table',
        'rich.prompt',
        'rich.box',
        'rich.syntax',
        'rich.progress',
        # SSH
        'paramiko',
        'paramiko.ed25519key',
        'paramiko.rsakey',
        'paramiko.ssh_exception',
        'nacl',
        'nacl.signing',
        'bcrypt',
        'cryptography',
        # QR codes
        'segno',
        'PIL',
        'PIL.Image',
        # YAML
        'yaml',
        # Standard library
        'sqlite3',
        'ipaddress',
        'socket',
        'getpass',
        'subprocess',
        'argparse',
        # Our modules
        'src.database',
        'src.raw_parser',
        'src.keygen',
        'src.ssh_client',
        'src.qr_generator',
        'src.tui',
        'src.app',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # Exclude test frameworks
        'pytest',
        'unittest',
        'test',
        # Exclude dev tools
        'setuptools',
        'pip',
        'wheel',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='wg-friend',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
