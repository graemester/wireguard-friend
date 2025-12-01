# -*- mode: python ; coding: utf-8 -*-

import sys
from pathlib import Path
import nacl

# Get the v1 directory
v1_dir = Path(SPECPATH)
repo_root = v1_dir.parent

# Find actual location of installed packages for binary collection
nacl_path = Path(nacl.__file__).parent.parent  # Go up to site-packages
site_packages = str(nacl_path)

block_cipher = None

# Collect all v1 modules
v1_modules = [
    'v1.cli.init_wizard',
    'v1.cli.import_configs',
    'v1.cli.peer_manager',
    'v1.cli.config_generator',
    'v1.cli.deploy',
    'v1.cli.status',
    'v1.cli.ssh_setup',
    'v1.cli.tui',
    'v1.schema_semantic',
    'v1.parser',
    'v1.generator',
    'v1.keygen',
    'v1.network_utils',
    'v1.config_detector',
    'v1.comment_system',
    'v1.formatting',
    'v1.shell_parser',
    'v1.entity_parser',
    'v1.patterns',
    'v1.system_state',
    'v1.unknown_fields',
]

a = Analysis(
    ['wg-friend'],
    pathex=[str(repo_root)],
    binaries=[
        # CFFI backend (required by PyNaCl)
        (f'{site_packages}/_cffi_backend*.so', '.'),
        # libsodium wrapper (required by PyNaCl)
        (f'{site_packages}/nacl/_sodium.abi3.so', 'nacl'),
    ],
    datas=[],
    hiddenimports=v1_modules + [
        'sqlite3',
        'qrcode',
        'nacl',
        'nacl.bindings',
        'nacl.public',
        'nacl.utils',
        '_cffi_backend',
        'cffi',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'test_*',
        'demo',
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
