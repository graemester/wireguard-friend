# v1 ↔ v2 Folder Rename Plan

## Objective

Rename folders to align with v1.0.0 release:
- `v1/` → `v-alpha/` (archive old code)
- `v2/` → `v1/` (make new code primary)

---

## Files Requiring Updates

### Category 1: Python Files with `from v2.` imports (19 files)

**CLI modules:**
1. `v2/wg-friend` - Main entry point
2. `v2/cli/peer_manager.py`
3. `v2/cli/deploy.py`
4. `v2/cli/status.py`
5. `v2/cli/ssh_setup.py`
6. `v2/cli/config_generator.py`
7. `v2/cli/tui.py`
8. `v2/cli/import_configs.py`
9. `v2/cli/init_wizard.py`

**Core modules:**
10. `v2/parser.py`
11. `v2/generator.py`
12. `v2/config_detector.py`
13. `v2/demo.py`

**Test files:**
14. `v2/test_import_with_guid.py`
15. `v2/test_permanent_guid.py`
16. `v2/test_full_roundtrip.py`
17. `v2/test_roundtrip_v2.py`
18. `v2/test_roundtrip.py`
19. `v2/integration-tests/test_connectivity.py`

### Category 2: Documentation Files with `v2/` path references

**In v2/ directory:**
1. `v2/README.md`
2. `v2/QUICK_START_V2.md`
3. `v2/COMMAND_REFERENCE.md`
4. `v2/IMPLEMENTATION.md`
5. `v2/FEATURE_COMPLETION_SUMMARY.md`
6. `v2/PERMANENT_GUID.md`
7. `v2/SMART_ROUTING.md`
8. `v2/SUMMARY.md`
9. `v2/VISION.md`
10. `v2/V1.0.0_FEATURES.md`
11. `v2/V1_FEATURES_TO_PORT.md`
12. `v2/integration-tests/README.md`
13. `v2/integration-tests/LOCAL_TESTING.md`
14. `v2/integration-tests/SUMMARY.md`

**Root level:**
15. `README.md`
16. `RELEASE_PREP_v1.0.0.md`

### Category 3: Other files

1. `v2/cli/__init__.py` (if it has imports)
2. `v2/schema.py` (check for v2 references)
3. `v2/schema_semantic.py` (check for v2 references)

---

## Update Strategy

### Phase 1: Update Python Imports (Critical)

**Pattern to find:** `from v2.`
**Replace with:** `from v1.`

**Estimated count:** ~50 import statements across 19 files

**Approach:** Use Edit tool file-by-file to ensure accuracy

### Phase 2: Update Documentation References

**Pattern to find:** `v2/` (in paths/links)
**Replace with:** `v1/`

**Pattern to find:** `"v2"` (in text describing the architecture)
**Handle contextually:** Some references to "v2" are historical/explanatory and should remain

### Phase 3: Rename Folders

**Order matters:**
1. `git mv v1 v-alpha` (clear the namespace)
2. `git mv v2 v1` (move new code into place)

### Phase 4: Verification

1. Test Python imports: `python3 -c "from v1.schema_semantic import WireGuardDBv2; print('OK')"`
2. Test CLI: `./v1/wg-friend --version`
3. Test CLI: `./v1/wg-friend --help`
4. Quick functional test: Run a simple command

---

## Execution Checklist

- [ ] Phase 1: Update all Python imports (19 files)
- [ ] Phase 2: Update documentation (16 files)
- [ ] Phase 3: Rename folders with git mv
- [ ] Phase 4: Verify everything works
- [ ] Phase 5: Review git diff
- [ ] Phase 6: Commit with clear message

---

## Import Update Details

### Files with multiple imports (high priority):

**v2/wg-friend** (9 imports):
```python
from v2.cli.init_wizard import run_init_wizard
from v2.cli.import_configs import run_import
from v2.cli.peer_manager import add_peer, rotate_keys, revoke_peer, run_preshared_key, run_generate_qr
from v2.cli.config_generator import generate_configs
from v2.cli.deploy import deploy_configs
from v2.cli.status import show_status
from v2.cli.tui import run_tui
from v2.cli.ssh_setup import ssh_setup
from v2.config_detector import ConfigDetector
```

**v2/generator.py** (5 imports):
```python
from v2.parser import ParsedConfig, InterfaceData, PeerData
from v2.comment_system import Comment, CommentPosition, CommentRenderer, EntityType
from v2.formatting import FormattingProfile, FormattingApplier
from v2.shell_parser import ParsedCommand, IptablesCommand, SysctlCommand, IpCommand, CustomCommand
from v2.parser import WireGuardParser  # (inside function)
from v2.unknown_fields import ValidationMode  # (inside function)
```

**v2/parser.py** (4 imports):
```python
from v2.comment_system import CommentExtractor, Comment, EntityType, CommentPosition
from v2.formatting import FormattingDetector, FormattingProfile
from v2.shell_parser import ShellCommandParser, ParsedCommand
from v2.unknown_fields import UnknownFieldHandler, FieldCategory, ValidationMode
```

### Files with few imports (lower risk):

Most CLI files: 1-3 imports each
Most test files: 2-4 imports each

---

## Git Operations

```bash
# After all updates are done:
git mv v1 v-alpha
git mv v2 v1
git status  # Review changes
git add -A  # Stage everything
git commit -m "Rename folders: v1→v-alpha, v2→v1 for v1.0.0 release alignment

- Archived old v1 code to v-alpha/
- Renamed v2/ to v1/ to align with v1.0.0 release
- Updated all Python imports from 'from v2.' to 'from v1.'
- Updated documentation references from v2/ to v1/
- Updated root README and release docs

This change aligns the folder structure with the external release
version (v1.0.0) while preserving all history and functionality."
```

---

## Rollback Plan (if needed)

```bash
# If something goes wrong:
git reset --hard HEAD  # Undo uncommitted changes
# Or
git mv v1 v2
git mv v-alpha v1
# Then revert import changes
```

---

## Testing After Rename

```bash
# 1. Test import
python3 -c "from v1.schema_semantic import WireGuardDBv2; print('✓ Import works')"

# 2. Test CLI help
./v1/wg-friend --help

# 3. Test version
./v1/wg-friend --version
# Should show: wg-friend v1.0.0

# 4. Test a simple command
./v1/wg-friend --db test.db status
```

---

## Notes

- All changes are reversible until committed
- Git tracks renames well (preserves history)
- No database changes needed
- No user data affected
- This is purely internal reorganization
