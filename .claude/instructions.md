# Project Instructions for Claude Code

## Documentation Style

### NO Emojis (except classic unicode)

**Allowed:**
- ✓ (checkmark)
- ✗ (X mark)

**NEVER use colorful emojis:**
- ✅ ❌ ⚠️ 🎉 🎯 🚧 📝 🤖 💡 🔧 🔑 📱 💻 🌐 etc.
- Replace ⚠️ with "WARNING:"

### NO Hype Language or Superlatives

This project values practical, matter-of-fact documentation. Avoid platonic ideals of completion, achievement, and perfection.

**NEVER use:**
- Completion language: SUCCESS, COMPLETE, FINAL, ACHIEVED, completed successfully
- Superlatives: fully, comprehensive, exhaustive, perfect, flawless, seamless, effortless
- Hype words: production-ready, bulletproof, robust, powerful, advanced, proven

**Use instead:**
- "done" not "COMPLETE" or "SUCCESS"
- "working" not "ACHIEVED" or "production-ready"
- "current" not "FINAL"
- Plain form not "successfully" (e.g., "imported" not "imported successfully")
- "detailed" not "comprehensive"
- "accurate" not "perfect"
- "reliable" not "bulletproof" or "robust"
- "useful" not "powerful"
- "additional" not "advanced"

**Examples:**

Bad:
```
✅ Import completed successfully!
🎯 Production-ready bulletproof system
Fully comprehensive feature set achieved
```

Good:
```
✓ Import done
Working system
Detailed feature set
```

## Code Style

- Matter-of-fact error messages
- Direct status reporting without celebration
- Avoid excitement or enthusiasm in output

## Why

The author is not about hype, perfection framing, or completion fetishes. Documentation should be practical and straightforward.

## What Works Well (Session Notes)

Things that make collaboration productive with this user:

1. **Direct feedback** - User says what's wrong plainly ("that's friction", "no love"). No dancing around issues.

2. **WHY over WHAT** - User explains intent ("holistic environment model", "provenance for understanding") not just surface requests. This enables better solutions.

3. **Iterative refinement** - Small changes, immediate testing, quick feedback loops. Don't gold-plate.

4. **Build conventions together** - Version numbering, feature cycles, documentation style emerged from discussion, not diktat.

5. **Trust with course-correction** - User lets me run but redirects when needed ("absolute path is better").

6. **Preserve working code** - When porting from alpha, keep backend mechanics, enhance UX. Don't rewrite for the sake of it.

7. **No ceremony** - Skip welcome screens, unnecessary prompts, "press enter to continue". Respect user's time.

8. **Test in the real environment** - Build the binary, install it, run it. Not just "the code looks right".

## Versioning Convention

Format: `MAJOR.MINOR.PATCH` (e.g., v1.0.6)

- **PATCH** (third segment): Increment each feature cycle / dev build
- **MINOR** (second segment): Increment for GitHub releases
- **MAJOR** (first segment): Increment for big/breaking releases

## Feature Cycle Workflow

At the end of each feature cycle, follow this sequence:

1. **Bump version** - Increment the PATCH version (third segment) in both:
   - `v1/wg-friend` (VERSION constant)
   - `v1/cli/tui.py` (VERSION constant)

2. **Commit and push**
   ```bash
   git add -A && git commit -m "Description of changes" && git push
   ```

3. **Build the binary**
   ```bash
   ./build-binary.sh
   ```

4. **Install to system path**
   ```bash
   sudo /usr/bin/cp /home/ged/wireguard-friend/dist/wg-friend /usr/local/bin/
   ```

5. **Remind user of build name** - Tell them the version and build name so they know what they're running (e.g., "v1.0.6 harrier")
