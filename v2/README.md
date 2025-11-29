# WireGuard Friend v2 - Vision & Experimentation

> **⚠️ EXPERIMENTAL** - This is a future-looking reimagining of WireGuard Friend.
> For stable, production-ready code, see [../v1/](../v1/)

---

## The V2 Paradigm Shift

**V1's Reality:** Dual storage (raw blocks + structured data) exists because we can't fully parameterize everything.

**V2's Vision:** Complete provenance model - if we can capture EVERYTHING in structured form, raw blocks become unnecessary.

---

## The Four Big Questions

### 1. Can you parse PostUp/PostDown into structured commands?
**Challenge:** These are arbitrary shell commands. Can we represent them as structured data?

**Approaches to explore:**
- AST representation of shell commands
- Command templates with parameters
- Composable command primitives

---

### 2. How do you store "comment attached to Peer 3, line 2"?
**Challenge:** Comments have context and position. How do we preserve this?

**Approaches to explore:**
- Comments as first-class entities with relationships
- Position markers (before/after/inline)
- Semantic attachment (comment describes what?)

---

### 3. How do you capture "user prefers 2 blank lines between peers"?
**Challenge:** Formatting preferences are implicit. How do we make them explicit?

**Approaches to explore:**
- Formatting profile system
- Per-entity style metadata
- Rendering templates with user preferences

---

### 4. What about unknown future WireGuard fields?
**Challenge:** WireGuard evolves. How do we handle fields we don't know about yet?

**Approaches to explore:**
- Generic key-value extension system
- Validation levels (strict/permissive)
- Unknown field preservation strategy

---

## What Success Looks Like

V2 eliminates raw blocks entirely. The database becomes a **complete AST** of WireGuard configurations:

```sql
-- Every element is parameterized
comments(id, entity_type, entity_id, position, text)
postup_commands(id, router_id, sequence, command_ast, variables)
formatting_prefs(id, entity_id, style_key, style_value)
peer_display(id, peer_id, order, spacing_before, spacing_after)
unknown_fields(id, entity_type, entity_id, field_name, field_value)
```

Configs are **generated** from this complete model, not reconstructed from preserved text.

---

## Experimentation Guidelines

- **No compatibility with v1 database** - start fresh
- **Break things** - this is the safe space for radical ideas
- **Document learnings** - what works, what doesn't, why
- **Bright line** - v2 code never touches v1, v1 stays stable

---

## Status

**Current:** Empty playground, awaiting first experiments

**Next:** TBD based on answers to the four questions above

---

_This is the future. V1 is the present. Both can coexist._
