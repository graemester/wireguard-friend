# WireGuard Friend v2 - Smart Routing

## Just run `wg-friend` and it figures out what to do!

When you run `wg-friend` with no arguments, it intelligently routes to the appropriate mode based on what it finds.

**Matches v1 workflow exactly!**

---

## Scenario 1: Database Exists → Maintenance Mode

**Detection:** `wireguard.db` exists in current directory

**Action:** Launch interactive TUI

**Output:**
```
Using database: wireguard.db

======================================================================
  WIREGUARD FRIEND v2 - INTERACTIVE MODE
======================================================================

  Welcome! This interactive mode lets you manage your WireGuard network.
  Navigate using the menu options below.

Press Enter to continue...
```

**Use case:** Day-to-day management of existing network

---

## Scenario 2: No Database → First-Run Experience

**Detection:** No `wireguard.db` in current directory

**Action:** Ask user what they want to do

**Output:**
```
======================================================================
  WireGuard Friend v2
======================================================================

Welcome! This tool helps you manage WireGuard VPN networks.

Do you have existing WireGuard configs to import?

  If you already have .conf files from a working WireGuard setup,
  we can import them. Otherwise, we'll help you create a new network.

Import existing configs? [y/N]: _
```

### 2a: User Has Configs (y)

**Flow:**
1. Creates `import/` directory
2. Checks if configs already present
3. If not, asks user to copy configs there and press Enter
4. **Analyzes each config to detect type** (uses v1's working detection logic)
5. Auto-detects coordination server config
6. Shows classified configs and asks to proceed
7. Imports coordination server

**Detection Logic (from v1):**
- **3+ peers** → coordination_server
- **Has FORWARD/POSTROUTING rules** → coordination_server or subnet_router
  - 1 peer → subnet_router
  - 2+ peers → coordination_server
- **1 peer with endpoint** → client
- **1 peer without endpoint** → subnet_router
- **Otherwise** → client

**Output:**
```
Import existing configs? [y/N]: y

Created import/ folder

Copy your WireGuard .conf files into:
  /home/user/import

Typical files to import:
  • Coordination server config (e.g., wg0.conf from your VPS)
  • Subnet router configs (if you have any)
  • Client peer configs (laptop, phone, etc.)

Press Enter when your configs are in place...

Found 3 config(s) in import/
  • wg0.conf
  • home-gateway.conf
  • alice-phone.conf

Detecting config types...
  • wg0.conf: coordination_server (5 peers)
  • home-gateway.conf: subnet_router (1 peer)
  • alice-phone.conf: client (1 peer)

Ready to import:
  → wg0.conf: coordination_server (5 peers)
    home-gateway.conf: subnet_router (1 peer)
    alice-phone.conf: client (1 peer)

Proceed with import? [Y/n]: y

Importing coordination server from: wg0.conf
(Other configs will need to be added manually with 'wg-friend add')

[Import proceeds...]
```

**Note:** The `→` marker shows which config was auto-detected as the coordination server.

### 2b: User Wants New Network (n)

**Flow:**
1. Explains what wizard will set up
2. Asks to start wizard
3. Launches init wizard if confirmed

**Output:**
```
Import existing configs? [y/N]: n

Great! Let's create a new WireGuard network.
The wizard will walk you through setting up:
  • Coordination server (your cloud VPS)
  • Subnet routers (optional - for accessing home/office LANs)
  • Client peers (laptops, phones, etc.)

Start the setup wizard? [Y/n]: y

======================================================================
  WireGuard Friend v2 - First Run Setup
======================================================================

[Wizard begins...]
```

**Use case:** Brand new WireGuard setup

---

## Override Smart Routing

You can always override the smart routing with explicit commands:

```bash
wg-friend init          # Force init wizard
wg-friend maintain      # Force TUI mode
wg-friend import --cs <file>  # Force import
wg-friend status        # Just show status
```

---

## Custom Database Location

If using a custom database path, smart routing still works:

```bash
wg-friend --db /path/to/custom.db
```

This will:
1. Check if `/path/to/custom.db` exists
2. If yes → TUI mode
3. If no → Look for configs → Suggest import or run init

---

## Examples of Smart Routing in Action

### Example 1: Fresh Install on New Server
```bash
$ wg-friend
Welcome to WireGuard Friend v2!

No database or existing configs found.
Let's set up your WireGuard network...

Public IP or hostname (e.g., vps.example.com): vps.example.com
Listen port [51820]:
VPN IPv4 network [10.66.0.0/24]:
...
```

### Example 2: Existing WireGuard Setup
```bash
$ wg-friend
No database found, but detected existing WireGuard configs:
  - /etc/wireguard/wg0.conf

Run import to bring these into WireGuard Friend:
  wg-friend import --cs /etc/wireguard/wg0.conf

$ wg-friend import --cs /etc/wireguard/wg0.conf
# ... import happens ...

$ wg-friend
Found existing database: wireguard.db
Launching interactive maintenance mode...
# ... TUI appears ...
```

### Example 3: Day-to-Day Management
```bash
$ wg-friend
Found existing database: wireguard.db
Launching interactive maintenance mode...

======================================================================
WIREGUARD FRIEND - MAIN MENU
======================================================================
  1. Network Status
  2. List All Peers
  3. Add Peer
  4. Remove Peer
  5. Rotate Keys
  6. Recent Key Rotations
  7. Generate Configs (requires running separate command)
  8. Deploy Configs (requires running separate command)
  q. Quit

Choice: _
```

---

## Why This is Great UX

**Before (explicit commands required):**
```bash
$ wg-friend
Usage: wg-friend <command>
...

$ wg-friend init
# ... setup ...

$ wg-friend maintain
# ... TUI ...
```

**After (smart routing):**
```bash
$ wg-friend
# Automatically does the right thing!
```

**Benefits:**
1. **Discoverability** - New users don't need to know commands
2. **Fewer steps** - Just run `wg-friend`, it figures it out
3. **Safe** - Detects existing setup, won't overwrite
4. **Helpful** - Suggests correct import command when configs found
5. **Fast** - Experienced users can still use explicit commands

---

## Detection Logic (pseudocode)

```python
if no_command_specified():
    if database_exists():
        launch_tui()
    elif configs_found():
        suggest_import_command()
    else:
        run_init_wizard()
```

---

## Config Detection Locations

Smart routing checks these paths for existing configs:
- `/etc/wireguard/wg0.conf`
- `/etc/wireguard/wg1.conf`
- `./wg0.conf` (current directory)
- `./coordination.conf` (current directory)

**Future enhancement:** Could add more paths or make this configurable.

---

## Philosophy

**"Do What I Mean, Not What I Say"**

Instead of making users memorize commands, WireGuard Friend v2 tries to understand the context and do the right thing automatically.

- New to WireGuard? → Guided setup wizard
- Migrating from manual setup? → Import suggestion
- Already set up? → Jump to management

This is especially useful for users who run `wg-friend` weeks or months after initial setup - it just works, no need to remember commands.
