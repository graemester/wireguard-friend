# Where Should I Run WireGuard Friend?

## The Most Important Question First

**Should I run it on my Coordination Server, Subnet Router, or Client device?**

### Quick Answer

```
Coordination Server:  WARNING:  Possible, but not recommended
Subnet Router:        ✓  YES - Best choice for most setups
Client (Laptop):      ✓  YES - Great for power users
```

**Recommended: Pick ONE location and stick with it.** SSH into that machine when you need to manage your network.

### Why This Matters

You have three types of WireGuard devices in your network:
1. **Coordination Server** (CS) - Cloud VPS, central hub
2. **Subnet Router** (SN) - Home/office gateway advertising LANs
3. **Client Peers** - Laptops, phones, tablets

WireGuard Friend can run on any of them (or somewhere else entirely), but **where you run it affects your workflow.**

## The Philosophy

WireGuard Friend is a **management tool**, not a runtime service. It:
- Reads your existing configs (onboarding)
- Stores them in a portable SQLite database
- Generates new configs when you make changes
- Deploys configs to your servers via SSH

**It doesn't need to run 24/7.** Run it when you need to manage your network, then it sits idle.

**Ideal workflow:** Pick one machine, install it there, SSH to that machine when you need to make changes. Don't move the database around unless you have a good reason.

## Option 1: Subnet Router (Recommended )

**Why this works well:**
```
Your Network:
┌─────────────────────────────────────────┐
│ Coordination Server (VPS in cloud)     │
│ • Runs WireGuard 24/7                   │
│ • No Python needed                      │
│ • Accessible via SSH                    │
└─────────────────────────────────────────┘
                    ▲
                    │ WireGuard tunnel
                    ▼
┌─────────────────────────────────────────┐
│ Subnet Router (your LAN gateway)       │  ← Run wireguard-friend HERE
│ • Runs WireGuard 24/7                   │
│ • Has Python + dependencies             │
│ • Can SSH to coordination server        │
│ • On your local network                 │
│ • Advertises 192.168.x.x/24             │
└─────────────────────────────────────────┘
                    │
        ┌───────────┼───────────┐
        ▼           ▼           ▼
    [Laptop]   [Desktop]   [NAS]
```

**Advantages:**
- ✓ Already managing WireGuard configs locally
- ✓ On your LAN - easy to access
- ✓ Has network access to coordination server
- ✓ Single point of management
- ✓ Can manage both its own config and CS config
- ✓ Database stays on local network (safer)
- ✓ Don't need to expose management tools to internet

**Disadvantages:**
- WARNING: Adds Python dependencies to router
- WARNING: If router goes down, can't manage network (but can use backup)

**Perfect for:**
- Home networks
- Small office setups
- Single-admin scenarios
- When you have a dedicated router/gateway device

## Option 2: Local Workstation/Laptop

**Your setup:**
```
Your Network:
┌─────────────────────────────────────────┐
│ Coordination Server (VPS)               │
│ • Runs WireGuard                        │
│ • SSH accessible                        │
└─────────────────────────────────────────┘
                    ▲
                    │
┌─────────────────────────────────────────┐
│ Subnet Router(s)                        │
│ • Runs WireGuard                        │
│ • SSH accessible                        │
└─────────────────────────────────────────┘
                    ▲
                    │ Your LAN
                    │
┌─────────────────────────────────────────┐
│ Your Laptop/Desktop                     │  ← Run wireguard-friend HERE
│ • Has Python                            │
│ • Can SSH to CS and SN                  │
│ • Database lives here                   │
└─────────────────────────────────────────┘
```

**Advantages:**
- ✓ Don't clutter servers with management tools
- ✓ Work offline (except deployments)
- ✓ Use your familiar development environment
- ✓ Easy to backup database with other files
- ✓ Keep WireGuard servers minimal/clean
- ✓ Multiple admins can each have their own copy

**Disadvantages:**
- WARNING: Need network access when deploying
- WARNING: Database moves if you switch machines (but it's portable!)
- WARNING: Need to set up SSH keys from your workstation

**Perfect for:**
- Developers/power users
- When you want servers to be minimal
- Multi-admin teams (each has their own copy)
- Testing/experimental setups

## Option 3: Coordination Server (Possible)

**Your setup:**
```
┌─────────────────────────────────────────┐
│ Coordination Server (VPS)               │  ← Run wireguard-friend HERE
│ • Runs WireGuard 24/7                   │
│ • Runs wireguard-friend when needed     │
│ • Has Python + dependencies             │
│ • Can SSH to subnet routers             │
└─────────────────────────────────────────┘
```

**Advantages:**
- ✓ Direct access to CS config files
- ✓ Central location for management
- ✓ No SSH needed for CS deployments (local copy)
- ✓ Always accessible (if server is up)

**Disadvantages:**
- WARNING: Adds dependencies to production server
- WARNING: Database contains private keys (security consideration)
- WARNING: Need to SSH into server to manage
- WARNING: Mixing management and runtime concerns

**Perfect for:**
- Small setups with only CS (no subnet routers)
- When you're already SSH'd into server frequently
- Dedicated admin server (not production VPN)

**Not recommended for:**
- Production VPN servers handling lots of traffic
- Security-conscious setups (keep admin tools separate)
- When you have multiple admins

## Option 4: Dedicated Admin Box

**Your setup:**
```
┌─────────────────────────────────────────┐
│ Dedicated Admin Server/VM/Pi            │  ← Run wireguard-friend HERE
│ • Only purpose: manage WireGuard        │
│ • Has Python                            │
│ • Can SSH to all WireGuard hosts        │
│ • Accessible on your network            │
│ • Could run on: Raspberry Pi, NAS, VM   │
└─────────────────────────────────────────┘
            │ SSH to manage
            ▼
    [CS, SN1, SN2, etc.]
```

**Advantages:**
- ✓ Clean separation of concerns
- ✓ Always available on your network
- ✓ Can run automated tasks (backups, monitoring)
- ✓ Multiple admins can SSH to same box
- ✓ Database in one central location

**Disadvantages:**
- WARNING: Need to maintain another device
- WARNING: Overkill for simple setups

**Perfect for:**
- Larger networks with multiple sites
- Enterprise/business setups
- When you want centralized management
- Running on NAS or always-on device

## Option 5: Anywhere! (Maximum Flexibility)

**The beauty of wireguard-friend:**

Because the database is portable and management is over SSH, you **technically** can run it anywhere.

**BUT - and this is important - the ideal workflow is:**

```bash
# Pick ONE location (e.g., your subnet router)
# Install wireguard-friend there once
# Then when you need to manage your network:

$ ssh subnet-router
subnet-router$ cd ~/wireguard-friend
subnet-router$ python3 wg-friend-maintain.py
# Make changes, deploy configs
# Exit SSH
```

**This is better than moving the database around!**

**However**, the portability is valuable for:

```bash
# Backup to NAS (regularly)
$ ./backup-database.sh /mnt/nas/backups

# Migration to new admin machine (occasionally)
$ scp wg-friend-backup.tar.gz new-machine:~/

# Emergency: Database corrupted, restore from backup
$ tar xzf /mnt/nas/backups/wg-friend-backup-*.tar.gz

# Testing changes safely (without affecting production)
$ cp wg-friend.db wg-friend-test.db
$ python3 wg-friend-maintain.py --db wg-friend-test.db
```

**Recommendation:** Pick one "home" for wireguard-friend. SSH to it when needed. Use portability for backups and emergencies, not daily workflow.

## Requirements Checklist

Wherever you run wireguard-friend, you need:

**Required:**
- ✓ Python 3.8+ installed
- ✓ Dependencies: `pip install -r requirements.txt`
- ✓ Network access to WireGuard hosts (for deployments)
- ✓ SSH keys set up for password-less access (for deployments)

**Optional but useful:**
-  Git (for version controlling the database)
-  Backup solution (NAS, cloud storage, etc.)
-  Text editor for manual config tweaks

**NOT required:**
- ✗ Static IP address
- ✗ Domain name
- ✗ Always-on server
- ✗ Root access on WireGuard hosts (regular user with sudo for wg commands)
- ✗ Database on network storage (local is better)

## Deployment Model

Understanding how deployment works helps choose the right location:

```
┌──────────────────────────────────────────┐
│ wireguard-friend                         │
│ • Read database                          │
│ • Reconstruct configs                    │
│ • Write to output/ directory             │
└──────────────────────────────────────────┘
                │
                │ Deploy via SSH
                ▼
┌──────────────────────────────────────────┐
│ Coordination Server                      │
│ • Receive new config via SCP             │
│ • Backup old config                      │
│ • Install new config                     │
│ • Restart WireGuard                      │
└──────────────────────────────────────────┘
```

**Key insight:** wireguard-friend doesn't need to be on the same machine as WireGuard!

It just needs to be able to **SSH** to the machines running WireGuard.

## Security Considerations

### Database Security

Your database contains:
- Private keys for all peers
- Network topology
- IP allocations
- Access control rules

**Keep it safe:**
- File permissions: `chmod 600 wg-friend.db`
- Store on encrypted disk
- Regular backups to secure location
- Don't commit to public Git repos
- Consider location carefully

**Safer locations (in order):**
1. Laptop with encrypted disk (travels with you)
2. Subnet router on private LAN (not internet-facing)
3. Dedicated admin box on LAN
4. Coordination server (internet-facing, less ideal)

### SSH Key Security

If you run wireguard-friend on a potentially compromised machine, someone could:
- Read your database (get all private keys)
- Use your SSH keys to access servers
- Deploy malicious configs

**Best practice:** Run on a trusted, secure machine.

## Multi-Admin Scenarios

### Shared Database (Not Recommended)

```
Admin 1's Laptop ──→ ┌──────────────┐ ←── Admin 2's Laptop
                     │ Database     │
                     │ on NAS       │
                     └──────────────┘
```

**Problems:**
- Race conditions
- SQLite corruption over network
- Conflicting changes

### Copy-Work-Copy (Better)

```
Admin 1:                           Admin 2:
  Copy from NAS                      Copy from NAS
  Work locally                       Work locally
  Deploy changes                     Deploy changes
  Copy back to NAS                   Copy back to NAS
```

**Better, but:**
- Can still conflict
- Need coordination between admins

### Git Repository (Best)

```
┌─────────────────────────────────────────┐
│ Private Git Repo                        │
│ • wg-friend.db (encrypted)              │
│ • Or: export configs to text files      │
└─────────────────────────────────────────┘
     ▲                              ▲
     │ git pull/push                │
     │                              │
Admin 1's Laptop            Admin 2's Laptop
```

**Advantages:**
- Version control
- Merge conflict detection
- Audit trail
- Coordinate changes

**Note:** This requires encrypting database or exporting configs as text.

## Migration Between Locations

**Moving is easy:**

```bash
# On old location
./backup-database.sh

# Copy to new location
scp backups/wg-friend-backup-*.tar.gz new-location:~/

# On new location
tar xzf wg-friend-backup-*.tar.gz
cp wg-friend-backup-*/wg-friend.db ~/wireguard-friend/
cp wg-friend-backup-*/.ssh/wg-friend-* ~/.ssh/

# Set up SSH keys if needed
python3 wg-friend-maintain.py
# [7] SSH Setup
```

See [BACKUP_RESTORE.md](BACKUP_RESTORE.md) for details.

## Recommendations by Use Case

### Home Lab / Personal Use
**Run on:** Subnet router or your laptop
- Simple, practical, keeps servers clean

### Small Business / Team
**Run on:** Dedicated admin box (NAS, Pi, VM)
- Central location, multiple SSH users

### Enterprise / Large Network
**Run on:** Dedicated admin server with access controls
- Multiple admins, audit logging, backups

### Developer / Experimenting
**Run on:** Your workstation
- Easy to test, iterate, rebuild

### "I just want it to work"
**Run on:** Subnet router
- Set it and forget it, manage occasionally

## Common Questions

**Q: Can I run it on multiple machines?**
A: Yes! The database is portable. Just copy it around.

**Q: Does it need to run 24/7?**
A: No! It's a management tool. Run it when you need to make changes.

**Q: Can I run it on Windows?**
A: Yes, Python works on Windows. SSH deployment might need tweaks.

**Q: What if my subnet router is a router appliance (pfSense, OPNsense)?**
A: Run on your workstation instead, SSH to the router for deployments.

**Q: Can I run it in a Docker container?**
A: Yes, but you'll need to mount the database and set up SSH keys.

**Q: What if I don't have a subnet router?**
A: Run on your workstation or a dedicated admin machine.

## Summary Table

| Location | Complexity | Security | Flexibility | Best For |
|----------|------------|----------|-------------|----------|
| Subnet Router |  |  |  | Home networks, pragmatic choice |
| Workstation |  |  |  | Developers, clean servers |
| Coordination Server |  |  |  | Small setups, CS-only |
| Dedicated Admin |  |  |  | Teams, larger networks |
| Anywhere |  | Varies |  | Maximum flexibility |

## The Real Answer

**Pick one place. Stick with it. SSH to it when needed.**

The database is portable and you *can* move it around, but the ideal workflow is:

1. **Choose a location** (subnet router for most people, workstation for power users)
2. **Install wireguard-friend there once**
3. **SSH to that machine** when you need to manage your network
4. **Make changes, deploy configs, exit**
5. **Repeat when needed**

**Don't** copy the database around for daily use. Do use portability for:
- Regular backups
- Migration to new hardware
- Emergency recovery
- Testing changes safely

**Recommended defaults:**

| Your Situation | Run It Here | Access Via |
|----------------|-------------|------------|
| Home network | Subnet router | `ssh subnet-router` |
| Power user / Developer | Your workstation | Direct (or SSH if remote) |
| Team / Enterprise | Dedicated admin box | `ssh admin-server` |
| CS-only network | Your workstation | Direct |

**The keys:**
- ✓ Pick one "home" for the database
- ✓ Back it up regularly to NAS/cloud
- ✓ SSH to the admin machine when needed
- ✗ Don't move database around for daily use

```bash
./backup-database.sh /mnt/nas/backups
```

## Need Help Deciding?

Ask yourself:

1. **Do you have a subnet router?**
   - Yes → Run it there
   - No → Continue to #2

2. **Do you want servers to stay minimal?**
   - Yes → Run on workstation
   - No → Run on coordination server

3. **Do you have multiple admins?**
   - Yes → Dedicated admin box
   - No → Subnet router or workstation

4. **Do you change configs often?**
   - Yes → Workstation (easier access)
   - No → Subnet router (set and forget)

**Still unsure?** Start on your workstation. It's easy to move later!
