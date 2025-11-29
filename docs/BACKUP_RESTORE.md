# Database Backup & Restore Guide

## Why Backup?

Your `wg-friend.db` contains:
- All WireGuard configurations (coordination server, subnet routers, peers)
- Private keys and public keys
- Firewall rules and peer order
- IP allocations and access levels

**This is critical data** - back it up regularly!

## Safe Backup Process

### Method 1: Simple File Copy (Recommended)

**Stop all write operations first:**
```bash
# Make sure no maintenance/onboarding scripts are running
# Then copy the database
cp wg-friend.db wg-friend.db.backup-$(date +%Y%m%d-%H%M%S)
```

**Full backup including SSH keys and configs:**
```bash
# Create backup directory
mkdir -p ~/wg-friend-backup-$(date +%Y%m%d)
cd ~/wg-friend-backup-$(date +%Y%m%d)

# Copy database
cp ~/wireguard-friend/wg-friend.db .

# Copy SSH keys (if you've set them up)
cp -r ~/.ssh/wg-friend-* . 2>/dev/null || true

# Copy generated configs
cp -r ~/wireguard-friend/output . 2>/dev/null || true

# Create archive
cd ..
tar czf wg-friend-backup-$(date +%Y%m%d).tar.gz wg-friend-backup-$(date +%Y%m%d)/
```

### Method 2: SQLite Backup Command (Most Reliable)

SQLite has a built-in backup command that's safer than file copy:

```bash
sqlite3 wg-friend.db ".backup wg-friend-backup-$(date +%Y%m%d).db"
```

This ensures:
- Database isn't corrupted mid-copy
- All transactions are complete
- File integrity is maintained

### Method 3: Export to SQL

For maximum portability:
```bash
sqlite3 wg-friend.db .dump > wg-friend-export-$(date +%Y%m%d).sql
```

Restore with:
```bash
sqlite3 wg-friend-new.db < wg-friend-export-YYYYMMDD.sql
```

## Copying to Another Machine

### Safe Copy Checklist

1. **Stop write operations** on source machine
2. **Verify database integrity** before copying:
   ```bash
   sqlite3 wg-friend.db "PRAGMA integrity_check;"
   ```
   Should return: `ok`

3. **Copy the file**:
   ```bash
   # Via SCP
   scp wg-friend.db user@other-machine:~/wireguard-friend/

   # Via rsync (recommended - verifies transfer)
   rsync -avz --checksum wg-friend.db user@other-machine:~/wireguard-friend/

   # Via USB drive
   cp wg-friend.db /media/usb-drive/
   ```

4. **Verify integrity on destination**:
   ```bash
   sqlite3 wg-friend.db "PRAGMA integrity_check;"
   ```

5. **Also copy these if needed**:
   - `~/.ssh/wg-friend-*` - SSH keys for deployment
   - `output/` - Generated configs
   - `import/` - Original imported configs (if you kept them)

### What Gets Copied

✅ **Database contains:**
- All peer/CS/SN configurations
- Private keys (encrypted in WireGuard configs)
- IP allocations
- Firewall rules
- Peer order
- Access levels

❌ **Database does NOT contain:**
- SSH keys (stored in `~/.ssh/`)
- Generated config files (stored in `output/`)
- Python scripts (stored in repo)

### Path Independence

Good news: The database is **path-independent**! It doesn't store absolute paths, so you can:
- Copy to any directory
- Rename the file
- Move between machines
- Change usernames

The database only stores:
- Configuration text (WireGuard configs)
- Keys and metadata
- Relative relationships

## ⚠️ Network Storage (NAS/NFS/SMB) - NOT RECOMMENDED

### Why SQLite + Network Storage = Risky

SQLite was designed for **local disk** access. Network file systems can cause:

**Corruption Risk:**
- NFS/SMB file locking is unreliable
- Concurrent writes can corrupt database
- Network interruptions can leave partial writes

**Performance Issues:**
- Every query requires network round-trip
- 10-100x slower than local disk
- Timeout errors on slow networks

**When It Might Work:**
- **Single user only** (no concurrent access)
- **Mostly read operations** (list/view configs)
- **Reliable network** (Gigabit LAN, not WiFi)
- **Modern NFS** (v4+ with proper locking)

### If You Must Use Network Storage

**Option 1: Read-Only Reference Copy**
```bash
# Keep working copy local
sqlite3 wg-friend.db

# Periodically copy to NAS for backup/reference
rsync -avz wg-friend.db /mnt/nas/backups/
```

**Option 2: Copy-Work-Copy Pattern**
```bash
# Copy from NAS to local
cp /mnt/nas/wg-friend.db ~/wg-friend.db

# Do all work locally
python3 wg-friend-maintain.py

# Copy back to NAS
cp ~/wg-friend.db /mnt/nas/wg-friend.db
```

**Option 3: Symbolic Link (Advanced)**
```bash
# Only if you understand the risks!
ln -s /mnt/nas/wg-friend.db ~/wireguard-friend/wg-friend.db

# Test integrity frequently
sqlite3 wg-friend.db "PRAGMA integrity_check;"
```

### Better Alternatives

**For Backup:**
- Use automated local → NAS backup script
- Git repository with encrypted database
- Cloud backup (encrypted)

**For Multi-Machine Access:**
- Run wg-friend on one "admin" machine
- SSH into that machine to manage configs
- Or: Export configs, version control them

**For Team/Shared Access:**
- SQLite isn't the right tool
- Consider: PostgreSQL, MySQL, or config files in Git
- But that would require major refactoring

## Database Migration Between Machines

### Use Case: Moving Admin Workstation

**Scenario:** You manage WireGuard on laptop A, want to switch to laptop B.

```bash
# On Machine A (old admin machine)
cd ~/wireguard-friend
tar czf wg-friend-migration.tar.gz wg-friend.db output/ ~/.ssh/wg-friend-*

# Copy to Machine B
scp wg-friend-migration.tar.gz machine-b:~/

# On Machine B (new admin machine)
cd ~
tar xzf wg-friend-migration.tar.gz
mv wg-friend.db ~/wireguard-friend/
mv .ssh/wg-friend-* ~/.ssh/
mv output ~/wireguard-friend/

# Verify
cd ~/wireguard-friend
sqlite3 wg-friend.db "PRAGMA integrity_check;"
python3 wg-friend-maintain.py
```

## Custom Database Path

You can specify a custom database location:

```bash
# Via command-line (if we add this feature)
python3 wg-friend-maintain.py --db /path/to/custom.db

# Via environment variable (if we add this feature)
export WG_FRIEND_DB=/mnt/nas/wg-friend.db
python3 wg-friend-maintain.py
```

## Automated Backup Script

See `backup-database.sh` for automated backups.

## Summary

✅ **DO:**
- Copy database files freely between machines
- Use `.backup` command for safe copies
- Verify integrity after copying
- Keep backups in multiple locations
- Store on local disk for daily use

❌ **DON'T:**
- Access database on NFS/SMB from multiple machines
- Copy database while scripts are running
- Assume network storage is safe for SQLite
- Forget to copy SSH keys and output/ directory

🤔 **MAYBE:**
- Single-user read-only access over NFS
- Backup copies to NAS (not working copy)
- Copy-work-copy workflow for occasional remote use

## Need Help?

If you run into issues:
1. Check integrity: `sqlite3 wg-friend.db "PRAGMA integrity_check;"`
2. Restore from backup
3. Report corruption immediately
4. Don't continue using corrupted database
