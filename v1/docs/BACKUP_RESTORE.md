# Database Backup & Restore Guide

## Database Contents

Your `wireguard.db` contains:
- WireGuard configurations (coordination server, subnet routers, peers)
- Private keys and public keys
- permanent_guid assignments
- IP allocations and access levels
- Key rotation history

Back it up regularly.

## Backup Methods

### Method 1: Simple File Copy

Stop all write operations first:
```bash
# Make sure no wg-friend operations are running
cp wireguard.db wireguard.db.backup-$(date +%Y%m%d-%H%M%S)
```

Complete backup including configs:
```bash
# Create backup directory
mkdir -p ~/wg-backup-$(date +%Y%m%d)
cd ~/wg-backup-$(date +%Y%m%d)

# Copy database
cp ~/wireguard-friend/wireguard.db .

# Copy generated configs
cp -r ~/wireguard-friend/generated . 2>/dev/null || true

# Create archive
cd ..
tar czf wg-backup-$(date +%Y%m%d).tar.gz wg-backup-$(date +%Y%m%d)/
```

### Method 2: SQLite Backup Command

SQLite's built-in backup ensures database integrity:

```bash
sqlite3 wireguard.db ".backup wireguard-backup-$(date +%Y%m%d).db"
```

This ensures:
- Database isn't corrupted mid-copy
- All transactions are complete
- File integrity is maintained

### Method 3: Export to SQL

For portability:
```bash
sqlite3 wireguard.db .dump > wireguard-export-$(date +%Y%m%d).sql
```

Restore with:
```bash
sqlite3 wireguard-new.db < wireguard-export-YYYYMMDD.sql
```

## Copying to Another Machine

### Safe Copy Checklist

1. Stop write operations on source machine
2. Verify database integrity before copying:
   ```bash
   sqlite3 wireguard.db "PRAGMA integrity_check;"
   ```
   Should return: `ok`

3. Copy the file:
   ```bash
   scp wireguard.db user@other-machine:/path/to/destination/
   ```

4. Verify integrity on destination:
   ```bash
   sqlite3 wireguard.db "PRAGMA integrity_check;"
   ```

5. Test with read-only query:
   ```bash
   sqlite3 wireguard.db "SELECT COUNT(*) FROM remote;"
   ```

## Restore Process

### From Backup File

```bash
# Verify backup integrity
sqlite3 wireguard.db.backup "PRAGMA integrity_check;"

# If ok, restore
cp wireguard.db.backup wireguard.db
```

### From SQL Dump

```bash
# Create new database from dump
sqlite3 wireguard-restored.db < wireguard-export-YYYYMMDD.sql

# Verify
sqlite3 wireguard-restored.db "PRAGMA integrity_check;"

# If ok, use it
mv wireguard-restored.db wireguard.db
```

## Backup Schedule

Recommended backup frequency:

- Before major changes (adding subnet router, bulk peer operations)
- Before key rotations
- Weekly for active networks
- Before software updates

## Database Migration

Moving to a new machine:

```bash
# On old machine
sqlite3 wireguard.db ".backup wireguard-$(hostname)-$(date +%Y%m%d).db"
scp wireguard-*.db user@new-machine:~/

# On new machine
cd ~/wireguard-friend
cp ~/wireguard-*.db wireguard.db
sqlite3 wireguard.db "PRAGMA integrity_check;"
wg-friend status  # Test it works
```

## What's NOT in the Database

These are generated from the database:
- `generated/*.conf` files
- `generated/*.png` QR codes

These can be regenerated anytime:
```bash
wg-friend generate --qr
```

## Recovery Scenarios

### Lost Database, Have Configs

Import existing configs:
```bash
wg-friend import --cs /etc/wireguard/wg0.conf
# Then add peers manually or import their configs
```

### Corrupted Database

Try recovery:
```bash
# Attempt to recover
sqlite3 wireguard.db ".recover" | sqlite3 wireguard-recovered.db

# Check integrity
sqlite3 wireguard-recovered.db "PRAGMA integrity_check;"

# If ok, use it
mv wireguard-recovered.db wireguard.db
```

### Database Too Old

Check schema version:
```bash
sqlite3 wireguard.db "SELECT * FROM sqlite_master WHERE type='table';"
```

If schema is incompatible, export and reimport configs.

## Security Considerations

Database contains private keys:
- Store backups securely (encrypted filesystem, secure storage)
- Don't commit to git
- Don't upload to cloud unencrypted
- Use proper file permissions: `chmod 600 wireguard.db*`

Encrypt backups:
```bash
# Create encrypted backup
tar czf - wireguard.db | gpg -c > wireguard-backup-$(date +%Y%m%d).tar.gz.gpg

# Restore encrypted backup
gpg -d wireguard-backup-YYYYMMDD.tar.gz.gpg | tar xzf -
```

## Automation

Simple backup script:
```bash
#!/bin/bash
# backup-db.sh

BACKUP_DIR="$HOME/wg-backups"
DATE=$(date +%Y%m%d-%H%M%S)

mkdir -p "$BACKUP_DIR"
sqlite3 wireguard.db ".backup $BACKUP_DIR/wireguard-$DATE.db"

# Keep only last 10 backups
ls -t "$BACKUP_DIR"/wireguard-*.db | tail -n +11 | xargs rm -f

echo "Backup created: $BACKUP_DIR/wireguard-$DATE.db"
```

Run weekly:
```bash
# Add to crontab
0 2 * * 0 /path/to/backup-db.sh
```
