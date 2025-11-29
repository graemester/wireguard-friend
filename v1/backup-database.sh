#!/bin/bash
#
# WireGuard Friend - Automated Backup Script
#
# This script safely backs up your WireGuard Friend database,
# SSH keys, and generated configurations.
#
# Usage:
#   ./backup-database.sh [backup_location]
#
# Examples:
#   ./backup-database.sh                    # Backup to ./backups/
#   ./backup-database.sh /mnt/nas/backups   # Backup to NAS
#   ./backup-database.sh ~/Dropbox/backups  # Backup to Dropbox
#

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
DB_FILE="wg-friend.db"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
DEFAULT_BACKUP_DIR="backups"
BACKUP_DIR="${1:-$DEFAULT_BACKUP_DIR}"
BACKUP_NAME="wg-friend-backup-${TIMESTAMP}"
BACKUP_PATH="${BACKUP_DIR}/${BACKUP_NAME}"

echo -e "${CYAN}WireGuard Friend - Database Backup${NC}"
echo "======================================"
echo ""

# Check if database exists
if [ ! -f "$DB_FILE" ]; then
    echo -e "${RED}✗ Database not found: $DB_FILE${NC}"
    echo -e "${YELLOW}  Run wg-friend-onboard-v2.py first to create database${NC}"
    exit 1
fi

echo -e "${CYAN}Checking database integrity...${NC}"
integrity_check=$(sqlite3 "$DB_FILE" "PRAGMA integrity_check;")
if [ "$integrity_check" != "ok" ]; then
    echo -e "${RED}✗ Database integrity check failed!${NC}"
    echo -e "${RED}  Result: $integrity_check${NC}"
    echo -e "${YELLOW}  Database may be corrupted. Restore from a previous backup.${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Database integrity OK${NC}"

# Create backup directory
mkdir -p "$BACKUP_PATH"
echo -e "${CYAN}Creating backup in: $BACKUP_PATH${NC}"

# Backup database using SQLite's .backup command (safest method)
echo -e "${CYAN}Backing up database...${NC}"
sqlite3 "$DB_FILE" ".backup '${BACKUP_PATH}/${DB_FILE}'"
echo -e "${GREEN}✓ Database backed up${NC}"

# Backup SSH keys if they exist
echo -e "${CYAN}Backing up SSH keys...${NC}"
ssh_keys_found=0
for key in ~/.ssh/wg-friend-*; do
    if [ -f "$key" ]; then
        cp "$key" "$BACKUP_PATH/"
        ssh_keys_found=$((ssh_keys_found + 1))
    fi
done

if [ $ssh_keys_found -gt 0 ]; then
    echo -e "${GREEN}✓ Backed up $ssh_keys_found SSH key file(s)${NC}"
else
    echo -e "${YELLOW}⚠ No SSH keys found (this is OK if you haven't set them up yet)${NC}"
fi

# Backup output directory if it exists
if [ -d "output" ]; then
    echo -e "${CYAN}Backing up generated configs...${NC}"
    cp -r output "$BACKUP_PATH/"
    config_count=$(find output -name "*.conf" | wc -l)
    echo -e "${GREEN}✓ Backed up output/ directory ($config_count config files)${NC}"
else
    echo -e "${YELLOW}⚠ No output/ directory found${NC}"
fi

# Create a manifest file
echo -e "${CYAN}Creating backup manifest...${NC}"
cat > "$BACKUP_PATH/MANIFEST.txt" <<EOF
WireGuard Friend Backup
=======================

Backup Date: $(date)
Backup Location: $BACKUP_PATH

Contents:
---------
EOF

# List backed up files
ls -lh "$BACKUP_PATH" >> "$BACKUP_PATH/MANIFEST.txt"

echo "" >> "$BACKUP_PATH/MANIFEST.txt"
echo "Database Info:" >> "$BACKUP_PATH/MANIFEST.txt"
echo "-------------" >> "$BACKUP_PATH/MANIFEST.txt"

# Get database stats
sqlite3 "$BACKUP_PATH/$DB_FILE" <<QUERY >> "$BACKUP_PATH/MANIFEST.txt"
SELECT 'Coordination Servers: ' || COUNT(*) FROM coordination_server;
SELECT 'Subnet Routers: ' || COUNT(*) FROM subnet_router;
SELECT 'Peers: ' || COUNT(*) FROM peer;
QUERY

echo -e "${GREEN}✓ Manifest created${NC}"

# Create compressed archive
echo -e "${CYAN}Creating compressed archive...${NC}"
cd "$BACKUP_DIR"
tar czf "${BACKUP_NAME}.tar.gz" "${BACKUP_NAME}/"
archive_size=$(du -h "${BACKUP_NAME}.tar.gz" | cut -f1)
echo -e "${GREEN}✓ Archive created: ${BACKUP_NAME}.tar.gz ($archive_size)${NC}"

# Verify archive
echo -e "${CYAN}Verifying archive...${NC}"
if tar tzf "${BACKUP_NAME}.tar.gz" > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Archive verified${NC}"
else
    echo -e "${RED}✗ Archive verification failed${NC}"
    exit 1
fi

# Clean up uncompressed backup
cd ..
rm -rf "$BACKUP_PATH"

echo ""
echo -e "${GREEN}======================================"
echo -e "Backup completed successfully!"
echo -e "======================================${NC}"
echo ""
echo -e "${CYAN}Backup Details:${NC}"
echo -e "  Location: ${BACKUP_DIR}/${BACKUP_NAME}.tar.gz"
echo -e "  Size: $archive_size"
echo ""
echo -e "${CYAN}To restore this backup:${NC}"
echo -e "  tar xzf ${BACKUP_DIR}/${BACKUP_NAME}.tar.gz"
echo -e "  cp ${BACKUP_NAME}/$DB_FILE ./"
echo -e "  cp ${BACKUP_NAME}/.ssh/wg-friend-* ~/.ssh/"
echo -e "  cp -r ${BACKUP_NAME}/output ./"
echo ""
echo -e "${CYAN}To copy to another machine:${NC}"
echo -e "  scp ${BACKUP_DIR}/${BACKUP_NAME}.tar.gz user@other-machine:~/"
echo ""

# Keep only last 10 backups
echo -e "${CYAN}Cleaning up old backups (keeping last 10)...${NC}"
cd "$BACKUP_DIR"
ls -t wg-friend-backup-*.tar.gz 2>/dev/null | tail -n +11 | xargs -r rm
backup_count=$(ls -1 wg-friend-backup-*.tar.gz 2>/dev/null | wc -l)
echo -e "${GREEN}✓ $backup_count backup(s) retained${NC}"
