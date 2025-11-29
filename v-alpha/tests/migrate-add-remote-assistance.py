#!/usr/bin/env python3
"""
Migration script to add 'remote_assistance' to access_level CHECK constraint

SQLite doesn't support altering CHECK constraints, so we need to recreate the table.
This migration:
1. Creates a new peer table with updated CHECK constraint
2. Copies all data from old table
3. Drops old table and renames new table
4. Recreates all dependent foreign keys
"""

import sys
import sqlite3
from pathlib import Path
from rich.console import Console

console = Console()

db_path = Path("wg-friend.db")

if not db_path.exists():
    console.print("[yellow]Database not found. No migration needed.[/yellow]")
    sys.exit(0)

console.print(f"[cyan]Migrating database: {db_path}[/cyan]")

conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row

# Enable foreign keys
conn.execute("PRAGMA foreign_keys = OFF")

try:
    cursor = conn.cursor()

    console.print("[cyan]Step 1: Creating new peer table with updated CHECK constraint...[/cyan]")

    # Create new peer table with updated constraint
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS peer_new (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            cs_id INTEGER NOT NULL,
            public_key TEXT NOT NULL,
            private_key TEXT,
            ipv4_address TEXT NOT NULL,
            ipv6_address TEXT NOT NULL,
            access_level TEXT NOT NULL,
            preshared_key TEXT,
            persistent_keepalive INTEGER,
            has_endpoint BOOLEAN DEFAULT 0,
            endpoint TEXT,
            raw_interface_block TEXT,
            raw_peer_block TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_rotated TIMESTAMP,
            FOREIGN KEY (cs_id) REFERENCES coordination_server(id) ON DELETE CASCADE,
            CHECK (access_level IN ('full_access', 'vpn_only', 'lan_only', 'custom', 'restricted_ip', 'remote_assistance'))
        )
    """)

    console.print("[cyan]Step 2: Copying data from old table...[/cyan]")

    # Copy all data
    cursor.execute("""
        INSERT INTO peer_new
        SELECT * FROM peer
    """)

    rows_copied = cursor.rowcount
    console.print(f"[green]✓ Copied {rows_copied} peer(s)[/green]")

    console.print("[cyan]Step 3: Dropping old table and renaming new table...[/cyan]")

    # Drop old table
    cursor.execute("DROP TABLE peer")

    # Rename new table
    cursor.execute("ALTER TABLE peer_new RENAME TO peer")

    console.print("[green]✓ Table structure updated[/green]")

    # Commit changes
    conn.commit()

    console.print("[green]✓ Migration successful![/green]")
    console.print("[green]✓ 'remote_assistance' access level is now available[/green]")

except Exception as e:
    conn.rollback()
    console.print(f"[red]Migration failed: {e}[/red]")
    console.print("[yellow]The database has been rolled back to its previous state.[/yellow]")
    sys.exit(1)
finally:
    # Re-enable foreign keys
    conn.execute("PRAGMA foreign_keys = ON")
    conn.close()
