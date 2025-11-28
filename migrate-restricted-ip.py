#!/usr/bin/env python3
"""
Migration script to add 'restricted_ip' to access_level constraint
"""

import sqlite3
from pathlib import Path
from rich.console import Console

console = Console()

db_path = Path("wg-friend.db")

if not db_path.exists():
    console.print("[red]Database not found. No migration needed.[/red]")
    exit(1)

console.print(f"[cyan]Migrating database: {db_path}[/cyan]")

conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row
cursor = conn.cursor()

try:
    # Check if migration is needed
    cursor.execute("SELECT access_level FROM peer LIMIT 1")

    console.print("[cyan]Creating new peer table with updated constraint...[/cyan]")

    # Create new table with updated constraint
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
            CHECK (access_level IN ('full_access', 'vpn_only', 'lan_only', 'custom', 'restricted_ip'))
        )
    """)

    # Copy data from old table
    cursor.execute("""
        INSERT INTO peer_new
        SELECT * FROM peer
    """)

    # Drop old table
    cursor.execute("DROP TABLE peer")

    # Rename new table
    cursor.execute("ALTER TABLE peer_new RENAME TO peer")

    conn.commit()
    console.print("[green]✓ Migration successful![/green]")
    console.print("[green]✓ Added 'restricted_ip' to access_level constraint[/green]")

except Exception as e:
    conn.rollback()
    console.print(f"[red]Migration failed: {e}[/red]")
    raise
finally:
    conn.close()
