#!/usr/bin/env python3
"""
Migration script to add 'allowed_ports' column to peer_ip_restrictions table
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
    # Check if column already exists
    cursor.execute("PRAGMA table_info(peer_ip_restrictions)")
    columns = [row['name'] for row in cursor.fetchall()]

    if 'allowed_ports' in columns:
        console.print("[yellow]Column 'allowed_ports' already exists. No migration needed.[/yellow]")
        exit(0)

    console.print("[cyan]Adding 'allowed_ports' column to peer_ip_restrictions...[/cyan]")

    # Add the column
    cursor.execute("""
        ALTER TABLE peer_ip_restrictions
        ADD COLUMN allowed_ports TEXT
    """)

    conn.commit()
    console.print("[green]✓ Migration successful![/green]")
    console.print("[green]✓ Added 'allowed_ports' column to peer_ip_restrictions[/green]")

except Exception as e:
    conn.rollback()
    console.print(f"[red]Migration failed: {e}[/red]")
    raise
finally:
    conn.close()
