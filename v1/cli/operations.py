"""
Operations Menu - Security, Backup, and Compliance Features

Provides TUI access to Phase 1 and Phase 2 features:
- Database Encryption
- Rotation Policies
- Audit Log Viewing
- Disaster Recovery (Backup/Restore)
- Configuration Drift Detection
- Compliance Reporting
- PSK Management
- Troubleshooting Wizard
- Prometheus Metrics
- Webhook Notifications
"""

import sys
from pathlib import Path
from datetime import datetime
from typing import Optional

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich import box
    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False
    console = None


def getch() -> str:
    """Read a single keypress without waiting for Enter"""
    import tty
    import termios
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        ch = sys.stdin.read(1)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
    return ch


def clear_screen():
    """Clear screen and move cursor to home"""
    if RICH_AVAILABLE:
        console.clear()
    print("\033[H", end="", flush=True)


def get_keypress_choice(max_choice: int, allow_quit: bool = True) -> Optional[int]:
    """Get a single keypress menu choice."""
    sys.stdout.flush()
    ch = getch()

    if allow_quit and ch.lower() == 'q':
        return None
    if ch == '\x03':  # Ctrl+C
        return None
    if ch == '\x1b':  # Escape
        return None

    if ch.isdigit() and ch != '0':
        num = int(ch)
        if 1 <= num <= max_choice:
            return num

    return -1


def print_menu(title: str, options: list, include_quit: bool = True):
    """Print a menu with Rich styling if available."""
    if RICH_AVAILABLE:
        menu_lines = []
        for i, option in enumerate(options, 1):
            if '[' in option and ']' in option and not option.startswith('['):
                main_text = option.split('[')[0].strip()
                hint = option.split('[')[1].split(']')[0]
                menu_lines.append(f"  [cyan]{i}.[/cyan] {main_text:32} [dim]- {hint}[/dim]")
            else:
                menu_lines.append(f"  [cyan]{i}.[/cyan] {option}")

        if include_quit:
            menu_lines.append(f"  [dim]q. Back[/dim]")

        console.print()
        console.print(Panel(
            "\n".join(menu_lines),
            title=f"[bold]{title}[/bold]",
            title_align="left",
            border_style="cyan",
            padding=(1, 2)
        ))
        console.print()
    else:
        print(f"\n{'=' * 70}")
        print(f"{title}")
        print(f"{'=' * 70}")
        for i, option in enumerate(options, 1):
            print(f"  {i}. {option}")
        if include_quit:
            print(f"  q. Back")
        print()


# =============================================================================
# MAIN OPERATIONS MENU
# =============================================================================

def show_operations_menu(db_path: str):
    """Main operations menu."""
    while True:
        clear_screen()
        print_menu(
            "OPERATIONS - Security & Administration",
            [
                "Security [encryption, PSK, audit log]",
                "Backup & Recovery [backup, restore, verify]",
                "Compliance [reports, rotation policies]",
                "Monitoring [drift detection, metrics]",
                "Troubleshooting [diagnostic wizard]",
                "Webhooks [notification endpoints]",
            ]
        )

        print("  Select: ", end="", flush=True)
        choice = get_keypress_choice(6)

        if choice is None:
            return

        if choice == -1:
            continue

        if choice == 1:
            show_security_menu(db_path)
        elif choice == 2:
            show_backup_menu(db_path)
        elif choice == 3:
            show_compliance_menu(db_path)
        elif choice == 4:
            show_monitoring_menu(db_path)
        elif choice == 5:
            show_troubleshooting_menu(db_path)
        elif choice == 6:
            show_webhooks_menu(db_path)


# =============================================================================
# SECURITY MENU
# =============================================================================

def show_security_menu(db_path: str):
    """Security submenu - encryption, PSK, audit log."""
    while True:
        clear_screen()
        print_menu(
            "SECURITY",
            [
                "Database Encryption [protect private keys at rest]",
                "PSK Management [pre-shared key automation]",
                "Audit Log [view security events]",
                "Export Audit Log [compliance export]",
            ]
        )

        print("  Select: ", end="", flush=True)
        choice = get_keypress_choice(4)

        if choice is None:
            return

        if choice == -1:
            continue

        if choice == 1:
            show_encryption_menu(db_path)
        elif choice == 2:
            show_psk_menu(db_path)
        elif choice == 3:
            show_audit_log(db_path)
        elif choice == 4:
            export_audit_log(db_path)


def show_encryption_menu(db_path: str):
    """Database encryption management."""
    from v1.encryption import EncryptionManager

    clear_screen()
    try:
        mgr = EncryptionManager(db_path)
        is_encrypted = mgr.is_encryption_enabled()

        if RICH_AVAILABLE:
            status = "[green]ENABLED[/green]" if is_encrypted else "[yellow]DISABLED[/yellow]"
            console.print(Panel(
                f"Database Encryption Status: {status}\n\n"
                f"Encryption protects private keys stored in the database.\n"
                f"If enabled, you'll be prompted for passphrase on startup.",
                title="[bold]DATABASE ENCRYPTION[/bold]",
                border_style="cyan"
            ))
        else:
            status = "ENABLED" if is_encrypted else "DISABLED"
            print(f"\nDatabase Encryption Status: {status}")

        print()
        if is_encrypted:
            print("  1. Change passphrase")
            print("  2. Disable encryption")
        else:
            print("  1. Enable encryption")

        print("  q. Back")
        print()

        action = input("  Choice: ").strip().lower()

        if action == 'q' or not action:
            return

        if not is_encrypted and action == '1':
            # Enable encryption
            import getpass
            passphrase = getpass.getpass("  Enter new passphrase: ")
            confirm = getpass.getpass("  Confirm passphrase: ")

            if passphrase != confirm:
                print("\n  Passphrases don't match.")
            elif len(passphrase) < 8:
                print("\n  Passphrase must be at least 8 characters.")
            else:
                try:
                    mgr.enable_encryption(passphrase)
                    print("\n  [green]Encryption enabled successfully.[/green]" if RICH_AVAILABLE
                          else "\n  Encryption enabled successfully.")
                except Exception as e:
                    print(f"\n  Error: {e}")

        elif is_encrypted and action == '1':
            # Change passphrase
            import getpass
            current = getpass.getpass("  Current passphrase: ")
            new_pass = getpass.getpass("  New passphrase: ")
            confirm = getpass.getpass("  Confirm new passphrase: ")

            if new_pass != confirm:
                print("\n  Passphrases don't match.")
            else:
                try:
                    mgr.change_passphrase(current, new_pass)
                    print("\n  Passphrase changed successfully.")
                except Exception as e:
                    print(f"\n  Error: {e}")

        elif is_encrypted and action == '2':
            # Disable encryption
            import getpass
            passphrase = getpass.getpass("  Enter current passphrase to disable: ")
            confirm = input("  Type 'DISABLE' to confirm: ").strip()

            if confirm != 'DISABLE':
                print("\n  Cancelled.")
            else:
                try:
                    mgr.disable_encryption(passphrase)
                    print("\n  Encryption disabled.")
                except Exception as e:
                    print(f"\n  Error: {e}")

    except Exception as e:
        print(f"\nError: {e}")

    print("\nPress any key..."); getch()


def show_psk_menu(db_path: str):
    """PSK management menu."""
    from v1.psk_management import PSKManager

    clear_screen()
    try:
        mgr = PSKManager(db_path)
        stats = mgr.get_psk_statistics()

        if RICH_AVAILABLE:
            table = Table(title="PSK Status", box=box.ROUNDED)
            table.add_column("Metric")
            table.add_column("Value", justify="right")

            table.add_row("Total Peer Pairs", str(stats.get('total_pairs', 0)))
            table.add_row("With PSK", str(stats.get('with_psk', 0)))
            table.add_row("Without PSK", str(stats.get('without_psk', 0)))
            table.add_row("PSK Coverage", f"{stats.get('coverage_percent', 0):.1f}%")

            console.print()
            console.print(table)
            console.print()
        else:
            print("\nPSK Statistics:")
            print(f"  Total peer pairs: {stats.get('total_pairs', 0)}")
            print(f"  With PSK: {stats.get('with_psk', 0)}")
            print(f"  Coverage: {stats.get('coverage_percent', 0):.1f}%")
            print()

        print("  1. Generate PSKs for all peers without")
        print("  2. Rotate all PSKs")
        print("  3. View PSK details")
        print("  q. Back")
        print()

        action = input("  Choice: ").strip()

        if action == '1':
            count = mgr.generate_missing_psks()
            print(f"\n  Generated {count} new PSKs.")
        elif action == '2':
            confirm = input("  Rotate all PSKs? [y/N]: ").strip().lower()
            if confirm == 'y':
                count = mgr.rotate_all_psks()
                print(f"\n  Rotated {count} PSKs.")
        elif action == '3':
            entries = mgr.list_psk_entries()
            print(f"\n  {len(entries)} PSK entries found.")
            for entry in entries[:10]:
                print(f"    - {entry.entity_type}:{entry.entity_id} -> "
                      f"peer:{entry.peer_entity_type}:{entry.peer_entity_id}")

    except Exception as e:
        print(f"\nError: {e}")

    print("\nPress any key..."); getch()


def show_audit_log(db_path: str):
    """View recent audit log entries."""
    from v1.audit_log import AuditLogger

    clear_screen()
    try:
        logger = AuditLogger(db_path)
        entries = logger.get_recent_entries(limit=20)

        if RICH_AVAILABLE:
            table = Table(title="Recent Security Events", box=box.ROUNDED)
            table.add_column("Time", style="dim", width=19)
            table.add_column("Event", style="cyan")
            table.add_column("Entity")
            table.add_column("Operator")

            for entry in entries:
                ts = entry.timestamp.strftime("%Y-%m-%d %H:%M:%S") if entry.timestamp else ""
                table.add_row(
                    ts,
                    entry.event_type.value if hasattr(entry.event_type, 'value') else str(entry.event_type),
                    f"{entry.entity_type}:{entry.entity_id}" if entry.entity_type else "-",
                    entry.operator or "system"
                )

            console.print()
            console.print(table)
        else:
            print("\nRecent Security Events:")
            print("-" * 70)
            for entry in entries:
                ts = entry.timestamp.strftime("%Y-%m-%d %H:%M:%S") if entry.timestamp else ""
                print(f"{ts} | {entry.event_type} | {entry.entity_type}:{entry.entity_id}")

    except Exception as e:
        print(f"\nError: {e}")

    print("\nPress any key..."); getch()


def export_audit_log(db_path: str):
    """Export audit log for compliance."""
    from v1.audit_log import AuditLogger

    clear_screen()
    try:
        logger = AuditLogger(db_path)

        print("\nExport Audit Log")
        print("-" * 40)
        print()
        days = input("  Days to export [90]: ").strip()
        days = int(days) if days else 90

        output_path = Path(f"audit_log_export_{datetime.now().strftime('%Y%m%d')}.json")
        logger.export_json(output_path, days=days)

        print(f"\n  Exported to: {output_path}")

    except Exception as e:
        print(f"\nError: {e}")

    print("\nPress any key..."); getch()


# =============================================================================
# BACKUP & RECOVERY MENU
# =============================================================================

def show_backup_menu(db_path: str):
    """Backup and recovery menu."""
    while True:
        clear_screen()
        print_menu(
            "BACKUP & RECOVERY",
            [
                "Create Backup [full database backup]",
                "List Backups [view backup history]",
                "Restore from Backup [restore database]",
                "Verify Backup [check backup integrity]",
            ]
        )

        print("  Select: ", end="", flush=True)
        choice = get_keypress_choice(4)

        if choice is None:
            return

        if choice == -1:
            continue

        if choice == 1:
            create_backup(db_path)
        elif choice == 2:
            list_backups(db_path)
        elif choice == 3:
            restore_backup(db_path)
        elif choice == 4:
            verify_backup(db_path)


def create_backup(db_path: str):
    """Create a new backup."""
    from v1.disaster_recovery import DisasterRecovery

    clear_screen()
    try:
        dr = DisasterRecovery(db_path)

        print("\nCreate Backup")
        print("-" * 40)
        print()

        encrypt = input("  Encrypt backup? [Y/n]: ").strip().lower()
        encrypt = encrypt != 'n'

        passphrase = None
        if encrypt:
            import getpass
            passphrase = getpass.getpass("  Backup passphrase: ")
            confirm = getpass.getpass("  Confirm passphrase: ")
            if passphrase != confirm:
                print("\n  Passphrases don't match.")
                print("\nPress any key..."); getch()
                return

        output_dir = Path("backups")
        output_dir.mkdir(exist_ok=True)

        backup_id = dr.create_backup(
            output_dir=output_dir,
            encrypt=encrypt,
            passphrase=passphrase
        )

        print(f"\n  Backup created: {backup_id}")
        print(f"  Location: {output_dir / backup_id}")

    except Exception as e:
        print(f"\nError: {e}")

    print("\nPress any key..."); getch()


def list_backups(db_path: str):
    """List available backups."""
    from v1.disaster_recovery import DisasterRecovery

    clear_screen()
    try:
        dr = DisasterRecovery(db_path)
        backups = dr.list_backups()

        if RICH_AVAILABLE:
            table = Table(title="Backup History", box=box.ROUNDED)
            table.add_column("ID")
            table.add_column("Created", style="dim")
            table.add_column("Type")
            table.add_column("Size", justify="right")
            table.add_column("Verified", justify="center")

            for b in backups:
                table.add_row(
                    b.backup_id[:20] + "...",
                    b.created_at.strftime("%Y-%m-%d %H:%M") if b.created_at else "",
                    b.backup_type,
                    f"{b.size_bytes / 1024:.1f} KB" if b.size_bytes else "-",
                    "[green]Yes[/green]" if b.verified else "[yellow]No[/yellow]"
                )

            console.print()
            console.print(table)
        else:
            print("\nBackup History:")
            print("-" * 70)
            for b in backups:
                print(f"  {b.backup_id[:30]} | {b.created_at} | {b.backup_type}")

    except Exception as e:
        print(f"\nError: {e}")

    print("\nPress any key..."); getch()


def restore_backup(db_path: str):
    """Restore from backup."""
    from v1.disaster_recovery import DisasterRecovery

    clear_screen()
    try:
        dr = DisasterRecovery(db_path)

        print("\nRestore from Backup")
        print("-" * 40)
        print()
        print("  [red]WARNING: This will overwrite the current database![/red]" if RICH_AVAILABLE
              else "  WARNING: This will overwrite the current database!")
        print()

        backup_path = input("  Backup file path: ").strip()
        if not backup_path:
            return

        backup_file = Path(backup_path)
        if not backup_file.exists():
            print(f"\n  File not found: {backup_file}")
            print("\nPress any key..."); getch()
            return

        passphrase = None
        if backup_file.suffix == '.enc' or 'encrypted' in str(backup_file):
            import getpass
            passphrase = getpass.getpass("  Backup passphrase: ")

        confirm = input("  Type 'RESTORE' to confirm: ").strip()
        if confirm != 'RESTORE':
            print("\n  Cancelled.")
            print("\nPress any key..."); getch()
            return

        dr.restore_backup(backup_file, passphrase=passphrase)
        print("\n  Database restored successfully.")

    except Exception as e:
        print(f"\nError: {e}")

    print("\nPress any key..."); getch()


def verify_backup(db_path: str):
    """Verify backup integrity."""
    from v1.disaster_recovery import DisasterRecovery

    clear_screen()
    try:
        dr = DisasterRecovery(db_path)

        print("\nVerify Backup")
        print("-" * 40)
        print()

        backup_path = input("  Backup file path: ").strip()
        if not backup_path:
            return

        backup_file = Path(backup_path)
        if not backup_file.exists():
            print(f"\n  File not found: {backup_file}")
            print("\nPress any key..."); getch()
            return

        passphrase = None
        if backup_file.suffix == '.enc' or 'encrypted' in str(backup_file):
            import getpass
            passphrase = getpass.getpass("  Backup passphrase: ")

        is_valid = dr.verify_backup(backup_file, passphrase=passphrase)

        if is_valid:
            print("\n  [green]Backup verified successfully.[/green]" if RICH_AVAILABLE
                  else "\n  Backup verified successfully.")
        else:
            print("\n  [red]Backup verification FAILED![/red]" if RICH_AVAILABLE
                  else "\n  Backup verification FAILED!")

    except Exception as e:
        print(f"\nError: {e}")

    print("\nPress any key..."); getch()


# =============================================================================
# COMPLIANCE MENU
# =============================================================================

def show_compliance_menu(db_path: str):
    """Compliance and reporting menu."""
    while True:
        clear_screen()
        print_menu(
            "COMPLIANCE & POLICIES",
            [
                "Generate Compliance Report [SOC2/ISO27001]",
                "Rotation Policies [scheduled key rotation]",
                "View Policy Status [check compliance]",
                "Run Pending Rotations [execute due rotations]",
            ]
        )

        print("  Select: ", end="", flush=True)
        choice = get_keypress_choice(4)

        if choice is None:
            return

        if choice == -1:
            continue

        if choice == 1:
            generate_compliance_report(db_path)
        elif choice == 2:
            show_rotation_policies(db_path)
        elif choice == 3:
            show_policy_status(db_path)
        elif choice == 4:
            run_pending_rotations(db_path)


def generate_compliance_report(db_path: str):
    """Generate compliance report."""
    from v1.compliance_reporting import ComplianceReporter, ReportType, OutputFormat

    clear_screen()
    try:
        reporter = ComplianceReporter(db_path)

        print("\nGenerate Compliance Report")
        print("-" * 40)
        print()
        print("  Report Types:")
        print("    1. Executive Summary")
        print("    2. Full Compliance Report")
        print("    3. Access Control Report")
        print("    4. Key Rotation Report")
        print("    5. Network Inventory")
        print()

        report_choice = input("  Report type [1]: ").strip()
        report_types = {
            '1': ReportType.EXECUTIVE_SUMMARY,
            '2': ReportType.FULL_COMPLIANCE,
            '3': ReportType.ACCESS_CONTROL,
            '4': ReportType.KEY_ROTATION,
            '5': ReportType.NETWORK_INVENTORY,
        }
        report_type = report_types.get(report_choice, ReportType.EXECUTIVE_SUMMARY)

        print()
        print("  Output Format:")
        print("    1. Markdown")
        print("    2. JSON")
        print("    3. CSV")
        print()

        format_choice = input("  Format [1]: ").strip()
        formats = {
            '1': OutputFormat.MARKDOWN,
            '2': OutputFormat.JSON,
            '3': OutputFormat.CSV,
        }
        output_format = formats.get(format_choice, OutputFormat.MARKDOWN)

        output_dir = Path("reports")
        output_dir.mkdir(exist_ok=True)

        report_path = reporter.generate_report(
            report_type=report_type,
            output_format=output_format,
            output_dir=output_dir
        )

        print(f"\n  Report generated: {report_path}")

        # Show preview
        if output_format == OutputFormat.MARKDOWN:
            view = input("\n  View report? [Y/n]: ").strip().lower()
            if view != 'n':
                content = Path(report_path).read_text()
                print()
                print("-" * 70)
                print(content[:2000])
                if len(content) > 2000:
                    print("\n  ... (truncated)")

    except Exception as e:
        print(f"\nError: {e}")

    print("\nPress any key..."); getch()


def show_rotation_policies(db_path: str):
    """Manage rotation policies."""
    from v1.rotation_policies import RotationPolicyManager, PolicyType, PolicyScope

    clear_screen()
    try:
        mgr = RotationPolicyManager(db_path)
        policies = mgr.list_policies()

        if RICH_AVAILABLE:
            table = Table(title="Rotation Policies", box=box.ROUNDED)
            table.add_column("ID", style="dim")
            table.add_column("Name", style="cyan")
            table.add_column("Type")
            table.add_column("Days", justify="right")
            table.add_column("Scope")
            table.add_column("Enabled", justify="center")

            for p in policies:
                table.add_row(
                    str(p.id),
                    p.name,
                    p.policy_type.value if hasattr(p.policy_type, 'value') else str(p.policy_type),
                    str(p.days_threshold) if p.days_threshold else "-",
                    p.scope.value if hasattr(p.scope, 'value') else str(p.scope),
                    "[green]Yes[/green]" if p.enabled else "[dim]No[/dim]"
                )

            console.print()
            console.print(table)
        else:
            print("\nRotation Policies:")
            print("-" * 70)
            for p in policies:
                print(f"  [{p.id}] {p.name} | {p.policy_type} | {p.days_threshold} days | {p.scope}")

        print()
        print("  1. Create new policy")
        print("  2. Toggle policy enabled/disabled")
        print("  3. Delete policy")
        print("  q. Back")
        print()

        action = input("  Choice: ").strip()

        if action == '1':
            name = input("\n  Policy name: ").strip()
            if not name:
                return

            print("  Type: 1=Time-based, 2=Usage-based")
            ptype = input("  Type [1]: ").strip()
            policy_type = PolicyType.TIME_BASED if ptype != '2' else PolicyType.USAGE_BASED

            days = input("  Days threshold [90]: ").strip()
            days = int(days) if days else 90

            print("  Scope: 1=All, 2=Remotes, 3=Routers")
            scope_input = input("  Scope [1]: ").strip()
            scopes = {'1': PolicyScope.ALL, '2': PolicyScope.REMOTES, '3': PolicyScope.ROUTERS}
            scope = scopes.get(scope_input, PolicyScope.ALL)

            policy_id = mgr.create_policy(name, policy_type, days, scope)
            print(f"\n  Created policy: {name} (ID: {policy_id})")

        elif action == '2' and policies:
            policy_id = input("\n  Policy ID to toggle: ").strip()
            if policy_id:
                mgr.toggle_policy(int(policy_id))
                print("\n  Policy toggled.")

        elif action == '3' and policies:
            policy_id = input("\n  Policy ID to delete: ").strip()
            if policy_id:
                confirm = input("  Confirm delete? [y/N]: ").strip().lower()
                if confirm == 'y':
                    mgr.delete_policy(int(policy_id))
                    print("\n  Policy deleted.")

    except Exception as e:
        print(f"\nError: {e}")

    print("\nPress any key..."); getch()


def show_policy_status(db_path: str):
    """Show rotation policy compliance status."""
    from v1.rotation_policies import RotationPolicyManager

    clear_screen()
    try:
        mgr = RotationPolicyManager(db_path)
        summary = mgr.get_compliance_summary()

        if RICH_AVAILABLE:
            console.print(Panel(
                f"[bold]Compliance Summary[/bold]\n\n"
                f"Total Entities: {summary.get('total_entities', 0)}\n"
                f"Compliant: [green]{summary.get('compliant', 0)}[/green]\n"
                f"Due Soon: [yellow]{summary.get('due_soon', 0)}[/yellow]\n"
                f"Overdue: [red]{summary.get('overdue', 0)}[/red]\n"
                f"Never Rotated: {summary.get('never_rotated', 0)}",
                border_style="cyan"
            ))
        else:
            print("\nCompliance Summary:")
            print("-" * 40)
            print(f"  Total Entities: {summary.get('total_entities', 0)}")
            print(f"  Compliant: {summary.get('compliant', 0)}")
            print(f"  Due Soon: {summary.get('due_soon', 0)}")
            print(f"  Overdue: {summary.get('overdue', 0)}")

        # Show overdue entities
        overdue = mgr.get_overdue_entities()
        if overdue:
            print()
            print("Overdue entities:")
            for entity in overdue[:10]:
                print(f"  - {entity.entity_type}:{entity.entity_id} ({entity.hostname}) - {entity.days_since_rotation} days")

    except Exception as e:
        print(f"\nError: {e}")

    print("\nPress any key..."); getch()


def run_pending_rotations(db_path: str):
    """Execute pending key rotations."""
    from v1.rotation_policies import RotationPolicyManager
    from v1.schema_semantic import WireGuardDBv2
    from v1.cli.peer_manager import rotate_keys

    clear_screen()
    try:
        mgr = RotationPolicyManager(db_path)
        pending = mgr.get_pending_rotations()

        if not pending:
            print("\n  No pending rotations.")
            print("\nPress any key..."); getch()
            return

        print(f"\n  {len(pending)} entities due for rotation:")
        for entity in pending:
            print(f"    - {entity.entity_type}:{entity.entity_id} ({entity.hostname})")

        print()
        confirm = input("  Execute all rotations? [y/N]: ").strip().lower()

        if confirm == 'y':
            db = WireGuardDBv2(db_path)
            rotated = 0
            for entity in pending:
                try:
                    rotate_keys(db, entity.entity_type, entity.entity_id, "Policy-scheduled rotation")
                    rotated += 1
                except Exception as e:
                    print(f"    Failed: {entity.hostname}: {e}")

            print(f"\n  Rotated {rotated}/{len(pending)} entities.")

    except Exception as e:
        print(f"\nError: {e}")

    print("\nPress any key..."); getch()


# =============================================================================
# MONITORING MENU
# =============================================================================

def show_monitoring_menu(db_path: str):
    """Monitoring submenu."""
    while True:
        clear_screen()
        print_menu(
            "MONITORING",
            [
                "Configuration Drift [detect deployed vs DB changes]",
                "Prometheus Metrics [export metrics endpoint]",
                "Bandwidth Stats [view usage data]",
            ]
        )

        print("  Select: ", end="", flush=True)
        choice = get_keypress_choice(3)

        if choice is None:
            return

        if choice == -1:
            continue

        if choice == 1:
            show_drift_detection(db_path)
        elif choice == 2:
            show_prometheus_menu(db_path)
        elif choice == 3:
            show_bandwidth_stats(db_path)


def show_drift_detection(db_path: str):
    """Show configuration drift detection."""
    from v1.drift_detection import DriftDetector

    clear_screen()
    try:
        detector = DriftDetector(db_path)

        print("\nConfiguration Drift Detection")
        print("-" * 40)
        print()
        print("  1. Run drift scan (requires SSH access)")
        print("  2. View last scan results")
        print("  3. View drift history")
        print("  q. Back")
        print()

        action = input("  Choice: ").strip()

        if action == '1':
            print("\n  Running drift scan...")
            results = detector.scan_all()
            print(f"\n  Scanned {len(results)} entities.")

            drifted = [r for r in results if r.is_drifted]
            if drifted:
                print(f"\n  [yellow]DRIFT DETECTED on {len(drifted)} entities![/yellow]" if RICH_AVAILABLE
                      else f"\n  DRIFT DETECTED on {len(drifted)} entities!")
                for r in drifted:
                    print(f"    - {r.entity_name}: {r.critical_count} critical, {r.warning_count} warning")
            else:
                print("\n  All configs match database.")

        elif action == '2':
            results = detector.get_last_scan_results()
            if results:
                print(f"\n  Last scan: {len(results)} entities")
                for r in results:
                    status = "[red]DRIFT[/red]" if r.is_drifted else "[green]OK[/green]"
                    print(f"    {r.entity_name}: {status if RICH_AVAILABLE else ('DRIFT' if r.is_drifted else 'OK')}")
            else:
                print("\n  No scan results found.")

        elif action == '3':
            history = detector.get_drift_history(limit=10)
            print(f"\n  Recent drift events: {len(history)}")
            for h in history:
                print(f"    {h.scan_time} | {h.entity_name} | {h.drift_type}")

    except Exception as e:
        print(f"\nError: {e}")

    print("\nPress any key..."); getch()


def show_prometheus_menu(db_path: str):
    """Prometheus metrics management."""
    from v1.prometheus_metrics import PrometheusMetricsCollector

    clear_screen()
    try:
        collector = PrometheusMetricsCollector(db_path)

        print("\nPrometheus Metrics")
        print("-" * 40)
        print()
        print("  1. View current metrics")
        print("  2. Export metrics to file")
        print("  3. Start metrics server (background)")
        print("  q. Back")
        print()

        action = input("  Choice: ").strip()

        if action == '1':
            metrics = collector.collect_all()
            output = collector.format_prometheus()
            print()
            print(output[:2000])
            if len(output) > 2000:
                print("\n  ... (truncated)")

        elif action == '2':
            output_path = Path(f"metrics_{datetime.now().strftime('%Y%m%d_%H%M%S')}.prom")
            metrics_text = collector.format_prometheus()
            output_path.write_text(metrics_text)
            print(f"\n  Exported to: {output_path}")

        elif action == '3':
            port = input("  Port [9100]: ").strip()
            port = int(port) if port else 9100
            print(f"\n  To start the metrics server, run:")
            print(f"    wg-friend metrics --port {port}")
            print("\n  Or use the PrometheusMetricsServer class programmatically.")

    except Exception as e:
        print(f"\nError: {e}")

    print("\nPress any key..."); getch()


def show_bandwidth_stats(db_path: str):
    """Show bandwidth statistics."""
    from v1.bandwidth_tracking import BandwidthTracker

    clear_screen()
    try:
        tracker = BandwidthTracker(db_path)

        print("\nBandwidth Statistics")
        print("-" * 40)
        print()
        print("  1. Collect bandwidth sample (local)")
        print("  2. View top consumers (24h)")
        print("  3. View aggregate stats")
        print("  q. Back")
        print()

        action = input("  Choice: ").strip()

        if action == '1':
            count = tracker.collect_local_samples()
            print(f"\n  Collected {count} bandwidth samples.")

        elif action == '2':
            top = tracker.get_top_consumers(hours=24, limit=10)
            print("\n  Top Bandwidth Consumers (24h):")
            for entry in top:
                total = entry.bytes_received + entry.bytes_sent
                print(f"    {entry.hostname}: {_format_bytes(total)}")

        elif action == '3':
            stats = tracker.get_aggregate_stats()
            print(f"\n  Total samples: {stats.get('total_samples', 0)}")
            print(f"  Date range: {stats.get('earliest')} to {stats.get('latest')}")

    except Exception as e:
        print(f"\nError: {e}")

    print("\nPress any key..."); getch()


def _format_bytes(num_bytes: int) -> str:
    """Format bytes as human-readable."""
    if num_bytes is None:
        return "0 B"
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if abs(num_bytes) < 1024.0:
            return f"{num_bytes:.1f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.1f} PB"


# =============================================================================
# TROUBLESHOOTING MENU
# =============================================================================

def show_troubleshooting_menu(db_path: str):
    """Troubleshooting wizard."""
    from v1.troubleshooting_wizard import TroubleshootingWizard

    clear_screen()
    try:
        wizard = TroubleshootingWizard(db_path)

        print("\nTroubleshooting Wizard")
        print("-" * 40)
        print()
        print("  1. Quick diagnostic (all checks)")
        print("  2. Connectivity check")
        print("  3. Handshake diagnostics")
        print("  4. DNS check")
        print("  5. Export diagnostic report")
        print("  q. Back")
        print()

        action = input("  Choice: ").strip()

        if action == '1':
            print("\n  Running quick diagnostics...")
            results = wizard.run_quick_diagnostic()
            _display_diagnostic_results(results)

        elif action == '2':
            print("\n  Running connectivity checks...")
            results = wizard.run_diagnostic('connectivity')
            _display_diagnostic_results(results)

        elif action == '3':
            print("\n  Running handshake diagnostics...")
            results = wizard.run_diagnostic('handshake')
            _display_diagnostic_results(results)

        elif action == '4':
            print("\n  Running DNS checks...")
            results = wizard.run_diagnostic('dns')
            _display_diagnostic_results(results)

        elif action == '5':
            output_path = Path(f"diagnostic_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
            report = wizard.generate_report()
            output_path.write_text(report)
            print(f"\n  Report exported to: {output_path}")

    except Exception as e:
        print(f"\nError: {e}")

    print("\nPress any key..."); getch()


def _display_diagnostic_results(results: list):
    """Display diagnostic results."""
    print()
    for result in results:
        status = "[green]PASS[/green]" if result.passed else "[red]FAIL[/red]"
        if RICH_AVAILABLE:
            console.print(f"  {status} {result.check_name}")
        else:
            status_plain = "PASS" if result.passed else "FAIL"
            print(f"  [{status_plain}] {result.check_name}")

        if not result.passed and result.remediation:
            print(f"        Suggestion: {result.remediation}")


# =============================================================================
# WEBHOOKS MENU
# =============================================================================

def show_webhooks_menu(db_path: str):
    """Webhook notifications management."""
    from v1.webhook_notifications import WebhookNotifier

    clear_screen()
    try:
        notifier = WebhookNotifier(db_path)
        endpoints = notifier.list_endpoints()

        if RICH_AVAILABLE:
            table = Table(title="Webhook Endpoints", box=box.ROUNDED)
            table.add_column("ID", style="dim")
            table.add_column("Name", style="cyan")
            table.add_column("URL", max_width=40)
            table.add_column("Format")
            table.add_column("Enabled", justify="center")

            for ep in endpoints:
                table.add_row(
                    str(ep.id),
                    ep.name,
                    ep.url[:40] + "..." if len(ep.url) > 40 else ep.url,
                    ep.format,
                    "[green]Yes[/green]" if ep.enabled else "[dim]No[/dim]"
                )

            console.print()
            console.print(table)
        else:
            print("\nWebhook Endpoints:")
            print("-" * 70)
            for ep in endpoints:
                print(f"  [{ep.id}] {ep.name} | {ep.url[:40]} | {ep.format}")

        print()
        print("  1. Add webhook endpoint")
        print("  2. Test endpoint")
        print("  3. Toggle enabled/disabled")
        print("  4. Delete endpoint")
        print("  5. View delivery stats")
        print("  q. Back")
        print()

        action = input("  Choice: ").strip()

        if action == '1':
            name = input("\n  Endpoint name: ").strip()
            if not name:
                return

            url = input("  Webhook URL: ").strip()
            if not url:
                return

            print("  Format: 1=Generic, 2=Slack, 3=Discord, 4=Teams")
            format_choice = input("  Format [1]: ").strip()
            formats = {'1': 'generic', '2': 'slack', '3': 'discord', '4': 'teams'}
            webhook_format = formats.get(format_choice, 'generic')

            secret = input("  HMAC secret (optional): ").strip() or None

            ep_id = notifier.add_endpoint(name, url, webhook_format, secret=secret)
            print(f"\n  Added endpoint: {name} (ID: {ep_id})")

        elif action == '2' and endpoints:
            ep_id = input("\n  Endpoint ID to test: ").strip()
            if ep_id:
                success = notifier.test_endpoint(int(ep_id))
                if success:
                    print("\n  Test notification sent successfully.")
                else:
                    print("\n  Test failed. Check endpoint URL and format.")

        elif action == '3' and endpoints:
            ep_id = input("\n  Endpoint ID to toggle: ").strip()
            if ep_id:
                notifier.toggle_endpoint(int(ep_id))
                print("\n  Endpoint toggled.")

        elif action == '4' and endpoints:
            ep_id = input("\n  Endpoint ID to delete: ").strip()
            if ep_id:
                confirm = input("  Confirm delete? [y/N]: ").strip().lower()
                if confirm == 'y':
                    notifier.delete_endpoint(int(ep_id))
                    print("\n  Endpoint deleted.")

        elif action == '5':
            stats = notifier.get_delivery_stats()
            print(f"\n  Total deliveries: {stats.get('total', 0)}")
            print(f"  Successful: {stats.get('successful', 0)}")
            print(f"  Failed: {stats.get('failed', 0)}")

    except Exception as e:
        print(f"\nError: {e}")

    print("\nPress any key..."); getch()
