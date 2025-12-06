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
    if ch in ('\r', '\n'):  # Enter/Return key - go back
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
        is_encrypted = mgr.is_encrypted

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
        stats = mgr.get_psk_stats()

        if RICH_AVAILABLE:
            table = Table(title="PSK Status", box=box.ROUNDED)
            table.add_column("Metric")
            table.add_column("Value", justify="right")

            table.add_row("Total PSKs", str(stats.get('total_psks', 0)))
            table.add_row("Fully Distributed", str(stats.get('fully_distributed', 0)))
            table.add_row("Expiring Soon", str(stats.get('expiring_soon', 0)))
            table.add_row("Total Rotations", str(stats.get('total_rotations', 0)))

            console.print()
            console.print(table)
            console.print()
        else:
            print("\nPSK Statistics:")
            print(f"  Total PSKs: {stats.get('total_psks', 0)}")
            print(f"  Fully Distributed: {stats.get('fully_distributed', 0)}")
            print(f"  Expiring Soon: {stats.get('expiring_soon', 0)}")
            print()

        print("  1. View expiring PSKs")
        print("  2. View undistributed PSKs")
        print("  3. View rotation history")
        print("  q. Back")
        print()

        action = input("  Choice: ").strip()

        if not action:
            return
        if action == '1':
            expiring = mgr.get_expiring_psks(days_ahead=30)
            print(f"\n  {len(expiring)} PSKs expiring in next 30 days:")
            for entry in expiring[:10]:
                print(f"    - {entry.peer1_type}:{entry.peer1_id} <-> "
                      f"{entry.peer2_type}:{entry.peer2_id} expires {entry.expires_at}")
        elif action == '2':
            undist = mgr.get_undistributed_psks()
            print(f"\n  {len(undist)} PSKs not fully distributed:")
            for item in undist[:10]:
                missing = ', '.join([f"{m['type']}:{m['id']}" for m in item['missing_distribution']])
                print(f"    - Entry {item['entry_id']}: missing {missing}")
        elif action == '3':
            history = mgr.get_rotation_history(limit=10)
            print(f"\n  Recent PSK rotations:")
            for h in history:
                print(f"    - {h['rotated_at']}: {h['peer1_type']}:{h['peer1_id']} <-> "
                      f"{h['peer2_type']}:{h['peer2_id']} ({h['trigger']})")

    except Exception as e:
        print(f"\nError: {e}")

    print("\nPress any key..."); getch()


def show_audit_log(db_path: str):
    """View recent audit log entries."""
    from v1.audit_log import AuditLogger

    clear_screen()
    try:
        logger = AuditLogger(db_path)
        entries = logger.get_entries(limit=20)

        if RICH_AVAILABLE:
            table = Table(title="Recent Security Events", box=box.ROUNDED)
            table.add_column("Time", style="dim", width=19)
            table.add_column("Event", style="cyan")
            table.add_column("Entity")
            table.add_column("Operator")

            for entry in entries:
                ts = entry.timestamp[:19] if entry.timestamp else ""
                table.add_row(
                    ts,
                    entry.event_type,
                    f"{entry.entity_type}:{entry.entity_id}" if entry.entity_type else "-",
                    entry.operator or "system"
                )

            console.print()
            console.print(table)
        else:
            print("\nRecent Security Events:")
            print("-" * 70)
            for entry in entries:
                ts = entry.timestamp[:19] if entry.timestamp else ""
                print(f"{ts} | {entry.event_type} | {entry.entity_type}:{entry.entity_id}")

    except Exception as e:
        print(f"\nError: {e}")

    print("\nPress any key..."); getch()


def export_audit_log(db_path: str):
    """Export audit log for compliance."""
    from v1.audit_log import AuditLogger
    from datetime import timedelta

    clear_screen()
    try:
        logger = AuditLogger(db_path)

        print("\nExport Audit Log")
        print("-" * 40)
        print()
        days = input("  Days to export [90]: ").strip()
        days = int(days) if days else 90

        start_time = datetime.now() - timedelta(days=days)
        output_path = Path(f"audit_log_export_{datetime.now().strftime('%Y%m%d')}.json")
        count = logger.export_json(output_path, start_time=start_time)

        print(f"\n  Exported {count} entries to: {output_path}")

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
    from v1.disaster_recovery import DisasterRecovery, BackupType

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

        backup_path = dr.create_backup(
            backup_type=BackupType.FULL,
            password=passphrase if encrypt else None
        )

        print(f"\n  Backup created: {backup_path}")

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
            table.add_column("Encrypted", justify="center")

            for b in backups:
                backup_id = b.get('backup_id', '')
                created_at = b.get('created_at', '')[:16] if b.get('created_at') else ""
                backup_type = b.get('backup_type', '')
                file_size = b.get('file_size')
                is_encrypted = b.get('is_encrypted', False)

                table.add_row(
                    backup_id[:25] + "..." if len(backup_id) > 25 else backup_id,
                    created_at,
                    backup_type,
                    f"{file_size / 1024:.1f} KB" if file_size else "-",
                    "[green]Yes[/green]" if is_encrypted else "[dim]No[/dim]"
                )

            console.print()
            console.print(table)
        else:
            print("\nBackup History:")
            print("-" * 70)
            for b in backups:
                print(f"  {b.get('backup_id', '')[:30]} | {b.get('created_at', '')} | {b.get('backup_type', '')}")

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

        result = dr.verify_backup(str(backup_file), password=passphrase)

        if result.get('valid'):
            print("\n  [green]Backup verified successfully.[/green]" if RICH_AVAILABLE
                  else "\n  Backup verified successfully.")
            if result.get('metadata'):
                meta = result['metadata']
                print(f"  Type: {meta.get('backup_type', 'unknown')}")
                print(f"  Created: {meta.get('created_at', 'unknown')}")
        else:
            print("\n  [red]Backup verification FAILED![/red]" if RICH_AVAILABLE
                  else "\n  Backup verification FAILED!")
            for err in result.get('errors', []):
                print(f"    - {err}")

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
        if not report_choice:
            report_choice = '1'
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
        if not format_choice:
            format_choice = '1'
        formats = {
            '1': OutputFormat.MARKDOWN,
            '2': OutputFormat.JSON,
            '3': OutputFormat.CSV,
        }
        output_format = formats.get(format_choice, OutputFormat.MARKDOWN)

        # Generate report (returns ComplianceReport object)
        report = reporter.generate_report(report_type=report_type)

        # Determine file extension and export
        ext_map = {
            OutputFormat.MARKDOWN: 'md',
            OutputFormat.JSON: 'json',
            OutputFormat.CSV: 'csv',
        }
        ext = ext_map.get(output_format, 'md')

        output_dir = Path("reports")
        output_dir.mkdir(exist_ok=True)
        output_path = output_dir / f"compliance_{report_type.value}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{ext}"

        report_path = reporter.export_report(report, str(output_path), output_format)

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
    from v1.rotation_policies import RotationPolicyManager, PolicyType, EntityScope

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
                    p.policy_type if isinstance(p.policy_type, str) else str(p.policy_type),
                    str(p.threshold_value) if p.threshold_value else "-",
                    p.applies_to if isinstance(p.applies_to, str) else str(p.applies_to),
                    "[green]Yes[/green]" if p.enabled else "[dim]No[/dim]"
                )

            console.print()
            console.print(table)
        else:
            print("\nRotation Policies:")
            print("-" * 70)
            for p in policies:
                print(f"  [{p.id}] {p.name} | {p.policy_type} | {p.threshold_value} days | {p.applies_to}")

        print()
        print("  1. Create new policy")
        print("  2. Toggle policy enabled/disabled")
        print("  3. Delete policy")
        print("  q. Back")
        print()

        action = input("  Choice: ").strip()
        if not action:
            return

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
            scopes = {'1': EntityScope.ALL, '2': EntityScope.REMOTES, '3': EntityScope.ROUTERS}
            scope = scopes.get(scope_input, EntityScope.ALL)

            policy_id = mgr.create_policy(
                name=name,
                policy_type=policy_type,
                threshold_value=days,
                applies_to=scope
            )
            print(f"\n  Created policy: {name} (ID: {policy_id})")

        elif action == '2' and policies:
            policy_id = input("\n  Policy ID to toggle: ").strip()
            if policy_id:
                pid = int(policy_id)
                policy = mgr.get_policy(pid)
                if policy:
                    mgr.update_policy(pid, enabled=not policy.enabled)
                    print("\n  Policy toggled.")
                else:
                    print("\n  Policy not found.")

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

        total = summary.get('total_scheduled', 0)
        overdue_count = summary.get('overdue_count', 0)
        compliant = total - overdue_count
        upcoming = summary.get('upcoming_count', 0)
        pct = summary.get('compliance_percentage', 100)

        if RICH_AVAILABLE:
            console.print(Panel(
                f"[bold]Compliance Summary[/bold]\n\n"
                f"Total Scheduled: {total}\n"
                f"Compliant: [green]{compliant}[/green]\n"
                f"Due Soon (7d): [yellow]{upcoming}[/yellow]\n"
                f"Overdue: [red]{overdue_count}[/red]\n"
                f"Compliance: {pct}%",
                border_style="cyan"
            ))
        else:
            print("\nCompliance Summary:")
            print("-" * 40)
            print(f"  Total Scheduled: {total}")
            print(f"  Compliant: {compliant}")
            print(f"  Due Soon (7d): {upcoming}")
            print(f"  Overdue: {overdue_count}")
            print(f"  Compliance: {pct}%")

        # Show overdue entities using get_pending_rotations with no future days
        pending = mgr.get_pending_rotations(include_upcoming_days=0)
        overdue = [p for p in pending if p.is_overdue]
        if overdue:
            print()
            print("Overdue entities:")
            for entity in overdue[:10]:
                days_overdue = abs(entity.days_until_rotation)
                print(f"  - {entity.entity_type}:{entity.entity_id} ({entity.entity_hostname}) - {days_overdue} days overdue")

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

        if not action:
            return
        if action == '1':
            print("\n  Running drift check...")
            summary = detector.get_drift_summary()
            total = summary.get('total_entities', 0)
            drifted_count = summary.get('entities_with_drift', 0)
            print(f"\n  Checked {total} entities.")

            if drifted_count > 0:
                print(f"\n  [yellow]DRIFT DETECTED on {drifted_count} entities![/yellow]" if RICH_AVAILABLE
                      else f"\n  DRIFT DETECTED on {drifted_count} entities!")
            else:
                print("\n  All configs match database.")

        elif action == '2':
            summary = detector.get_drift_summary()
            total = summary.get('total_entities', 0)
            drifted_count = summary.get('entities_with_drift', 0)
            print(f"\n  Drift Summary:")
            print(f"    Total entities: {total}")
            print(f"    With drift: {drifted_count}")
            print(f"    Last checked: {summary.get('last_scan', 'Never')}")

        elif action == '3':
            history = detector.get_drift_history(days=30)
            print(f"\n  Recent drift events: {len(history)}")
            for h in history[:10]:  # Show first 10
                print(f"    {h.get('scan_time', '-')} | {h.get('entity_name', '-')} | {h.get('drift_type', '-')}")

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
        if not action:
            return

        if action == '1':
            metrics = collector.collect_all_metrics()
            output = collector.format_prometheus(metrics)
            print()
            print(output[:2000])
            if len(output) > 2000:
                print("\n  ... (truncated)")

        elif action == '2':
            metrics = collector.collect_all_metrics()
            output_path = Path(f"metrics_{datetime.now().strftime('%Y%m%d_%H%M%S')}.prom")
            metrics_text = collector.format_prometheus(metrics)
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
        if not action:
            return

        if action == '1':
            count = tracker.collect_samples()
            print(f"\n  Collected {count} bandwidth samples.")

        elif action == '2':
            top = tracker.get_top_consumers(days=1, limit=10)  # 1 day = 24h
            print("\n  Top Bandwidth Consumers (24h):")
            for entry in top:
                if isinstance(entry, dict):
                    total_bytes = entry.get('bytes_received', 0) + entry.get('bytes_sent', 0)
                    hostname = entry.get('hostname', entry.get('entity_id', 'unknown'))
                else:
                    total_bytes = getattr(entry, 'bytes_received', 0) + getattr(entry, 'bytes_sent', 0)
                    hostname = getattr(entry, 'hostname', str(entry))
                print(f"    {hostname}: {_format_bytes(total_bytes)}")

        elif action == '3':
            stats = tracker.get_statistics()
            print(f"\n  Total samples: {stats.get('total_samples', 0)}")
            print(f"  Date range: {stats.get('first_sample', 'N/A')} to {stats.get('last_sample', 'N/A')}")

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
        if not action:
            return

        if action == '1':
            print("\n  Running full diagnostics...")
            session = wizard.run_full_diagnostic()
            if session and hasattr(session, 'results') and session.results:
                _display_diagnostic_results(session.results)
            else:
                print("\n  Diagnostics completed. No issues found.")

        elif action == '2':
            print("\n  Running connectivity checks...")
            session = wizard.run_full_diagnostic()
            if session and hasattr(session, 'results'):
                conn_results = [r for r in session.results if 'connect' in str(r).lower()]
                if conn_results:
                    _display_diagnostic_results(conn_results)
                else:
                    print("\n  No connectivity issues found.")
            else:
                print("\n  No connectivity issues found.")

        elif action == '3':
            print("\n  Running handshake diagnostics...")
            session = wizard.run_full_diagnostic()
            if session and hasattr(session, 'results'):
                hs_results = [r for r in session.results if 'handshake' in str(r).lower()]
                if hs_results:
                    _display_diagnostic_results(hs_results)
                else:
                    print("\n  No handshake issues found.")
            else:
                print("\n  No handshake issues found.")

        elif action == '4':
            print("\n  Running DNS checks...")
            session = wizard.run_full_diagnostic()
            if session and hasattr(session, 'results'):
                dns_results = [r for r in session.results if 'dns' in str(r).lower()]
                if dns_results:
                    _display_diagnostic_results(dns_results)
                else:
                    print("\n  No DNS issues found.")
            else:
                print("\n  No DNS issues found.")

        elif action == '5':
            output_path = Path(f"diagnostic_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
            session = wizard.run_full_diagnostic()
            report = wizard.export_report(session)
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
        if not action:
            return

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
                pid = int(ep_id)
                endpoint = notifier.get_endpoint(pid)
                if endpoint:
                    notifier.update_endpoint(pid, enabled=not endpoint.enabled)
                    print("\n  Endpoint toggled.")
                else:
                    print("\n  Endpoint not found.")

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
