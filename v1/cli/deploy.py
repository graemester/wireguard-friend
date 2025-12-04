"""
SSH Deployment - Push Configs to Remote Servers

Deploys generated WireGuard configs to remote servers via SSH.
"""

import sys
import subprocess
import shutil
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from v1.schema_semantic import WireGuardDBv2
from v1.network_utils import is_local_host

# Rich imports for spinners
try:
    from rich.console import Console
    from rich.live import Live
    from rich.spinner import Spinner
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False
    console = None


def prompt_yes_no(question: str, default: bool = False) -> bool:
    """Prompt for yes/no"""
    default_str = "Y/n" if default else "y/N"
    response = input(f"{question} [{default_str}]: ").strip().lower()

    if not response:
        return default
    return response in ('y', 'yes')


def ssh_command(host: str, command: str, user: str = 'root', dry_run: bool = False) -> Tuple[int, str, str]:
    """
    Execute command on remote host via SSH.

    Args:
        host: Hostname or IP
        command: Command to execute
        user: SSH user (default: root)
        dry_run: If True, print command but don't execute

    Returns:
        (returncode, stdout, stderr)
    """
    ssh_cmd = ['ssh', f'{user}@{host}', command]

    if dry_run:
        print(f"  [DRY RUN] {' '.join(ssh_cmd)}")
        return 0, "", ""

    result = subprocess.run(ssh_cmd, capture_output=True, text=True)
    return result.returncode, result.stdout, result.stderr


def scp_file(local_path: Path, host: str, remote_path: str, user: str = 'root', dry_run: bool = False) -> int:
    """
    Copy file to remote host via SCP.

    Args:
        local_path: Local file path
        host: Hostname or IP
        remote_path: Remote file path
        user: SSH user (default: root)
        dry_run: If True, print command but don't execute

    Returns:
        Return code (0 = success)
    """
    scp_cmd = ['scp', str(local_path), f'{user}@{host}:{remote_path}']

    if dry_run:
        print(f"  [DRY RUN] {' '.join(scp_cmd)}")
        return 0

    result = subprocess.run(scp_cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"  Error: {result.stderr}")
    return result.returncode


def run_with_spinner(message: str, operation, success_msg: str = None, error_msg: str = None):
    """
    Run an operation with a spinner for visual feedback.

    Args:
        message: Message to show while running
        operation: Callable that returns (success, result_or_error)
        success_msg: Message on success (optional)
        error_msg: Message on error (optional)

    Returns:
        Result from operation
    """
    if RICH_AVAILABLE:
        with Live(Spinner("dots", text=f"[cyan]{message}[/cyan]"), console=console, refresh_per_second=10) as live:
            success, result = operation()
            if success:
                live.update(f"[green]✓ {success_msg or message}[/green]")
            else:
                live.update(f"[red]✗ {error_msg or message}[/red]")
            return success, result
    else:
        print(f"  {message}...")
        success, result = operation()
        if success:
            print(f"  ✓ {success_msg or 'Done'}")
        else:
            print(f"  ✗ {error_msg or 'Failed'}")
        return success, result


def backup_remote_config(host: str, remote_path: str, user: str = 'root', dry_run: bool = False) -> bool:
    """
    Backup existing config on remote host.

    Args:
        host: Hostname or IP
        remote_path: Remote config path (e.g., /etc/wireguard/wg0.conf)
        user: SSH user
        dry_run: If True, don't actually backup

    Returns:
        True if backup succeeded (or file doesn't exist), False on error
    """
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_path = f"{remote_path}.backup.{timestamp}"

    if dry_run:
        print(f"  [DRY RUN] Would backup {remote_path} to {backup_path}")
        return True

    # Check if file exists
    def check_exists():
        returncode, stdout, stderr = ssh_command(
            host,
            f'test -f {remote_path} && echo exists || echo notfound',
            user=user,
            dry_run=False
        )
        if returncode != 0:
            return False, stderr
        return True, stdout

    success, result = run_with_spinner(
        "Checking for existing config",
        check_exists,
        success_msg="Config check complete"
    )

    if not success:
        print(f"  Error checking for existing config: {result}")
        return False

    if 'notfound' in result:
        print(f"  No existing config to backup")
        return True

    # File exists, back it up
    def do_backup():
        returncode, stdout, stderr = ssh_command(
            host,
            f'cp {remote_path} {backup_path}',
            user=user,
            dry_run=False
        )
        if returncode != 0:
            return False, stderr
        return True, backup_path

    success, result = run_with_spinner(
        f"Backing up to {backup_path}",
        do_backup,
        success_msg=f"Backed up to {backup_path}"
    )

    if not success:
        print(f"  Error backing up config: {result}")
        return False

    return True


def restart_wireguard(host: str, interface: str = 'wg0', user: str = 'root', dry_run: bool = False) -> bool:
    """
    Restart WireGuard on remote host.

    Args:
        host: Hostname or IP
        interface: WireGuard interface name (default: wg0)
        user: SSH user
        dry_run: If True, don't actually restart

    Returns:
        True if restart succeeded, False on error
    """
    if dry_run:
        print(f"  [DRY RUN] Would restart WireGuard ({interface})")
        return True

    def do_restart():
        # Try wg-quick down first (may not be running)
        ssh_command(host, f'wg-quick down {interface}', user=user, dry_run=False)

        # Bring it up
        returncode, stdout, stderr = ssh_command(
            host,
            f'wg-quick up {interface}',
            user=user,
            dry_run=False
        )

        if returncode != 0:
            return False, stderr
        return True, None

    success, result = run_with_spinner(
        f"Restarting WireGuard ({interface})",
        do_restart,
        success_msg=f"WireGuard restarted ({interface})"
    )

    if not success:
        print(f"  Error restarting WireGuard: {result}")
        return False

    return True


def deploy_to_host(
    hostname: str,
    config_file: Path,
    endpoint: str,
    interface: str = 'wg0',
    user: str = 'root',
    restart: bool = False,
    dry_run: bool = False
) -> bool:
    """
    Deploy config to a single host.

    Args:
        hostname: Human-readable hostname (for display)
        config_file: Local config file to deploy
        endpoint: SSH target (hostname or IP)
        interface: WireGuard interface name
        user: SSH user
        restart: Whether to restart WireGuard after deploy
        dry_run: If True, print what would be done

    Returns:
        True if deploy succeeded, False on error
    """
    remote_path = f'/etc/wireguard/{interface}.conf'

    print(f"\n{'─' * 70}")
    print(f"Deploy: {hostname} ({endpoint})")
    print(f"{'─' * 70}")
    print(f"  Local:  {config_file}")
    print(f"  Remote: {remote_path}")

    if not config_file.exists():
        print(f"  Error: Config file not found: {config_file}")
        return False

    # Check if target is localhost
    if is_local_host(endpoint.split(':')[0]):  # Strip port if present
        print(f"  Detected localhost - using direct file copy")

        if dry_run:
            print(f"  [DRY RUN] Would copy {config_file} to {remote_path}")
        else:
            # Backup existing config
            remote_path_obj = Path(remote_path)
            if remote_path_obj.exists():
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                backup_path = f"{remote_path}.backup.{timestamp}"
                print(f"  Backing up to {backup_path}")
                shutil.copy2(remote_path_obj, backup_path)

            # Copy new config
            print(f"  Copying config...")
            try:
                shutil.copy2(config_file, remote_path_obj)
                print(f"  ✓ Config deployed")
            except Exception as e:
                print(f"  ✗ Deploy failed: {e}")
                return False
    else:
        # Backup existing config
        if not backup_remote_config(endpoint, remote_path, user=user, dry_run=dry_run):
            print(f"  Warning: Backup failed, continuing anyway...")

        # Deploy new config
        if dry_run:
            print(f"  [DRY RUN] Would deploy config via SCP")
        else:
            def do_scp():
                result = scp_file(config_file, endpoint, remote_path, user=user, dry_run=False)
                if result != 0:
                    return False, "SCP failed"
                return True, None

            success, result = run_with_spinner(
                "Deploying config via SCP",
                do_scp,
                success_msg="Config deployed"
            )

            if not success:
                print(f"  ✗ Deploy failed")
                return False

    # Restart if requested
    if restart:
        if not restart_wireguard(endpoint, interface=interface, user=user, dry_run=dry_run):
            print(f"  ✗ Restart failed")
            return False

    print(f"  ✓ Deploy complete")
    return True


def deploy_all(db: WireGuardDBv2, output_dir: Path, user: str = 'root', restart: bool = False, dry_run: bool = False) -> int:
    """
    Deploy all configs to their respective hosts.

    Args:
        db: Database connection
        output_dir: Directory containing generated configs
        user: SSH user
        restart: Whether to restart WireGuard
        dry_run: If True, print what would be done

    Returns:
        Number of failed deployments
    """
    print("\n" + "=" * 70)
    print("DEPLOY ALL CONFIGS")
    print("=" * 70)

    deployments = []

    with db._connection() as conn:
        cursor = conn.cursor()

        # Coordination Server
        cursor.execute("""
            SELECT hostname, endpoint
            FROM coordination_server
        """)
        row = cursor.fetchone()
        if row:
            hostname, endpoint = row
            config_file = output_dir / 'coordination.conf'
            if endpoint and endpoint != 'UNKNOWN':
                deployments.append({
                    'entity_type': 'Coordination Server',
                    'hostname': hostname,
                    'config_file': config_file,
                    'endpoint': endpoint,
                    'user': user  # Use command-line user
                })
            else:
                print(f"\nWARNING:  Skipping {hostname}: No endpoint configured")

        # Subnet Routers
        cursor.execute("""
            SELECT hostname, endpoint
            FROM subnet_router
            WHERE endpoint IS NOT NULL AND endpoint != ''
            ORDER BY hostname
        """)
        for hostname, endpoint in cursor.fetchall():
            config_file = output_dir / f'{hostname}.conf'
            deployments.append({
                'entity_type': 'Subnet Router',
                'hostname': hostname,
                'config_file': config_file,
                'endpoint': endpoint,
                'user': user  # Use command-line user
            })

        # Exit Nodes
        cursor.execute("""
            SELECT hostname, ssh_host, ssh_user, ssh_port
            FROM exit_node
            WHERE ssh_host IS NOT NULL AND ssh_host != ''
            ORDER BY hostname
        """)
        for hostname, ssh_host, ssh_user, ssh_port in cursor.fetchall():
            config_file = output_dir / f'{hostname}.conf'
            # Use ssh_host:ssh_port as the endpoint for SSH
            ssh_endpoint = f"{ssh_host}:{ssh_port}" if ssh_port and ssh_port != 22 else ssh_host
            deployments.append({
                'entity_type': 'Exit Node',
                'hostname': hostname,
                'config_file': config_file,
                'endpoint': ssh_endpoint,
                'user': ssh_user or 'root'  # Use DB-stored user
            })

        # Note: Remotes (clients) don't have endpoints - they're behind NAT
        # and initiate connections TO the coordination server, not vice versa.
        # Deployment targets are: coordination server, subnet routers, exit nodes.

    if not deployments:
        print("\nWARNING:  No deployable hosts found (endpoints not configured)")
        return 0

    # Summary
    print(f"\nFound {len(deployments)} deployable host(s):")
    for d in deployments:
        print(f"  - {d['hostname']:30} ({d['entity_type']:20}) → {d['endpoint']}")

    print()
    if dry_run:
        print("[DRY RUN MODE - No actual changes will be made]")
    elif not prompt_yes_no("Proceed with deployment?", default=False):
        print("Cancelled.")
        return 0

    # Deploy with progress indicator
    failures = 0

    if RICH_AVAILABLE and len(deployments) > 1 and not dry_run:
        # Show overall progress bar for multiple deployments
        print()
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("({task.completed}/{task.total})"),
            console=console
        ) as progress:
            task = progress.add_task("[cyan]Deploying configs...", total=len(deployments))

            for d in deployments:
                progress.update(task, description=f"[cyan]Deploying to {d['hostname']}...")
                success = deploy_to_host(
                    hostname=d['hostname'],
                    config_file=d['config_file'],
                    endpoint=d['endpoint'],
                    user=d['user'],
                    restart=restart,
                    dry_run=dry_run
                )
                if not success:
                    failures += 1
                progress.advance(task)
    else:
        # No progress bar for single deployment or dry run
        for d in deployments:
            success = deploy_to_host(
                hostname=d['hostname'],
                config_file=d['config_file'],
                endpoint=d['endpoint'],
                user=d['user'],
                restart=restart,
                dry_run=dry_run
            )
            if not success:
                failures += 1

    # Summary
    print(f"\n{'=' * 70}")
    print("DEPLOYMENT SUMMARY")
    print(f"{'=' * 70}")
    print(f"  Total:   {len(deployments)}")
    print(f"  Success: {len(deployments) - failures}")
    print(f"  Failed:  {failures}")
    print()

    return failures


def deploy_single(
    db: WireGuardDBv2,
    output_dir: Path,
    target: str,
    user: str = 'root',
    restart: bool = False,
    dry_run: bool = False
) -> int:
    """
    Deploy config to a single host by hostname.

    Args:
        db: Database connection
        output_dir: Directory containing generated configs
        target: Target hostname (e.g., 'home-gateway', 'coordination-server')
        user: SSH user
        restart: Whether to restart WireGuard
        dry_run: If True, print what would be done

    Returns:
        0 on success, 1 on failure
    """
    with db._connection() as conn:
        cursor = conn.cursor()

        # Try coordination server
        cursor.execute("""
            SELECT hostname, endpoint
            FROM coordination_server
            WHERE hostname = ?
        """, (target,))
        row = cursor.fetchone()
        if row:
            hostname, endpoint = row
            config_file = output_dir / 'coordination.conf'
            if not endpoint or endpoint == 'UNKNOWN':
                print(f"Error: {hostname} has no endpoint configured")
                return 1

            success = deploy_to_host(
                hostname=hostname,
                config_file=config_file,
                endpoint=endpoint,
                user=user,
                restart=restart,
                dry_run=dry_run
            )
            return 0 if success else 1

        # Try subnet router
        cursor.execute("""
            SELECT hostname, endpoint
            FROM subnet_router
            WHERE hostname = ?
        """, (target,))
        row = cursor.fetchone()
        if row:
            hostname, endpoint = row
            config_file = output_dir / f'{hostname}.conf'
            if not endpoint:
                print(f"Error: {hostname} has no endpoint configured")
                return 1

            success = deploy_to_host(
                hostname=hostname,
                config_file=config_file,
                endpoint=endpoint,
                user=user,
                restart=restart,
                dry_run=dry_run
            )
            return 0 if success else 1

        # Try remote
        cursor.execute("""
            SELECT hostname, endpoint
            FROM remote
            WHERE hostname = ?
        """, (target,))
        row = cursor.fetchone()
        if row:
            hostname, endpoint = row
            config_file = output_dir / f'{hostname}.conf'
            if not endpoint:
                print(f"Error: {hostname} has no endpoint configured")
                return 1

            success = deploy_to_host(
                hostname=hostname,
                config_file=config_file,
                endpoint=endpoint,
                user=user,
                restart=restart,
                dry_run=dry_run
            )
            return 0 if success else 1

        # Try exit node
        cursor.execute("""
            SELECT hostname, ssh_host, ssh_user, ssh_port
            FROM exit_node
            WHERE hostname = ?
        """, (target,))
        row = cursor.fetchone()
        if row:
            hostname, ssh_host, ssh_user, ssh_port = row
            config_file = output_dir / f'{hostname}.conf'
            if not ssh_host:
                print(f"Error: {hostname} has no SSH host configured")
                return 1

            # Use ssh_host:ssh_port as endpoint for SSH
            ssh_endpoint = f"{ssh_host}:{ssh_port}" if ssh_port and ssh_port != 22 else ssh_host
            exit_user = ssh_user or 'root'

            success = deploy_to_host(
                hostname=hostname,
                config_file=config_file,
                endpoint=ssh_endpoint,
                user=exit_user,
                restart=restart,
                dry_run=dry_run
            )
            return 0 if success else 1

    print(f"Error: Host not found: {target}")
    return 1


def deploy_configs(args) -> int:
    """CLI handler for 'wg-friend deploy' command"""
    db = WireGuardDBv2(args.db)
    output_dir = Path(args.output)

    if not output_dir.exists():
        print(f"Error: Output directory not found: {output_dir}")
        print(f"Run 'wg-friend generate' first to create configs")
        return 1

    user = getattr(args, 'user', 'root')
    restart = getattr(args, 'restart', False)
    dry_run = getattr(args, 'dry_run', False)

    # Deploy to specific host or all hosts?
    entity = getattr(args, 'entity', None) or getattr(args, 'host', None)
    if entity:
        return deploy_single(db, output_dir, entity, user=user, restart=restart, dry_run=dry_run)
    else:
        failures = deploy_all(db, output_dir, user=user, restart=restart, dry_run=dry_run)
        return 1 if failures > 0 else 0


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('--db', default='wireguard.db')
    parser.add_argument('--output', default='generated')
    parser.add_argument('--host', help='Deploy to specific host (by hostname)')
    parser.add_argument('--user', default='root', help='SSH user')
    parser.add_argument('--restart', action='store_true', help='Restart WireGuard after deploy')
    parser.add_argument('--dry-run', dest='dry_run', action='store_true', help='Show what would be done')

    args = parser.parse_args()
    sys.exit(deploy_configs(args))
