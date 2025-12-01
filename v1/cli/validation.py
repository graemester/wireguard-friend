"""
Validation Checks for Import

Phase 5-style validation from alpha - validates imported data:
- WireGuard key format (44 chars base64)
- IP address and CIDR notation
- Network reachability (optional ping test)
"""

import re
import ipaddress
import subprocess
from pathlib import Path
from typing import List, Tuple

# Rich imports for enhanced UI
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


def rprint(msg: str = "", style: str = None, end: str = "\n"):
    """Print with Rich if available, else plain print"""
    if RICH_AVAILABLE:
        if style:
            console.print(f"[{style}]{msg}[/{style}]", end=end)
        else:
            console.print(msg, end=end)
    else:
        plain = re.sub(r'\[/?[^\]]+\]', '', msg)
        print(plain, end=end)


def validate_key_format(key: str) -> Tuple[bool, str]:
    """
    Validate WireGuard key format (44 chars base64 ending in =)

    Returns:
        (is_valid, error_message)
    """
    if not key:
        return True, ""  # Optional keys are ok

    if len(key) != 44:
        return False, f"Invalid length ({len(key)} chars, expected 44)"

    if not re.match(r'^[A-Za-z0-9+/]{43}=$', key):
        return False, "Invalid base64 format"

    return True, ""


def validate_ip_address(ip_str: str) -> Tuple[bool, str]:
    """
    Validate IP address format

    Returns:
        (is_valid, error_message)
    """
    if not ip_str:
        return True, ""  # Optional IPs are ok

    # Strip CIDR suffix if present
    if '/' in ip_str:
        ip_str = ip_str.split('/')[0]

    try:
        ipaddress.ip_address(ip_str)
        return True, ""
    except ValueError as e:
        return False, f"Invalid IP address: {e}"


def validate_cidr(cidr_str: str) -> Tuple[bool, str]:
    """
    Validate CIDR notation

    Returns:
        (is_valid, error_message)
    """
    if not cidr_str:
        return True, ""

    try:
        ipaddress.ip_network(cidr_str, strict=False)
        return True, ""
    except ValueError as e:
        return False, f"Invalid CIDR: {e}"


def ping_host(host: str, timeout: int = 2) -> Tuple[bool, str]:
    """
    Ping a host to check connectivity

    Returns:
        (is_reachable, message)
    """
    try:
        result = subprocess.run(
            ['ping', '-c', '1', '-W', str(timeout), host],
            capture_output=True,
            timeout=timeout + 1
        )
        if result.returncode == 0:
            return True, "Reachable"
        else:
            return False, "Not reachable"
    except subprocess.TimeoutExpired:
        return False, "Timeout"
    except FileNotFoundError:
        return False, "Ping not available"
    except Exception as e:
        return False, str(e)


def run_validation_checks(db, ping_endpoint: bool = True) -> Tuple[int, int, List[str]]:
    """
    Run validation checks on imported data

    Args:
        db: WireGuardDBv2 database instance
        ping_endpoint: Whether to ping the CS endpoint

    Returns:
        (checks_passed, checks_failed, warnings)
    """
    checks_passed = 0
    checks_failed = 0
    warnings = []

    if RICH_AVAILABLE:
        console.print()
        console.print(Panel.fit(
            "[bold cyan]Phase 5: Validation[/bold cyan]\n\n"
            "Running validation checks on imported data...",
            border_style="cyan"
        ))
        console.print()
    else:
        rprint()
        rprint("[bold]Phase 5: Validation[/bold]")
        rprint("Running validation checks...")
        rprint()

    with db._connection() as conn:
        cursor = conn.cursor()

        # Get CS data
        cursor.execute("SELECT * FROM coordination_server WHERE id = 1")
        cs_row = cursor.fetchone()
        if not cs_row:
            rprint("[red]Error: No coordination server found![/red]")
            return 0, 1, ["No coordination server in database"]

        cs = dict(cs_row)

        # 1. Validate CS keys
        rprint("[bold]Checking WireGuard keys...[/bold]")

        valid, msg = validate_key_format(cs.get('current_public_key'))
        if valid:
            rprint(f"  [green]OK[/green] CS public key format")
            checks_passed += 1
        else:
            rprint(f"  [red]FAIL[/red] CS public key: {msg}")
            warnings.append(f"CS public key: {msg}")
            checks_failed += 1

        valid, msg = validate_key_format(cs.get('private_key'))
        if valid:
            rprint(f"  [green]OK[/green] CS private key format")
            checks_passed += 1
        else:
            rprint(f"  [red]FAIL[/red] CS private key: {msg}")
            warnings.append(f"CS private key: {msg}")
            checks_failed += 1

        # 2. Validate CS networks
        rprint()
        rprint("[bold]Checking network configuration...[/bold]")

        valid, msg = validate_cidr(cs.get('network_ipv4'))
        if valid:
            rprint(f"  [green]OK[/green] VPN IPv4 network: {cs.get('network_ipv4')}")
            checks_passed += 1
        else:
            rprint(f"  [red]FAIL[/red] VPN IPv4 network: {msg}")
            warnings.append(f"VPN IPv4 network: {msg}")
            checks_failed += 1

        valid, msg = validate_cidr(cs.get('network_ipv6'))
        if valid:
            rprint(f"  [green]OK[/green] VPN IPv6 network: {cs.get('network_ipv6')}")
            checks_passed += 1
        else:
            rprint(f"  [red]FAIL[/red] VPN IPv6 network: {msg}")
            warnings.append(f"VPN IPv6 network: {msg}")
            checks_failed += 1

        # 3. Validate CS endpoint
        endpoint = cs.get('endpoint')
        if endpoint and endpoint != 'UNKNOWN':
            rprint(f"  [green]OK[/green] CS endpoint: {endpoint}")
            checks_passed += 1

            # Optional ping test
            if ping_endpoint:
                rprint()
                rprint(f"[bold]Checking endpoint connectivity...[/bold]")
                rprint(f"  Pinging {endpoint}...", end=" ")

                reachable, msg = ping_host(endpoint)
                if reachable:
                    if RICH_AVAILABLE:
                        console.print(f"[green]{msg}[/green]")
                    else:
                        print(f"{msg}")
                    checks_passed += 1
                else:
                    if RICH_AVAILABLE:
                        console.print(f"[yellow]{msg}[/yellow]")
                    else:
                        print(f"{msg}")
                    warnings.append(f"CS endpoint not reachable: {msg}")
                    # Don't count as failure, just warning
        else:
            rprint(f"  [yellow]WARN[/yellow] CS endpoint not set or unknown")
            warnings.append("CS endpoint not configured")

        # 4. Validate subnet routers
        cursor.execute("SELECT * FROM subnet_router")
        routers = [dict(row) for row in cursor.fetchall()]

        if routers:
            rprint()
            rprint("[bold]Checking subnet routers...[/bold]")

            for router in routers:
                valid, msg = validate_key_format(router.get('current_public_key'))
                if valid:
                    rprint(f"  [green]OK[/green] {router['hostname']} public key")
                    checks_passed += 1
                else:
                    rprint(f"  [red]FAIL[/red] {router['hostname']} public key: {msg}")
                    warnings.append(f"{router['hostname']} public key: {msg}")
                    checks_failed += 1

                valid, msg = validate_ip_address(router.get('ipv4_address'))
                if valid:
                    checks_passed += 1
                else:
                    rprint(f"  [red]FAIL[/red] {router['hostname']} IPv4: {msg}")
                    warnings.append(f"{router['hostname']} IPv4: {msg}")
                    checks_failed += 1

        # 5. Validate remotes
        cursor.execute("SELECT * FROM remote")
        remotes = [dict(row) for row in cursor.fetchall()]

        if remotes:
            rprint()
            rprint("[bold]Checking remote clients...[/bold]")

            for remote in remotes:
                valid, msg = validate_key_format(remote.get('current_public_key'))
                if valid:
                    rprint(f"  [green]OK[/green] {remote['hostname']} public key")
                    checks_passed += 1
                else:
                    rprint(f"  [red]FAIL[/red] {remote['hostname']} public key: {msg}")
                    warnings.append(f"{remote['hostname']} public key: {msg}")
                    checks_failed += 1

                valid, msg = validate_ip_address(remote.get('ipv4_address'))
                if valid:
                    checks_passed += 1
                else:
                    rprint(f"  [red]FAIL[/red] {remote['hostname']} IPv4: {msg}")
                    warnings.append(f"{remote['hostname']} IPv4: {msg}")
                    checks_failed += 1

    # Summary
    rprint()
    if RICH_AVAILABLE:
        if checks_failed == 0:
            console.print(Panel(
                f"[green]{checks_passed} checks passed[/green]\n"
                + (f"[yellow]{len(warnings)} warnings[/yellow]" if warnings else ""),
                title="[bold green]Validation Complete[/bold green]",
                border_style="green"
            ))
        else:
            console.print(Panel(
                f"[green]{checks_passed} passed[/green], [red]{checks_failed} failed[/red]\n"
                + (f"[yellow]{len(warnings)} warnings[/yellow]" if warnings else ""),
                title="[bold yellow]Validation Complete[/bold yellow]",
                border_style="yellow"
            ))
    else:
        rprint(f"Validation complete: {checks_passed} passed, {checks_failed} failed")
        if warnings:
            rprint(f"Warnings: {len(warnings)}")

    if warnings:
        rprint()
        rprint("[bold]Warnings:[/bold]")
        for warning in warnings:
            rprint(f"  [yellow]*[/yellow] {warning}")

    return checks_passed, checks_failed, warnings


if __name__ == '__main__':
    import sys
    import argparse

    sys.path.insert(0, str(Path(__file__).parent.parent.parent))
    from v1.schema_semantic import WireGuardDBv2

    parser = argparse.ArgumentParser()
    parser.add_argument('--db', default='wireguard.db')
    parser.add_argument('--skip-ping', action='store_true')
    args = parser.parse_args()

    db_path = Path(args.db)
    if not db_path.exists():
        print(f"Error: Database not found: {db_path}")
        sys.exit(1)

    db = WireGuardDBv2(db_path)
    passed, failed, warnings = run_validation_checks(db, ping_endpoint=not args.skip_ping)

    sys.exit(0 if failed == 0 else 1)
