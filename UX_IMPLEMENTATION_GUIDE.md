# WireGuard Friend - UX Implementation Guide

**Companion to:** UX_UI_ASSESSMENT.md
**Purpose:** Concrete code patterns and implementation examples
**For:** Development team implementing UX improvements

---

## Table of Contents

1. [Enhanced Visual Hierarchy Patterns](#enhanced-visual-hierarchy-patterns)
2. [Loading States Library](#loading-states-library)
3. [Error Handling Framework](#error-handling-framework)
4. [Navigation Enhancement Kit](#navigation-enhancement-kit)
5. [Table Display Patterns](#table-display-patterns)
6. [Testing Utilities](#testing-utilities)

---

## Enhanced Visual Hierarchy Patterns

### Pattern 1: Hierarchical Peer Display

**File:** `/home/ged/wireguard-friend/v1/cli/peer_manager.py`
**Function:** `list_peers()` (lines 318-362)

**Current Implementation:**
```python
def list_peers(db: WireGuardDBv2):
    """List all peers in the database"""
    print("\n" + "=" * 70)
    print("PEERS")
    print("=" * 70)
    # ... flat list output ...
```

**Enhanced Implementation:**
```python
from rich.tree import Tree
from rich.text import Text

def list_peers(db: WireGuardDBv2, show_keys: bool = False):
    """
    List all peers with hierarchical display.

    Args:
        db: Database connection
        show_keys: If True, show full public keys (default: truncated)
    """
    with db._connection() as conn:
        cursor = conn.cursor()

        # Coordination Server
        cursor.execute("""
            SELECT hostname, ipv4_address, current_public_key
            FROM coordination_server
        """)
        cs = cursor.fetchone()

        # Routers
        cursor.execute("""
            SELECT id, hostname, ipv4_address, current_public_key
            FROM subnet_router
            ORDER BY hostname
        """)
        routers = cursor.fetchall()

        # Remotes
        cursor.execute("""
            SELECT id, hostname, ipv4_address, current_public_key, access_level
            FROM remote
            ORDER BY hostname
        """)
        remotes = cursor.fetchall()

    # Build tree structure
    tree = Tree(
        f"[bold cyan]Network Peers[/bold cyan] [dim]({1 + len(routers) + len(remotes)} total)[/dim]"
    )

    # Coordination Server
    if cs:
        hostname, ipv4, pubkey = cs
        cs_node = tree.add("[bold green]◆ Coordination Server[/bold green]")
        cs_node.add(f"[cyan]{hostname}[/cyan]")
        cs_node.add(f"IP: {ipv4}")
        key_display = pubkey if show_keys else f"{pubkey[:40]}..."
        cs_node.add(f"Key: [dim]{key_display}[/dim]")

    # Subnet Routers
    if routers:
        router_branch = tree.add(f"[bold magenta]▶ Subnet Routers[/bold magenta] [dim]({len(routers)})[/dim]")
        for router_id, hostname, ipv4, pubkey in routers:
            router_node = router_branch.add(f"[magenta][{router_id}] {hostname}[/magenta]")
            router_node.add(f"IP: {ipv4}")
            key_display = pubkey if show_keys else f"{pubkey[:40]}..."
            router_node.add(f"Key: [dim]{key_display}[/dim]")

    # Remote Clients
    if remotes:
        remote_branch = tree.add(f"[bold yellow]◉ Remote Clients[/bold yellow] [dim]({len(remotes)})[/dim]")
        for remote_id, hostname, ipv4, pubkey, access in remotes:
            remote_node = remote_branch.add(f"[yellow][{remote_id}] {hostname}[/yellow]")
            remote_node.add(f"IP: {ipv4}  Access: [cyan]{access}[/cyan]")
            key_display = pubkey if show_keys else f"{pubkey[:40]}..."
            remote_node.add(f"Key: [dim]{key_display}[/dim]")

    console.print()
    console.print(tree)
    console.print()
    console.print("[dim]Tip: Keys are truncated. Use 'wg-friend list --full-keys' to see complete keys.[/dim]")
    console.print()
```

**Benefits:**
- Clear visual hierarchy
- Entity type immediately visible
- Compact yet informative
- Scalable to large networks

---

### Pattern 2: Status Indicators

**File:** `/home/ged/wireguard-friend/v1/cli/status.py`
**Function:** `show_live_peer_status()` (lines 292-400)

**Enhanced Implementation:**
```python
from rich.table import Table
from rich.panel import Panel
from rich.columns import Columns
from datetime import datetime, timedelta

def show_live_peer_status(db: WireGuardDBv2, interface: str = 'wg0', user: str = 'root'):
    """Show live peer connection status with visual indicators"""

    # ... existing setup code ...

    if not peer_status:
        console.print("\n[yellow]No peers connected[/yellow]\n")
        return

    # Create status table
    table = Table(
        title=f"[bold]Live Peer Status[/bold] - {cs_hostname}",
        show_header=True,
        header_style="bold cyan",
        border_style="cyan"
    )

    table.add_column("Status", justify="center", width=6, no_wrap=True)
    table.add_column("Hostname", style="cyan", no_wrap=True)
    table.add_column("Type", style="magenta", width=10)
    table.add_column("Endpoint", width=22)
    table.add_column("Last Handshake", width=18)
    table.add_column("Transfer", justify="right", width=25)

    online_count = 0
    offline_count = 0

    for pubkey, status in sorted(peer_status.items(), key=lambda x: peer_db_info.get(x[0], {}).get('hostname', '')):
        db_info = peer_db_info.get(pubkey, {
            'hostname': f'Unknown ({pubkey[:10]}...)',
            'type': 'unknown'
        })

        hostname = db_info['hostname']
        peer_type = db_info['type']
        endpoint = status.get('endpoint', 'N/A')
        handshake = status.get('latest_handshake', 'Never')
        rx = status.get('transfer_rx', '0 B')
        tx = status.get('transfer_tx', '0 B')

        # Parse handshake time
        is_online = False
        status_text = "[dim]○[/dim] Offline"
        style = "dim"

        if handshake and handshake != '(none)' and 'ago' in handshake:
            # Parse "X minutes ago" or "X seconds ago"
            is_online = True
            online_count += 1
            status_text = "[green]●[/green] Online"
            style = None
        else:
            offline_count += 1

        # Format transfer with units
        transfer = f"[dim]↓[/dim] {rx}  [dim]↑[/dim] {tx}"

        table.add_row(
            status_text,
            hostname,
            peer_type,
            endpoint,
            handshake,
            transfer,
            style=style
        )

    # Print table
    console.print()
    console.print(table)

    # Summary cards
    summary_cards = [
        Panel(
            f"[bold green]{online_count}[/bold green]\n[dim]Online[/dim]",
            border_style="green",
            expand=False
        ),
        Panel(
            f"[bold]{offline_count}[/bold]\n[dim]Offline[/dim]",
            border_style="dim",
            expand=False
        ),
        Panel(
            f"[bold cyan]{len(peer_status)}[/bold cyan]\n[dim]Total[/dim]",
            border_style="cyan",
            expand=False
        ),
    ]

    console.print()
    console.print(Columns(summary_cards, equal=True, expand=True))
    console.print()
```

**Benefits:**
- Instant visual status assessment
- Summary metrics at a glance
- Professional table formatting
- Responsive to terminal width

---

## Loading States Library

**Create new file:** `/home/ged/wireguard-friend/v1/cli/ui_feedback.py`

```python
"""
UI Feedback Components - Loading states, spinners, progress bars

Provides consistent feedback during long-running operations.
"""

from rich.spinner import Spinner
from rich.live import Live
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.console import Console
from contextlib import contextmanager
from typing import Optional, List, Tuple
import time

console = Console()


@contextmanager
def loading_spinner(message: str, success_message: Optional[str] = None):
    """
    Context manager for simple loading spinner.

    Usage:
        with loading_spinner("Connecting to server..."):
            result = ssh_command(...)
        # Automatically stops spinner when done
    """
    with Live(Spinner("dots", text=f"[cyan]{message}[/cyan]"), console=console, refresh_per_second=10) as live:
        try:
            yield live
            if success_message:
                live.update(f"[green]✓ {success_message}[/green]")
                time.sleep(0.3)  # Brief pause for satisfaction
        except Exception as e:
            live.update(f"[red]✗ Failed: {e}[/red]")
            raise


@contextmanager
def batch_progress(total_items: int, description: str = "Processing"):
    """
    Context manager for batch operations with progress bar.

    Usage:
        with batch_progress(len(items), "Deploying configs") as progress:
            for item in items:
                # ... do work ...
                progress.advance()
    """
    progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console
    )

    with progress:
        task = progress.add_task(f"[cyan]{description}[/cyan]", total=total_items)

        class ProgressWrapper:
            def advance(self, amount: int = 1):
                progress.advance(task, amount)

            def update(self, description: str):
                progress.update(task, description=f"[cyan]{description}[/cyan]")

        yield ProgressWrapper()


class MultiStepProgress:
    """
    Multi-step progress indicator for complex operations.

    Usage:
        mp = MultiStepProgress([
            "Generate coordination server config",
            "Generate router configs",
            "Generate remote configs",
            "Write files to disk"
        ])

        with mp:
            mp.start_step(0)
            # ... work ...
            mp.complete_step(0)

            mp.start_step(1)
            # ... work ...
            mp.complete_step(1)
    """

    def __init__(self, steps: List[str]):
        self.steps = steps
        self.current_step = 0
        self.progress = None
        self.tasks = []

    def __enter__(self):
        self.progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            console=console
        )
        self.progress.__enter__()

        # Create tasks for all steps
        for step in self.steps:
            task = self.progress.add_task(f"[dim]{step}[/dim]", total=1, start=False)
            self.tasks.append(task)

        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.progress.__exit__(exc_type, exc_val, exc_tb)

    def start_step(self, step_index: int):
        """Start a specific step"""
        self.current_step = step_index
        self.progress.update(
            self.tasks[step_index],
            description=f"[cyan]{self.steps[step_index]}[/cyan]",
            completed=0
        )
        self.progress.start_task(self.tasks[step_index])

    def complete_step(self, step_index: int, success: bool = True):
        """Mark a step as complete"""
        if success:
            self.progress.update(
                self.tasks[step_index],
                description=f"[green]✓ {self.steps[step_index]}[/green]",
                completed=1
            )
        else:
            self.progress.update(
                self.tasks[step_index],
                description=f"[red]✗ {self.steps[step_index]}[/red]",
                completed=1
            )


# Quick spinner types for different operation speeds
def quick_spinner(message: str) -> Live:
    """Fast spinner for operations < 2 seconds"""
    return Live(Spinner("dots", text=f"[cyan]{message}[/cyan]"), console=console)


def medium_spinner(message: str) -> Live:
    """Medium spinner for operations 2-10 seconds"""
    return Live(Spinner("line", text=f"[cyan]{message}[/cyan]"), console=console)


def long_spinner(message: str) -> Live:
    """Slow spinner for operations > 10 seconds"""
    return Live(Spinner("arc", text=f"[cyan]{message}[/cyan]"), console=console)
```

**Integration Example - SSH Deploy:**

**File:** `/home/ged/wireguard-friend/v1/cli/deploy.py`
**Function:** `deploy_to_host()` (lines 170-250)

```python
from v1.cli.ui_feedback import loading_spinner, batch_progress

def deploy_to_host(
    hostname: str,
    config_file: Path,
    endpoint: str,
    interface: str = 'wg0',
    user: str = 'root',
    restart: bool = False,
    dry_run: bool = False
) -> bool:
    """Deploy config to a single host with progress feedback"""

    remote_path = f'/etc/wireguard/{interface}.conf'

    console.print()
    console.print(Panel(
        f"[cyan]{hostname}[/cyan] ({endpoint})\n"
        f"Local:  {config_file}\n"
        f"Remote: {remote_path}",
        title="[bold]Deployment Target[/bold]",
        border_style="cyan"
    ))

    if not config_file.exists():
        console.print(f"[red]✗ Config file not found: {config_file}[/red]")
        return False

    # Check if localhost
    is_local = is_local_host(endpoint.split(':')[0])

    try:
        # Step 1: Backup existing config
        with loading_spinner(
            "Backing up existing config..." if not dry_run else "Would backup existing config...",
            "Backup complete" if not dry_run else "Dry run - no backup"
        ):
            if not dry_run:
                backup_remote_config(endpoint, remote_path, user=user, dry_run=dry_run)

        # Step 2: Deploy new config
        with loading_spinner(
            "Deploying config..." if not dry_run else "Would deploy config...",
            "Config deployed" if not dry_run else "Dry run - no deploy"
        ):
            if not dry_run:
                if is_local:
                    shutil.copy2(config_file, remote_path)
                else:
                    result = scp_file(config_file, endpoint, remote_path, user=user, dry_run=False)
                    if result != 0:
                        raise Exception("SCP failed")

        # Step 3: Restart if requested
        if restart:
            with loading_spinner(
                "Restarting WireGuard..." if not dry_run else "Would restart WireGuard...",
                "WireGuard restarted" if not dry_run else "Dry run - no restart"
            ):
                if not dry_run:
                    restart_wireguard(endpoint, interface=interface, user=user, dry_run=False)

        console.print("[green]✓ Deployment complete[/green]\n")
        return True

    except Exception as e:
        console.print(f"[red]✗ Deployment failed: {e}[/red]\n")
        return False
```

---

## Error Handling Framework

**Create new file:** `/home/ged/wireguard-friend/v1/cli/ui_alerts.py`

```python
"""
UI Alerts - Standardized error, warning, and success messages

Provides consistent visual feedback for different message types.
"""

from rich.panel import Panel
from rich.console import Console
from typing import Optional, List
import sys

console = Console()


def show_error(
    message: str,
    details: Optional[str] = None,
    suggestions: Optional[List[str]] = None,
    fatal: bool = False
):
    """
    Display a standardized error message.

    Args:
        message: Main error message
        details: Optional detailed explanation
        suggestions: Optional list of suggested actions
        fatal: If True, exit after displaying error
    """
    content = f"[bold red]{message}[/bold red]"

    if details:
        content += f"\n\n{details}"

    if suggestions:
        content += "\n\n[yellow]Suggested actions:[/yellow]"
        for suggestion in suggestions:
            content += f"\n  • {suggestion}"

    if not fatal:
        content += "\n\n[dim]Press Enter to continue...[/dim]"

    panel = Panel(
        content,
        title="[bold red]Error[/bold red]",
        border_style="red",
        padding=(1, 2)
    )

    console.print()
    console.print(panel)

    if fatal:
        sys.exit(1)
    else:
        input()


def show_warning(
    message: str,
    details: Optional[str] = None,
    continue_anyway: bool = True
) -> bool:
    """
    Display a warning message and optionally ask for confirmation.

    Args:
        message: Main warning message
        details: Optional detailed explanation
        continue_anyway: If True, ask if user wants to continue

    Returns:
        True if user wants to continue, False otherwise
    """
    content = f"[bold yellow]{message}[/bold yellow]"

    if details:
        content += f"\n\n{details}"

    if continue_anyway:
        content += "\n\n[dim]Do you want to continue anyway?[/dim]"

    panel = Panel(
        content,
        title="[bold yellow]Warning[/bold yellow]",
        border_style="yellow",
        padding=(1, 2)
    )

    console.print()
    console.print(panel)

    if continue_anyway:
        response = input("\nContinue? [y/N]: ").strip().lower()
        return response in ('y', 'yes')
    else:
        input("\nPress Enter to continue...")
        return True


def show_success(
    message: str,
    details: Optional[str] = None,
    next_steps: Optional[List[str]] = None,
    pause: bool = True
):
    """
    Display a success message with optional next steps.

    Args:
        message: Main success message
        details: Optional detailed explanation
        next_steps: Optional list of next steps
        pause: If True, wait for Enter before continuing
    """
    content = f"[bold green]✓ {message}[/bold green]"

    if details:
        content += f"\n\n{details}"

    if next_steps:
        content += "\n\n[cyan]Next steps:[/cyan]"
        for i, step in enumerate(next_steps, 1):
            content += f"\n  {i}. {step}"

    if pause:
        content += "\n\n[dim]Press Enter to continue...[/dim]"

    panel = Panel(
        content,
        title="[bold green]Success[/bold green]",
        border_style="green",
        padding=(1, 2)
    )

    console.print()
    console.print(panel)

    if pause:
        input()


def show_info(message: str, details: Optional[str] = None):
    """Display an informational message."""
    content = f"[bold cyan]{message}[/bold cyan]"

    if details:
        content += f"\n\n{details}"

    panel = Panel(
        content,
        title="[bold cyan]Info[/bold cyan]",
        border_style="cyan",
        padding=(1, 2)
    )

    console.print()
    console.print(panel)


def confirm_destructive_action(
    action: str,
    target: str,
    consequences: List[str],
    confirmation_text: Optional[str] = None
) -> bool:
    """
    Get confirmation for destructive actions with impact preview.

    Args:
        action: Description of action (e.g., "remove peer")
        target: What will be affected (e.g., "alice-laptop")
        consequences: List of consequences
        confirmation_text: Optional text user must type to confirm

    Returns:
        True if confirmed, False otherwise
    """
    content = (
        f"[bold red]DESTRUCTIVE ACTION[/bold red]\n\n"
        f"You are about to [red]{action}[/red]: [cyan]{target}[/cyan]\n\n"
        f"[yellow]This will:[/yellow]"
    )

    for consequence in consequences:
        content += f"\n  • {consequence}"

    content += "\n\n[dim]This action is logged but cannot be undone.[/dim]"

    panel = Panel(
        content,
        title="[bold red]Confirm Action[/bold red]",
        border_style="red",
        padding=(1, 2)
    )

    console.print()
    console.print(panel)
    console.print()

    if confirmation_text:
        response = input(f"Type '{confirmation_text}' to confirm: ").strip()
        return response == confirmation_text
    else:
        response = input("Type 'YES' to confirm: ").strip()
        return response == 'YES'
```

**Integration Example - Peer Removal:**

**File:** `/home/ged/wireguard-friend/v1/cli/peer_manager.py`
**Function:** `remove_peer()` (lines 365-453)

```python
from v1.cli.ui_alerts import confirm_destructive_action, show_success

def remove_peer(db: WireGuardDBv2, peer_type: str, peer_id: int, reason: str = "Manual revocation") -> bool:
    """Remove/revoke a peer with enhanced confirmation"""

    # ... fetch peer details ...

    # Confirm with impact preview
    confirmed = confirm_destructive_action(
        action="remove peer",
        target=hostname,
        consequences=[
            "Delete peer from database",
            "Revoke all VPN access",
            "Add revocation entry to key rotation history",
            "Require config regeneration and deployment",
        ],
        confirmation_text=hostname
    )

    if not confirmed:
        console.print("[yellow]Removal cancelled[/yellow]\n")
        return False

    # ... perform deletion ...

    # Success message with next steps
    show_success(
        message=f"Removed {peer_type}: {hostname}",
        details=f"Revocation logged with reason: {reason}",
        next_steps=[
            "Regenerate configs: wg-friend generate",
            "Deploy to coordination server: wg-friend deploy",
        ]
    )

    return True
```

---

## Navigation Enhancement Kit

**File:** `/home/ged/wireguard-friend/v1/cli/tui.py`

Add navigation context tracking:

```python
class NavigationContext:
    """Track navigation history and provide breadcrumbs"""

    def __init__(self):
        self.history = ["Main Menu"]
        self.shortcuts = {
            'h': self.go_home,
            'b': self.go_back,
        }

    def push(self, location: str):
        """Add location to navigation history"""
        self.history.append(location)

    def pop(self) -> str:
        """Go back one level"""
        if len(self.history) > 1:
            return self.history.pop()
        return self.history[0]

    def go_back(self):
        """Go back to previous menu"""
        self.pop()

    def go_home(self):
        """Return to main menu"""
        self.history = ["Main Menu"]

    def get_breadcrumb(self) -> str:
        """Get current navigation path"""
        return " > ".join(self.history)

    def is_deep(self) -> bool:
        """Check if we're in a deep menu (3+ levels)"""
        return len(self.history) >= 3


# Global navigation context
nav_context = NavigationContext()


def print_menu_with_nav(title: str, options: List[str], include_quit: bool = True):
    """Enhanced menu with navigation context"""

    # Show breadcrumb if we're deep in menus
    if nav_context.is_deep():
        console.print(f"[dim]{nav_context.get_breadcrumb()}[/dim]\n")

    # Build menu options
    menu_lines = []
    for i, option in enumerate(options, 1):
        menu_lines.append(f"  [cyan]{i}.[/cyan] {option}")

    # Add navigation help
    nav_help = []
    if len(nav_context.history) > 1:
        nav_help.append("[dim]b. Back[/dim]")
    if len(nav_context.history) > 2:
        nav_help.append("[dim]h. Home[/dim]")
    if include_quit:
        nav_help.append("[dim]q. Quit[/dim]")

    if nav_help:
        menu_lines.append("\n  " + " | ".join(nav_help))

    console.print()
    console.print(Panel(
        "\n".join(menu_lines),
        title=f"[bold]{title}[/bold]",
        border_style="cyan",
        padding=(1, 2)
    ))
    console.print()


def get_menu_choice_with_nav(max_choice: int, allow_quit: bool = True) -> Optional[int]:
    """
    Enhanced menu choice handling with navigation shortcuts.

    Returns:
        Choice number, -1 for back, -2 for home, None for quit
    """
    while True:
        choice = input("Choice: ").strip().lower()

        # Handle navigation shortcuts
        if choice == 'b' and len(nav_context.history) > 1:
            return -1  # Back signal
        if choice == 'h' and len(nav_context.history) > 2:
            return -2  # Home signal
        if allow_quit and choice in ('q', 'quit', 'exit'):
            return None  # Quit signal

        # Handle numeric choice
        try:
            choice_int = int(choice)
            if 1 <= choice_int <= max_choice:
                return choice_int
            print(f"  Invalid choice. Enter 1-{max_choice}.")
        except ValueError:
            print(f"  Invalid input. Enter a number 1-{max_choice}.")


# Example usage in extramural menu
def extramural_menu(db_path: str):
    """Extramural configs menu with enhanced navigation"""
    nav_context.push("Extramural")

    while True:
        print_menu_with_nav(
            "EXTRAMURAL - External VPN Configs",
            [
                "List All Configs",
                "View by Sponsor",
                "View by Local Peer",
                "Import Config File",
                "Generate Single Config",
                "Manage Sponsors",
                "Manage Local Peers",
            ],
            include_quit=False
        )

        choice = get_menu_choice_with_nav(7, allow_quit=True)

        if choice == -1:  # Back
            nav_context.pop()
            return
        elif choice == -2:  # Home
            nav_context.go_home()
            return
        elif choice is None:  # Quit
            return
        elif choice == 1:
            nav_context.push("List Configs")
            extramural_list_all(ops, db_path)
            nav_context.pop()
        # ... handle other choices ...
```

---

## Table Display Patterns

**File:** `/home/ged/wireguard-friend/v1/cli/status.py`

Replace fixed-width string formatting with Rich tables:

```python
from rich.table import Table
from rich.text import Text

def show_network_overview(db: WireGuardDBv2):
    """Display network overview with rich tables"""

    with db._connection() as conn:
        cursor = conn.cursor()

        # Header
        console.print()
        console.print(Panel(
            "[bold cyan]WireGuard Network Status[/bold cyan]",
            border_style="cyan"
        ))
        console.print()

        # Coordination Server table
        cursor.execute("""
            SELECT hostname, endpoint, listen_port, network_ipv4, network_ipv6,
                   ipv4_address, ipv6_address, current_public_key
            FROM coordination_server
        """)
        cs = cursor.fetchone()

        if cs:
            hostname, endpoint, port, net4, net6, ip4, ip6, pubkey = cs

            cs_table = Table(title="Coordination Server", show_header=False, border_style="green")
            cs_table.add_column("Property", style="cyan", width=20)
            cs_table.add_column("Value")

            cs_table.add_row("Hostname", hostname)
            cs_table.add_row("Endpoint", f"{endpoint}:{port}")
            cs_table.add_row("VPN Networks", f"{net4}\n{net6}")
            cs_table.add_row("VPN Address", f"{ip4}\n{ip6}")
            cs_table.add_row("Public Key", f"{pubkey[:50]}...")

            console.print(cs_table)
            console.print()

        # Subnet Routers table
        cursor.execute("""
            SELECT id, hostname, ipv4_address, endpoint, current_public_key
            FROM subnet_router
            ORDER BY hostname
        """)
        routers = cursor.fetchall()

        if routers:
            router_table = Table(title=f"Subnet Routers ({len(routers)})", border_style="magenta")
            router_table.add_column("ID", justify="center", width=4)
            router_table.add_column("Hostname", style="cyan")
            router_table.add_column("VPN IP")
            router_table.add_column("Endpoint")
            router_table.add_column("Public Key", style="dim")

            for router_id, hostname, ip4, endpoint, pubkey in routers:
                # Get advertised networks
                cursor.execute("""
                    SELECT network_cidr
                    FROM advertised_network
                    WHERE subnet_router_id = ?
                """, (router_id,))
                networks = [row[0] for row in cursor.fetchall()]
                networks_str = ", ".join(networks)

                router_table.add_row(
                    str(router_id),
                    f"{hostname}\n[dim]Advertises: {networks_str}[/dim]",
                    ip4,
                    endpoint or "[dim]Dynamic[/dim]",
                    f"{pubkey[:30]}..."
                )

            console.print(router_table)
            console.print()

        # Remote Clients table
        cursor.execute("""
            SELECT id, hostname, ipv4_address, access_level, current_public_key
            FROM remote
            ORDER BY hostname
        """)
        remotes = cursor.fetchall()

        if remotes:
            remote_table = Table(title=f"Remote Clients ({len(remotes)})", border_style="yellow")
            remote_table.add_column("ID", justify="center", width=4)
            remote_table.add_column("Hostname", style="cyan")
            remote_table.add_column("VPN IP")
            remote_table.add_column("Access Level", style="magenta")
            remote_table.add_column("Public Key", style="dim")

            for remote_id, hostname, ip4, access, pubkey in remotes:
                remote_table.add_row(
                    str(remote_id),
                    hostname,
                    ip4,
                    access,
                    f"{pubkey[:30]}..."
                )

            console.print(remote_table)
            console.print()
```

---

## Testing Utilities

**Create new file:** `/home/ged/wireguard-friend/v1/cli/ui_testing.py`

```python
"""
UI Testing Utilities - Helpers for testing TUI components

Provides utilities for testing UI components in isolation.
"""

from rich.console import Console
from io import StringIO
import sys
from contextlib import contextmanager

@contextmanager
def capture_console_output():
    """
    Capture Rich console output for testing.

    Usage:
        with capture_console_output() as output:
            console.print("Hello world")

        assert "Hello world" in output.getvalue()
    """
    string_io = StringIO()
    test_console = Console(file=string_io, force_terminal=True, width=80)

    # Replace global console temporarily
    import v1.cli.tui as tui_module
    original_console = tui_module.console
    tui_module.console = test_console

    try:
        yield string_io
    finally:
        tui_module.console = original_console


def simulate_user_input(inputs: list):
    """
    Simulate user input for testing interactive prompts.

    Usage:
        simulate_user_input(['alice-laptop', 'y'])
        hostname = prompt("Enter hostname")
        confirmed = prompt_yes_no("Continue?")
    """
    import builtins
    original_input = builtins.input

    input_iter = iter(inputs)

    def mock_input(prompt=""):
        print(prompt, end='')  # Echo prompt for testing visibility
        return next(input_iter)

    builtins.input = mock_input
    return original_input


# Example test cases
def test_list_peers_output():
    """Test that peer listing produces correct output"""
    from v1.schema_semantic import WireGuardDBv2
    from v1.cli.peer_manager import list_peers

    db = WireGuardDBv2(':memory:')  # In-memory test database

    # ... populate test data ...

    with capture_console_output() as output:
        list_peers(db)

    result = output.getvalue()

    # Assertions
    assert "PEERS" in result
    assert "Coordination Server" in result
    assert "test-hostname" in result


def test_menu_navigation():
    """Test menu navigation with simulated input"""
    original_input = simulate_user_input(['1', 'q'])

    try:
        # ... test menu interaction ...
        pass
    finally:
        import builtins
        builtins.input = original_input
```

---

## Quick Reference: Before/After Patterns

### Pattern: Error Display

**Before:**
```python
print(f"Error: Config file not found: {config_file}")
return False
```

**After:**
```python
from v1.cli.ui_alerts import show_error

show_error(
    message="Config file not found",
    details=f"Looking for: {config_file}",
    suggestions=[
        "Run 'wg-friend generate' to create configs",
        "Check the output directory path"
    ]
)
return False
```

---

### Pattern: SSH Operation

**Before:**
```python
print(f"  Deploying config...")
result = scp_file(config_file, endpoint, remote_path, user=user)
if result != 0:
    print(f"  Error: SCP failed")
    return False
print(f"  ✓ Config deployed")
```

**After:**
```python
from v1.cli.ui_feedback import loading_spinner

with loading_spinner("Deploying config...", "Config deployed"):
    result = scp_file(config_file, endpoint, remote_path, user=user)
    if result != 0:
        raise Exception("SCP failed")
```

---

### Pattern: Batch Operations

**Before:**
```python
for i, deployment in enumerate(deployments):
    print(f"Deploying {i+1}/{len(deployments)}: {deployment.hostname}")
    deploy_to_host(deployment)
```

**After:**
```python
from v1.cli.ui_feedback import batch_progress

with batch_progress(len(deployments), "Deploying configs") as progress:
    for deployment in deployments:
        deploy_to_host(deployment)
        progress.advance()
```

---

### Pattern: Destructive Confirmation

**Before:**
```python
print(f"\nRemove {peer_type}: {hostname}")
print(f"  This will DELETE the peer from the database.")
response = input("Are you sure? [y/N]: ").strip().lower()
if response not in ('y', 'yes'):
    print("Cancelled.")
    return False
```

**After:**
```python
from v1.cli.ui_alerts import confirm_destructive_action

confirmed = confirm_destructive_action(
    action="remove peer",
    target=hostname,
    consequences=[
        "Delete peer from database",
        "Revoke VPN access",
        "Cannot be undone"
    ],
    confirmation_text=hostname
)
if not confirmed:
    return False
```

---

## Implementation Checklist

Use this checklist when implementing UX improvements:

### Phase 1: Foundation
- [ ] Create `ui_feedback.py` with loading components
- [ ] Create `ui_alerts.py` with alert components
- [ ] Add loading spinners to SSH operations in `deploy.py`
- [ ] Standardize error messages in `peer_manager.py`
- [ ] Convert `list_peers()` to use hierarchical display

### Phase 2: Enhancement
- [ ] Add breadcrumb navigation to deep menus
- [ ] Implement keyboard shortcuts (h=home, b=back)
- [ ] Convert status tables to Rich Table components
- [ ] Add confirmation previews to destructive actions
- [ ] Enhance menu display with hints

### Phase 3: Polish
- [ ] Add config previews to peer addition
- [ ] Implement state history visualization
- [ ] Add summary panels to generation
- [ ] Create keyboard shortcuts help screen
- [ ] Add success messages with next steps

---

## Performance Considerations

### Lazy Loading for Large Networks

```python
from rich.table import Table
from rich.console import Console

def list_peers_paginated(db: WireGuardDBv2, page_size: int = 20):
    """List peers with pagination for large networks"""

    # ... fetch counts ...

    if total_peers > page_size:
        console.print(f"[yellow]Large network detected ({total_peers} peers)[/yellow]")
        console.print(f"[dim]Showing first {page_size}. Use --all to show all.[/dim]\n")
        limit = page_size
    else:
        limit = total_peers

    # ... show limited results ...
```

### Async Operations (Future Enhancement)

```python
import asyncio
from rich.progress import Progress

async def deploy_all_async(deployments):
    """Deploy to multiple hosts in parallel"""
    with Progress() as progress:
        task = progress.add_task("Deploying...", total=len(deployments))

        async def deploy_one(deployment):
            result = await asyncio.create_subprocess_exec(...)
            progress.advance(task)
            return result

        results = await asyncio.gather(*[deploy_one(d) for d in deployments])

    return results
```

---

## Troubleshooting

### Rich Not Rendering Correctly

**Issue:** Panels and colors not displaying
**Solution:** Check terminal compatibility

```python
from rich.console import Console

console = Console()
if not console.is_terminal:
    print("Warning: Rich features disabled (not a terminal)")
    # Fall back to plain mode
```

### Unicode Characters Not Displaying

**Issue:** Box drawing characters showing as `?`
**Solution:** Use ASCII fallback

```python
from rich import box

# Use ASCII box style if unicode issues
table = Table(box=box.ASCII if unicode_issues else box.ROUNDED)
```

### Performance Issues with Large Tables

**Issue:** Table rendering slow with 100+ rows
**Solution:** Implement pagination or virtual scrolling

```python
# Show summary + option to view details
console.print(f"Found {total} items")
if total > 50:
    show_first = 20
    console.print(f"Showing first {show_first}. Use --all for complete list.")
```

---

## Additional Resources

### Rich Library Documentation
- Tables: https://rich.readthedocs.io/en/latest/tables.html
- Progress: https://rich.readthedocs.io/en/latest/progress.html
- Panels: https://rich.readthedocs.io/en/latest/panel.html

### Terminal UI Best Practices
- Clear visual hierarchy
- Consistent patterns across application
- Provide feedback for all operations
- Support both keyboard and mouse when possible
- Graceful degradation for simple terminals

### Testing Resources
- Rich console testing: Use `Console(file=StringIO())`
- Mock user input: Override `builtins.input`
- Snapshot testing: Capture output and compare
