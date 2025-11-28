#!/usr/bin/env python3
"""
wg-friend - Unified WireGuard Network Manager

Single entry point that detects state and routes to appropriate mode:
- No database: Onboard mode (import configs or create new network)
- Has database: Maintenance mode (manage peers, deploy, etc.)
"""

import sys
import os
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm

# Version info - updated by build/release process
__version__ = "0.1.0"
__build_date__ = "dev"

console = Console()

# Default paths
DEFAULT_DB_NAME = "wg-friend.db"
DEFAULT_IMPORT_DIR = "import"
DEFAULT_OUTPUT_DIR = "output"


def get_data_dir() -> Path:
    """Get the data directory for wg-friend.

    Uses current working directory for now.
    Could later support XDG_DATA_HOME or ~/.wg-friend/
    """
    return Path.cwd()


def find_database() -> Path | None:
    """Find existing wg-friend database."""
    data_dir = get_data_dir()
    db_path = data_dir / DEFAULT_DB_NAME

    if db_path.exists():
        return db_path

    return None


def check_for_update() -> tuple[bool, str | None]:
    """Check if a newer version is available.

    Returns:
        (update_available, latest_version)
    """
    try:
        import urllib.request
        import json

        # Check GitHub releases API
        url = "https://api.github.com/repos/graemester/wireguard-friend/releases/latest"
        req = urllib.request.Request(url, headers={"User-Agent": "wg-friend"})

        with urllib.request.urlopen(req, timeout=3) as response:
            data = json.loads(response.read().decode())
            latest = data.get("tag_name", "").lstrip("v")

            if latest and latest != __version__:
                return True, latest

    except Exception:
        # Silently fail - network issues, rate limits, etc.
        pass

    return False, None


def self_update() -> bool:
    """Download and install the latest version.

    Returns:
        True if update successful
    """
    try:
        import urllib.request
        import json
        import tempfile
        import platform
        import stat

        console.print("[cyan]Checking for updates...[/cyan]")

        # Get latest release info
        url = "https://api.github.com/repos/graemester/wireguard-friend/releases/latest"
        req = urllib.request.Request(url, headers={"User-Agent": "wg-friend"})

        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode())

        latest_version = data.get("tag_name", "").lstrip("v")

        if not latest_version:
            console.print("[red]Could not determine latest version[/red]")
            return False

        if latest_version == __version__:
            console.print(f"[green]Already on latest version ({__version__})[/green]")
            return True

        console.print(f"[yellow]New version available: {latest_version} (current: {__version__})[/yellow]")

        # Determine which asset to download
        system = platform.system().lower()
        machine = platform.machine().lower()

        if machine in ("x86_64", "amd64"):
            arch = "x86_64"
        elif machine in ("arm64", "aarch64"):
            arch = "arm64"
        else:
            console.print(f"[red]Unsupported architecture: {machine}[/red]")
            return False

        asset_name = f"wg-friend-{system}-{arch}"
        if system == "windows":
            asset_name += ".exe"

        # Find the asset
        asset_url = None
        for asset in data.get("assets", []):
            if asset["name"] == asset_name:
                asset_url = asset["browser_download_url"]
                break

        if not asset_url:
            console.print(f"[red]No binary available for {system}-{arch}[/red]")
            console.print("[yellow]Available assets:[/yellow]")
            for asset in data.get("assets", []):
                console.print(f"  - {asset['name']}")
            return False

        # Download
        console.print(f"[cyan]Downloading {asset_name}...[/cyan]")

        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            req = urllib.request.Request(asset_url, headers={"User-Agent": "wg-friend"})
            with urllib.request.urlopen(req, timeout=60) as response:
                tmp.write(response.read())
            tmp_path = tmp.name

        # Get current executable path
        current_exe = Path(sys.executable)
        if current_exe.name == "python" or current_exe.name.startswith("python"):
            # Running from Python, not a binary
            console.print("[yellow]Self-update only works with compiled binary[/yellow]")
            console.print(f"[yellow]Download manually from: {asset_url}[/yellow]")
            os.unlink(tmp_path)
            return False

        # Replace current executable
        console.print("[cyan]Installing update...[/cyan]")

        backup_path = current_exe.with_suffix(".backup")

        try:
            # Backup current
            if backup_path.exists():
                backup_path.unlink()
            current_exe.rename(backup_path)

            # Move new binary
            Path(tmp_path).rename(current_exe)

            # Make executable
            current_exe.chmod(current_exe.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

            # Remove backup
            backup_path.unlink()

            console.print(f"[green]Updated to version {latest_version}![/green]")
            console.print("[yellow]Please restart wg-friend[/yellow]")
            return True

        except Exception as e:
            # Restore backup
            if backup_path.exists() and not current_exe.exists():
                backup_path.rename(current_exe)
            console.print(f"[red]Update failed: {e}[/red]")
            return False

    except Exception as e:
        console.print(f"[red]Update check failed: {e}[/red]")
        return False


def show_welcome():
    """Show welcome banner."""
    console.print(Panel.fit(
        f"[bold cyan]WireGuard Friend[/bold cyan] v{__version__}\n"
        "Manage your WireGuard VPN network",
        border_style="cyan"
    ))


def run_onboard_mode(db_path: Path, import_dir: Path):
    """Run onboarding/import mode."""
    # Import dynamically to handle both development and binary modes
    import importlib.util
    import os

    # Try to find the module
    script_dir = Path(__file__).parent.parent  # Go up from src/ to repo root

    # For PyInstaller, modules are bundled
    try:
        # Try direct import first (works in PyInstaller bundle)
        from wg_friend_onboard import WireGuardOnboarder
    except ImportError:
        # Development mode - load from file
        spec = importlib.util.spec_from_file_location(
            "wg_friend_onboard",
            script_dir / "wg-friend-onboard.py"
        )
        module = importlib.util.module_from_spec(spec)
        sys.modules["wg_friend_onboard"] = module
        spec.loader.exec_module(module)
        WireGuardOnboarder = module.WireGuardOnboarder

    onboarder = WireGuardOnboarder(import_dir, db_path, auto_confirm=False)
    onboarder.run()


def run_maintenance_mode(db_path: Path):
    """Run maintenance mode."""
    import importlib.util

    script_dir = Path(__file__).parent.parent

    try:
        from wg_friend_maintain import WireGuardMaintainer
    except ImportError:
        spec = importlib.util.spec_from_file_location(
            "wg_friend_maintain",
            script_dir / "wg-friend-maintain.py"
        )
        module = importlib.util.module_from_spec(spec)
        sys.modules["wg_friend_maintain"] = module
        spec.loader.exec_module(module)
        WireGuardMaintainer = module.WireGuardMaintainer

    maintainer = WireGuardMaintainer(db_path)
    maintainer.run()


def main():
    """Main entry point."""
    # Handle special commands
    if len(sys.argv) > 1:
        cmd = sys.argv[1].lower()

        if cmd in ("--version", "-v", "version"):
            console.print(f"wg-friend {__version__}")
            sys.exit(0)

        if cmd in ("--update", "update"):
            self_update()
            sys.exit(0)

        if cmd in ("--help", "-h", "help"):
            show_welcome()
            console.print("\n[bold]Usage:[/bold]")
            console.print("  wg-friend              Launch interactive mode")
            console.print("  wg-friend --version    Show version")
            console.print("  wg-friend --update     Update to latest version")
            console.print("  wg-friend --help       Show this help")
            console.print("\n[bold]How it works:[/bold]")
            console.print("  • First run: Import existing WireGuard configs or create new network")
            console.print("  • After setup: Manage peers, rotate keys, deploy configs")
            console.print("\n[bold]Files:[/bold]")
            console.print(f"  • Database: ./{DEFAULT_DB_NAME}")
            console.print(f"  • Import configs from: ./{DEFAULT_IMPORT_DIR}/")
            console.print(f"  • Exported configs: ./{DEFAULT_OUTPUT_DIR}/")
            sys.exit(0)

    show_welcome()

    # Check for updates (non-blocking)
    update_available, latest_version = check_for_update()
    if update_available:
        console.print(f"[yellow]Update available: v{latest_version} (run 'wg-friend --update')[/yellow]\n")

    # Detect state
    data_dir = get_data_dir()
    db_path = data_dir / DEFAULT_DB_NAME
    import_dir = data_dir / DEFAULT_IMPORT_DIR

    if db_path.exists():
        # Database exists - maintenance mode
        console.print(f"[dim]Using database: {db_path}[/dim]\n")
        run_maintenance_mode(db_path)
    else:
        # No database - onboard mode
        console.print("[dim]No database found - starting setup[/dim]\n")
        run_onboard_mode(db_path, import_dir)


if __name__ == "__main__":
    main()
