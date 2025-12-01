"""
Built-in Documentation System

Provides a man-page style help system with content loading hierarchy:
1. Online fetch from GitHub (always up-to-date)
2. Local file in repo (for development/offline)
3. Embedded fallback (binary self-contained)
"""

import sys
import urllib.request
import urllib.error
from pathlib import Path
from typing import Optional, List, Tuple

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

# Rich imports
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.text import Text
    from rich.markdown import Markdown
    from rich import box
    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False
    console = None


# =============================================================================
# CONTENT LOADING (Online -> Local -> Embedded)
# =============================================================================

GITHUB_RAW_BASE = "https://raw.githubusercontent.com/graemester/wireguard-friend/main/v1/docs/help"
LOCAL_HELP_DIR = Path(__file__).parent.parent / "docs" / "help"

# Topics that have external files (others use embedded only)
EXTERNAL_TOPICS = {"about"}


def load_external_content(topic_key: str) -> Optional[str]:
    """
    Try to load content from external source.

    Order: GitHub raw -> Local file -> None (use embedded)
    """
    if topic_key not in EXTERNAL_TOPICS:
        return None

    filename = f"{topic_key}.txt"

    # Try GitHub first (2 second timeout)
    try:
        url = f"{GITHUB_RAW_BASE}/{filename}"
        with urllib.request.urlopen(url, timeout=2) as response:
            content = response.read().decode('utf-8')
            if content.strip():
                return content
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError):
        pass  # Fall through to local file

    # Try local file
    local_path = LOCAL_HELP_DIR / filename
    if local_path.exists():
        try:
            return local_path.read_text()
        except IOError:
            pass  # Fall through to embedded

    return None  # Use embedded fallback


def generate_sysinfo() -> str:
    """Generate dynamic system information content."""
    import os
    import platform
    import sqlite3

    # Get version info from tui module
    try:
        from v1.cli.tui import VERSION, BUILD_NAME
    except ImportError:
        VERSION = "unknown"
        BUILD_NAME = "unknown"

    lines = []
    lines.append("")

    # Version
    lines.append("VERSION")
    lines.append("-------")
    lines.append(f"  WireGuard Friend: v{VERSION}")
    lines.append(f"  Build Name: {BUILD_NAME}")
    lines.append("")

    # Environment
    lines.append("ENVIRONMENT")
    lines.append("-----------")
    lines.append(f"  Working Directory: {os.getcwd()}")

    # Find database
    db_path = None
    for candidate in ['wireguard.db', './wireguard.db']:
        if os.path.exists(candidate):
            db_path = os.path.abspath(candidate)
            break
    if db_path:
        db_size = os.path.getsize(db_path)
        if db_size > 1024 * 1024:
            size_str = f"{db_size / 1024 / 1024:.1f} MB"
        elif db_size > 1024:
            size_str = f"{db_size / 1024:.1f} KB"
        else:
            size_str = f"{db_size} bytes"
        lines.append(f"  Database: {db_path}")
        lines.append(f"  Database Size: {size_str}")
    else:
        lines.append("  Database: (not found in current directory)")
    lines.append("")

    # Python info
    lines.append("PYTHON")
    lines.append("------")
    lines.append(f"  Version: {platform.python_version()}")
    lines.append(f"  Implementation: {platform.python_implementation()}")
    lines.append(f"  Executable: {sys.executable}")
    lines.append("")

    # Platform
    lines.append("PLATFORM")
    lines.append("--------")
    lines.append(f"  System: {platform.system()}")
    lines.append(f"  Release: {platform.release()}")
    lines.append(f"  Machine: {platform.machine()}")
    lines.append("")

    # Dependencies
    lines.append("DEPENDENCIES")
    lines.append("------------")

    deps = [
        ("rich", "Terminal UI"),
        ("nacl", "Cryptography (PyNaCl)"),
        ("qrcode", "QR code generation"),
        ("paramiko", "SSH deployment"),
    ]

    for module_name, description in deps:
        try:
            mod = __import__(module_name)
            version = getattr(mod, '__version__', 'installed')
            lines.append(f"  {description}: {version}")
        except ImportError:
            lines.append(f"  {description}: (not installed)")

    # SQLite version
    lines.append(f"  SQLite: {sqlite3.sqlite_version}")
    lines.append("")

    # Get coordination server endpoint for connectivity test
    cs_endpoint = None
    if db_path and os.path.exists(db_path):
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT endpoint FROM coordination_server WHERE id = 1")
            row = cursor.fetchone()
            cs_endpoint = row[0] if row else None
            conn.close()
        except:
            pass

    # Connectivity tests
    import socket

    lines.append("CONNECTIVITY")
    lines.append("------------")

    def test_connection(host: str, port: int, timeout: float = 2.0) -> tuple:
        """Test TCP connection, return (success, latency_ms or error)"""
        import time
        try:
            start = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            latency = (time.time() - start) * 1000
            sock.close()
            return True, f"{latency:.0f}ms"
        except socket.timeout:
            return False, "timeout"
        except socket.gaierror:
            return False, "DNS failed"
        except Exception as e:
            return False, str(e)[:20]

    # Test Cloudflare (HTTPS port)
    ok, result = test_connection("1.1.1.1", 443)
    status = f"OK ({result})" if ok else f"FAILED ({result})"
    lines.append(f"  Cloudflare (1.1.1.1:443): {status}")

    # Test coordination server with ICMP ping
    if cs_endpoint:
        # Parse endpoint (might be hostname:port or just hostname)
        if ':' in cs_endpoint:
            host = cs_endpoint.rsplit(':', 1)[0]
        else:
            host = cs_endpoint

        # ICMP ping test
        import subprocess
        try:
            result = subprocess.run(
                ['ping', '-c', '1', '-W', '2', host],
                capture_output=True,
                text=True,
                timeout=3
            )
            if result.returncode == 0:
                # Parse time from output (e.g., "time=45.3 ms")
                import re
                match = re.search(r'time[=<](\d+\.?\d*)', result.stdout)
                if match:
                    latency = match.group(1)
                    lines.append(f"  Coordination Server ({host}): OK ({latency}ms)")
                else:
                    lines.append(f"  Coordination Server ({host}): OK")
            else:
                lines.append(f"  Coordination Server ({host}): NO RESPONSE")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            lines.append(f"  Coordination Server ({host}): TIMEOUT")
    else:
        lines.append("  Coordination Server: (not configured)")

    lines.append("")

    return "\n".join(lines)


def get_content(topic_key: str) -> str:
    """Get content for a topic, trying external sources first."""
    # Dynamic content
    if topic_key == "sysinfo":
        return generate_sysinfo()

    external = load_external_content(topic_key)
    if external:
        return external
    return CONTENT.get(topic_key, "Content not found.")


# =============================================================================
# DOCUMENTATION CONTENT (Embedded Fallbacks)
# =============================================================================

TOPICS = [
    ("Quick Start", "quickstart"),
    ("Network Concepts", "concepts"),
    ("Adding & Managing Peers", "peers"),
    ("Key Rotation & Security", "security"),
    ("Deploying Configs", "deploy"),
    ("Extramural (Commercial VPNs)", "extramural"),
    ("Troubleshooting", "troubleshooting"),
    ("Diagnostics", "sysinfo"),
    ("About & Links", "about"),
]

# Topics with dynamic content (generated at runtime)
DYNAMIC_TOPICS = {"sysinfo"}

CONTENT = {
    "quickstart": """
QUICK START
===========

WireGuard Friend manages WireGuard VPN configurations using a SQLite
database. It supports hub-and-spoke networks with a central coordination
server, subnet routers for LAN access, and remote clients.


FIRST RUN - NEW NETWORK
-----------------------

  1. Run: wg-friend
  2. Choose "Initialize new network" when prompted
  3. Enter your coordination server details:
     - Public endpoint (e.g., vps.example.com)
     - Listen port (default: 51820)
     - VPN network ranges (e.g., 10.66.0.0/24)
  4. Add subnet routers if you have LANs to expose
  5. Add remote clients (phones, laptops, etc.)
  6. Generate configs: Menu option 7
  7. Deploy to servers: Menu option 8


FIRST RUN - EXISTING NETWORK
----------------------------

If you already have WireGuard configs:

  1. Place your coordination server config in ./import/
  2. Run: wg-friend
  3. Choose "Import existing configs"
  4. The importer auto-detects:
     - Coordination server (has ListenPort + multiple peers)
     - Subnet routers (has PostUp with forwarding)
     - Remote clients (simple peer configs)


TYPICAL WORKFLOW
----------------

  Adding a new device:
    1. Menu: Add Peer
    2. Enter hostname, device type, access level
    3. Menu: Generate Configs
    4. Menu: Deploy Configs (to coordination server)
    5. Give the .conf file or QR code to the user

  Revoking access:
    1. Menu: Remove Peer
    2. Select the peer to remove
    3. Menu: Generate Configs
    4. Menu: Deploy Configs

  Key rotation:
    1. Menu: Rotate Keys
    2. Select the entity to rotate
    3. Menu: Generate Configs
    4. Menu: Deploy Configs
""",

    "concepts": """
NETWORK CONCEPTS
================

WireGuard Friend uses a hub-and-spoke topology with three entity types:


COORDINATION SERVER (CS)
------------------------

The central hub of your VPN network.

  - Runs on a cloud VPS with a public IP
  - All peers connect TO this server
  - Routes traffic between peers
  - Has a static endpoint (e.g., vps.example.com:51820)
  - Typically the only peer with ListenPort configured

  Database: Single row in coordination_server table
  Config: /etc/wireguard/wg0.conf on your VPS


SUBNET ROUTERS
--------------

Gateway devices that expose local networks to the VPN.

  - Run on your LAN (home, office, etc.)
  - Advertise local network ranges (e.g., 192.168.1.0/24)
  - Have PostUp/PostDown rules for NAT and forwarding
  - Connect TO the coordination server
  - Allow VPN peers to access LAN resources

  Example: A Raspberry Pi at home running WireGuard, allowing
  you to access your NAS, printer, or home automation.

  Database: subnet_router table + advertised_network table


REMOTE CLIENTS
--------------

Individual devices that connect to the VPN.

  - Phones, laptops, tablets, friend's computers
  - Connect TO the coordination server
  - Have configurable access levels:

    full_access  - Route all traffic through VPN + access all LANs
    vpn_only     - Only access VPN network (10.66.0.0/24)
    lan_only     - Access VPN + specific LANs only
    custom       - User-defined AllowedIPs

  Database: remote table


TOPOLOGY DIAGRAM
----------------

                    INTERNET
                        |
            +-----------+-----------+
            |                       |
    +-------+-------+       +-------+-------+
    | Coordination  |       |    Remote     |
    |    Server     |       |    Clients    |
    | (Cloud VPS)   |       | (Anywhere)    |
    +-------+-------+       +---------------+
            |
    +-------+-------+
    | Subnet Router |
    | (Your LAN)    |
    +-------+-------+
            |
    +-------+-------+
    |  LAN Devices  |
    | NAS, Printer  |
    +---------------+
""",

    "peers": """
ADDING & MANAGING PEERS
=======================


ADDING A REMOTE CLIENT
----------------------

Menu: Add Peer > Add Remote Client

You'll be prompted for:
  - Hostname: Unique name (e.g., alice-phone, bob-laptop)
  - Device type: mobile, laptop, desktop, server
  - Access level: full_access, vpn_only, lan_only, custom

The system automatically:
  - Assigns the next available VPN IP
  - Generates a new keypair
  - Creates a permanent GUID for tracking


ADDING A SUBNET ROUTER
----------------------

Menu: Add Peer > Add Subnet Router

You'll be prompted for:
  - Hostname: Unique name (e.g., home-gateway, office-router)
  - LAN networks to advertise (e.g., 192.168.1.0/24)
  - LAN interface (e.g., eth0, br0)
  - Endpoint (if it has a static IP)

PostUp/PostDown rules are auto-generated for:
  - IP forwarding
  - NAT masquerading
  - MSS clamping


MANAGE PEERS (DRILL-DOWN)
-------------------------

Menu: Manage Peers

This provides an entity-centered view:
  1. See all peers grouped by type
  2. Select any peer to view full details
  3. Access contextual actions:
     - Rotate Keys
     - View Key History
     - Generate Config
     - Deploy Config
     - Change Access Level (remotes only)
     - Generate QR Code (remotes only)
     - Remove Peer


REMOVING A PEER
---------------

Menu: Remove Peer

  1. Select peer type (router or remote)
  2. Select the peer to remove
  3. Enter a reason (for audit trail)
  4. Type the hostname to confirm

The removal is logged in key_rotation_history.
Remember to regenerate and deploy configs afterward.


ACCESS LEVELS EXPLAINED
-----------------------

  full_access:
    AllowedIPs = 0.0.0.0/0, ::/0
    All traffic routes through VPN, access to all LANs.
    Best for: Administrators, trusted devices.

  vpn_only:
    AllowedIPs = 10.66.0.0/24, fd66::/64
    Only VPN network accessible, no LAN access.
    Best for: Contractors, temporary access.

  lan_only:
    AllowedIPs = 10.66.0.0/24, 192.168.1.0/24
    VPN network + specific LANs only.
    Best for: Remote workers needing LAN resources.

  custom:
    AllowedIPs = (user defined)
    Fully customizable routing.
    Best for: Special cases, split tunneling.
""",

    "security": """
KEY ROTATION & SECURITY
=======================


WHY ROTATE KEYS?
----------------

  - Limit exposure if a key is compromised
  - Comply with security policies
  - Revoke access from specific devices
  - Best practice: rotate monthly or quarterly


HOW KEY ROTATION WORKS
----------------------

Each entity has two key identifiers:

  permanent_guid:
    - Set when entity is first created
    - NEVER changes, even after rotation
    - Used for tracking and audit trails
    - Links comments and history to the entity

  current_public_key:
    - The active public key
    - Changes on each rotation
    - Used in WireGuard configs


ROTATING KEYS
-------------

Menu: Rotate Keys

  1. Select entity type (CS, router, or remote)
  2. Select the specific entity
  3. Enter a reason for the rotation
  4. Confirm the rotation

After rotation:
  - New keypair is generated
  - Old key is logged in history
  - Database is updated
  - You MUST regenerate and deploy configs


VIEWING KEY HISTORY
-------------------

Menu: History > Key Rotation History

Or from Manage Peers > [peer] > View Key History

Shows:
  - Timestamp of each rotation
  - Old and new public keys
  - Reason for rotation
  - Entity permanent_guid


PRESHARED KEYS (PSK)
--------------------

WireGuard supports preshared keys for additional security
(post-quantum resistance). Each peer can have a PSK that
is used in addition to the Curve25519 key exchange.

PSKs are stored in the database and included in generated
configs automatically.


SECURITY BEST PRACTICES
-----------------------

  1. Protect the database file (wireguard.db)
     - Contains private keys
     - Set restrictive permissions: chmod 600

  2. Rotate keys regularly
     - Monthly for high-security environments
     - Quarterly for typical use

  3. Use access levels appropriately
     - Don't give full_access to everyone
     - Use vpn_only for temporary access

  4. Review peer list periodically
     - Remove unused/unknown devices
     - Audit access levels

  5. Keep backups
     - Database contains all config data
     - Backup before major changes
""",

    "deploy": """
DEPLOYING CONFIGS
=================


GENERATE CONFIGS
----------------

Menu: Generate Configs

Creates .conf files for all entities:
  - generated/coordination.conf
  - generated/[router-hostname].conf
  - generated/[remote-hostname].conf
  - generated/[remote-hostname].png (QR codes for mobile)

Files are created with 600 permissions (owner read/write only).


DEPLOY VIA SSH
--------------

Menu: Deploy Configs

Deploys configs to servers that have SSH credentials configured:
  - Coordination server
  - Subnet routers with endpoints

Deployment process:
  1. Backup existing config (timestamped)
  2. Upload new config via SCP
  3. Optionally restart WireGuard

Requirements:
  - SSH key authentication (password auth not supported)
  - Root access or sudo permissions
  - WireGuard installed on target


CONFIGURING SSH ACCESS
----------------------

When adding a coordination server or subnet router, you can
specify SSH credentials:
  - SSH host (can differ from WireGuard endpoint)
  - SSH user (default: root)
  - SSH port (default: 22)

For key-based auth:
  1. Generate SSH key: ssh-keygen -t ed25519
  2. Copy to server: ssh-copy-id user@server
  3. Test: ssh user@server


DRY RUN MODE
------------

Menu: Deploy Configs > Dry Run

Shows what would be deployed without making changes:
  - Lists target hosts
  - Shows config file paths
  - Displays commands that would run

Use this to verify before actual deployment.


MANUAL DEPLOYMENT
-----------------

If SSH deployment isn't suitable, manually copy configs:

  # To coordination server
  scp generated/coordination.conf root@vps:/etc/wireguard/wg0.conf
  ssh root@vps "wg-quick down wg0; wg-quick up wg0"

  # To subnet router
  scp generated/home-router.conf root@router:/etc/wireguard/wg0.conf
  ssh root@router "wg-quick down wg0; wg-quick up wg0"

  # For mobile devices
  # Show QR code or transfer .conf file
""",

    "extramural": """
EXTRAMURAL CONFIGS
==================

"Extramural" means outside the walls - configs from external
VPN providers like Mullvad, ProtonVPN, IVPN, etc.

These are separate from your mesh network and managed in
their own database.


WHY EXTRAMURAL?
---------------

  - Keep commercial VPN configs organized
  - Switch between server locations easily
  - Track which device uses which config
  - Manage multiple providers


IMPORTING A CONFIG
------------------

Menu: Extramural > Import Config

  1. Provide path to .conf file from your provider
  2. Enter sponsor name (e.g., "Mullvad VPN")
  3. Enter local peer name (your device)
  4. Optionally add interface name

The config is parsed and stored:
  - Private/public keys
  - Server endpoint
  - DNS settings
  - AllowedIPs


MANAGING CONFIGS
----------------

Menu: Extramural

Options:
  - List all configs
  - View config details
  - Switch active server
  - Generate .conf file
  - Import new config


SWITCHING SERVERS
-----------------

Many VPN providers give you multiple server configs
(US, EU, Asia, etc.). Import multiple configs from the
same sponsor, then switch between them:

  1. Import us-server.conf (Mullvad, my-laptop)
  2. Import eu-server.conf (Mullvad, my-laptop)
  3. Menu: Extramural > Switch Server
  4. Select which server to make active


SPONSORS VS LOCAL PEERS
-----------------------

  Sponsor:
    The VPN provider (Mullvad, ProtonVPN, etc.)
    Has server endpoints you connect to.

  Local Peer:
    Your device (my-laptop, my-phone, etc.)
    Gets assigned an IP by the provider.

One local peer can have configs from multiple sponsors.
One sponsor can have configs for multiple local peers.
""",

    "troubleshooting": """
TROUBLESHOOTING
===============


CONNECTION ISSUES
-----------------

Peer can't connect:
  1. Check endpoint is correct and reachable
  2. Verify port 51820 is open (UDP)
  3. Ensure public keys match on both ends
  4. Check AllowedIPs includes the peer's IP
  5. Verify PersistentKeepalive is set (for NAT)

Can't reach LAN resources:
  1. Verify subnet router is connected
  2. Check IP forwarding is enabled
  3. Verify NAT/masquerade rules in PostUp
  4. Ensure AllowedIPs includes the LAN range


DATABASE ISSUES
---------------

"Database not found":
  - Run from the directory containing wireguard.db
  - Or specify: wg-friend --db /path/to/wireguard.db

"Database is locked":
  - Another process may be using it
  - Close other wg-friend instances
  - Check for zombie processes

Corrupted database:
  - Restore from backup
  - Or reimport configs: wg-friend import


CONFIG GENERATION ISSUES
------------------------

"No coordination server found":
  - Initialize first: wg-friend init
  - Or import: wg-friend import

Missing PostUp/PostDown rules:
  - Re-import the coordination server config
  - Or manually edit the database

Wrong AllowedIPs:
  - Check access_level setting for the peer
  - Verify advertised networks on routers


DEPLOYMENT ISSUES
-----------------

SSH connection failed:
  - Verify SSH key is installed on target
  - Check SSH host, user, port settings
  - Test manually: ssh user@host

Permission denied:
  - Need root or sudo access
  - Check /etc/wireguard permissions

WireGuard restart failed:
  - Check config syntax: wg-quick up wg0
  - Look for errors in syslog


GETTING HELP
------------

Check the GitHub repository for:
  - Issue tracker
  - Latest documentation
  - Example configurations

See: About & Links (topic 8)
""",

    "about": """
ABOUT WIREGUARD FRIEND
======================

Version: See main menu banner
License: MIT


PROJECT LINKS
-------------

  GitHub Repository:
    https://github.com/graemester/wireguard-friend

  Issues & Bug Reports:
    https://github.com/graemester/wireguard-friend/issues

  Documentation:
    https://github.com/graemester/wireguard-friend/tree/main/v1/docs


WHAT IS WIREGUARD?
------------------

WireGuard is a modern VPN protocol that is:
  - Fast and lightweight
  - Cryptographically sound
  - Easy to configure
  - Cross-platform

Learn more: https://www.wireguard.com/


CREDITS
-------

WireGuard Friend is built with:
  - Python 3.8+
  - SQLite for data storage
  - Rich for terminal UI
  - PyInstaller for binary distribution


PHILOSOPHY
----------

WireGuard Friend aims to be:
  - Self-contained (single binary, embedded docs)
  - Database-driven (queryable, auditable)
  - Non-destructive (backups before changes)
  - Transparent (show what's happening)


CONTRIBUTING
------------

Contributions welcome! See the GitHub repository for:
  - Development setup
  - Code style guidelines
  - Testing procedures
""",
}


# =============================================================================
# DISPLAY FUNCTIONS
# =============================================================================

def show_topic_list():
    """Display the list of help topics (in alternate screen)"""
    if RICH_AVAILABLE:
        # Build menu content matching main menu style
        menu_lines = []
        for i, (title, _) in enumerate(TOPICS, 1):
            menu_lines.append(f"  [cyan]{i}.[/cyan] {title}")
        menu_lines.append(f"  [dim]q. Back to Main Menu[/dim]")

        console.clear()
        print("\033[H", end="")  # Cursor to home position
        console.print()
        console.print(Panel(
            "\n".join(menu_lines),
            title="[bold]DOCUMENTATION[/bold]",
            title_align="left",
            border_style="cyan",
            padding=(1, 2)
        ))
        console.print()
        print("  Select: ", end="", flush=True)
    else:
        print("\033[2J\033[H", end="")  # Clear screen, cursor home
        print("=" * 70)
        print("DOCUMENTATION")
        print("=" * 70)
        for i, (title, _) in enumerate(TOPICS, 1):
            print(f"  {i}. {title}")
        print(f"  q. Back to Main Menu")
        print()
        print("  Select: ", end="", flush=True)


def enter_alternate_screen():
    """Enter terminal alternate screen buffer"""
    print("\033[?1049h", end="", flush=True)


def exit_alternate_screen():
    """Exit terminal alternate screen buffer"""
    print("\033[?1049l", end="", flush=True)


def get_terminal_size() -> Tuple[int, int]:
    """Get terminal dimensions (width, height)"""
    import shutil
    size = shutil.get_terminal_size((80, 24))
    return size.columns, size.lines


def getch() -> str:
    """Read a single keypress without waiting for Enter"""
    import sys
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


def show_topic_content(topic_key: str, topic_title: str):
    """Display the content of a specific topic (already in alternate screen)"""
    content = get_content(topic_key)
    lines = content.strip().split('\n')

    total_lines = len(lines)
    current_line = 0

    while current_line < total_lines:
        # Get terminal size for dynamic page sizing
        term_width, term_height = get_terminal_size()
        # Reserve lines for: title bar, bottom border, nav line, input prompt
        page_size = term_height - 6

        # Get current page
        page_lines = lines[current_line:current_line + page_size]

        # Pad to fill screen
        while len(page_lines) < page_size:
            page_lines.append("")

        page_content = '\n'.join(page_lines)

        # Calculate progress
        end_line = min(current_line + page_size, total_lines)
        progress = f"Lines {current_line + 1}-{end_line} of {total_lines}"

        # Determine if more pages
        has_more = end_line < total_lines

        if RICH_AVAILABLE:
            console.clear()
            console.print(Panel(
                page_content,
                title=f"[bold]{topic_title}[/bold]",
                title_align="left",
                subtitle=f"[dim]{progress}[/dim]",
                border_style="green",
                padding=(0, 2),
                height=term_height - 2
            ))

            if has_more:
                nav_text = "  [dim]Space/Enter: next | -: prev | B: back | Q: quit[/dim]"
            else:
                nav_text = "  [dim]Enter/B: back to topics | Q: quit[/dim]"
            console.print(nav_text, end="", highlight=False)
        else:
            print("\033[2J\033[H", end="")  # Clear screen, cursor home
            print("=" * 70)
            print(f"{topic_title}  ({progress})")
            print("=" * 70)
            print(page_content)
            print("-" * 70)
            if has_more:
                print("  Space/Enter: next | -: prev | B: back | Q: quit", end="")
            else:
                print("  Enter/B: back to topics | Q: quit", end="")

        # Get single keypress
        sys.stdout.flush()
        ch = getch()

        if ch.lower() == 'b':
            return 'back'
        elif ch.lower() == 'q':
            return 'quit'
        elif ch in ('\r', '\n', ' ', 'n', 'N'):
            # Next page: Enter, Space, n
            if has_more:
                current_line += page_size
            else:
                return 'back'
        elif ch in ('-', 'p', 'P'):
            # Previous page: minus, p
            if current_line > 0:
                current_line = max(0, current_line - page_size)
            # else stay on first page
        elif ch == '\x03':
            # Ctrl+C
            return 'quit'
        else:
            # Unknown input, go next if possible
            if has_more:
                current_line += page_size
            else:
                return 'back'

    return 'back'


def documentation_menu():
    """Main documentation menu loop - runs in alternate screen"""
    enter_alternate_screen()

    try:
        while True:
            show_topic_list()

            # Get single keypress
            sys.stdout.flush()
            ch = getch()

            # Exit on q, Escape, or Ctrl+C
            if ch.lower() in ('q', '\x1b', '\x03'):
                return

            # Try to parse as topic number (1-9)
            if ch.isdigit():
                topic_num = int(ch)
                if 1 <= topic_num <= len(TOPICS):
                    title, key = TOPICS[topic_num - 1]
                    result = show_topic_content(key, title)
                    if result == 'quit':
                        return
                    # 'back' continues the loop
            # Enter goes back to main menu
            elif ch in ('\r', '\n'):
                return
    finally:
        exit_alternate_screen()


if __name__ == '__main__':
    # Test the documentation system
    documentation_menu()
