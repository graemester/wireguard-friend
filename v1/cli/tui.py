"""
Interactive TUI - Text-based User Interface

Provides an interactive menu-driven interface for managing WireGuard network.
"""

import sys
from pathlib import Path
from typing import List, Dict, Optional

# Version info (keep in sync with wg-friend)
VERSION = "1.0.4"
BUILD_NAME = "griffin"

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

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

from v1.schema_semantic import WireGuardDBv2
from v1.cli.peer_manager import add_remote, add_router, list_peers, rotate_keys, remove_peer
from v1.cli.status import show_network_overview, show_recent_rotations, show_state_history, show_entity_history


def print_menu(title: str, options: List[str], include_quit: bool = True):
    """Print a menu with Rich styling if available"""
    if RICH_AVAILABLE:
        # Build menu content
        menu_lines = []
        for i, option in enumerate(options, 1):
            menu_lines.append(f"  [cyan]{i}.[/cyan] {option}")
        if include_quit:
            menu_lines.append(f"  [dim]q. Quit[/dim]")

        console.print()
        console.print(Panel(
            "\n".join(menu_lines),
            title=f"[bold]{title}[/bold]",
            border_style="cyan",
            padding=(1, 2)
        ))
        console.print()
    else:
        # Fallback to plain text
        print(f"\n{'=' * 70}")
        print(f"{title}")
        print(f"{'=' * 70}")
        for i, option in enumerate(options, 1):
            print(f"  {i}. {option}")
        if include_quit:
            print(f"  q. Quit")
        print()


def get_menu_choice(max_choice: int, allow_quit: bool = True, default_back: bool = False) -> Optional[int]:
    """
    Get menu choice from user.

    Args:
        max_choice: Maximum valid choice number
        allow_quit: Whether 'q' is valid (for main menu)
        default_back: If True, empty input returns max_choice (back option)
                     If False with allow_quit, empty input returns None (quit)

    Returns:
        Choice number, None for quit, or max_choice for back
    """
    while True:
        choice = input("Choice: ").strip().lower()

        # Handle empty input (Enter key)
        if not choice:
            if default_back:
                return max_choice  # Return the "Back" option
            elif allow_quit:
                return None  # Quit

        if allow_quit and choice in ('q', 'quit', 'exit'):
            return None

        try:
            choice_int = int(choice)
            if 1 <= choice_int <= max_choice:
                return choice_int
            print(f"  Invalid choice. Enter 1-{max_choice} or 'q' to quit.")
        except ValueError:
            print(f"  Invalid choice. Enter 1-{max_choice} or 'q' to quit.")


def main_menu(db: WireGuardDBv2, db_path: str = 'wireguard.db') -> bool:
    """
    Display main menu and handle user choice.

    Returns:
        True to continue, False to exit
    """
    print_menu(
        f"WIREGUARD FRIEND v{VERSION} ({BUILD_NAME})",
        [
            "Network Status",
            "List All Peers",
            "Add Peer",
            "Remove Peer",
            "Rotate Keys",
            "History",
            "Extramural (external VPNs)",
            "Generate Configs",
            "Deploy Configs",
        ]
    )

    choice = get_menu_choice(9)
    if choice is None:
        return False

    if choice == 1:
        # Network Status
        show_network_overview(db)
        input("\nPress Enter to continue...")

    elif choice == 2:
        # List All Peers
        list_peers(db)
        input("\nPress Enter to continue...")

    elif choice == 3:
        # Add Peer
        peer_type_menu(db)

    elif choice == 4:
        # Remove Peer
        remove_peer_menu(db)

    elif choice == 5:
        # Rotate Keys
        rotate_keys_menu(db)

    elif choice == 6:
        # History submenu
        history_menu(db, db_path)

    elif choice == 7:
        # Extramural configs
        extramural_menu(db_path)

    elif choice == 8:
        # Generate Configs
        generate_configs_menu(db, db_path)

    elif choice == 9:
        # Deploy Configs
        deploy_configs_menu(db, db_path)

    return True


def peer_type_menu(db: WireGuardDBv2):
    """Menu for adding peers"""
    print_menu(
        "ADD PEER",
        [
            "Add Remote Client (phone, laptop, etc.)",
            "Add Subnet Router (LAN gateway)",
            "Back to Main Menu",
        ],
        include_quit=False
    )

    choice = get_menu_choice(3, allow_quit=False, default_back=True)
    if choice == 3:
        return

    if choice == 1:
        # Add remote
        try:
            add_remote(db)
            print("\n✓ Remote added")
            print("  Run 'wg-friend generate' to create updated configs.")
            input("\nPress Enter to continue...")
        except Exception as e:
            print(f"\nError adding remote: {e}")
            input("\nPress Enter to continue...")

    elif choice == 2:
        # Add router
        try:
            add_router(db)
            print("\n✓ Router added")
            print("  Run 'wg-friend generate' to create updated configs.")
            input("\nPress Enter to continue...")
        except Exception as e:
            print(f"\nError adding router: {e}")
            input("\nPress Enter to continue...")


def remove_peer_menu(db: WireGuardDBv2):
    """Menu for removing peers"""
    # List peers first
    list_peers(db)

    print("\n" + "─" * 70)
    print("REMOVE PEER")
    print("─" * 70)

    peer_type = input("Peer type [router/remote] (or 'q' to cancel): ").strip().lower()
    if peer_type in ('q', 'quit', 'cancel', ''):
        return

    if peer_type not in ('router', 'remote'):
        print("Invalid peer type.")
        input("\nPress Enter to continue...")
        return

    try:
        peer_id = int(input("Peer ID: ").strip())
    except ValueError:
        print("Invalid peer ID.")
        input("\nPress Enter to continue...")
        return

    reason = input("Reason for removal [Manual revocation]: ").strip()
    if not reason:
        reason = "Manual revocation"

    try:
        success = remove_peer(db, peer_type, peer_id, reason)
        if success:
            print("\n✓ Peer removed")
            print("  Run 'wg-friend generate' to create updated configs.")
        input("\nPress Enter to continue...")
    except Exception as e:
        print(f"\nError removing peer: {e}")
        input("\nPress Enter to continue...")


def rotate_keys_menu(db: WireGuardDBv2):
    """Menu for rotating keys"""
    # List peers first
    list_peers(db)

    print("\n" + "─" * 70)
    print("ROTATE KEYS")
    print("─" * 70)

    peer_type = input("Peer type [cs/router/remote] (or 'q' to cancel): ").strip().lower()
    if peer_type in ('q', 'quit', 'cancel', ''):
        return

    if peer_type not in ('cs', 'router', 'remote'):
        print("Invalid peer type.")
        input("\nPress Enter to continue...")
        return

    peer_id = None
    if peer_type != 'cs':
        try:
            peer_id = int(input("Peer ID: ").strip())
        except ValueError:
            print("Invalid peer ID.")
            input("\nPress Enter to continue...")
            return

    reason = input("Reason for rotation [Scheduled rotation]: ").strip()
    if not reason:
        reason = "Scheduled rotation"

    try:
        success = rotate_keys(db, peer_type, peer_id, reason)
        if success:
            print("\n✓ Keys rotated")
            print("  Run 'wg-friend generate' to create updated configs.")
            print("  Then 'wg-friend deploy' to push to servers.")
        input("\nPress Enter to continue...")
    except Exception as e:
        print(f"\nError rotating keys: {e}")
        input("\nPress Enter to continue...")


def history_menu(db: WireGuardDBv2, db_path: str):
    """History submenu - key rotations, state timeline, peer history"""
    print_menu(
        "HISTORY",
        [
            "Recent Key Rotations",
            "State History Timeline",
            "Peer History",
            "Back to Main Menu",
        ],
        include_quit=False
    )

    choice = get_menu_choice(4, allow_quit=False, default_back=True)
    if choice == 4:
        return

    if choice == 1:
        # Recent Key Rotations
        show_recent_rotations(db, limit=20)
        input("\nPress Enter to continue...")

    elif choice == 2:
        # State History Timeline
        state_history_menu(db, db_path)

    elif choice == 3:
        # Peer History
        peer_history_menu(db, db_path)


def state_history_menu(db: WireGuardDBv2, db_path: str):
    """Menu for viewing state history timeline"""
    # Show timeline first
    show_state_history(db_path, limit=20)

    # Offer to view specific state details
    print("─" * 70)
    state_id_input = input("Enter state ID for details (or Enter to go back): ").strip()

    if state_id_input:
        try:
            state_id = int(state_id_input)
            show_state_history(db_path, state_id=state_id)
            input("\nPress Enter to continue...")
        except ValueError:
            print("Invalid state ID.")
            input("\nPress Enter to continue...")


def peer_history_menu(db: WireGuardDBv2, db_path: str):
    """Menu for viewing individual peer history"""
    # List peers first
    list_peers(db)

    print("\n" + "─" * 70)
    print("PEER HISTORY")
    print("─" * 70)

    peer_name = input("Enter peer hostname or ID (or 'q' to cancel): ").strip()

    if peer_name in ('q', 'quit', 'cancel', ''):
        return

    show_entity_history(db, db_path, peer_name)
    input("\nPress Enter to continue...")


def generate_configs_menu(db: WireGuardDBv2, db_path: str):
    """Generate configs menu"""
    from pathlib import Path
    from v1.cli.config_generator import generate_configs, generate_cs_config, generate_router_config, generate_remote_config

    print_menu(
        "GENERATE CONFIGS",
        [
            "Generate all configs",
            "Generate all configs + QR codes",
            "Generate single entity config",
            "Back to Main Menu",
        ],
        include_quit=False
    )

    choice = get_menu_choice(4, allow_quit=False, default_back=True)

    if choice == 4:
        return

    if choice == 3:
        # Single entity generation
        generate_single_entity_config(db, db_path)
        return

    # Create args object for generate_configs
    class Args:
        pass

    args = Args()
    args.db = db_path
    args.output = 'generated'
    args.qr = (choice == 2)

    print()
    result = generate_configs(args)

    if result == 0:
        print()
        print("Configs written to 'generated/' directory.")
        if args.qr:
            print("QR codes generated for mobile devices.")
    else:
        print("\nGeneration failed. Check errors above.")

    input("\nPress Enter to continue...")


def generate_single_entity_config(db: WireGuardDBv2, db_path: str):
    """Generate config for a single entity"""
    from pathlib import Path
    from v1.cli.config_generator import generate_cs_config, generate_router_config, generate_remote_config

    # Build list of all entities
    entities = []

    with db._connection() as conn:
        cursor = conn.cursor()

        # Get CS
        cursor.execute("SELECT hostname FROM coordination_server WHERE id = 1")
        cs = cursor.fetchone()
        if cs:
            entities.append(('cs', 1, cs['hostname']))

        # Get routers
        cursor.execute("SELECT id, hostname FROM subnet_router ORDER BY hostname")
        for row in cursor.fetchall():
            entities.append(('router', row['id'], row['hostname']))

        # Get remotes
        cursor.execute("SELECT id, hostname FROM remote ORDER BY hostname")
        for row in cursor.fetchall():
            entities.append(('remote', row['id'], row['hostname']))

    if not entities:
        print("\nNo entities found in database.")
        input("\nPress Enter to continue...")
        return

    print(f"\n{'=' * 70}")
    print("SELECT ENTITY")
    print(f"{'=' * 70}\n")

    for i, (etype, eid, hostname) in enumerate(entities, 1):
        type_label = {'cs': 'Coordination Server', 'router': 'Subnet Router', 'remote': 'Remote Client'}.get(etype, etype)
        print(f"  {i}. [{type_label}] {hostname}")

    print(f"\n  b. Back")
    print()

    choice = input("Select entity: ").strip().lower()

    if choice == 'b':
        return

    try:
        idx = int(choice) - 1
        if not (0 <= idx < len(entities)):
            print("Invalid choice.")
            input("\nPress Enter to continue...")
            return

        etype, eid, hostname = entities[idx]

        # Generate config
        if etype == 'cs':
            config = generate_cs_config(db)
            filename = "coordination.conf"
        elif etype == 'router':
            config = generate_router_config(db, eid)
            filename = f"{hostname}.conf"
        else:
            config = generate_remote_config(db, eid)
            filename = f"{hostname}.conf"

        # Show options
        print(f"\n{'─' * 70}")
        print(f"Config for: {hostname}")
        print(f"{'─' * 70}")
        print()
        print("  1. View config")
        print("  2. Save to file")
        print("  3. View and save")
        print("  4. Generate QR code (remotes only)")
        print()

        action = input("Action [1]: ").strip()
        if not action:
            action = '1'

        output_dir = Path('generated')
        output_dir.mkdir(exist_ok=True)
        output_path = output_dir / filename

        if action in ('1', '3'):
            print(f"\n{'─' * 70}")
            print(config)
            print(f"{'─' * 70}")

        if action in ('2', '3'):
            output_path.write_text(config)
            output_path.chmod(0o600)
            print(f"\n✓ Saved to: {output_path}")

        if action == '4' and etype == 'remote':
            try:
                import qrcode
                qr = qrcode.QRCode()
                qr.add_data(config)
                qr.make()

                qr_file = output_dir / f"{hostname}.png"
                img = qr.make_image(fill_color="black", back_color="white")
                img.save(qr_file)
                print(f"\n✓ QR code saved to: {qr_file}")
            except ImportError:
                print("\n  (qrcode module not installed - pip install qrcode)")

    except ValueError:
        print("Invalid choice.")

    input("\nPress Enter to continue...")


def deploy_configs_menu(db: WireGuardDBv2, db_path: str):
    """Deploy configs menu"""
    from pathlib import Path
    from v1.cli.deploy import deploy_configs

    # Check if generated directory exists
    if not Path('generated').exists():
        print("\nNo configs found in 'generated/' directory.")
        print("Generate configs first (option 8).")
        input("\nPress Enter to continue...")
        return

    print_menu(
        "DEPLOY CONFIGS",
        [
            "Deploy all (dry run - show what would happen)",
            "Deploy all",
            "Deploy all + restart WireGuard",
            "Deploy specific entity",
            "Back to Main Menu",
        ],
        include_quit=False
    )

    choice = get_menu_choice(5, allow_quit=False, default_back=True)

    if choice == 5:
        return

    # Create args object for deploy_configs
    class Args:
        pass

    args = Args()
    args.db = db_path
    args.output = 'generated'
    args.user = 'root'
    args.entity = None
    args.dry_run = False
    args.restart = False

    if choice == 1:
        args.dry_run = True
    elif choice == 2:
        pass  # defaults
    elif choice == 3:
        args.restart = True
    elif choice == 4:
        # Prompt for entity
        entity = input("\nEntity hostname to deploy: ").strip()
        if not entity:
            print("Cancelled.")
            input("\nPress Enter to continue...")
            return
        args.entity = entity

    print()
    result = deploy_configs(args)

    if result == 0:
        print("\nDeployment complete.")
    else:
        print("\nDeployment had failures. Check errors above.")

    input("\nPress Enter to continue...")


def extramural_menu(db_path: str):
    """Extramural configs menu - manage external VPN configurations"""
    from pathlib import Path
    from v1.extramural_ops import ExtramuralOps

    ops = ExtramuralOps(Path(db_path))

    while True:
        print_menu(
            "EXTRAMURAL - External VPN Configs",
            [
                "List All Configs",
                "View by Sponsor",
                "View by Local Peer",
                "Import Config File",
                "Generate Single Config",
                "Manage Sponsors",
                "Manage Local Peers",
                "Back to Main Menu",
            ],
            include_quit=False
        )

        choice = get_menu_choice(8, allow_quit=False, default_back=True)

        if choice == 8:
            return

        elif choice == 1:
            # List all configs
            extramural_list_all(ops, db_path)

        elif choice == 2:
            # View by sponsor
            extramural_by_sponsor(ops, db_path)

        elif choice == 3:
            # View by local peer
            extramural_by_local_peer(ops, db_path)

        elif choice == 4:
            # Import config
            extramural_import_config(ops, db_path)

        elif choice == 5:
            # Generate single config
            extramural_generate_single(ops, db_path)

        elif choice == 6:
            # Manage sponsors
            extramural_manage_sponsors(ops)

        elif choice == 7:
            # Manage local peers
            extramural_manage_local_peers(ops)


def extramural_generate_single(ops, db_path: str):
    """Generate a single extramural config"""
    from pathlib import Path
    from v1.extramural_generator import ExtramuralConfigGenerator

    configs = ops.list_extramural_configs()

    if not configs:
        print("\nNo extramural configs found.")
        print("Import a config first using option 4.")
        input("\nPress Enter to continue...")
        return

    print(f"\n{'=' * 70}")
    print("SELECT EXTRAMURAL CONFIG")
    print(f"{'=' * 70}\n")

    for i, config in enumerate(configs, 1):
        peer = ops.get_local_peer(config.local_peer_id)
        sponsor = ops.get_sponsor(config.sponsor_id)
        active_peer = ops.get_active_peer(config.id)

        peer_name = peer.name if peer else 'Unknown'
        sponsor_name = sponsor.name if sponsor else 'Unknown'
        endpoint = active_peer.endpoint if active_peer else 'N/A'

        print(f"  {i}. {peer_name} / {sponsor_name}")
        print(f"      Interface: {config.interface_name or 'N/A'}, Endpoint: {endpoint}")

    print(f"\n  b. Back")
    print()

    choice = input("Select config: ").strip().lower()

    if choice == 'b' or not choice:
        return

    try:
        idx = int(choice) - 1
        if not (0 <= idx < len(configs)):
            print("Invalid choice.")
            input("\nPress Enter to continue...")
            return

        config = configs[idx]
        peer = ops.get_local_peer(config.local_peer_id)
        sponsor = ops.get_sponsor(config.sponsor_id)

        # Generate config
        gen = ExtramuralConfigGenerator(db_path)
        content = gen.generate_config(config.id)

        # Filename: [Sponsor]-[hostname]-date.conf
        from datetime import datetime
        sponsor_slug = sponsor.name.lower().replace(' ', '-')
        peer_slug = peer.name.lower().replace(' ', '-')
        date_str = datetime.now().strftime('%Y%m%d')
        filename = f"{sponsor_slug}-{peer_slug}-{date_str}.conf"

        # Show options
        print(f"\n{'─' * 70}")
        print(f"Config for: {peer.name} / {sponsor.name}")
        print(f"{'─' * 70}")
        print()
        print("  1. View config")
        print("  2. Save to file")
        print("  3. View and save")
        print()

        action = input("Action [1]: ").strip()
        if not action:
            action = '1'

        output_dir = Path('generated')
        output_dir.mkdir(exist_ok=True)
        output_path = output_dir / filename

        if action in ('1', '3'):
            print(f"\n{'─' * 70}")
            print(content)
            print(f"{'─' * 70}")

        if action in ('2', '3'):
            output_path.write_text(content)
            output_path.chmod(0o600)
            print(f"\n✓ Saved to: {output_path}")

    except ValueError:
        print("Invalid choice.")

    input("\nPress Enter to continue...")


def extramural_list_all(ops, db_path: str):
    """List all extramural configs with option to select one"""
    while True:
        configs = ops.list_extramural_configs()

        if not configs:
            print("\nNo extramural configs found.")
            print("\nTo add one, use 'Import Config File' or the CLI:")
            print("  wg-friend extramural import <config.conf> --sponsor <name> --peer <device>")
            input("\nPress Enter to continue...")
            return

        print(f"\n{'=' * 70}")
        print(f"EXTRAMURAL CONFIGS ({len(configs)})")
        print(f"{'=' * 70}\n")

        for i, config in enumerate(configs, 1):
            peer = ops.get_local_peer(config.local_peer_id)
            sponsor = ops.get_sponsor(config.sponsor_id)
            active_peer = ops.get_active_peer(config.id)

            peer_name = peer.name if peer else 'Unknown'
            sponsor_name = sponsor.name if sponsor else 'Unknown'
            endpoint = active_peer.endpoint if active_peer else 'N/A'

            status = ""
            if config.pending_remote_update:
                status = " [PENDING UPDATE]"
            elif config.last_deployed_at:
                status = f" (deployed)"

            print(f"  {i}. {peer_name} / {sponsor_name}{status}")
            print(f"      Interface: {config.interface_name or 'N/A'}, Endpoint: {endpoint}")

        print(f"\n  b. Back")
        print()

        choice = input("Select config (or Enter to go back): ").strip().lower()

        if choice == 'b' or not choice:
            return

        try:
            idx = int(choice) - 1
            if 0 <= idx < len(configs):
                extramural_config_detail(ops, configs[idx], db_path)
            else:
                print("Invalid choice.")
                input("\nPress Enter to continue...")
        except ValueError:
            print("Invalid choice.")
            input("\nPress Enter to continue...")


def extramural_by_sponsor(ops, db_path: str):
    """View configs organized by sponsor"""
    sponsors = ops.list_sponsors()

    if not sponsors:
        print("\nNo sponsors found. Add one first.")
        input("\nPress Enter to continue...")
        return

    while True:
        print(f"\n{'=' * 70}")
        print("EXTRAMURAL - BY SPONSOR")
        print(f"{'=' * 70}\n")

        for i, sponsor in enumerate(sponsors, 1):
            configs = ops.list_extramural_configs(sponsor_id=sponsor.id)
            print(f"  {i}. {sponsor.name} ({len(configs)} configs)")
            if sponsor.website:
                print(f"      {sponsor.website}")

        print(f"\n  b. Back")
        print()

        choice = input("Select sponsor (or Enter to go back): ").strip().lower()

        if choice == 'b' or not choice:
            return

        try:
            idx = int(choice) - 1
            if 0 <= idx < len(sponsors):
                extramural_sponsor_detail(ops, sponsors[idx], db_path)
            else:
                print("Invalid choice.")
        except ValueError:
            print("Invalid choice.")


def extramural_sponsor_detail(ops, sponsor, db_path: str):
    """Show configs for a specific sponsor"""
    configs = ops.list_extramural_configs(sponsor_id=sponsor.id)

    print(f"\n{'=' * 70}")
    print(f"{sponsor.name.upper()}")
    if sponsor.website:
        print(f"{sponsor.website}")
    print(f"{'=' * 70}\n")

    if not configs:
        print("No configs for this sponsor.")
        input("\nPress Enter to continue...")
        return

    print("Configs:")
    for i, config in enumerate(configs, 1):
        peer = ops.get_local_peer(config.local_peer_id)
        active_peer = ops.get_active_peer(config.id)

        peer_name = peer.name if peer else 'Unknown'
        active_name = active_peer.name if active_peer else 'N/A'

        status = "never deployed"
        if config.pending_remote_update:
            status = "PENDING UPDATE"
        elif config.last_deployed_at:
            status = f"deployed {config.last_deployed_at}"

        print(f"  {i}. {peer_name} [{active_name}] - {status}")

    print(f"\n  b. Back")
    print()

    choice = input("Select config (or Enter to go back): ").strip().lower()

    if choice == 'b' or not choice:
        return

    try:
        idx = int(choice) - 1
        if 0 <= idx < len(configs):
            extramural_config_detail(ops, configs[idx], db_path)
    except ValueError:
        pass


def extramural_by_local_peer(ops, db_path: str):
    """View configs organized by local peer"""
    peers = ops.list_local_peers()

    if not peers:
        print("\nNo local peers found. Add one first.")
        input("\nPress Enter to continue...")
        return

    while True:
        print(f"\n{'=' * 70}")
        print("EXTRAMURAL - BY LOCAL PEER")
        print(f"{'=' * 70}\n")

        for i, peer in enumerate(peers, 1):
            configs = ops.list_extramural_configs(local_peer_id=peer.id)
            ssh_info = ""
            if peer.ssh_host_id:
                ssh_host = ops.get_ssh_host(peer.ssh_host_id)
                if ssh_host:
                    ssh_info = f" - {ssh_host.ssh_user or 'root'}@{ssh_host.ssh_host}"
            print(f"  {i}. {peer.name} ({len(configs)} configs){ssh_info}")

        print(f"\n  b. Back")
        print()

        choice = input("Select local peer (or Enter to go back): ").strip().lower()

        if choice == 'b' or not choice:
            return

        try:
            idx = int(choice) - 1
            if 0 <= idx < len(peers):
                extramural_local_peer_detail(ops, peers[idx], db_path)
            else:
                print("Invalid choice.")
        except ValueError:
            print("Invalid choice.")


def extramural_local_peer_detail(ops, peer, db_path: str):
    """Show configs for a specific local peer"""
    configs = ops.list_extramural_configs(local_peer_id=peer.id)

    print(f"\n{'=' * 70}")
    print(f"{peer.name.upper()}")

    if peer.ssh_host_id:
        ssh_host = ops.get_ssh_host(peer.ssh_host_id)
        if ssh_host:
            print(f"SSH: {ssh_host.ssh_user or 'root'}@{ssh_host.ssh_host}:{ssh_host.ssh_port}")

    print(f"{'=' * 70}\n")

    if not configs:
        print("No configs for this peer.")
        input("\nPress Enter to continue...")
        return

    print("Configs:")
    for i, config in enumerate(configs, 1):
        sponsor = ops.get_sponsor(config.sponsor_id)
        active_peer = ops.get_active_peer(config.id)

        sponsor_name = sponsor.name if sponsor else 'Unknown'
        active_name = active_peer.name if active_peer else 'N/A'

        status = "never deployed"
        if config.pending_remote_update:
            status = "PENDING UPDATE"
        elif config.last_deployed_at:
            status = f"deployed {config.last_deployed_at}"

        print(f"  {i}. {sponsor_name} [{active_name}] - {status}")

    print(f"\n  b. Back")
    print()

    choice = input("Select config (or Enter to go back): ").strip().lower()

    if choice == 'b' or not choice:
        return

    try:
        idx = int(choice) - 1
        if 0 <= idx < len(configs):
            extramural_config_detail(ops, configs[idx], db_path)
    except ValueError:
        pass


def extramural_config_detail(ops, config, db_path: str):
    """Show and manage a specific extramural config"""
    from v1.extramural_generator import ExtramuralConfigGenerator

    peer = ops.get_local_peer(config.local_peer_id)
    sponsor = ops.get_sponsor(config.sponsor_id)
    ext_peers = ops.list_extramural_peers(config.id)
    active_peer = ops.get_active_peer(config.id)

    while True:
        print(f"\n{'=' * 70}")
        print(f"{sponsor.name.upper()} -> {peer.name.upper()}")
        print(f"{'=' * 70}\n")

        if config.pending_remote_update:
            print("  !! PENDING REMOTE UPDATE !!")
            print(f"  Your new public key: {config.local_public_key}")
            print("  Update this at your sponsor's portal.\n")

        print(f"  Interface: {config.interface_name or 'N/A'}")
        print(f"  Your Public Key: {config.local_public_key[:32]}...")
        print(f"  Assigned IP: {config.assigned_ipv4 or ''} {config.assigned_ipv6 or ''}")

        if config.last_deployed_at:
            print(f"  Last Deployed: {config.last_deployed_at}")
        else:
            print(f"  Last Deployed: Never")

        print(f"\n  Available Endpoints:")
        for p in ext_peers:
            marker = "*" if p.is_active else " "
            print(f"    {marker} {p.name or 'unnamed'}: {p.endpoint or 'N/A'}")

        print_menu(
            "",
            [
                "Switch Active Endpoint",
                "View Full Config",
                "Generate Config File",
                "Mark Remote Updated (clear pending)",
                "Delete Config",
                "Back",
            ],
            include_quit=False
        )

        choice = get_menu_choice(6, allow_quit=False, default_back=True)

        if choice == 6:
            return

        elif choice == 1:
            # Switch active endpoint
            if len(ext_peers) <= 1:
                print("\nOnly one endpoint available.")
                input("\nPress Enter to continue...")
                continue

            print("\nSelect new active endpoint:")
            for i, p in enumerate(ext_peers, 1):
                marker = "[ACTIVE]" if p.is_active else ""
                print(f"  {i}. {p.name or 'unnamed'} - {p.endpoint} {marker}")

            try:
                idx = int(input("\nChoice: ").strip()) - 1
                if 0 <= idx < len(ext_peers):
                    ops.set_active_peer(ext_peers[idx].id)
                    print(f"\n✓ Switched to: {ext_peers[idx].name}")
                    # Refresh
                    ext_peers = ops.list_extramural_peers(config.id)
            except ValueError:
                pass
            input("\nPress Enter to continue...")

        elif choice == 2:
            # View full config
            gen = ExtramuralConfigGenerator(db_path)
            content = gen.generate_config(config.id)
            print(f"\n{'─' * 70}")
            print(content)
            print(f"{'─' * 70}")
            input("\nPress Enter to continue...")

        elif choice == 3:
            # Generate config file
            from datetime import datetime as dt
            gen = ExtramuralConfigGenerator(db_path)
            output_dir = Path("generated")
            output_dir.mkdir(exist_ok=True)

            # Filename: [Sponsor]-[hostname]-date.conf
            sponsor_slug = sponsor.name.lower().replace(' ', '-')
            peer_slug = peer.name.lower().replace(' ', '-')
            date_str = dt.now().strftime('%Y%m%d')
            output_path = output_dir / f"{sponsor_slug}-{peer_slug}-{date_str}.conf"

            gen.generate_config(config.id, output_path)
            print(f"\n✓ Config written to: {output_path}")
            input("\nPress Enter to continue...")

        elif choice == 4:
            # Mark remote updated
            if not config.pending_remote_update:
                print("\nNo pending update to clear.")
            else:
                ops.clear_pending_update(config.id)
                print("\n✓ Pending update cleared.")
                # Refresh config
                config = ops.get_extramural_config(config.id)
            input("\nPress Enter to continue...")

        elif choice == 5:
            # Delete config
            print(f"\nAre you sure you want to delete this config?")
            print(f"  Sponsor: {sponsor.name}")
            print(f"  Local Peer: {peer.name}")
            print(f"  Interface: {config.interface_name or 'N/A'}")
            print()
            confirm = input("Type 'DELETE' to confirm: ").strip()
            if confirm == 'DELETE':
                ops.delete_extramural_config(config.id)
                print("\n✓ Config deleted.")
                input("\nPress Enter to continue...")
                return  # Exit the config detail view
            else:
                print("\nDeletion cancelled.")
            input("\nPress Enter to continue...")


def extramural_import_config(ops, db_path: str):
    """Import a config file from sponsor"""
    from pathlib import Path as P
    import tempfile
    from v1.extramural_import import import_extramural_config

    print(f"\n{'=' * 70}")
    print("IMPORT EXTRAMURAL CONFIG")
    print(f"{'=' * 70}\n")

    print("  1. Import from file path")
    print("  2. Paste config content")
    print()

    method = input("Choice [1]: ").strip()

    config_file = None
    temp_file = None

    if method == '2':
        # Paste mode
        print("\nPaste your config below, then type END on its own line when done:")
        print("(Blank lines are OK - only END will stop the input)")
        print("─" * 40)

        import sys
        lines = []
        while True:
            try:
                sys.stdout.flush()
                line = input()
                if line.strip().upper() == 'END':
                    break
                lines.append(line)
            except EOFError:
                break
            except KeyboardInterrupt:
                print("\nCancelled.")
                return

        if not lines:
            print("\nNo config content provided.")
            input("\nPress Enter to continue...")
            return

        # Validate we got both sections
        content = '\n'.join(lines)
        if '[Interface]' not in content:
            print("\nError: No [Interface] section found in pasted content.")
            input("\nPress Enter to continue...")
            return
        if '[Peer]' not in content:
            print("\nError: No [Peer] section found in pasted content.")
            input("\nPress Enter to continue...")
            return

        # Write to temp file
        temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False)
        temp_file.write(content + '\n')
        temp_file.close()
        config_file = P(temp_file.name)
        print(f"\n✓ Read {len(lines)} lines")

    else:
        # File path mode
        config_path = input("Path to .conf file: ").strip()
        if not config_path:
            return

        config_file = P(config_path)
        if not config_file.exists():
            print(f"\nError: File not found: {config_file}")
            input("\nPress Enter to continue...")
            return

    # Get or create sponsor - show existing sponsors for selection
    existing_sponsors = ops.list_sponsors()
    sponsor_name = None
    sponsor_website = None

    if existing_sponsors:
        print("\nExisting sponsors:")
        for i, s in enumerate(existing_sponsors, 1):
            print(f"  {i}. {s.name}")
        print(f"  n. New sponsor")
        print()

        choice = input("Select sponsor or 'n' for new: ").strip().lower()

        if choice == 'n' or not choice:
            sponsor_name = input("New sponsor name (e.g., 'Mullvad', 'Work VPN'): ").strip()
            if sponsor_name:
                sponsor_website = input("Sponsor website (optional): ").strip() or None
        else:
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(existing_sponsors):
                    sponsor_name = existing_sponsors[idx].name
            except ValueError:
                pass
    else:
        sponsor_name = input("Sponsor name (e.g., 'Mullvad', 'Work VPN'): ").strip()
        if sponsor_name:
            sponsor_website = input("Sponsor website (optional): ").strip() or None

    if not sponsor_name:
        print("\nSponsor name required.")
        input("\nPress Enter to continue...")
        return

    # Get or create local peer - show existing peers for selection
    existing_peers = ops.list_local_peers()
    peer_name = None

    if existing_peers:
        print("\nExisting local peers:")
        for i, p in enumerate(existing_peers, 1):
            print(f"  {i}. {p.name}")
        print(f"  n. New local peer")
        print()

        choice = input("Select local peer or 'n' for new: ").strip().lower()

        if choice == 'n' or not choice:
            peer_name = input("New local peer name (e.g., 'my-laptop', 'phone'): ").strip()
        else:
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(existing_peers):
                    peer_name = existing_peers[idx].name
            except ValueError:
                pass
    else:
        peer_name = input("Local peer name (e.g., 'my-laptop', 'phone'): ").strip()
    if not peer_name:
        print("\nLocal peer name required.")
        input("\nPress Enter to continue...")
        return

    # Interface name - use sponsor name as default for pasted content
    default_interface = config_file.stem if temp_file is None else sponsor_name.lower().replace(' ', '-')
    interface_name = input(f"Interface name [{default_interface}]: ").strip()
    if not interface_name:
        interface_name = default_interface

    try:
        config_id, sponsor_id, peer_id = import_extramural_config(
            db_path=P(db_path),
            config_path=config_file,
            sponsor_name=sponsor_name,
            local_peer_name=peer_name,
            interface_name=interface_name,
            sponsor_website=sponsor_website
        )

        print(f"\n✓ Imported config successfully!")
        print(f"  Config ID: {config_id}")
        print(f"  Sponsor: {sponsor_name}")
        print(f"  Local Peer: {peer_name}")

    except Exception as e:
        print(f"\nError importing config: {e}")

    finally:
        # Clean up temp file if we created one
        if temp_file is not None:
            import os
            try:
                os.unlink(temp_file.name)
            except:
                pass

    input("\nPress Enter to continue...")


def extramural_manage_sponsors(ops):
    """Manage sponsors"""
    while True:
        sponsors = ops.list_sponsors()

        print(f"\n{'=' * 70}")
        print("MANAGE SPONSORS")
        print(f"{'=' * 70}\n")

        if sponsors:
            for i, sponsor in enumerate(sponsors, 1):
                print(f"  {i}. {sponsor.name}")
                if sponsor.website:
                    print(f"      {sponsor.website}")
        else:
            print("  No sponsors yet.")

        print(f"\n  a. Add Sponsor")
        print(f"  b. Back")
        print()

        choice = input("Choice: ").strip().lower()

        if choice == 'b':
            return

        elif choice == 'a':
            name = input("\nSponsor name: ").strip()
            if name:
                website = input("Website (optional): ").strip() or None
                support_url = input("Support URL (optional): ").strip() or None

                try:
                    sponsor_id = ops.add_sponsor(name=name, website=website, support_url=support_url)
                    print(f"\n✓ Added sponsor: {name} (ID: {sponsor_id})")
                except Exception as e:
                    print(f"\nError: {e}")

                input("\nPress Enter to continue...")


def extramural_manage_local_peers(ops):
    """Manage local peers"""
    while True:
        peers = ops.list_local_peers()

        print(f"\n{'=' * 70}")
        print("MANAGE LOCAL PEERS")
        print(f"{'=' * 70}\n")

        if peers:
            for i, peer in enumerate(peers, 1):
                ssh_info = "[no SSH]"
                if peer.ssh_host_id:
                    ssh_host = ops.get_ssh_host(peer.ssh_host_id)
                    if ssh_host:
                        ssh_info = f"{ssh_host.ssh_user or 'root'}@{ssh_host.ssh_host}"
                print(f"  {i}. {peer.name} - {ssh_info}")
        else:
            print("  No local peers yet.")

        print(f"\n  a. Add Local Peer")
        print(f"  b. Back")
        print()

        choice = input("Choice: ").strip().lower()

        if choice == 'b':
            return

        elif choice == 'a':
            name = input("\nLocal peer name (e.g., 'my-laptop'): ").strip()
            if name:
                notes = input("Notes (optional): ").strip() or None

                try:
                    peer_id = ops.add_local_peer(name=name, notes=notes)
                    print(f"\n✓ Added local peer: {name} (ID: {peer_id})")
                except Exception as e:
                    print(f"\nError: {e}")

                input("\nPress Enter to continue...")


def run_tui(db_path: str) -> int:
    """Run the interactive TUI"""
    db = WireGuardDBv2(db_path)

    print("\n" + "=" * 70)
    print("  WIREGUARD FRIEND - INTERACTIVE MODE")
    print("=" * 70)
    print("\n  Welcome! This interactive mode lets you manage your WireGuard network.")
    print("  Navigate using the menu options below.")
    print()
    input("Press Enter to continue...")

    # Main loop
    while True:
        try:
            continue_running = main_menu(db, db_path)
            if not continue_running:
                print("\nGoodbye!")
                return 0
        except KeyboardInterrupt:
            print("\n\nGoodbye!")
            return 0
        except Exception as e:
            print(f"\n\nError: {e}")
            import traceback
            traceback.print_exc()
            print("\nReturning to main menu...")
            input("Press Enter to continue...")


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--db', default='wireguard.db')
    args = parser.parse_args()
    sys.exit(run_tui(args.db))
