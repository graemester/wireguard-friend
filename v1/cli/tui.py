"""
Interactive TUI - Text-based User Interface

Provides an interactive menu-driven interface for managing WireGuard network.
"""

import sys
from pathlib import Path
from typing import List, Dict, Optional

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from v1.schema_semantic import WireGuardDBv2
from v1.cli.peer_manager import add_remote, add_router, list_peers, rotate_keys, remove_peer
from v1.cli.status import show_network_overview, show_recent_rotations, show_state_history, show_entity_history


def print_menu(title: str, options: List[str], include_quit: bool = True):
    """Print a menu"""
    print(f"\n{'=' * 70}")
    print(f"{title}")
    print(f"{'=' * 70}")
    for i, option in enumerate(options, 1):
        print(f"  {i}. {option}")
    if include_quit:
        print(f"  q. Quit")
    print()


def get_menu_choice(max_choice: int, allow_quit: bool = True) -> Optional[int]:
    """Get menu choice from user"""
    while True:
        choice = input("Choice: ").strip().lower()

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
        "WIREGUARD FRIEND - MAIN MENU",
        [
            "Network Status",
            "List All Peers",
            "Add Peer",
            "Remove Peer",
            "Rotate Keys",
            "Recent Key Rotations",
            "State History Timeline",
            "Peer History",
            "Generate Configs (requires running separate command)",
            "Deploy Configs (requires running separate command)",
        ]
    )

    choice = get_menu_choice(10)
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
        # Recent Rotations
        show_recent_rotations(db, limit=20)
        input("\nPress Enter to continue...")

    elif choice == 7:
        # State History Timeline
        state_history_menu(db, db_path)

    elif choice == 8:
        # Peer History
        peer_history_menu(db, db_path)

    elif choice == 9:
        # Generate Configs
        print("\nTo generate configs, run:")
        print("  wg-friend generate --qr")
        input("\nPress Enter to continue...")

    elif choice == 10:
        # Deploy Configs
        print("\nTo deploy configs, run:")
        print("  wg-friend deploy --restart")
        input("\nPress Enter to continue...")

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

    choice = get_menu_choice(3, allow_quit=False)
    if choice == 3:
        return

    if choice == 1:
        # Add remote
        try:
            add_remote(db)
            print("\n✓ Remote added successfully!")
            print("  Run 'wg-friend generate' to create updated configs.")
            input("\nPress Enter to continue...")
        except Exception as e:
            print(f"\nError adding remote: {e}")
            input("\nPress Enter to continue...")

    elif choice == 2:
        # Add router
        try:
            add_router(db)
            print("\n✓ Router added successfully!")
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
            print("\n✓ Peer removed successfully!")
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
            print("\n✓ Keys rotated successfully!")
            print("  Run 'wg-friend generate' to create updated configs.")
            print("  Then 'wg-friend deploy' to push to servers.")
        input("\nPress Enter to continue...")
    except Exception as e:
        print(f"\nError rotating keys: {e}")
        input("\nPress Enter to continue...")


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


def run_tui(db_path: str) -> int:
    """Run the interactive TUI"""
    db = WireGuardDBv2(db_path)

    print("\n" + "=" * 70)
    print("  WIREGUARD FRIEND v2 - INTERACTIVE MODE")
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
