#!/usr/bin/env python3
"""
wg-friend - WireGuard Peer Manager
A terminal UI for managing WireGuard VPN peers with ease
"""

import argparse
import logging
import sys
from pathlib import Path
import yaml

from src.tui import WGFriendTUI
from src.peer_manager import WireGuardPeerManager
from src.config_builder import WireGuardConfigBuilder
from src.metadata_db import PeerDatabase
from src.qr_generator import display_qr_code


def load_config(config_path: Path) -> dict:
    """Load configuration file"""
    if not config_path.exists():
        print(f"Error: Config file not found: {config_path}")
        print(f"Copy config.example.yaml to {config_path} and edit it")
        sys.exit(1)

    with open(config_path) as f:
        return yaml.safe_load(f)


def setup_logging(config: dict):
    """Setup logging"""
    log_level = config.get('logging', {}).get('level', 'INFO')
    log_file = config.get('logging', {}).get('file')

    if log_file:
        log_file = Path(log_file).expanduser()
        log_file.parent.mkdir(parents=True, exist_ok=True)

    logging.basicConfig(
        level=getattr(logging, log_level),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file) if log_file else logging.StreamHandler(),
        ]
    )


def cmd_tui(args, config: dict):
    """Launch interactive TUI"""
    db_path = Path(config.get('metadata_db', '~/.wg-friend/peers.db')).expanduser()
    tui = WGFriendTUI(config, db_path)
    tui.run()


def cmd_status(args, config: dict):
    """Show peer status (non-interactive)"""
    peer_manager = WireGuardPeerManager(config)

    print("Fetching peer status...")
    wg_show_peers = peer_manager.get_current_peers_from_wg_show()
    config_peers = peer_manager.parse_coordinator_config()
    peers = peer_manager.merge_status_with_config(wg_show_peers, config_peers)

    if not peers:
        print("No peers found")
        return

    print(f"\n{'Status':<8} {'Name/IP':<25} {'Endpoint':<30} {'Handshake':<15}")
    print("-" * 80)

    for peer in peers:
        status = "ONLINE" if peer.is_online else "OFFLINE"
        name = peer.name or peer.ipv4 or "Unknown"
        endpoint = peer.endpoint or "N/A"

        if peer.latest_handshake:
            from datetime import datetime
            delta = datetime.now() - peer.latest_handshake
            if delta.total_seconds() < 3600:
                handshake = f"{int(delta.total_seconds() / 60)}m ago"
            elif delta.total_seconds() < 86400:
                handshake = f"{int(delta.total_seconds() / 3600)}h ago"
            else:
                handshake = f"{int(delta.total_seconds() / 86400)}d ago"
        else:
            handshake = "Never"

        print(f"{status:<8} {name:<25} {endpoint:<30} {handshake:<15}")

    print(f"\nTotal: {len(peers)} | Online: {sum(1 for p in peers if p.is_online)}")


def cmd_add_peer(args, config: dict):
    """Add a new peer (non-interactive)"""
    from src.keygen import generate_keypair

    db_path = Path(config.get('metadata_db', '~/.wg-friend/peers.db')).expanduser()
    db = PeerDatabase(db_path)

    # Check if peer exists
    if db.get_peer(args.name):
        print(f"Error: Peer '{args.name}' already exists")
        sys.exit(1)

    # Get IP
    ipv4 = args.ip or db.get_next_available_ip(
        config.get('ip_allocation', {}).get('start_ipv4', '10.66.0.50')
    )

    if not ipv4:
        print("Error: No available IPs")
        sys.exit(1)

    config_builder = WireGuardConfigBuilder(config)
    ipv6 = config_builder.ipv6_from_ipv4(ipv4)

    # Build config
    print(f"Generating configuration for '{args.name}'...")

    result = config_builder.build_client_config(
        client_name=args.name,
        client_ipv4=ipv4,
        client_ipv6=ipv6,
        peer_type=args.type,
        comment=args.comment
    )

    # Display config
    print("\n=== Client Configuration ===")
    print(result['client_config'])

    print("\n=== Add to Coordinator ===")
    print(result['coordinator_peer'])

    # QR code
    if args.qr:
        display_qr_code(result['client_config'])

    # Save
    if args.save:
        output_dir = Path(config.get('data_dir', '~/.wg-friend')).expanduser() / "configs"
        config_path = config_builder.save_client_config(args.name, result['client_config'], output_dir)
        print(f"\n✓ Config saved to {config_path}")

        # QR code PNG
        if args.qr:
            from src.qr_generator import generate_qr_code
            qr_dir = Path(config.get('qr_code', {}).get('output_dir', '~/.wg-friend/qr-codes')).expanduser()
            qr_path = qr_dir / f"{args.name}.png"
            generate_qr_code(result['client_config'], output_path=qr_path)
            print(f"✓ QR code saved to {qr_path}")

    # Add to coordinator
    if args.add_to_coordinator:
        peer_manager = WireGuardPeerManager(config)
        if peer_manager.add_peer_to_config(result['coordinator_peer']):
            print("✓ Peer added to coordinator")
        else:
            print("✗ Failed to add peer to coordinator")
            sys.exit(1)

    # Save to database
    peer_data = result['metadata']
    db.save_peer(peer_data)
    print(f"✓ Peer '{args.name}' saved to database")


def cmd_revoke(args, config: dict):
    """Revoke a peer (non-interactive)"""
    db_path = Path(config.get('metadata_db', '~/.wg-friend/peers.db')).expanduser()
    db = PeerDatabase(db_path)

    # Get peer
    peer = db.get_peer(args.name)
    if not peer:
        print(f"Error: Peer '{args.name}' not found")
        sys.exit(1)

    if peer.get('revoked_at'):
        print(f"Error: Peer '{args.name}' is already revoked")
        sys.exit(1)

    # Revoke
    print(f"Revoking peer '{args.name}'...")

    peer_manager = WireGuardPeerManager(config)
    if peer_manager.revoke_peer(peer['public_key'], peer['name']):
        db.revoke_peer(args.name)
        print(f"✓ Peer '{args.name}' revoked successfully")
    else:
        print(f"✗ Failed to revoke peer")
        sys.exit(1)


def cmd_list(args, config: dict):
    """List all peers"""
    db_path = Path(config.get('metadata_db', '~/.wg-friend/peers.db')).expanduser()
    db = PeerDatabase(db_path)

    active = db.get_active_peers()
    revoked = db.get_revoked_peers()

    if active:
        print("\n=== Active Peers ===")
        for peer in active:
            from datetime import datetime
            created = datetime.fromisoformat(peer['created_at']).strftime('%Y-%m-%d')
            print(f"  • {peer['name']:<20} {peer['ipv4']:<15} (created {created})")

    if revoked:
        print("\n=== Revoked Peers ===")
        for peer in revoked:
            from datetime import datetime
            revoked_date = datetime.fromisoformat(peer['revoked_at']).strftime('%Y-%m-%d')
            print(f"  • {peer['name']:<20} {peer['ipv4']:<15} (revoked {revoked_date})")

    if not active and not revoked:
        print("No peers found")


def cmd_export(args, config: dict):
    """Export coordinator config for deployment"""
    db_path = Path(config.get('metadata_db', '~/.wg-friend/peers.db')).expanduser()
    db = PeerDatabase(db_path)

    # Default output path
    if args.output:
        output_path = Path(args.output)
    else:
        output_path = Path.home() / '.wg-friend' / 'coordinator-wg0.conf'

    print(f"Exporting coordinator config to {output_path}...")

    peer_manager = WireGuardPeerManager(config)
    if peer_manager.export_coordinator_config(db, output_path):
        active_peers = db.get_active_peers()
        print(f"✓ Exported config with {len(active_peers)} active peers")
        print(f"✓ Ready for deployment: {output_path}")
    else:
        print("✗ Failed to export coordinator config")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description='wg-friend - WireGuard Peer Manager',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  wg-friend tui                           Launch interactive TUI
  wg-friend status                        Show peer status
  wg-friend add iphone-alice --qr         Add peer with QR code
  wg-friend revoke iphone-alice           Revoke a peer
  wg-friend list                          List all peers
        """
    )

    parser.add_argument(
        '-c', '--config',
        type=Path,
        default=Path('~/.wg-friend/config.yaml').expanduser(),
        help='Config file path (default: ~/.wg-friend/config.yaml)'
    )

    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # TUI command
    subparsers.add_parser('tui', help='Launch interactive TUI')

    # Status command
    subparsers.add_parser('status', help='Show peer status')

    # Add peer command
    add_parser = subparsers.add_parser('add', help='Add a new peer')
    add_parser.add_argument('name', help='Peer name')
    add_parser.add_argument('--ip', help='IPv4 address (auto-assigned if not provided)')
    add_parser.add_argument('--type', default='mobile_client', help='Peer type template')
    add_parser.add_argument('--comment', help='Optional comment')
    add_parser.add_argument('--qr', action='store_true', help='Generate QR code')
    add_parser.add_argument('--save', action='store_true', default=True, help='Save config file')
    add_parser.add_argument('--add-to-coordinator', action='store_true', help='Add to coordinator automatically')

    # Revoke command
    revoke_parser = subparsers.add_parser('revoke', help='Revoke a peer')
    revoke_parser.add_argument('name', help='Peer name')

    # List command
    subparsers.add_parser('list', help='List all peers')

    # Export command
    export_parser = subparsers.add_parser('export', help='Export coordinator config for deployment')
    export_parser.add_argument('-o', '--output', help='Output path (default: ~/.wg-friend/coordinator-wg0.conf)')

    args = parser.parse_args()

    # Load config
    config = load_config(args.config)
    setup_logging(config)

    # Route to command
    if not args.command or args.command == 'tui':
        cmd_tui(args, config)
    elif args.command == 'status':
        cmd_status(args, config)
    elif args.command == 'add':
        cmd_add_peer(args, config)
    elif args.command == 'revoke':
        cmd_revoke(args, config)
    elif args.command == 'list':
        cmd_list(args, config)
    elif args.command == 'export':
        cmd_export(args, config)
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
