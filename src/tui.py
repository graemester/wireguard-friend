"""Rich-based TUI for WireGuard peer management"""

import logging
from pathlib import Path
from datetime import datetime
from typing import Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.text import Text
from rich import box

from .peer_manager import WireGuardPeerManager, WireGuardPeerStatus
from .config_builder import WireGuardConfigBuilder
from .metadata_db import PeerDatabase
from .qr_generator import generate_qr_code


logger = logging.getLogger(__name__)


class WGFriendTUI:
    """Rich-based terminal UI for wg-friend"""

    def __init__(self, config: dict, db_path: Path):
        self.config = config
        self.console = Console()
        self.peer_manager = WireGuardPeerManager(config)
        self.config_builder = WireGuardConfigBuilder(config)
        self.db = PeerDatabase(db_path)

    def show_header(self):
        """Display application header"""
        self.console.print("\n[bold cyan]wg-friend[/bold cyan] - WireGuard Peer Manager", justify="center")
        self.console.print(f"Coordinator: [yellow]{self.config['coordinator']['name']}[/yellow]\n", justify="center")

    def show_menu(self):
        """Display main menu"""
        menu = Table(show_header=False, box=box.SIMPLE)
        menu.add_column("Option", style="cyan", no_wrap=True)
        menu.add_column("Description")

        menu.add_row("1", "View peer status")
        menu.add_row("2", "Add new peer")
        menu.add_row("3", "Rotate peer keys")
        menu.add_row("4", "Revoke peer")
        menu.add_row("5", "List peer history")
        menu.add_row("q", "Quit")

        self.console.print(menu)
        self.console.print()

    def view_peer_status(self):
        """Display current peer status"""
        self.console.print("\n[bold]Fetching peer status...[/bold]")

        # Get runtime status
        wg_show_peers = self.peer_manager.get_current_peers_from_wg_show()

        # Get config metadata
        config_peers = self.peer_manager.parse_coordinator_config()

        # Merge
        peers = self.peer_manager.merge_status_with_config(wg_show_peers, config_peers)

        if not peers:
            self.console.print("[yellow]No peers found[/yellow]")
            return

        # Create table
        table = Table(title="WireGuard Peer Status", box=box.ROUNDED)
        table.add_column("Status", justify="center", style="bold", no_wrap=True)
        table.add_column("Name/IP", style="cyan")
        table.add_column("Public Key", style="dim")
        table.add_column("Endpoint")
        table.add_column("Handshake", justify="right")
        table.add_column("Transfer", justify="right")
        table.add_column("Age", justify="right")

        online_count = 0

        for peer in peers:
            # Status icon
            status = Text(peer.status_icon, style=peer.status_color)
            if peer.is_online:
                online_count += 1

            # Name or IP
            name = peer.name or peer.ipv4 or peer.ipv6 or "Unknown"

            # Public key (truncated)
            pub_key = peer.public_key[:20] + "..." if len(peer.public_key) > 20 else peer.public_key

            # Endpoint
            endpoint = peer.endpoint or "N/A"

            # Handshake
            if peer.latest_handshake:
                delta = datetime.now() - peer.latest_handshake
                if delta.total_seconds() < 120:
                    handshake = f"{int(delta.total_seconds())}s ago"
                elif delta.total_seconds() < 3600:
                    handshake = f"{int(delta.total_seconds() / 60)}m ago"
                elif delta.total_seconds() < 86400:
                    handshake = f"{int(delta.total_seconds() / 3600)}h ago"
                else:
                    handshake = f"{int(delta.total_seconds() / 86400)}d ago"
            else:
                handshake = "Never"

            # Transfer
            if peer.transfer_rx or peer.transfer_tx:
                rx_mb = peer.transfer_rx / (1024 ** 2)
                tx_mb = peer.transfer_tx / (1024 ** 2)
                transfer = f"↓{rx_mb:.1f}M ↑{tx_mb:.1f}M"
            else:
                transfer = "N/A"

            # Age
            if peer.created:
                age_days = (datetime.now() - peer.created).days
                if age_days < 30:
                    age = f"{age_days}d"
                elif age_days < 365:
                    age = f"{age_days // 30}mo"
                else:
                    age = f"{age_days // 365}y"

                if peer.is_old:
                    age = f"⚠ {age}"
            else:
                age = "Unknown"

            table.add_row(status, name, pub_key, endpoint, handshake, transfer, age)

        self.console.print(table)
        self.console.print(f"\n[dim]Total: {len(peers)} | Online: {online_count} | Offline: {len(peers) - online_count}[/dim]\n")

    def add_new_peer(self):
        """Interactive peer creation"""
        self.console.print("\n[bold]Add New Peer[/bold]\n")

        # Get peer name
        name = Prompt.ask("Peer name (e.g., iphone-graeme)")

        # Check if name already exists
        existing = self.db.get_peer(name)
        if existing:
            self.console.print(f"[red]Error: Peer '{name}' already exists[/red]")
            return

        # Select peer type
        self.console.print("\nPeer types:")
        templates = list(self.config['peer_templates'].keys())
        for i, template in enumerate(templates, 1):
            desc = self.config['peer_templates'][template]['description']
            self.console.print(f"  {i}. [cyan]{template}[/cyan] - {desc}")

        choice = Prompt.ask("\nSelect peer type", choices=[str(i) for i in range(1, len(templates) + 1)], default="1")
        peer_type = templates[int(choice) - 1]

        # Get next available IP
        next_ip = self.db.get_next_available_ip(
            self.config.get('ip_allocation', {}).get('start_ipv4', '10.66.0.50')
        )

        if not next_ip:
            self.console.print("[red]Error: No available IPs[/red]")
            return

        ipv4 = Prompt.ask(f"IPv4 address", default=next_ip)
        ipv6 = self.config_builder.ipv6_from_ipv4(ipv4)

        # Optional comment
        comment = Prompt.ask("Comment (optional)", default="")

        # Build config
        self.console.print("\n[bold]Generating configuration...[/bold]")

        result = self.config_builder.build_client_config(
            client_name=name,
            client_ipv4=ipv4,
            client_ipv6=ipv6,
            peer_type=peer_type,
            comment=comment or None
        )

        # Display client config
        self.console.print("\n[bold green]Client Configuration:[/bold green]")
        self.console.print(Panel(result['client_config'], border_style="green"))

        # Display coordinator peer block
        self.console.print("\n[bold yellow]Add this to coordinator:[/bold yellow]")
        self.console.print(Panel(result['coordinator_peer'], border_style="yellow"))

        # Generate QR code
        show_qr = Confirm.ask("\nGenerate QR code?", default=True)
        if show_qr:
            qr_ascii = generate_qr_code(result['client_config'])
            self.console.print("\n[bold]Scan with WireGuard mobile app:[/bold]")
            self.console.print(qr_ascii)

        # Save config file
        save_file = Confirm.ask("\nSave configuration file?", default=True)
        config_path = None
        qr_path = None

        if save_file:
            output_dir = Path(self.config.get('data_dir', '~/.wg-friend')).expanduser() / "configs"
            config_path = self.config_builder.save_client_config(name, result['client_config'], output_dir)
            self.console.print(f"[green]✓ Saved to {config_path}[/green]")

            # Save QR code PNG
            if show_qr:
                qr_dir = Path(self.config.get('qr_code', {}).get('output_dir', '~/.wg-friend/qr-codes')).expanduser()
                qr_path = qr_dir / f"{name}.png"
                generate_qr_code(result['client_config'], output_path=qr_path)
                self.console.print(f"[green]✓ QR code saved to {qr_path}[/green]")

        # Add to coordinator
        add_to_coordinator = Confirm.ask("\nAdd peer to coordinator automatically?", default=True)

        if add_to_coordinator:
            success = self.peer_manager.add_peer_to_config(result['coordinator_peer'])
            if success:
                self.console.print("[green]✓ Peer added to coordinator and WireGuard restarted[/green]")
            else:
                self.console.print("[red]✗ Failed to add peer to coordinator[/red]")
                return

        # Save to database
        peer_data = result['metadata']
        peer_data['config_path'] = str(config_path) if config_path else None
        peer_data['qr_code_path'] = str(qr_path) if qr_path else None

        self.db.save_peer(peer_data)
        self.console.print(f"[green]✓ Peer '{name}' saved to database[/green]\n")

    def rotate_peer_keys(self):
        """Interactive key rotation"""
        self.console.print("\n[bold]Rotate Peer Keys[/bold]\n")

        # List active peers
        active_peers = self.db.get_active_peers()

        if not active_peers:
            self.console.print("[yellow]No active peers found[/yellow]")
            return

        self.console.print("Active peers:")
        for i, peer in enumerate(active_peers, 1):
            self.console.print(f"  {i}. [cyan]{peer['name']}[/cyan] ({peer['ipv4']})")

        choice = Prompt.ask("\nSelect peer to rotate", choices=[str(i) for i in range(1, len(active_peers) + 1)])
        peer = active_peers[int(choice) - 1]

        self.console.print(f"\n[yellow]Rotating keys for '{peer['name']}'...[/yellow]")

        # Build new config with same IPs
        result = self.config_builder.build_client_config(
            client_name=peer['name'],
            client_ipv4=peer['ipv4'],
            client_ipv6=peer['ipv6'],
            peer_type=peer['peer_type'],
            comment=f"{peer['name']} (key rotated {datetime.now().strftime('%Y-%m-%d')})"
        )

        # Update coordinator
        success = self.peer_manager.update_peer_in_config(
            peer['public_key'],
            result['coordinator_peer']
        )

        if not success:
            self.console.print("[red]✗ Failed to update coordinator[/red]")
            return

        # Update database
        peer_data = result['metadata']
        self.db.save_peer(peer_data)

        self.console.print(f"[green]✓ Keys rotated successfully[/green]")
        self.console.print("\n[bold green]New Client Configuration:[/bold green]")
        self.console.print(Panel(result['client_config'], border_style="green"))

    def revoke_peer(self):
        """Interactive peer revocation"""
        self.console.print("\n[bold red]Revoke Peer[/bold red]\n")

        # List active peers
        active_peers = self.db.get_active_peers()

        if not active_peers:
            self.console.print("[yellow]No active peers to revoke[/yellow]")
            return

        self.console.print("Active peers:")
        for i, peer in enumerate(active_peers, 1):
            self.console.print(f"  {i}. [cyan]{peer['name']}[/cyan] ({peer['ipv4']})")

        choice = Prompt.ask("\nSelect peer to revoke", choices=[str(i) for i in range(1, len(active_peers) + 1)])
        peer = active_peers[int(choice) - 1]

        # Confirm
        self.console.print(f"\n[bold yellow]Warning:[/bold yellow] This will:")
        self.console.print("  • Remove peer from coordinator wg0.conf")
        self.console.print("  • Mark as revoked in database")
        self.console.print("  • Restart WireGuard service")
        self.console.print("[red]This action cannot be undone![/red]\n")

        confirmed = Confirm.ask(f"Revoke peer '[cyan]{peer['name']}[/cyan]'?", default=False)

        if not confirmed:
            self.console.print("Revocation cancelled")
            return

        # Revoke from coordinator
        success = self.peer_manager.revoke_peer(peer['public_key'], peer['name'])

        if not success:
            self.console.print("[red]✗ Failed to revoke peer from coordinator[/red]")
            return

        # Mark as revoked in database
        self.db.revoke_peer(peer['name'])

        self.console.print(f"[green]✓ Peer '{peer['name']}' revoked successfully[/green]\n")

    def list_peer_history(self):
        """Display peer history including revoked peers"""
        self.console.print("\n[bold]Peer History[/bold]\n")

        active = self.db.get_active_peers()
        revoked = self.db.get_revoked_peers()

        if active:
            self.console.print("[bold green]Active Peers:[/bold green]")
            for peer in active:
                created = datetime.fromisoformat(peer['created_at']).strftime('%Y-%m-%d')
                self.console.print(f"  • [cyan]{peer['name']}[/cyan] - {peer['ipv4']} (created {created})")

        if revoked:
            self.console.print("\n[bold red]Revoked Peers:[/bold red]")
            for peer in revoked:
                revoked_date = datetime.fromisoformat(peer['revoked_at']).strftime('%Y-%m-%d')
                self.console.print(f"  • [dim]{peer['name']}[/dim] - {peer['ipv4']} (revoked {revoked_date})")

        if not active and not revoked:
            self.console.print("[yellow]No peers found[/yellow]")

        self.console.print()

    def run(self):
        """Main TUI loop"""
        while True:
            self.show_header()
            self.show_menu()

            choice = Prompt.ask("Select an option", choices=["1", "2", "3", "4", "5", "q"])

            if choice == "1":
                self.view_peer_status()
                input("\nPress Enter to continue...")
            elif choice == "2":
                self.add_new_peer()
                input("\nPress Enter to continue...")
            elif choice == "3":
                self.rotate_peer_keys()
                input("\nPress Enter to continue...")
            elif choice == "4":
                self.revoke_peer()
                input("\nPress Enter to continue...")
            elif choice == "5":
                self.list_peer_history()
                input("\nPress Enter to continue...")
            elif choice == "q":
                self.console.print("\n[cyan]Goodbye![/cyan]\n")
                break

            self.console.clear()
