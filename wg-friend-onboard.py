#!/usr/bin/env python3
"""
wg-friend Onboarding Script v2
Import existing WireGuard configs with raw block preservation
"""

import argparse
import sys
import getpass
from pathlib import Path
from typing import List, Dict, Optional, Tuple

from rich.console import Console
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.panel import Panel
from rich.table import Table
from rich import box

from src.database import WireGuardDB
from src.raw_parser import (
    RawBlockParser,
    ConfigDetector,
    StructuredDataExtractor,
    ParsedWireGuardConfig,
    RawPeerBlock
)

console = Console()


class WireGuardOnboarder:
    """Import WireGuard configs with raw block preservation"""

    def __init__(self, import_dir: Path, db_path: Path, auto_confirm: bool = False):
        self.import_dir = Path(import_dir)
        self.db_path = Path(db_path)
        self.db = WireGuardDB(db_path)
        self.parser = RawBlockParser()
        self.detector = ConfigDetector()
        self.extractor = StructuredDataExtractor()
        self.auto_confirm = auto_confirm

        # Parsed configs
        self.parsed_configs: List[ParsedWireGuardConfig] = []
        self.cs_config: Optional[ParsedWireGuardConfig] = None
        self.sn_configs: List[ParsedWireGuardConfig] = []
        self.client_configs: List[ParsedWireGuardConfig] = []

        # Database IDs after Phase 2/3
        self.cs_id: Optional[int] = None

    def _confirm(self, prompt: str, default: bool = True) -> bool:
        """Ask for confirmation, or auto-confirm if in non-interactive mode"""
        if self.auto_confirm:
            console.print(f"{prompt} [dim](auto-confirmed)[/dim]")
            return True
        return Confirm.ask(prompt, default=default)

    def run(self):
        """Run the complete import workflow"""
        console.print(Panel.fit(
            "[bold cyan]WireGuard Friend - Configuration Import[/bold cyan]\n"
            "Importing existing WireGuard configurations with perfect fidelity",
            border_style="cyan"
        ))

        try:
            # Phase 1: Parse and classify
            self._phase1_parse_configs()

            # Phase 2: Coordination Server confirmation
            if self.cs_config:
                self._phase2_confirm_cs()
            else:
                console.print("[red]No coordination server config found![/red]")
                return

            # Phase 3: Subnet Router confirmation
            if self.sn_configs:
                self._phase3_confirm_subnet_routers()

            # Phase 4: Peer review
            if self.client_configs:
                self._phase4_review_peers()

            # Phase 5: Verification and finalization
            self._phase5_verify_and_finalize()

            console.print("\n[bold green]✓ Import completed successfully![/bold green]")

        except KeyboardInterrupt:
            console.print("\n[yellow]Import cancelled by user[/yellow]")
            sys.exit(1)
        except Exception as e:
            console.print(f"\n[red]Error during import: {e}[/red]")
            raise

    def _phase1_parse_configs(self):
        """Phase 1: Parse all configs and classify them"""
        console.print("\n[bold]Phase 1: Parsing configurations[/bold]")

        # Find all .conf files
        conf_files = list(self.import_dir.glob("*.conf"))
        if not conf_files:
            raise ValueError(f"No .conf files found in {self.import_dir}")

        console.print(f"Found {len(conf_files)} configuration files")

        # Parse each file
        for conf_file in conf_files:
            try:
                parsed = self.parser.parse_file(conf_file)
                config_type = self.detector.detect_type(parsed)

                console.print(f"  • {conf_file.name}: [cyan]{config_type}[/cyan]")

                # Classify
                if config_type == 'coordination_server':
                    if self.cs_config:
                        console.print(f"[yellow]Warning: Multiple coordination servers detected, using first one[/yellow]")
                    else:
                        self.cs_config = parsed
                elif config_type == 'subnet_router':
                    self.sn_configs.append(parsed)
                elif config_type == 'client':
                    self.client_configs.append(parsed)

                self.parsed_configs.append(parsed)

            except Exception as e:
                console.print(f"  [red]✗ Failed to parse {conf_file.name}: {e}[/red]")

    def _phase2_confirm_cs(self):
        """Phase 2: Coordination Server confirmation workflow"""
        console.print("\n[bold]Phase 2: Coordination Server Configuration[/bold]")

        cs = self.cs_config
        interface = cs.interface
        network_info = self.extractor.extract_network_info(interface)

        # Extract endpoint from client configs (they have the server endpoint)
        endpoint_fqdn = None
        endpoint_port = "51820"

        # Check client configs for endpoint (they point to the CS)
        for client_config in self.client_configs:
            if client_config.peers and client_config.peers[0].endpoint:
                endpoint = client_config.peers[0].endpoint
                if ':' in endpoint:
                    endpoint_fqdn, endpoint_port = endpoint.split(':', 1)
                else:
                    endpoint_fqdn = endpoint
                break

        # If no client configs, check subnet router configs
        if not endpoint_fqdn:
            for sn_config in self.sn_configs:
                if sn_config.peers and sn_config.peers[0].endpoint:
                    endpoint = sn_config.peers[0].endpoint
                    if ':' in endpoint:
                        endpoint_fqdn, endpoint_port = endpoint.split(':', 1)
                    else:
                        endpoint_fqdn = endpoint
                    break

        # Display Coordination Server public details first
        console.print("\n[bold cyan]Coordination Server (Public Endpoint):[/bold cyan]")

        if endpoint_fqdn:
            console.print(f"  FQDN: [yellow]{endpoint_fqdn}[/yellow]")

            # Try to resolve FQDN to IP
            try:
                import socket
                resolved_ip = socket.gethostbyname(endpoint_fqdn)
                console.print(f"  Resolved IP: [yellow]{resolved_ip}[/yellow] [dim](current DNS resolution)[/dim]")
            except Exception as e:
                console.print(f"  Resolved IP: [dim]Could not resolve ({e})[/dim]")

            console.print(f"  Port: [yellow]{endpoint_port}[/yellow]")
            console.print(f"  Full Endpoint: [yellow]{endpoint_fqdn}:{endpoint_port}[/yellow]")
        else:
            console.print(f"  [yellow]No endpoint found in client configs[/yellow]")
            console.print(f"  Port: [yellow]{interface.listen_port or 51820}[/yellow]")

        # Display VPN network configuration (internal addresses)
        console.print("\n[bold cyan]VPN Network Configuration (Internal):[/bold cyan]")

        table = Table(show_header=True, box=box.ROUNDED)
        table.add_column("Setting", style="cyan")
        table.add_column("Value", style="yellow")
        table.add_column("Action", style="dim")

        table.add_row("IPv4 Network", network_info['network_ipv4'] or "Not set", "[E]dit")
        table.add_row("IPv6 Network", network_info['network_ipv6'] or "Not set", "[E]dit")
        table.add_row("Coordination Server IPv4", network_info['ipv4_address'] or "Not set", "[E]dit")
        table.add_row("Coordination Server IPv6", network_info['ipv6_address'] or "Not set", "[E]dit")
        table.add_row("ListenPort", str(interface.listen_port) if interface.listen_port else "Not set", "[E]dit")

        mtu_value = str(interface.mtu) if interface.mtu else "Not set (will use 1420)"
        table.add_row("MTU", mtu_value, "[E]dit")

        console.print(table)

        # For now, auto-accept (will add editing later if needed)
        if not self._confirm("\nAccept network configuration?", default=True):
            console.print("[yellow]Network configuration editing not yet implemented[/yellow]")
            return

        # Display PostUp rules
        if interface.postup_rules:
            console.print("\n[bold cyan]PostUp Rules:[/bold cyan]")
            for i, rule in enumerate(interface.postup_rules, 1):
                console.print(f"  [{i}] {rule}")

            if not self._confirm("\nAccept all PostUp rules?", default=True):
                console.print("[yellow]PostUp rule editing not yet implemented[/yellow]")
                return

        # Display PostDown rules
        if interface.postdown_rules:
            console.print("\n[bold cyan]PostDown Rules:[/bold cyan]")
            for i, rule in enumerate(interface.postdown_rules, 1):
                console.print(f"  [{i}] {rule}")

            if not self._confirm("\nAccept all PostDown rules?", default=True):
                console.print("[yellow]PostDown rule editing not yet implemented[/yellow]")
                return

        # SSH Configuration
        console.print("\n[bold cyan]SSH Configuration:[/bold cyan]")

        # Try to extract hostname from endpoint if we have one
        ssh_host_default = "UPDATE_ME"
        for peer in cs.peers:
            if peer.endpoint:
                ssh_host_default = peer.endpoint.split(':')[0]
                break

        if self.auto_confirm:
            ssh_host = ssh_host_default
            ssh_user = getpass.getuser()
            ssh_port = 22
            console.print(f"  SSH hostname: {ssh_host} [dim](default)[/dim]")
            console.print(f"  SSH username: {ssh_user} [dim](default)[/dim]")
            console.print(f"  SSH port: {ssh_port} [dim](default)[/dim]")
        else:
            ssh_host = Prompt.ask("SSH hostname or IP address", default=ssh_host_default)
            ssh_user = Prompt.ask("SSH username", default=getpass.getuser())
            ssh_port = IntPrompt.ask("SSH port", default=22)

        # Derive endpoint from SSH host if not found
        endpoint = ssh_host + ":51820"  # Default WireGuard port

        # Derive public key from private key
        try:
            public_key = self.extractor.derive_public_key_from_private(interface.private_key)
        except Exception as e:
            console.print(f"[red]Failed to derive public key: {e}[/red]")
            console.print("[yellow]Make sure WireGuard tools are installed (wg command)[/yellow]")
            return

        # Save to database
        self.cs_id = self.db.save_coordination_server(
            endpoint=endpoint,
            public_key=public_key,
            private_key=interface.private_key,
            network_ipv4=network_info['network_ipv4'],
            network_ipv6=network_info['network_ipv6'],
            ipv4_address=network_info['ipv4_address'],
            ipv6_address=network_info['ipv6_address'],
            raw_interface_block=interface.raw_text,
            listen_port=interface.listen_port,
            mtu=interface.mtu,
            ssh_host=ssh_host,
            ssh_user=ssh_user,
            ssh_port=ssh_port,
        )

        # Save PostUp/PostDown rules
        if interface.postup_rules:
            self.db.save_cs_postup_rules(self.cs_id, interface.postup_rules)
        if interface.postdown_rules:
            self.db.save_cs_postdown_rules(self.cs_id, interface.postdown_rules)

        # Save ALL peers from CS config (even if we don't have their client configs)
        # This preserves the original CS config perfectly
        for position, peer in enumerate(cs.peers, start=1):
            # Save peer order
            self.db.save_peer_order(self.cs_id, peer.public_key, position, is_subnet_router=False)

            # Extract peer info
            peer_info = self.extractor.extract_peer_addresses(peer)
            friendly_name = peer.comment_lines[0] if peer.comment_lines else f"Peer-{position}"

            # Save peer to database (without client config - raw_interface_block=None)
            # This will be updated later if we find matching client config
            try:
                self.db.save_peer(
                    name=friendly_name,
                    cs_id=self.cs_id,
                    public_key=peer.public_key,
                    ipv4_address=peer_info['ipv4_address'] or '0.0.0.0',
                    ipv6_address=peer_info['ipv6_address'] or '::',
                    access_level='full_access',  # Default
                    raw_peer_block=peer.raw_text,
                    private_key=None,  # Don't have it yet
                    raw_interface_block=None,  # Don't have client config yet
                    preshared_key=peer.preshared_key,
                    persistent_keepalive=peer.persistent_keepalive,
                    has_endpoint=peer.endpoint is not None,
                    endpoint=peer.endpoint,
                )
            except Exception as e:
                # Ignore duplicate name errors - will update in Phase 3/4
                pass

        console.print(f"\n[green]✓ Coordination server saved (ID: {self.cs_id})[/green]")

    def _phase3_confirm_subnet_routers(self):
        """Phase 3: Subnet Router confirmation workflow"""
        console.print("\n[bold]Phase 3: Subnet Router Configuration[/bold]")

        for sn_config in self.sn_configs:
            console.print(f"\n[bold cyan]Subnet Router: {sn_config.file_path.name}[/bold cyan]")

            # Derive public key from SN's private key
            sn_interface = sn_config.interface
            try:
                sn_public_key = self.extractor.derive_public_key_from_private(sn_interface.private_key)
            except Exception as e:
                console.print(f"[red]Failed to derive public key: {e}[/red]")
                continue

            # Find matching peer in CS config
            matching_peer = None
            for peer in self.cs_config.peers:
                if peer.public_key == sn_public_key:
                    matching_peer = peer
                    break

            if not matching_peer:
                console.print(f"[yellow]No matching peer found in CS config for {sn_config.file_path.name}[/yellow]")

                # Let user select which CS peer this is
                console.print("\nAvailable peers in CS config:")
                for i, peer in enumerate(self.cs_config.peers, 1):
                    peer_info = self.extractor.extract_peer_addresses(peer)
                    name = peer.comment_lines[0] if peer.comment_lines else f"Peer {i}"
                    console.print(f"  [{i}] {name} ({peer_info['ipv4_address']}, {peer_info['ipv6_address']})")

                if self.auto_confirm:
                    console.print("[yellow]Auto-confirm mode: Skipping this subnet router (no public key match)[/yellow]")
                    continue
                else:
                    selection = IntPrompt.ask("Select peer number (0 to skip)", default=0)
                    if selection == 0 or selection > len(self.cs_config.peers):
                        console.print("[yellow]Skipping this subnet router[/yellow]")
                        continue

                    matching_peer = self.cs_config.peers[selection - 1]

            # Extract info from matching peer
            peer_info = self.extractor.extract_peer_addresses(matching_peer)
            friendly_name = matching_peer.comment_lines[0] if matching_peer.comment_lines else sn_config.file_path.stem

            console.print(f"\n[green]✓ Matched to peer: {friendly_name}[/green]")
            console.print(f"  IPv4: {peer_info['ipv4_address']}")
            console.print(f"  IPv6: {peer_info['ipv6_address']}")

            # Extract LAN networks
            lan_networks = self.extractor.extract_lan_networks(matching_peer)
            if lan_networks:
                console.print(f"\n[bold cyan]LAN networks advertised:[/bold cyan]")
                for lan in lan_networks:
                    console.print(f"  • {lan}")

            if not self._confirm("\nConfirm this subnet router?", default=True):
                console.print("[yellow]Skipping[/yellow]")
                continue

            # Update the existing peer record to mark it as a subnet router
            # First, delete the peer record (it will be replaced by subnet_router record)
            with self.db._connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    DELETE FROM peer WHERE cs_id = ? AND public_key = ?
                """, (self.cs_id, sn_public_key))

            # Save to subnet_router table
            sn_id = self.db.save_subnet_router(
                name=friendly_name,
                cs_id=self.cs_id,
                public_key=sn_public_key,
                private_key=sn_interface.private_key,
                ipv4_address=peer_info['ipv4_address'],
                ipv6_address=peer_info['ipv6_address'],
                allowed_ips=matching_peer.allowed_ips,
                raw_interface_block=sn_interface.raw_text,
                raw_peer_block=matching_peer.raw_text,
                mtu=sn_interface.mtu,
                has_endpoint=matching_peer.endpoint is not None,
                endpoint=matching_peer.endpoint,
            )

            # Save PostUp/PostDown rules
            if sn_interface.postup_rules:
                self.db.save_sn_postup_rules(sn_id, sn_interface.postup_rules)
            if sn_interface.postdown_rules:
                self.db.save_sn_postdown_rules(sn_id, sn_interface.postdown_rules)

            # Save LAN networks
            if lan_networks:
                self.db.save_sn_lan_networks(sn_id, lan_networks)

            # Update peer order to mark as subnet router
            with self.db._connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE cs_peer_order
                    SET is_subnet_router = 1
                    WHERE cs_id = ? AND peer_public_key = ?
                """, (self.cs_id, sn_public_key))

            console.print(f"[green]✓ Subnet router '{friendly_name}' saved (ID: {sn_id})[/green]")

    def _phase4_review_peers(self):
        """Phase 4: Peer review workflow"""
        console.print("\n[bold]Phase 4: Peer Review[/bold]")

        for client_config in self.client_configs:
            console.print(f"\n[bold cyan]Client: {client_config.file_path.name}[/bold cyan]")

            # Derive public key from client's private key
            client_interface = client_config.interface
            try:
                client_public_key = self.extractor.derive_public_key_from_private(client_interface.private_key)
            except Exception as e:
                console.print(f"[red]Failed to derive public key: {e}[/red]")
                continue

            # Find matching peer in CS config
            matching_peer = None
            for peer in self.cs_config.peers:
                if peer.public_key == client_public_key:
                    matching_peer = peer
                    break

            if not matching_peer:
                console.print(f"[yellow]No matching peer found in CS config[/yellow]")
                # Could offer to add as new peer in future
                continue

            # Extract peer info
            peer_info = self.extractor.extract_peer_addresses(matching_peer)
            friendly_name = matching_peer.comment_lines[0] if matching_peer.comment_lines else client_config.file_path.stem

            console.print(f"\n[green]✓ Matches existing peer: {friendly_name}[/green]")
            console.print(f"  IPv4: {peer_info['ipv4_address']}")
            console.print(f"  IPv6: {peer_info['ipv6_address']}")
            console.print(f"  PresharedKey: {'Yes' if matching_peer.preshared_key else 'No'}")
            console.print(f"  PersistentKeepalive: {matching_peer.persistent_keepalive or 'Not set'}")

            # Determine access level from AllowedIPs
            console.print("\n[bold cyan]Access Level:[/bold cyan]")
            console.print("  [1] Full access (all AllowedIPs from CS peer)")
            console.print("  [2] VPN only (10.66.0.0/24, fd66:6666::/64)")
            console.print("  [3] LAN only (access via subnet routers)")
            console.print("  [4] Custom (specify - parking lot)")

            if self.auto_confirm:
                access_choice = 1
                console.print(f"  Selected: 1 (Full access) [dim](default)[/dim]")
            else:
                access_choice = IntPrompt.ask("Select access level", default=1)

            access_level_map = {
                1: 'full_access',
                2: 'vpn_only',
                3: 'lan_only',
                4: 'custom'
            }
            access_level = access_level_map.get(access_choice, 'full_access')

            if access_level == 'custom':
                console.print("[yellow]Custom access levels not yet implemented, using full_access[/yellow]")
                access_level = 'full_access'

            if not self._confirm("\nConfirm this peer?", default=True):
                console.print("[yellow]Skipping[/yellow]")
                continue

            # Update existing peer record with client config details
            with self.db._connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE peer
                    SET private_key = ?,
                        raw_interface_block = ?,
                        access_level = ?
                    WHERE cs_id = ? AND public_key = ?
                """, (client_interface.private_key, client_interface.raw_text, access_level,
                      self.cs_id, client_public_key))

            console.print(f"[green]✓ Peer '{friendly_name}' updated with client config[/green]")

    def _phase5_verify_and_finalize(self):
        """Phase 5: Verify reconstructed configs match originals"""
        console.print("\n[bold]Phase 5: Verification[/bold]")

        # Reconstruct CS config
        console.print("\n[bold cyan]Reconstructing coordination server config...[/bold cyan]")
        reconstructed_cs = self.db.reconstruct_cs_config()

        # Display
        console.print(Panel(
            self._mask_private_keys(reconstructed_cs),
            title="Reconstructed Coordination Server Config",
            border_style="green"
        ))

        # Save to output directory
        output_dir = Path("output")
        output_dir.mkdir(exist_ok=True)

        cs_output_file = output_dir / "coordination.conf"
        with open(cs_output_file, 'w') as f:
            f.write(reconstructed_cs)
        cs_output_file.chmod(0o600)

        console.print(f"\n[green]✓ Saved to {cs_output_file}[/green]")

        if not self._confirm("\nFinalize import?", default=True):
            console.print("[yellow]Import cancelled, but data is saved in database[/yellow]")
            return

        console.print("\n[bold green]✓ Import finalized successfully![/bold green]")
        console.print(f"Database: {self.db_path}")
        console.print(f"Configs: {output_dir}/")

    def _mask_private_keys(self, config_text: str) -> str:
        """Mask PrivateKey values in config text for display"""
        lines = []
        for line in config_text.split('\n'):
            if 'PrivateKey' in line and '=' in line:
                key, value = line.split('=', 1)
                lines.append(f"{key}= ******* [dim](masked in preview)[/dim]")
            else:
                lines.append(line)
        return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Import existing WireGuard configurations"
    )
    parser.add_argument(
        "--import-dir",
        type=Path,
        default=Path("import"),
        help="Directory containing .conf files to import"
    )
    parser.add_argument(
        "--db",
        type=Path,
        default=Path("wg-friend.db"),
        help="SQLite database path"
    )
    parser.add_argument(
        "--clear-db",
        action="store_true",
        help="Clear all data from database before import"
    )
    parser.add_argument(
        "-y", "--yes",
        action="store_true",
        help="Auto-confirm all prompts (non-interactive mode)"
    )

    args = parser.parse_args()

    # Clear database if requested
    if args.clear_db:
        if args.db.exists():
            db = WireGuardDB(args.db)
            db.clear_all_data()
            console.print(f"[yellow]Cleared all data from {args.db}[/yellow]")

    # Run import
    onboarder = WireGuardOnboarder(args.import_dir, args.db, auto_confirm=args.yes)
    onboarder.run()


if __name__ == "__main__":
    main()
