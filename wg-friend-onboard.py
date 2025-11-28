#!/usr/bin/env python3
"""
wg-friend Onboarding Script v2
Import existing WireGuard configs or create new ones
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
    """Import WireGuard configs or create new ones via wizard"""

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
            "Import existing WireGuard configurations or create new ones",
            border_style="cyan"
        ))

        try:
            # Check if import directory is empty - offer wizard mode
            if not self.import_dir.exists() or not list(self.import_dir.glob("*.conf")):
                console.print(f"\n[yellow]No WireGuard configs found in {self.import_dir}/[/yellow]")

                if self.auto_confirm:
                    console.print("[yellow]Auto-confirm mode: Cannot run wizard mode non-interactively[/yellow]")
                    console.print(f"[yellow]Place .conf files in {self.import_dir}/ and run again[/yellow]")
                    sys.exit(0)

                if Confirm.ask("\n[bold]Create new WireGuard network from scratch?[/bold]", default=False):
                    self._wizard_mode()
                    # Wizard creates configs in import/, now continue with normal import
                else:
                    console.print(f"\n[yellow]Place your WireGuard .conf files in {self.import_dir}/ and run again[/yellow]")
                    sys.exit(0)

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

        # Check if database already has data (for re-imports without --clear-db)
        existing_cs = self.db.get_coordination_server()
        if existing_cs:
            console.print("[yellow]⚠ Database already contains imported data[/yellow]")
            console.print("[yellow]  Re-importing will replace existing data[/yellow]")
            if not self.auto_confirm:
                if not Confirm.ask("Continue and replace existing data?", default=False):
                    console.print("[yellow]Import cancelled. Use --clear-db to start fresh.[/yellow]")
                    sys.exit(0)
            # Clear existing data
            self.db.clear_all_data()
            console.print("[green]✓ Cleared existing data[/green]")

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

        # Display WireGuard network configuration (internal addresses)
        console.print("\n[bold cyan]WireGuard Network Configuration (Internal):[/bold cyan]")

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

        # SSH Configuration for Coordination Server
        console.print("\n[bold cyan]SSH Configuration (Coordination Server):[/bold cyan]")
        console.print("[dim]Used for deploying updated configs to the server[/dim]")

        # Use the endpoint FQDN we already extracted
        ssh_host_default = endpoint_fqdn if endpoint_fqdn else "UPDATE_ME"

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

        # Use the endpoint we already have, or derive from SSH host
        endpoint = f"{endpoint_fqdn}:{endpoint_port}" if endpoint_fqdn else f"{ssh_host}:51820"

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

            # Display PostUp/PostDown rules for verification
            if sn_interface.postup_rules:
                console.print(f"\n[bold cyan]PostUp rules ({len(sn_interface.postup_rules)}):[/bold cyan]")
                for i, rule in enumerate(sn_interface.postup_rules, 1):
                    console.print(f"  [{i}] [yellow]{rule}[/yellow]")
            else:
                console.print(f"\n[dim]No PostUp rules[/dim]")

            if sn_interface.postdown_rules:
                console.print(f"\n[bold cyan]PostDown rules ({len(sn_interface.postdown_rules)}):[/bold cyan]")
                for i, rule in enumerate(sn_interface.postdown_rules, 1):
                    console.print(f"  [{i}] [yellow]{rule}[/yellow]")
            else:
                console.print(f"\n[dim]No PostDown rules[/dim]")

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

                # Also delete existing subnet_router with same name (for re-imports)
                cursor.execute("""
                    DELETE FROM subnet_router WHERE cs_id = ? AND name = ?
                """, (self.cs_id, friendly_name))

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

            # Extract and analyze current AllowedIPs from client config
            client_allowed_ips = ""
            if client_config.peers and client_config.peers[0].allowed_ips:
                client_allowed_ips = client_config.peers[0].allowed_ips

            console.print(f"\n[bold cyan]Current Access (from client config):[/bold cyan]")
            console.print(f"  AllowedIPs: [yellow]{client_allowed_ips}[/yellow]")

            # Infer access level from current AllowedIPs
            cs = self.db.get_coordination_server()
            vpn_networks = {cs['network_ipv4'], cs['network_ipv6']}

            # Get LAN networks from subnet routers
            lan_networks = set()
            for sn in self.db.get_subnet_routers(cs['id']):
                lan_networks.update(self.db.get_sn_lan_networks(sn['id']))

            # Parse client's current allowed IPs
            client_networks = set(ip.strip() for ip in client_allowed_ips.split(',') if ip.strip())

            # Infer access level
            has_vpn = vpn_networks.issubset(client_networks)
            has_lans = lan_networks.issubset(client_networks) if lan_networks else False

            if has_lans and has_vpn:
                inferred_level = 1  # full_access or lan_only
                inferred_text = "Full access (has VPN + LAN networks)"
            elif has_vpn and not has_lans:
                inferred_level = 2  # vpn_only
                inferred_text = "VPN only (only VPN networks, no LANs)"
            elif has_lans:
                inferred_level = 3  # lan_only
                inferred_text = "LAN only (has LAN access)"
            else:
                inferred_level = 1  # Default to full_access if unclear
                inferred_text = "Full access (default)"

            console.print(f"  Inferred: [green]{inferred_text}[/green]")

            # Determine access level from AllowedIPs
            console.print("\n[bold cyan]Select Access Level:[/bold cyan]")
            console.print("  [1] Full access (all AllowedIPs from CS peer)")
            console.print("  [2] VPN only (VPN network only)")
            console.print("  [3] LAN only (access via subnet routers)")
            console.print("  [4] Custom (specify - parking lot)")

            if self.auto_confirm:
                access_choice = inferred_level
                console.print(f"  Selected: {inferred_level} [dim](inferred)[/dim]")
            else:
                access_choice = IntPrompt.ask("Select access level", default=inferred_level)

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
        console.print("\n[bold]Phase 5: Verification & Validation[/bold]")

        # Basic validation checks
        console.print("\n[bold cyan]Running validation checks...[/bold cyan]")
        self._run_validation_checks()

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

        # Reconstruct and save subnet router configs
        cs = self.db.get_coordination_server()
        subnet_routers = self.db.get_subnet_routers(cs['id'])
        if subnet_routers:
            console.print("\n[bold cyan]Reconstructing subnet router configs...[/bold cyan]")
            for sn in subnet_routers:
                reconstructed_sn = self.db.reconstruct_sn_config(sn['id'])
                sn_output_file = output_dir / f"{sn['name']}.conf"
                with open(sn_output_file, 'w') as f:
                    f.write(reconstructed_sn)
                sn_output_file.chmod(0o600)
                console.print(f"[green]✓ Saved {sn['name']} to {sn_output_file}[/green]")

        if not self._confirm("\nFinalize import?", default=True):
            console.print("[yellow]Import cancelled, but data is saved in database[/yellow]")
            return

        console.print("\n[bold green]✓ Import finalized successfully![/bold green]")
        console.print(f"Database: {self.db_path}")
        console.print(f"Configs: {output_dir}/")

    def _run_validation_checks(self):
        """Run basic validation checks on imported data"""
        import re
        import ipaddress
        import subprocess

        warnings = []
        checks_passed = 0

        cs = self.db.get_coordination_server()

        # 1. Validate WireGuard key format (44 chars base64)
        def validate_key(key: str, key_type: str, entity: str) -> bool:
            if not key:
                return True  # Optional keys are ok
            if len(key) != 44:
                warnings.append(f"  ⚠ {entity} {key_type}: Invalid length ({len(key)} chars, expected 44)")
                return False
            if not re.match(r'^[A-Za-z0-9+/]{43}=$', key):
                warnings.append(f"  ⚠ {entity} {key_type}: Invalid base64 format")
                return False
            return True

        # Validate CS keys
        if validate_key(cs['public_key'], 'PublicKey', 'CS'):
            checks_passed += 1
        if validate_key(cs['private_key'], 'PrivateKey', 'CS'):
            checks_passed += 1

        # 2. Validate IP addresses and CIDR notation
        def validate_ip(ip_str: str, ip_type: str, entity: str) -> bool:
            if not ip_str:
                return True  # Optional IPs are ok
            try:
                ipaddress.ip_address(ip_str)
                return True
            except ValueError:
                warnings.append(f"  ⚠ {entity} {ip_type}: Invalid IP address '{ip_str}'")
                return False

        def validate_cidr(cidr_str: str, cidr_type: str, entity: str) -> bool:
            if not cidr_str:
                return True
            try:
                ipaddress.ip_network(cidr_str, strict=False)
                return True
            except ValueError:
                warnings.append(f"  ⚠ {entity} {cidr_type}: Invalid CIDR '{cidr_str}'")
                return False

        # Validate CS networks
        if validate_cidr(cs['network_ipv4'], 'IPv4 Network', 'CS'):
            checks_passed += 1
        if validate_cidr(cs['network_ipv6'], 'IPv6 Network', 'CS'):
            checks_passed += 1
        if validate_ip(cs['ipv4_address'], 'IPv4 Address', 'CS'):
            checks_passed += 1
        if validate_ip(cs['ipv6_address'], 'IPv6 Address', 'CS'):
            checks_passed += 1

        # Validate subnet routers
        for sn in self.db.get_subnet_routers(cs['id']):
            if validate_key(sn['public_key'], 'PublicKey', f"SN:{sn['name']}"):
                checks_passed += 1
            if validate_ip(sn['ipv4_address'], 'IPv4', f"SN:{sn['name']}"):
                checks_passed += 1
            if validate_ip(sn['ipv6_address'], 'IPv6', f"SN:{sn['name']}"):
                checks_passed += 1

            # Validate LAN networks
            for lan in self.db.get_sn_lan_networks(sn['id']):
                if validate_cidr(lan, 'LAN Network', f"SN:{sn['name']}"):
                    checks_passed += 1

        # Validate peers
        for peer in self.db.get_peers(cs['id']):
            if validate_key(peer['public_key'], 'PublicKey', f"Peer:{peer['name']}"):
                checks_passed += 1
            if validate_ip(peer['ipv4_address'], 'IPv4', f"Peer:{peer['name']}"):
                checks_passed += 1
            if validate_ip(peer['ipv6_address'], 'IPv6', f"Peer:{peer['name']}"):
                checks_passed += 1

        # 3. Ping CS endpoint (friendly check)
        if cs['ssh_host']:
            console.print(f"  Checking connectivity to {cs['ssh_host']}...", end=" ")
            try:
                result = subprocess.run(
                    ['ping', '-c', '1', '-W', '2', cs['ssh_host']],
                    capture_output=True,
                    timeout=3
                )
                if result.returncode == 0:
                    console.print("[green]✓ Reachable[/green]")
                    checks_passed += 1
                else:
                    console.print("[yellow]✗ Not reachable[/yellow]")
                    warnings.append(f"  ⚠ CS endpoint '{cs['ssh_host']}' is not reachable")
            except (subprocess.TimeoutExpired, FileNotFoundError):
                console.print("[dim]⊘ Ping unavailable[/dim]")

        # Display results
        if warnings:
            console.print(f"\n[yellow]Validation warnings ({len(warnings)}):[/yellow]")
            for warning in warnings:
                console.print(warning)

        console.print(f"[green]✓ {checks_passed} validation checks passed[/green]")

    def _wizard_mode(self):
        """Wizard mode for creating configs from scratch"""
        from src.keygen import generate_keypair

        console.print("\n[bold cyan]═══ Create New WireGuard Network ═══[/bold cyan]")
        console.print("\nThis wizard will help you create WireGuard configurations from scratch.\n")

        # Ensure import directory exists
        self.import_dir.mkdir(exist_ok=True)

        # Step 1: Create Coordination Server
        console.print("[bold]Step 1: Coordination Server[/bold]")
        console.print("This runs on your cloud VPS or dedicated server with a public IP.\n")

        cs_config = self._wizard_create_coordination_server()

        # Step 2: Create Subnet Routers (optional)
        subnet_routers = []
        if Confirm.ask("\n[bold]Add subnet router(s)?[/bold]", default=False):
            while True:
                sr_config = self._wizard_create_subnet_router(cs_config)
                if sr_config:
                    subnet_routers.append(sr_config)
                if not Confirm.ask("\nAdd another subnet router?", default=False):
                    break

        # Step 3: Create Client Peers (optional)
        client_peers = []
        if Confirm.ask("\n[bold]Create initial client peer(s)?[/bold]", default=False):
            while True:
                peer_config = self._wizard_create_client_peer(cs_config, subnet_routers)
                if peer_config:
                    client_peers.append(peer_config)
                if not Confirm.ask("\nAdd another peer?", default=False):
                    break

        # Summary
        console.print("\n[bold cyan]═══ Summary ═══[/bold cyan]")
        console.print(f"\nCreated {1 + len(subnet_routers) + len(client_peers)} configuration(s):")
        console.print(f"  ✓ {self.import_dir}/coordination.conf")
        for sr in subnet_routers:
            console.print(f"  ✓ {self.import_dir}/{sr['name']}.conf")
        for peer in client_peers:
            console.print(f"  ✓ {self.import_dir}/{peer['name']}.conf")

        console.print("\n[green]Proceeding with import...[/green]\n")

    def _wizard_create_coordination_server(self):
        """Create coordination server config"""
        from src.keygen import generate_keypair

        # Get server details
        endpoint = Prompt.ask("Public IP or hostname", default="UPDATE_ME")
        port = IntPrompt.ask("WireGuard port", default=51820)

        # VPN networks
        vpn_v4 = Prompt.ask("VPN IPv4 network", default="10.20.0.0/24")
        vpn_v6 = Prompt.ask("VPN IPv6 network", default="fd20::/64")
        use_ipv6 = Confirm.ask("Use IPv6?", default=True)

        # CS addresses (first IP in networks)
        cs_ipv4 = ".".join(vpn_v4.split("/")[0].split(".")[:3]) + ".1"
        cs_ipv6 = vpn_v6.split("/")[0].rstrip(":") + "::1"

        # Generate keys
        private_key, public_key = generate_keypair()

        # Build config
        config_lines = ["[Interface]"]
        config_lines.append(f"PrivateKey = {private_key}")
        config_lines.append(f"Address = {cs_ipv4}/24" + (f", {cs_ipv6}/64" if use_ipv6 else ""))
        config_lines.append(f"ListenPort = {port}")
        config_lines.append("")

        # Save config
        cs_path = self.import_dir / "coordination.conf"
        with open(cs_path, 'w') as f:
            f.write("\n".join(config_lines) + "\n")
        cs_path.chmod(0o600)

        console.print(f"\n[green]✓ Coordination server config created: {cs_path}[/green]")

        return {
            'endpoint': f"{endpoint}:{port}",
            'public_key': public_key,
            'vpn_v4': vpn_v4,
            'vpn_v6': vpn_v6 if use_ipv6 else None,
            'cs_ipv4': cs_ipv4,
            'cs_ipv6': cs_ipv6 if use_ipv6 else None,
        }

    def _wizard_create_subnet_router(self, cs_config):
        """Create subnet router config"""
        from src.keygen import generate_keypair

        console.print("\n[bold cyan]═══ Subnet Router Configuration ═══[/bold cyan]")

        name = Prompt.ask("\nRouter name (e.g., 'home-router', 'office-gateway')")

        # LAN network
        console.print("\n[bold]LAN Network[/bold]")
        console.print("[dim]The subnet your LAN uses (configured at your router/gateway)[/dim]\n")
        console.print("[yellow]💡 Good Neighbor Tip:[/yellow]")
        console.print("[dim]If your router currently uses 192.168.0.0/24 or 192.168.1.0/24,")
        console.print("consider changing it (at the router level) to a less common subnet.")
        console.print("Many public WiFi networks use these ranges, which can cause routing")
        console.print("conflicts when you connect to WireGuard from remote locations.")
        console.print("Using a third octet between 15-230 (e.g., 192.168.47.0/24) minimizes")
        console.print("these conflicts. This is configured at your router, not by this script.[/dim]\n")
        console.print("Examples: 192.168.10.0/24, 192.168.47.0/24, 10.0.10.0/24")
        lan_network = Prompt.ask("Network CIDR")

        # LAN interface with detailed instructions
        console.print("\n[bold yellow]⚠  LAN Interface Name (on the subnet router host)[/bold yellow]")
        console.print("\n[dim]This is the network interface ON THE SUBNET ROUTER HOST, not this machine.[/dim]\n")
        console.print("To find the interface name, SSH to your subnet router and run:\n")
        console.print("  [cyan]ip link show[/cyan]        # Lists all network interfaces")
        console.print("  [cyan]ip addr show[/cyan]        # Shows IPs assigned to each interface\n")
        console.print("Look for the interface connected to your LAN network.\n")
        console.print("[bold]Common examples:[/bold]")
        console.print("  • eth0, eth1          (traditional naming)")
        console.print("  • enp1s0, ens18       (predictable naming)")
        console.print("  • br0                 (bridge interface)\n")

        lan_iface = Prompt.ask("LAN interface name (on subnet router host)")

        # Generate PostUp/PostDown
        gen_rules = Confirm.ask("\nGenerate default NAT rules?", default=True)

        if gen_rules:
            console.print("\n[dim]Default rules will include:")
            console.print("  ✓ Enable IP forwarding")
            console.print("  ✓ NAT/Masquerade for VPN → LAN traffic")
            if cs_config['vpn_v6']:
                console.print("  ✓ IPv6 support")
            console.print("\nℹ  Advanced rules (FORWARD chains, MSS clamping, port forwarding)")
            console.print("   can be added manually after import.[/dim]\n")

        # Generate keys
        private_key, public_key = generate_keypair()

        # Allocate IP (next after CS)
        sr_ipv4 = ".".join(cs_config['cs_ipv4'].split(".")[:3]) + ".20"  # Simple allocation
        sr_ipv6 = cs_config['cs_ipv6'].rsplit(":", 1)[0] + ":20" if cs_config['vpn_v6'] else None

        # Build config
        config_lines = ["[Interface]"]
        config_lines.append(f"PrivateKey = {private_key}")
        config_lines.append(f"Address = {sr_ipv4}/24" + (f", {sr_ipv6}/64" if sr_ipv6 else ""))

        if gen_rules:
            postup, postdown = self._generate_default_postup_postdown(
                lan_iface,
                cs_config['vpn_v4'],
                cs_config['vpn_v6'],
                bool(cs_config['vpn_v6'])
            )
            for rule in postup:
                config_lines.append(f"PostUp = {rule}")
            for rule in postdown:
                config_lines.append(f"PostDown = {rule}")

        config_lines.append("")
        config_lines.append("[Peer]")
        config_lines.append(f"PublicKey = {cs_config['public_key']}")
        config_lines.append(f"Endpoint = {cs_config['endpoint']}")
        config_lines.append(f"AllowedIPs = {cs_config['vpn_v4']}" + (f", {cs_config['vpn_v6']}" if cs_config['vpn_v6'] else ""))
        config_lines.append("PersistentKeepalive = 25")
        config_lines.append("")

        # Save config
        sr_path = self.import_dir / f"{name}.conf"
        with open(sr_path, 'w') as f:
            f.write("\n".join(config_lines) + "\n")
        sr_path.chmod(0o600)

        console.print(f"\n[green]✓ Subnet router config created: {sr_path}[/green]")

        # Update coordination.conf with this peer
        cs_path = self.import_dir / "coordination.conf"
        with open(cs_path, 'a') as f:
            f.write(f"# {name}\n")
            f.write(f"[Peer]\n")
            f.write(f"PublicKey = {public_key}\n")
            f.write(f"AllowedIPs = {sr_ipv4}/32" + (f", {sr_ipv6}/128" if sr_ipv6 else "") + f", {lan_network}\n")
            f.write("\n")

        return {
            'name': name,
            'lan_network': lan_network,
            'ipv4': sr_ipv4,
            'ipv6': sr_ipv6,
        }

    def _wizard_create_client_peer(self, cs_config, subnet_routers):
        """Create client peer config"""
        from src.keygen import generate_keypair

        console.print("\n[bold cyan]═══ Client Peer Configuration ═══[/bold cyan]")

        name = Prompt.ask("\nPeer name (e.g., 'alice-laptop', 'my-phone')")

        # Allocate IP (simple: .10+)
        peer_num = 10  # Could track this better
        peer_ipv4 = ".".join(cs_config['cs_ipv4'].split(".")[:3]) + f".{peer_num}"
        peer_ipv6 = cs_config['cs_ipv6'].rsplit(":", 1)[0] + f":{peer_num:x}" if cs_config['vpn_v6'] else None

        # Access level
        console.print("\n[bold]Access Level:[/bold]")
        console.print("  [1] Full access (VPN + all LANs)")
        console.print("  [2] VPN only")
        console.print("  [3] LAN only")
        access = IntPrompt.ask("Select", default=1)

        # Calculate AllowedIPs
        allowed_ips = [cs_config['vpn_v4']]
        if cs_config['vpn_v6']:
            allowed_ips.append(cs_config['vpn_v6'])

        if access in [1, 3]:  # full_access or lan_only
            for sr in subnet_routers:
                allowed_ips.append(sr['lan_network'])

        # Generate keys
        private_key, public_key = generate_keypair()

        # Build client config
        config_lines = ["[Interface]"]
        config_lines.append(f"PrivateKey = {private_key}")
        config_lines.append(f"Address = {peer_ipv4}/24" + (f", {peer_ipv6}/64" if peer_ipv6 else ""))
        config_lines.append(f"DNS = {cs_config['cs_ipv4']}")
        config_lines.append("")
        config_lines.append("[Peer]")
        config_lines.append(f"PublicKey = {cs_config['public_key']}")
        config_lines.append(f"Endpoint = {cs_config['endpoint']}")
        config_lines.append(f"AllowedIPs = {', '.join(allowed_ips)}")
        config_lines.append("PersistentKeepalive = 25")
        config_lines.append("")

        # Save client config
        peer_path = self.import_dir / f"{name}.conf"
        with open(peer_path, 'w') as f:
            f.write("\n".join(config_lines) + "\n")
        peer_path.chmod(0o600)

        console.print(f"\n[green]✓ Client peer config created: {peer_path}[/green]")

        # Update coordination.conf with this peer
        cs_path = self.import_dir / "coordination.conf"
        with open(cs_path, 'a') as f:
            f.write(f"# {name}\n")
            f.write(f"[Peer]\n")
            f.write(f"PublicKey = {public_key}\n")
            f.write(f"AllowedIPs = {peer_ipv4}/32" + (f", {peer_ipv6}/128\n" if peer_ipv6 else "\n"))
            f.write("\n")

        return {
            'name': name,
            'ipv4': peer_ipv4,
            'ipv6': peer_ipv6,
        }

    def _generate_default_postup_postdown(self, lan_iface, vpn_v4_network, vpn_v6_network, use_ipv6):
        """Generate minimal working PostUp/PostDown rules for subnet router"""

        postup = [
            "sysctl -w net.ipv4.ip_forward=1",
        ]

        if use_ipv6:
            postup.append("sysctl -w net.ipv6.conf.all.forwarding=1")

        postup.append(f"iptables -t nat -A POSTROUTING -o {lan_iface} -s {vpn_v4_network} -j MASQUERADE")

        if use_ipv6:
            postup.append(f"ip6tables -t nat -A POSTROUTING -o {lan_iface} -s {vpn_v6_network} -j MASQUERADE")

        postdown = [
            f"iptables -t nat -D POSTROUTING -o {lan_iface} -s {vpn_v4_network} -j MASQUERADE",
        ]

        if use_ipv6:
            postdown.append(f"ip6tables -t nat -D POSTROUTING -o {lan_iface} -s {vpn_v6_network} -j MASQUERADE")

        return postup, postdown

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
