#!/usr/bin/env python3
"""
wg-friend Onboarding Script
Import existing WireGuard configs or setup from scratch with wizard
"""

import argparse
import yaml
import difflib
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

from rich.console import Console
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.panel import Panel
from rich.table import Table
from rich import box
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.syntax import Syntax

# Import wg-friend components
from src.keygen import generate_keypair, derive_public_key
from src.peer_manager import WireGuardPeerManager
from src.config_builder import WireGuardConfigBuilder
from src.metadata_db import PeerDatabase
from src.ssh_client import SSHClient
from src.qr_generator import generate_qr_code


console = Console()


class PeerStatus(Enum):
    """Peer connection status"""
    ACTIVE = "active"
    RECENT = "recent"
    STALE = "stale"
    DEAD = "dead"
    NEVER_CONNECTED = "never"


@dataclass
class CoordinatorPeer:
    """Peer found in coordinator config"""
    name: str
    public_key: str
    ipv4: str
    ipv6: str
    allowed_ips: List[str]
    comment: str
    created: Optional[datetime] = None
    last_handshake: Optional[datetime] = None
    inferred_type: str = "mobile_client"
    is_infrastructure: bool = False
    preshared_key: Optional[str] = None
    persistent_keepalive: Optional[int] = None
    endpoint: Optional[str] = None

    @property
    def status(self) -> PeerStatus:
        """Determine peer status from last handshake"""
        if self.last_handshake is None:
            return PeerStatus.NEVER_CONNECTED

        from datetime import timedelta
        age = datetime.now() - self.last_handshake

        if age < timedelta(hours=1):
            return PeerStatus.ACTIVE
        elif age < timedelta(days=7):
            return PeerStatus.RECENT
        elif age < timedelta(days=180):
            return PeerStatus.STALE
        else:
            return PeerStatus.DEAD

    @property
    def is_active(self) -> bool:
        """Check if peer is currently active"""
        return self.status == PeerStatus.ACTIVE


@dataclass
class ParsedConfig:
    """Parsed WireGuard configuration"""
    file_path: Path
    interface: Dict
    peers: List[Dict]
    config_type: Optional[str] = None


class ConfigScanner:
    """Scan directory for WireGuard configs"""

    def __init__(self, scan_path: Path):
        self.scan_path = Path(scan_path).expanduser()

    def find_configs(self) -> List[Path]:
        """Find all .conf files"""
        if not self.scan_path.exists():
            console.print(f"[red]Error: Path not found: {self.scan_path}[/red]")
            return []

        if self.scan_path.is_file():
            return [self.scan_path] if self.scan_path.suffix == '.conf' else []

        return sorted(self.scan_path.glob('*.conf'))

    def parse_config(self, config_path: Path) -> Optional[ParsedConfig]:
        """Parse a WireGuard config file - preserving peer block integrity"""
        try:
            with open(config_path) as f:
                lines = f.readlines()

            interface = {}
            peers = []
            current_section = None
            current_peer_lines = []  # Store raw lines for current peer block

            i = 0
            while i < len(lines):
                line = lines[i]
                line_stripped = line.strip()

                # Section headers
                if line_stripped.startswith('[Interface]'):
                    current_section = 'interface'
                    i += 1
                    continue

                elif line_stripped.startswith('[Peer]'):
                    # Save previous peer block if exists
                    if current_peer_lines:
                        peer_dict = self._parse_peer_block(current_peer_lines)
                        if peer_dict:
                            peers.append(peer_dict)

                    current_section = 'peer'
                    current_peer_lines = []
                    i += 1
                    continue

                # Collect lines for current section
                if current_section == 'interface':
                    if not line_stripped:
                        i += 1
                        continue

                    # Handle comments in Interface section - preserve them!
                    if line_stripped.startswith('#'):
                        # Store interface comments to preserve them
                        if 'comments' not in interface:
                            interface['comments'] = []
                        interface['comments'].append(line_stripped[1:].strip())
                        i += 1
                        continue

                    if '=' in line_stripped:
                        key, value = line_stripped.split('=', 1)
                        key = key.strip()
                        value = value.strip()

                        # Handle multiple values for same key (Address, PostUp, PostDown)
                        if key in ['Address', 'PostUp', 'PostDown']:
                            if key in interface:
                                if not isinstance(interface[key], list):
                                    interface[key] = [interface[key]]
                                interface[key].append(value)
                            else:
                                interface[key] = value
                        else:
                            interface[key] = value

                elif current_section == 'peer':
                    # Collect ALL lines in this peer block (including comments, blank lines)
                    current_peer_lines.append(line)

                i += 1

            # Add last peer block if exists
            if current_peer_lines:
                peer_dict = self._parse_peer_block(current_peer_lines)
                if peer_dict:
                    peers.append(peer_dict)

            return ParsedConfig(
                file_path=config_path,
                interface=interface,
                peers=peers
            )

        except Exception as e:
            console.print(f"[yellow]Warning: Failed to parse {config_path}: {e}[/yellow]")
            return None

    def _parse_peer_block(self, lines: List[str]) -> Optional[Dict]:
        """Parse a peer block preserving ALL comments and their positions"""
        peer = {}
        all_comments = []

        for line in lines:
            line_stripped = line.strip()

            if not line_stripped:
                continue

            if line_stripped.startswith('#'):
                comment = line_stripped.lstrip('#').strip()
                all_comments.append(comment)
                continue

            if '=' in line_stripped:
                key, value = line_stripped.split('=', 1)
                peer[key.strip()] = value.strip()

        # Store ALL comments concatenated (preserves multi-line comments)
        if all_comments:
            peer['comment'] = '\n'.join(all_comments)

        return peer if peer else None

    def detect_config_type(self, config: ParsedConfig) -> str:
        """Detect if config is coordinator, subnet_router, or client"""
        interface = config.interface
        peers = config.peers

        has_listen_port = 'ListenPort' in interface

        # Check for forwarding/routing infrastructure (subnet router signals)
        postup = interface.get('PostUp', '')
        postdown = interface.get('PostDown', '')
        combined_rules = f"{postup} {postdown}"

        has_forwarding = any([
            'MASQUERADE' in combined_rules,
            'SNAT' in combined_rules,
            'FORWARD' in combined_rules,
            'ip_forward=1' in combined_rules,
            'ip-forward=1' in combined_rules,
        ])

        # Key insight: clients have a single peer WITH an Endpoint (they connect TO the server)
        # Coordinators have multiple peers WITHOUT Endpoints (peers connect TO them)
        single_peer_with_endpoint = (
            len(peers) == 1 and
            peers[0].get('Endpoint')
        )

        # Coordination server: has listen port and many peers (even if it also has forwarding/NAT)
        # Check this FIRST - peer count is the strongest signal for coordination servers
        if has_listen_port and len(peers) > 3:
            return 'coordination_server'

        # Subnet router: has forwarding infrastructure (MASQUERADE, FORWARD rules, ip_forward)
        # Typically has few peers (just connects to coordination server)
        if has_forwarding:
            return 'subnet_router'

        # Client: single peer with endpoint and NO forwarding
        # (ListenPort may or may not be present - some generators add it unnecessarily)
        if single_peer_with_endpoint:
            return 'client'

        # Coordination server with few peers (small setup)
        if has_listen_port and len(peers) >= 1:
            return 'coordination_server'

        return 'unknown'


class WizardSetup:
    """Interactive wizard for from-scratch setup"""

    def __init__(self):
        self.console = Console()

    def run(self) -> Path:
        """Run complete wizard"""
        self.show_welcome()

        # Gather configuration
        coordinator = self.configure_coordinator()
        network = self.configure_network()
        subnet_router = self.configure_subnet_router()
        dns = self.configure_dns(subnet_router)
        templates = self.configure_templates(network, subnet_router, dns)

        # Build config
        config = self.build_config(coordinator, network, subnet_router, dns, templates)

        # Review and save
        self.review_config(config)

        if Confirm.ask("\nSave this configuration?", default=True):
            config_path = self.save_config(config)
            self.console.print(f"\n[green]✓ Saved to: {config_path}[/green]")

            # Initialize database
            db_path = Path(config['metadata_db']).expanduser()
            db_path.parent.mkdir(parents=True, exist_ok=True)
            with PeerDatabase(db_path) as db:
                pass  # Just create the DB
            self.console.print(f"[green]✓ Created: {db_path}[/green]")

            # Offer to initialize infrastructure
            if Confirm.ask("\nInitialize WireGuard on your servers now?", default=False):
                self.initialize_infrastructure(config)

            self.show_completion(config_path)
            return config_path
        else:
            self.console.print("\n[yellow]Configuration not saved[/yellow]")
            return None

    def show_welcome(self):
        """Display welcome message"""
        self.console.clear()
        welcome = Panel(
            "[bold cyan]wg-friend Setup Wizard[/bold cyan]\n\n"
            "Create your WireGuard network from scratch\n\n"
            "This wizard will create:\n"
            "  • Coordinator server config (public VPS hub)\n"
            "  • Optional subnet router config (LAN gateway)\n"
            "  • Network settings and IP allocation\n"
            "  • Peer templates for different access levels\n"
            "  • Complete config.yaml for wg-friend",
            title="Welcome",
            border_style="cyan"
        )
        self.console.print(welcome)
        input("\nPress Enter to begin...")

    def configure_coordinator(self) -> Dict:
        """Configure coordinator server"""
        self.console.clear()
        self.console.print("\n[bold]" + "═" * 60 + "[/bold]")
        self.console.print("[bold] Step 1/6: Coordinator Server[/bold]")
        self.console.print("[bold]" + "═" * 60 + "[/bold]\n")

        self.console.print("Your coordinator is the central WireGuard hub (usually a VPS with a public IP).\n")

        has_existing = Confirm.ask("Do you have an EXISTING coordinator running?", default=False)

        coordinator = {}

        if not has_existing:
            self.console.print("\n[cyan]Let's set up a new one![/cyan]\n")

        coordinator['name'] = Prompt.ask("Coordinator hostname (e.g., vpn.example.com)")
        coordinator['host'] = coordinator['name']  # Can be same or different
        coordinator['port'] = IntPrompt.ask("SSH port", default=22)
        coordinator['user'] = Prompt.ask("SSH username")
        coordinator['ssh_key'] = Prompt.ask("SSH key path", default="~/.ssh/id_ed25519")

        self.console.print("\n[bold]WireGuard settings:[/bold]")
        coordinator['config_path'] = Prompt.ask("  Config path", default="/etc/wireguard/wg0.conf")
        coordinator['interface'] = Prompt.ask("  Interface name", default="wg0")
        coordinator['listen_port'] = IntPrompt.ask("  Listen port", default=51820)

        coordinator['endpoint'] = Prompt.ask("\nPublic endpoint (clients connect here)",
                                              default=f"{coordinator['name']}:{coordinator['listen_port']}")

        # Keys
        if has_existing:
            self.console.print("\n[bold]Existing coordinator keys:[/bold]")
            coordinator['public_key'] = Prompt.ask("  Public key")
            coordinator['has_private_key'] = True
        else:
            if Confirm.ask("\nDo you have existing coordinator keys?", default=False):
                coordinator['public_key'] = Prompt.ask("  Public key")
                coordinator['has_private_key'] = True
            else:
                self.console.print("\n  Generating coordinator keypair...")
                private_key, public_key = generate_keypair()
                coordinator['private_key'] = private_key
                coordinator['public_key'] = public_key
                coordinator['has_private_key'] = False
                self.console.print(f"  [green]✓ Private key: (hidden)[/green]")
                self.console.print(f"  [green]✓ Public key: {public_key}[/green]")

        return coordinator

    def configure_network(self) -> Dict:
        """Configure network settings"""
        self.console.print("\n[bold]" + "═" * 60 + "[/bold]")
        self.console.print("[bold] Step 2/6: Network Configuration[/bold]")
        self.console.print("[bold]" + "═" * 60 + "[/bold]\n")

        self.console.print("Choose your VPN network ranges:\n")

        network = {}
        network['ipv4'] = Prompt.ask("IPv4 network", default="10.66.0.0/24")
        network['ipv6'] = Prompt.ask("IPv6 network", default="fd66:6666::/64")

        self.console.print("\n[bold]Coordinator IP addresses:[/bold]")
        network['coordinator_ipv4'] = Prompt.ask("  IPv4", default="10.66.0.1")
        network['coordinator_ipv6'] = Prompt.ask("  IPv6", default="fd66:6666::1")

        self.console.print("\n[bold]Client IP allocation:[/bold]")
        network['start_ipv4'] = Prompt.ask("  Start at", default="10.66.0.50")
        network['end_ipv4'] = Prompt.ask("  End at", default="10.66.0.254")

        reserved_default = f"{network['coordinator_ipv4']}"
        network['reserved'] = Prompt.ask("  Reserved IPs (infrastructure)", default=reserved_default)

        return network

    def configure_subnet_router(self) -> Optional[Dict]:
        """Configure optional subnet router"""
        self.console.print("\n[bold]" + "═" * 60 + "[/bold]")
        self.console.print("[bold] Step 3/6: Subnet Router (Optional)[/bold]")
        self.console.print("[bold]" + "═" * 60 + "[/bold]\n")

        self.console.print("A subnet router allows VPN clients to access your home LAN.\n")

        if not Confirm.ask("Do you have a subnet router?", default=False):
            return None

        self.console.print("\n[cyan]Great! This is typically your home server.[/cyan]\n")

        router = {}
        router['name'] = Prompt.ask("Router name (e.g., home-server)")
        router['host'] = Prompt.ask("Internal IP address")
        router['vpn_ipv4'] = Prompt.ask("VPN IP address", default="10.66.0.20")

        self.console.print("\n[bold]Home network subnets to route:[/bold]")
        subnets = []
        subnet1 = Prompt.ask("  Subnet 1")
        subnets.append(subnet1)

        while Confirm.ask("  Add another?", default=False):
            subnet = Prompt.ask(f"  Subnet {len(subnets) + 1}")
            subnets.append(subnet)

        router['subnets'] = subnets
        router['dns'] = Prompt.ask("\nDNS server", default=router['host'])
        router['lan_interface'] = Prompt.ask("LAN interface", default="eth0")

        if Confirm.ask("\nEnable IP forwarding and NAT?", default=True):
            router['enable_nat'] = True

        return router

    def configure_dns(self, subnet_router: Optional[Dict]) -> Dict:
        """Configure DNS settings"""
        self.console.print("\n[bold]" + "═" * 60 + "[/bold]")
        self.console.print("[bold] Step 4/6: DNS Configuration[/bold]")
        self.console.print("[bold]" + "═" * 60 + "[/bold]\n")

        self.console.print("DNS servers for different peer types:\n")

        dns = {}

        if subnet_router:
            dns['full_access'] = Prompt.ask("Full access peers (VPN + LAN)",
                                            default=subnet_router['dns'])
        else:
            dns['full_access'] = Prompt.ask("Full access peers", default="10.66.0.1")

        dns['vpn_only'] = Prompt.ask("VPN-only peers", default="10.66.0.1")

        if Confirm.ask("\nLooks good?", default=True):
            return dns
        else:
            return self.configure_dns(subnet_router)

    def configure_templates(self, network: Dict, subnet_router: Optional[Dict], dns: Dict) -> Dict:
        """Configure peer templates"""
        self.console.print("\n[bold]" + "═" * 60 + "[/bold]")
        self.console.print("[bold] Step 5/6: Peer Templates[/bold]")
        self.console.print("[bold]" + "═" * 60 + "[/bold]\n")

        self.console.print("Peer templates define configurations for different device types.\n")

        templates = {}

        # Define common settings used across templates
        allowed_ips = [network['ipv4'], network['ipv6']]
        if subnet_router:
            for subnet in subnet_router['subnets']:
                allowed_ips.append(subnet)

        # Mobile client template
        self.console.print("[bold cyan]Creating template: mobile_client[/bold cyan]")
        self.console.print("  Description: Mobile/desktop devices with full network access\n")

        keepalive = IntPrompt.ask("  PersistentKeepalive", default=25)
        mtu = IntPrompt.ask("  MTU", default=1280)

        self.console.print(f"\n  [green]Access:[/green]")
        self.console.print(f"    ✓ VPN mesh ({network['ipv4']}, {network['ipv6']})")
        if subnet_router:
            for subnet in subnet_router['subnets']:
                self.console.print(f"    ✓ Home LAN ({subnet})")

        templates['mobile_client'] = {
            'description': 'Mobile/desktop devices with full network access',
            'persistent_keepalive': keepalive,
            'dns': dns['full_access'],
            'allowed_ips': allowed_ips,
            'mtu': mtu
        }

        # Mesh only template
        self.console.print("\n[bold cyan]Creating template: mesh_only[/bold cyan]")
        self.console.print("  Description: VPN mesh only, no LAN access\n")

        keepalive_mesh = IntPrompt.ask("  PersistentKeepalive", default=25)

        self.console.print(f"\n  [green]Access:[/green]")
        self.console.print(f"    ✓ VPN mesh only")

        templates['mesh_only'] = {
            'description': 'VPN mesh only, no LAN access',
            'persistent_keepalive': keepalive_mesh,
            'dns': dns['vpn_only'],
            'allowed_ips': [network['ipv4'], network['ipv6']],
            'mtu': mtu
        }

        # Restricted and server templates (simplified)
        templates['restricted_external'] = {
            'description': 'External collaborators, limited access',
            'persistent_keepalive': 25,
            'dns': dns['vpn_only'],
            'allowed_ips': [network['ipv4'], network['ipv6']],
            'mtu': mtu
        }

        templates['server_peer'] = {
            'description': 'Always-on infrastructure',
            'persistent_keepalive': 0,
            'dns': dns['full_access'],
            'allowed_ips': allowed_ips,
            'mtu': mtu
        }

        self.console.print("\n[dim]Also created: restricted_external, server_peer[/dim]")

        return templates

    def build_config(self, coordinator: Dict, network: Dict, subnet_router: Optional[Dict],
                     dns: Dict, templates: Dict) -> Dict:
        """Build complete configuration dictionary"""
        config = {
            'data_dir': '~/.wg-friend',
            'metadata_db': '~/.wg-friend/peers.db',
            'ssh': {
                'key_path': coordinator['ssh_key'],
                'timeout': 10
            },
            'coordinator': {
                'name': coordinator['name'],
                'host': coordinator['host'],
                'port': coordinator['port'],
                'user': coordinator['user'],
                'config_path': coordinator['config_path'],
                'interface': coordinator['interface'],
                'endpoint': coordinator['endpoint'],
                'public_key': coordinator['public_key'],
                'network': {
                    'ipv4': network['ipv4'],
                    'ipv6': network['ipv6']
                },
                'coordinator_ip': {
                    'ipv4': network['coordinator_ipv4'],
                    'ipv6': network['coordinator_ipv6']
                }
            },
            'peer_templates': templates,
            'ip_allocation': {
                'start_ipv4': network['start_ipv4'],
                'end_ipv4': network['end_ipv4'],
                'reserved': [ip.strip() for ip in network['reserved'].split(',')]
            },
            'qr_code': {
                'enabled': True,
                'output_dir': '~/.wg-friend/qr-codes',
                'save_png': True
            },
            'logging': {
                'level': 'INFO',
                'file': '~/.wg-friend/wg-friend.log'
            }
        }

        if subnet_router:
            config['subnet_router'] = {
                'name': subnet_router['name'],
                'host': subnet_router['host'],
                'user': coordinator['user'],
                'config_path': '/etc/wireguard/wg0.conf',
                'interface': 'wg0',
                'vpn_ip': {
                    'ipv4': subnet_router['vpn_ipv4']
                },
                'routed_subnets': subnet_router['subnets'],
                'dns': subnet_router['dns'],
                'lan_interface': subnet_router['lan_interface']
            }

            # Add to reserved IPs
            if subnet_router['vpn_ipv4'] not in config['ip_allocation']['reserved']:
                config['ip_allocation']['reserved'].append(subnet_router['vpn_ipv4'])

        # Store coordinator private key if generated
        if 'private_key' in coordinator:
            config['_coordinator_private_key'] = coordinator['private_key']

        return config

    def review_config(self, config: Dict):
        """Display configuration for review"""
        self.console.print("\n[bold]" + "═" * 60 + "[/bold]")
        self.console.print("[bold] Step 6/6: Review Configuration[/bold]")
        self.console.print("[bold]" + "═" * 60 + "[/bold]\n")

        self.console.print("Here's your complete configuration:\n")

        # Create displayable config (without private key)
        display_config = {k: v for k, v in config.items() if not k.startswith('_')}
        config_yaml = yaml.dump(display_config, default_flow_style=False, sort_keys=False)

        panel = Panel(
            config_yaml,
            title="config.yaml",
            border_style="cyan"
        )
        self.console.print(panel)

    def save_config(self, config: Dict) -> Path:
        """Save configuration to file"""
        config_path = Path('~/.wg-friend/config.yaml').expanduser()
        config_path.parent.mkdir(parents=True, exist_ok=True)

        # Remove internal keys before saving
        save_config = {k: v for k, v in config.items() if not k.startswith('_')}

        with open(config_path, 'w') as f:
            f.write(f"# wg-friend configuration\n")
            f.write(f"# Generated by setup wizard on {datetime.now().strftime('%Y-%m-%d')}\n\n")
            yaml.dump(save_config, f, default_flow_style=False, sort_keys=False)

        return config_path

    def initialize_infrastructure(self, config: Dict):
        """Optionally initialize WireGuard on servers"""
        self.console.print("\n[bold]" + "═" * 60 + "[/bold]")
        self.console.print("[bold] Optional: Initialize Infrastructure[/bold]")
        self.console.print("[bold]" + "═" * 60 + "[/bold]\n")

        self.console.print("⚠️  This will SSH to your servers and:")
        self.console.print("  • Create /etc/wireguard/wg0.conf")
        self.console.print("  • Enable and start wg-quick@wg0 service")
        self.console.print("  • Enable IP forwarding (on subnet router)\n")

        # TODO: Implement actual initialization
        self.console.print("[yellow]Initialization not yet implemented - you'll need to set up manually[/yellow]")

    def show_completion(self, config_path: Path):
        """Show completion message"""
        completion = Panel(
            "[bold green]🎉 Setup Complete![/bold green]\n\n"
            f"✓ Configuration:   {config_path}\n"
            f"✓ Database:        ~/.wg-friend/peers.db\n\n"
            "[bold]Next steps:[/bold]\n\n"
            "  1. Add your first peer:\n"
            "     [cyan]./wg-friend.py add my-phone --qr --add-to-coordinator[/cyan]\n\n"
            "  2. Launch interactive TUI:\n"
            "     [cyan]./wg-friend.py tui[/cyan]\n\n"
            "  3. View network status:\n"
            "     [cyan]./wg-friend.py status[/cyan]\n\n"
            "Need help? Check [cyan]docs/SETUP.md[/cyan]",
            title="Success",
            border_style="green"
        )
        self.console.print("\n")
        self.console.print(completion)


class ImportOrchestrator:
    """Handle importing existing WireGuard configs"""

    def __init__(self, scan_path: Path, recover: bool = False):
        self.scan_path = scan_path
        self.recover = recover
        self.console = Console()
        self.scanner = ConfigScanner(scan_path)

    def _find_client_match_in_coordinator(self, client_config: ParsedConfig, all_parsed: List) -> Optional[Dict]:
        """Check if this client matches any peer in coordinator configs"""
        try:
            # Derive public key from client's private key
            private_key = client_config.interface.get('PrivateKey')
            if not private_key:
                return None

            client_pubkey = derive_public_key(private_key)

            # Find coordination server configs
            for parsed, suggested_type in all_parsed:
                if suggested_type in ['coordination_server', 'subnet_router']:
                    # Check if this coordination server has a peer with matching public key
                    for peer in parsed.peers:
                        if peer.get('PublicKey') == client_pubkey:
                            # Extract name and IP
                            name = peer.get('comment', 'unknown')
                            if '(' in name:
                                name = name.split('(')[0].strip()

                            allowed_ips = peer.get('AllowedIPs', '')
                            ip = allowed_ips.split(',')[0].strip() if allowed_ips else 'unknown'
                            if '/' in ip:
                                ip = ip.split('/')[0]

                            return {
                                'name': name,
                                'ip': ip,
                                'coordinator': parsed.file_path.name
                            }

        except Exception:
            pass

        return None

    def confirm_config_type(self, config: ParsedConfig, suggested_type: str, all_parsed: List = None) -> str:
        """Show detected type and let user confirm or override"""
        filename = config.file_path.name
        interface = config.interface
        peers = config.peers

        # For client configs, check if it matches a coordinator peer
        match_info = None
        if suggested_type == 'client' and all_parsed:
            match_info = self._find_client_match_in_coordinator(config, all_parsed)

        # Build a brief summary for the user
        has_endpoint = len(peers) == 1 and peers[0].get('Endpoint')
        has_listen_port = 'ListenPort' in interface

        postup = interface.get('PostUp', '')
        postdown = interface.get('PostDown', '')
        combined_rules = f"{postup} {postdown}"

        has_masquerade = 'MASQUERADE' in combined_rules or 'SNAT' in combined_rules
        has_forwarding = 'FORWARD' in combined_rules
        has_ip_forward = 'ip_forward=1' in combined_rules or 'ip-forward=1' in combined_rules

        # Describe why we think it's this type
        hints = []
        if has_endpoint:
            hints.append("has Endpoint (connects to server)")
        if has_listen_port:
            hints.append("has ListenPort")
        if has_masquerade:
            hints.append("has NAT/MASQUERADE")
        if has_forwarding:
            hints.append("has FORWARD rules")
        if has_ip_forward:
            hints.append("has ip_forward enabled")
        hints.append(f"{len(peers)} peer(s)")

        type_icons = {
            'coordination_server': '🌐',
            'subnet_router': '🔀',
            'client': '📱',
            'unknown': '❓'
        }

        self.console.print(f"\n[bold]{filename}[/bold]")
        self.console.print(f"  [dim]{', '.join(hints)}[/dim]")
        self.console.print(f"  Detected: {type_icons.get(suggested_type, '❓')} [cyan]{suggested_type}[/cyan]")

        # Show match info for clients
        if match_info:
            self.console.print(f"  [green]✓ Matches existing peer:[/green] {match_info['name']} ({match_info['ip']})")

        # Let user confirm or choose
        choice = Prompt.ask(
            "  Type ([cyan]c[/cyan]oordination_server / [cyan]s[/cyan]ubnet_router / clien[cyan]t[/cyan] / skip)",
            choices=["coordination_server", "c", "subnet_router", "s", "client", "t", "skip"],
            default=suggested_type,
            show_choices=False
        )

        # Expand shortcuts
        shortcut_map = {'c': 'coordination_server', 's': 'subnet_router', 't': 'client'}
        choice = shortcut_map.get(choice, choice)

        if choice == "skip":
            self.console.print("  [dim]Skipping this config[/dim]")
            return "skip"

        if choice != suggested_type:
            self.console.print(f"  [yellow]→ Changed to {choice}[/yellow]")

        return choice

    def run(self) -> bool:
        """Run import process"""
        # Check if scan path exists, create if it's ./import
        if not self.scan_path.exists():
            if self.scan_path.name == 'import':
                self.console.print(Panel(
                    "[yellow]No import directory found![/yellow]\n\n"
                    "To import existing WireGuard configs:\n"
                    "1. Create an [cyan]import/[/cyan] directory\n"
                    "2. Copy your .conf files there (coordinator, subnet router, clients)\n"
                    "3. Run this script again\n\n"
                    "Example:\n"
                    "  [dim]mkdir import[/dim]\n"
                    "  [dim]cp /path/to/coordinator-wg0.conf import/[/dim]\n"
                    "  [dim]cp /path/to/icculus-wg0.conf import/[/dim]",
                    title="📁 Import Directory",
                    border_style="yellow"
                ))
            else:
                self.console.print(f"[red]Error: Path not found: {self.scan_path}[/red]")
            return False

        self.console.print(f"\n[bold cyan]🔍 Scanning {self.scan_path} for configs...[/bold cyan]\n")

        # Find configs
        config_files = self.scanner.find_configs()

        if not config_files:
            self.console.print("[red]No .conf files found![/red]")
            return False

        # Show what we found
        self.console.print(f"[green]Found {len(config_files)} config(s):[/green]")
        for config_file in config_files:
            self.console.print(f"  • {config_file.name}")
        self.console.print()

        # Parse all configs first (detect types but don't confirm yet)
        all_parsed = []
        for config_file in config_files:
            parsed = self.scanner.parse_config(config_file)
            if parsed:
                suggested_type = self.scanner.detect_config_type(parsed)
                all_parsed.append((parsed, suggested_type))

        # Now confirm with user, showing match info for clients
        parsed_configs = []
        for parsed, suggested_type in all_parsed:
            confirmed_type = self.confirm_config_type(parsed, suggested_type, all_parsed)
            if confirmed_type != "skip":
                parsed.config_type = confirmed_type
                parsed_configs.append(parsed)

        # Find coordination server
        coordinator_config = None
        client_configs = []
        subnet_router_config = None

        for config in parsed_configs:
            if config.config_type == 'coordination_server':
                coordinator_config = config
            elif config.config_type == 'subnet_router':
                subnet_router_config = config
            elif config.config_type == 'client':
                client_configs.append(config)

        if not coordinator_config:
            self.console.print("[yellow]⚠️  No coordination server config found[/yellow]")
            self.console.print("Using --wizard might be better for your setup")
            return False

        # Display findings
        self.display_scan_results(coordinator_config, client_configs, subnet_router_config)

        # Ask to proceed
        if not Confirm.ask("\nProceed with import?", default=True):
            return False

        # Extract coordinator info to build config
        coord_info = self.extract_coordinator_info(coordinator_config, client_configs)

        # Prompt for SSH configuration
        self.console.print("\n[bold cyan]" + "═" * 60 + "[/bold cyan]")
        self.console.print("[bold cyan]📡 Coordination Server SSH Access[/bold cyan]")
        self.console.print("[bold cyan]" + "═" * 60 + "[/bold cyan]\n")

        self.console.print("[bold]Auto-detected from configs:[/bold]")
        self.console.print(f"  • Endpoint: {coord_info['endpoint']}")
        self.console.print(f"  • Public key: {coord_info['public_key'][:32]}... [dim](truncated for display)[/dim]")
        self.console.print(f"  • VPN network: {coord_info['network_ipv4']}\n")

        # Extract hostname/IP from endpoint
        ssh_host_default = coord_info['ssh_host']
        if ssh_host_default == 'UPDATE_ME':
            ssh_host_default = coord_info['endpoint'].split(':')[0] if ':' in coord_info['endpoint'] else coord_info['endpoint']

        ssh_host = Prompt.ask(
            "SSH hostname or IP address",
            default=ssh_host_default
        )
        coord_info['ssh_host'] = ssh_host

        import getpass
        current_user = getpass.getuser()

        ssh_user = Prompt.ask(
            "SSH username",
            default=current_user
        )
        coord_info['ssh_user'] = ssh_user

        ssh_port = IntPrompt.ask(
            "SSH port",
            default=22
        )
        coord_info['ssh_port'] = ssh_port

        # Match peers
        matched, unmatched = self.match_peers(coordinator_config, client_configs)

        self.console.print(f"\n[bold]📊 Matching Results:[/bold]")
        self.console.print(f"  ✓ Matched (with client configs): {len(matched)}")
        self.console.print(f"  ⚠️  Coordination server-only: {len(unmatched)}")

        # Handle recovery if requested
        recovered_peers = []
        if self.recover and unmatched:
            self.console.print("\n[bold cyan]" + "━" * 60 + "[/bold cyan]")
            self.console.print("[bold cyan] Recovery Mode[/bold cyan]")
            self.console.print("[bold cyan]" + "━" * 60 + "[/bold cyan]")
            recovered_peers = self.handle_recovery(unmatched, coord_info)

        # Generate config.yaml
        config_yaml_path = self.generate_config_yaml(coord_info, coordinator_config, subnet_router_config)

        # Save to database (including ALL coordinator peers)
        db_path = Path(config_yaml_path).parent / 'peers.db'
        self.save_to_database(matched, recovered_peers, unmatched, db_path)

        # Show summary
        self.show_import_summary(matched, recovered_peers, config_yaml_path)

        # Offer verification
        if Confirm.ask("\n[bold cyan]Would you like to review the generated configs before finalizing?[/bold cyan]", default=True):
            self.verify_import(coordinator_config, subnet_router_config, config_yaml_path, matched, recovered_peers, unmatched)

        return True

    def display_scan_results(self, coordinator: ParsedConfig, clients: List[ParsedConfig],
                             subnet_router: Optional[ParsedConfig] = None):
        """Display what was found"""
        self.console.print(f"[bold green]Found coordination server:[/bold green] {coordinator.file_path.name}")
        self.console.print(f"  ✓ {len(coordinator.peers)} peer entries detected\n")

        if subnet_router:
            self.console.print(f"[bold green]Found subnet router:[/bold green] {subnet_router.file_path.name}")
            self.console.print(f"  ✓ Detected NAT/routing configuration\n")

        if clients:
            self.console.print(f"[bold green]Found client configs:[/bold green] {len(clients)} files")
            for client in clients[:5]:  # Show first 5
                self.console.print(f"  ✓ {client.file_path.name}")
            if len(clients) > 5:
                self.console.print(f"  ... and {len(clients) - 5} more")
        else:
            self.console.print("[yellow]No client configs found[/yellow]")

    def extract_coordinator_info(self, coordinator: ParsedConfig, client_configs: List[ParsedConfig]) -> Dict:
        """Extract coordinator information from configs"""
        interface = coordinator.interface

        # Extract coordinator's own address (e.g., "10.66.0.1/24")
        address = interface.get('Address', '10.66.0.1/24')

        # Handle multiple addresses (IPv4, IPv6)
        addresses = [a.strip() for a in address.split(',')]
        ipv4_addr = next((a for a in addresses if '.' in a), '10.66.0.1/24')
        ipv6_addr = next((a for a in addresses if ':' in a), 'fd66:6666::1/64')

        # Parse coordinator IP and network CIDR
        coordinator_ipv4 = ipv4_addr.split('/')[0] if '/' in ipv4_addr else ipv4_addr
        coordinator_ipv6 = ipv6_addr.split('/')[0] if '/' in ipv6_addr else ipv6_addr

        # Extract network CIDR (e.g., "10.66.0.0/24")
        ipv4_cidr = ipv4_addr  # Keep the full CIDR notation
        ipv6_cidr = ipv6_addr

        # Extract public key from coordinator
        public_key = interface.get('PublicKey', '')

        # Preserve PostUp/PostDown rules from coordinator
        postup_rules = []
        postdown_rules = []
        for key, value in interface.items():
            if key == 'PostUp':
                # Handle multiple PostUp lines
                if isinstance(value, list):
                    postup_rules.extend(value)
                else:
                    postup_rules.append(value)
            elif key == 'PostDown':
                # Handle multiple PostDown lines
                if isinstance(value, list):
                    postdown_rules.extend(value)
                else:
                    postdown_rules.append(value)

        # Extract public endpoint from client configs (they know the coordinator's endpoint)
        endpoint = None
        for client in client_configs:
            if client.peers:
                client_peer = client.peers[0]
                if client_peer.get('Endpoint'):
                    endpoint = client_peer.get('Endpoint')
                    break

        # If no client config, try to infer from coordinator's config filename or use placeholder
        if not endpoint:
            endpoint = f"UPDATE_ME:51820"

        # Try to extract hostname from endpoint for SSH host suggestion
        ssh_host = 'UPDATE_ME'
        if endpoint and endpoint != 'UPDATE_ME:51820':
            ssh_host = endpoint.split(':')[0]

        return {
            'coordinator_ipv4': coordinator_ipv4,
            'coordinator_ipv6': coordinator_ipv6,
            'network_ipv4': ipv4_cidr,
            'network_ipv6': ipv6_cidr,
            'listen_port': interface.get('ListenPort', '51820'),
            'public_key': public_key,
            'endpoint': endpoint,
            'ssh_host': ssh_host,
            'postup': postup_rules,
            'postdown': postdown_rules,
        }

    def match_peers(self, coordinator: ParsedConfig, clients: List[ParsedConfig]) -> Tuple[List, List]:
        """Match client configs with coordinator peers"""
        matched = []
        unmatched = []

        # Build lookup of client public keys
        client_by_pubkey = {}
        for client in clients:
            if client.interface.get('PrivateKey'):
                # Derive public key from private key
                try:
                    pubkey = derive_public_key(client.interface['PrivateKey'])
                    client_by_pubkey[pubkey] = client
                except Exception as e:
                    # Skip if key derivation fails (invalid key format)
                    pass

        # Match coordinator peers
        for peer in coordinator.peers:
            pub_key = peer.get('PublicKey')
            if pub_key and pub_key in client_by_pubkey:
                # Match found
                matched.append({
                    'coord_peer': peer,
                    'client_config': client_by_pubkey[pub_key]
                })
            else:
                # No match - coordinator only
                coord_peer = self.parse_coordinator_peer(peer)
                unmatched.append(coord_peer)

        return matched, unmatched

    def parse_coordinator_peer(self, peer: Dict) -> CoordinatorPeer:
        """Parse coordinator peer dict into CoordinatorPeer object"""
        # Get comment (may be multi-line)
        full_comment = peer.get('comment', 'unknown')

        # Extract name from first line of comment
        if '\n' in full_comment:
            name = full_comment.split('\n')[0].strip()
        else:
            name = full_comment

        if '(' in name:
            name = name.split('(')[0].strip()

        allowed_ips = peer.get('AllowedIPs', '').split(',')
        ipv4 = None
        ipv6 = None

        for ip in allowed_ips:
            ip = ip.strip()
            if '.' in ip:
                ipv4 = ip.split('/')[0] if '/' in ip else ip
            elif ':' in ip:
                ipv6 = ip.split('/')[0] if '/' in ip else ip

        # Extract creation date from comment
        created = None
        import re
        comment = peer.get('comment', '')
        date_match = re.search(r'(\d{4}-\d{2}-\d{2})', comment)
        if date_match:
            try:
                created = datetime.strptime(date_match.group(1), '%Y-%m-%d')
            except ValueError:
                # Skip if date format is invalid
                pass

        # Extract optional fields
        preshared_key = peer.get('PresharedKey')
        persistent_keepalive = peer.get('PersistentKeepalive')
        if persistent_keepalive is not None:
            try:
                persistent_keepalive = int(persistent_keepalive)
            except (ValueError, TypeError):
                persistent_keepalive = None
        endpoint = peer.get('Endpoint')

        return CoordinatorPeer(
            name=name,
            public_key=peer.get('PublicKey', ''),
            ipv4=ipv4 or 'unknown',
            ipv6=ipv6 or 'unknown',
            allowed_ips=[ip.strip() for ip in allowed_ips],
            comment=full_comment,  # Store the full multi-line comment
            created=created,
            preshared_key=preshared_key,
            persistent_keepalive=persistent_keepalive,
            endpoint=endpoint
        )

    def handle_recovery(self, unmatched_peers: List[CoordinatorPeer], coord_info: Dict) -> List:
        """Handle recovery of coordination server-only peers"""
        recovered = []

        self.console.print(f"\n[yellow]Found {len(unmatched_peers)} coordination server-only peers[/yellow]")
        self.console.print("These peers exist on the coordination server but have no client config.\n")

        # Ask handling preference
        choice = Prompt.ask(
            "How to handle these peers?",
            choices=["individual", "skip-all"],
            default="individual"
        )

        if choice == "skip-all":
            self.console.print("[dim]Skipping all coordination server-only peers[/dim]")
            return []

        # Individual handling
        for peer in unmatched_peers:
            self.console.print("\n[bold cyan]" + "━" * 60 + "[/bold cyan]")
            self.console.print(f"\nPeer: [bold]{peer.name}[/bold] ({peer.ipv4})")
            if peer.created:
                age_days = (datetime.now() - peer.created).days
                self.console.print(f"  Created: {peer.created.strftime('%Y-%m-%d')} ({age_days} days ago)")

            self.console.print("\nOptions:")
            self.console.print("  [green]r)[/green] Rotate keys (generate new keypair, update coordination server)")
            self.console.print("  [yellow]s)[/yellow] Skip (import metadata only, no client config)")
            self.console.print("  [dim]i)[/dim] Ignore (don't import at all)")

            action = Prompt.ask("\nChoice", choices=['r', 's', 'i'], default='s')

            if action == 'r':
                # Rotate keys - generate new config
                recovered_peer = self.rotate_peer(peer, coord_info)
                if recovered_peer:
                    recovered.append(recovered_peer)
                    self.console.print("[green]✓ Generated new keypair and config[/green]")

            elif action == 's':
                # Skip - just save metadata
                self.console.print("[dim]✓ Will import metadata only[/dim]")
                recovered.append({
                    'peer': peer,
                    'action': 'metadata_only'
                })

            else:  # ignore
                self.console.print("[dim]⊗ Peer ignored[/dim]")

        return recovered

    def rotate_peer(self, peer: CoordinatorPeer, coord_info: Dict) -> Optional[Dict]:
        """Generate new keys and config for a peer"""
        try:
            # Generate new keypair
            private_key, public_key = generate_keypair()

            # Infer peer type from AllowedIPs
            peer_type = 'mobile_client'  # Default

            # Build client config
            config_builder = WireGuardConfigBuilder({
                'coordinator': {
                    'public_key': 'PLACEHOLDER',  # Will be replaced
                    'endpoint': f"coordinator:51820",  # Placeholder
                    'network': {
                        'ipv4': coord_info['network_ipv4'],
                        'ipv6': coord_info['network_ipv6']
                    }
                },
                'peer_templates': {
                    'mobile_client': {
                        'description': 'Mobile client',
                        'persistent_keepalive': 25,
                        'dns': '10.66.0.1',
                        'allowed_ips': peer.allowed_ips,
                        'mtu': 1280
                    }
                }
            })

            result = config_builder.build_client_config(
                client_name=peer.name,
                client_ipv4=peer.ipv4,
                client_ipv6=peer.ipv6,
                peer_type=peer_type,
                private_key=private_key,
                comment=f"{peer.name} (recovered {datetime.now().strftime('%Y-%m-%d')})"
            )

            # Save config file
            output_dir = Path('~/.wg-friend/configs').expanduser()
            config_path = config_builder.save_client_config(peer.name, result['client_config'], output_dir)

            # Generate QR code
            qr_dir = Path('~/.wg-friend/qr-codes').expanduser()
            qr_path = qr_dir / f"{peer.name}.png"
            generate_qr_code(result['client_config'], output_path=qr_path)

            return {
                'peer': peer,
                'action': 'rotated',
                'old_public_key': peer.public_key,
                'new_public_key': public_key,
                'config_path': config_path,
                'qr_path': qr_path,
                'coordinator_peer_block': result['coordinator_peer'],
                'metadata': result['metadata']
            }

        except Exception as e:
            self.console.print(f"[red]Error generating config: {e}[/red]")
            return None

    def generate_config_yaml(self, coord_info: Dict, coordinator: ParsedConfig, subnet_router: Optional[ParsedConfig]) -> Path:
        """Generate config.yaml from imported data"""
        config_path = Path('~/.wg-friend/config.yaml').expanduser()
        config_path.parent.mkdir(parents=True, exist_ok=True)

        # Extract subnet router info if present
        subnet_info = None
        lan_subnets = []
        if subnet_router:
            sr_interface = subnet_router.interface
            sr_address = sr_interface.get('Address', '10.66.0.20/24')
            sr_addresses = [a.strip() for a in sr_address.split(',')]
            sr_ipv4 = next((a for a in sr_addresses if '.' in a), '10.66.0.20/24')
            sr_ipv4_addr = sr_ipv4.split('/')[0] if '/' in sr_ipv4 else sr_ipv4

            # Extract PostUp/PostDown rules from subnet router
            sr_postup = sr_interface.get('PostUp', [])
            sr_postdown = sr_interface.get('PostDown', [])
            # Ensure they're lists
            if not isinstance(sr_postup, list):
                sr_postup = [sr_postup] if sr_postup else []
            if not isinstance(sr_postdown, list):
                sr_postdown = [sr_postdown] if sr_postdown else []

            # Extract LAN subnets from coordinator's peer entry for the subnet router
            # The coordinator knows what subnets are routed through the subnet router
            for peer in coordinator.peers:
                peer_allowed = peer.get('AllowedIPs', '')
                # Check if this peer has the subnet router's VPN IP
                if sr_ipv4_addr in peer_allowed:
                    # Extract all non-VPN subnets from this peer's AllowedIPs
                    for ip in peer_allowed.split(','):
                        ip = ip.strip()
                        # Skip the subnet router's own VPN IP
                        if ip.startswith(sr_ipv4_addr):
                            continue
                        # Skip VPN network itself
                        if ip == coord_info['network_ipv4'] or ip == coord_info['network_ipv6']:
                            continue
                        # Skip IPv6 link-local or VPN IPs
                        if ip.startswith('fd66:6666::'):
                            continue
                        # Keep LAN subnets (192.168.x.x, 10.x.x.x, 172.16-31.x.x)
                        if ('192.168' in ip or '172.1' in ip or '172.2' in ip or '172.3' in ip or
                            ('10.' in ip and '10.66.0' not in ip)) and '/' in ip:
                            lan_subnets.append(ip)
                    break

            subnet_info = {
                'vpn_ipv4': sr_ipv4_addr,
                'lan_subnets': lan_subnets if lan_subnets else ['192.168.12.0/24'],
                'postup': sr_postup,
                'postdown': sr_postdown,
            }

        # Build config with clear sections
        config = {
            'data_dir': '~/.wg-friend',
            'metadata_db': '~/.wg-friend/peers.db',

            'ssh': {
                'key_path': '~/.ssh/id_ed25519',
                'timeout': 10
            },

            # ═══════════════════════════════════════════════════════════
            # COORDINATION SERVER (VPS/Cloud - Public Endpoint)
            # ═══════════════════════════════════════════════════════════
            'coordinator': {
                'name': 'coordinator',
                'host': coord_info['ssh_host'],
                'port': coord_info['ssh_port'],
                'user': coord_info['ssh_user'],
                'config_path': '/etc/wireguard/wg0.conf',
                'interface': 'wg0',
                'endpoint': coord_info['endpoint'],
                'public_key': coord_info['public_key'],
                'network': {
                    'ipv4': coord_info['network_ipv4'],  # Full WireGuard network CIDR
                    'ipv6': coord_info['network_ipv6']
                },
                'coordinator_ip': {
                    'ipv4': coord_info['coordinator_ipv4'],  # Coordinator's VPN IP
                    'ipv6': coord_info['coordinator_ipv6']
                },
                'postup': coord_info['postup'],  # Preserved from import
                'postdown': coord_info['postdown']  # Preserved from import
            },

            # ═══════════════════════════════════════════════════════════
            # PEER TEMPLATES (Access Levels)
            # ═══════════════════════════════════════════════════════════
            'peer_templates': {}
        }

        # Build templates based on what we have
        if subnet_info:
            # Full access template (VPN + LAN)
            config['peer_templates']['full_access'] = {
                'description': 'Full access: VPN mesh + LAN subnets',
                'persistent_keepalive': 25,
                'dns': subnet_info['vpn_ipv4'],  # Use subnet router for DNS (can resolve LAN hosts)
                'allowed_ips': [coord_info['network_ipv4'], coord_info['network_ipv6']] + subnet_info['lan_subnets'],
                'mtu': 1280
            }

            # VPN-only template
            config['peer_templates']['vpn_only'] = {
                'description': 'VPN mesh only (no LAN access)',
                'persistent_keepalive': 25,
                'dns': coord_info['coordinator_ipv4'],
                'allowed_ips': [coord_info['network_ipv4'], coord_info['network_ipv6']],
                'mtu': 1280
            }

            # LAN-only template (can only reach LAN, not other VPN peers)
            config['peer_templates']['lan_only'] = {
                'description': 'LAN access only (no VPN peer mesh)',
                'persistent_keepalive': 25,
                'dns': subnet_info['vpn_ipv4'],
                'allowed_ips': subnet_info['lan_subnets'],
                'mtu': 1280
            }
        else:
            # No subnet router - simpler templates
            config['peer_templates']['standard'] = {
                'description': 'Standard VPN mesh access',
                'persistent_keepalive': 25,
                'dns': coord_info['coordinator_ipv4'],
                'allowed_ips': [coord_info['network_ipv4'], coord_info['network_ipv6']],
                'mtu': 1280
            }

        # ACL template (restrict to specific hosts)
        config['peer_templates']['restricted'] = {
            'description': 'Restricted: Specify allowed_ips manually for ACL',
            'persistent_keepalive': 25,
            'dns': coord_info['coordinator_ipv4'],
            'allowed_ips': ['10.66.0.1/32'],  # Example: only coordinator
            'mtu': 1280,
            'comment': 'Edit allowed_ips to restrict access to specific hosts'
        }

        # Add subnet router section if present
        if subnet_info:
            config['subnet_router'] = {
                'name': 'subnet_router',
                'host': 'UPDATE_ME',  # Internal LAN IP
                'user': 'UPDATE_ME',
                'config_path': '/etc/wireguard/wg0.conf',
                'interface': 'wg0',
                'vpn_ip': {
                    'ipv4': subnet_info['vpn_ipv4']
                },
                'routed_subnets': subnet_info['lan_subnets'],
                'dns': subnet_info['vpn_ipv4'],
                'postup': subnet_info['postup'],  # Preserved from import
                'postdown': subnet_info['postdown']  # Preserved from import
            }

        # IP allocation and other settings
        reserved_ips = [coord_info['coordinator_ipv4']]
        if subnet_info:
            reserved_ips.append(subnet_info['vpn_ipv4'])

        config['ip_allocation'] = {
            'start_ipv4': '10.66.0.50',
            'end_ipv4': '10.66.0.254',
            'reserved': reserved_ips
        }

        config['qr_code'] = {
            'enabled': True,
            'output_dir': '~/.wg-friend/qr-codes',
            'save_png': True
        }

        config['logging'] = {
            'level': 'INFO',
            'file': '~/.wg-friend/wg-friend.log'
        }

        with open(config_path, 'w') as f:
            f.write(f"# wg-friend configuration\n")
            f.write(f"# Generated from import on {datetime.now().strftime('%Y-%m-%d')}\n\n")
            f.write(f"# ═══════════════════════════════════════════════════════════\n")
            f.write(f"# Auto-detected and configured:\n")
            f.write(f"#   ✓ Coordination server endpoint: {coord_info['endpoint']}\n")
            f.write(f"#   ✓ Coordination server public key: {coord_info['public_key'][:16]}...\n")
            f.write(f"#   ✓ VPN network: {coord_info['network_ipv4']}\n")
            f.write(f"#   ✓ SSH access: {coord_info['ssh_user']}@{coord_info['ssh_host']}:{coord_info['ssh_port']}\n")
            f.write(f"#   ✓ PostUp/PostDown rules: {len(coord_info['postup'])} rules preserved\n")
            if subnet_info:
                f.write(f"#   ✓ Subnet router VPN IP: {subnet_info['vpn_ipv4']}\n")
                f.write(f"#   ✓ Subnet router LAN subnets: {', '.join(subnet_info['lan_subnets'])}\n")
                f.write(f"#   ✓ Subnet router PostUp/PostDown: {len(subnet_info['postup'])} rules preserved\n")
            f.write(f"#\n")
            if subnet_info:
                f.write(f"# Optional to update:\n")
                f.write(f"#   - subnet_router.host (LAN IP or hostname for SSH access)\n")
                f.write(f"#   - subnet_router.user (SSH username)\n")
                f.write(f"#   - subnet_router.port (SSH port, default 22)\n")
            f.write(f"# ═══════════════════════════════════════════════════════════\n\n")
            yaml.dump(config, f, default_flow_style=False, sort_keys=False)

        return config_path

    def save_to_database(self, matched: List, recovered: List, unmatched: List, db_path: Path):
        """Save imported peers to database"""
        with PeerDatabase(db_path) as db:
            # Save matched peers (with client configs)
            for match in matched:
                peer = match['coord_peer']
                client = match['client_config']

                # Extract data
                name = peer.get('comment', client.file_path.stem)
                if '(' in name:
                    name = name.split('(')[0].strip()

                allowed_ips = peer.get('AllowedIPs', '').split(',')
                ipv4 = ipv6 = None
                for ip in allowed_ips:
                    ip = ip.strip()
                    if '.' in ip:
                        ipv4 = ip.split('/')[0] if '/' in ip else ip
                    elif ':' in ip:
                        ipv6 = ip.split('/')[0] if '/' in ip else ip

                # Save to DB
                peer_data = {
                    'name': name,
                    'public_key': peer.get('PublicKey', ''),
                    'private_key': client.interface.get('PrivateKey'),
                    'ipv4': ipv4 or 'unknown',
                    'ipv6': ipv6 or 'unknown',
                    'peer_type': 'mobile_client',
                    'allowed_ips': peer.get('AllowedIPs', ''),
                    'comment': peer.get('comment', ''),
                    'created_at': datetime.now().isoformat(),
                    'config_path': str(client.file_path)
                }
                db.save_peer(peer_data)

            # Save recovered peers (rotated keys)
            for recovered_peer in recovered:
                if recovered_peer.get('action') == 'rotated':
                    metadata = recovered_peer['metadata']
                    metadata['config_path'] = str(recovered_peer['config_path'])
                    metadata['qr_code_path'] = str(recovered_peer['qr_path'])
                    db.save_peer(metadata)

            # Save ALL unmatched peers (coordination server-only, no client config)
            # This preserves existing peers when rebuilding coordination server config
            for coord_peer in unmatched:
                # Check if already saved (recovered peers are in both lists)
                if any(r.get('metadata', {}).get('public_key') == coord_peer.public_key
                       for r in recovered if r.get('action') == 'rotated'):
                    continue  # Skip if already saved as recovered peer

                peer_data = {
                    'name': coord_peer.name,
                    'public_key': coord_peer.public_key,
                    'private_key': None,  # No private key for coordinator-only peers
                    'ipv4': coord_peer.ipv4,
                    'ipv6': coord_peer.ipv6,
                    'peer_type': 'coordinator_only',
                    'allowed_ips': ', '.join(coord_peer.allowed_ips),
                    'comment': coord_peer.comment,
                    'created_at': coord_peer.created.isoformat() if coord_peer.created else datetime.now().isoformat(),
                }
                db.save_peer(peer_data)

    def verify_import(self, coordinator_config: ParsedConfig, subnet_router_config: Optional[ParsedConfig],
                      config_yaml_path: Path, matched: List, recovered_peers: List, unmatched: List):
        """Verify import by showing FULL generated configs and comparing with originals"""
        self.console.print("\n[bold cyan]" + "═" * 60 + "[/bold cyan]")
        self.console.print("[bold cyan]📋 Generated Configuration Review[/bold cyan]")
        self.console.print("[bold cyan]" + "═" * 60 + "[/bold cyan]\n")

        try:
            # Load the config.yaml we just created
            with open(config_yaml_path.expanduser()) as f:
                config = yaml.safe_load(f)

            # Create output directory
            output_dir = Path.cwd() / 'output'
            output_dir.mkdir(exist_ok=True)

            # Build and save coordination server config
            coord_config_text = self._build_coordinator_config_string(config, matched, recovered_peers, unmatched, coordinator_config)
            coord_output_path = output_dir / 'coordination-server.conf'
            coord_output_path.write_text(coord_config_text)
            coord_output_path.chmod(0o600)

            # Show FULL coordination server config
            self.console.print("[bold]Generated Coordination Server Config:[/bold]")
            self.console.print(f"[dim]Saved to: {coord_output_path}[/dim]")
            self.console.print(f"[dim]Note: PrivateKey masked in preview - actual file has real key from original[/dim]\n")
            self.console.print("[dim]" + "─" * 60 + "[/dim]")
            self._display_config_with_syntax(coord_config_text)
            self.console.print("[dim]" + "─" * 60 + "[/dim]\n")

            # Count peers
            peer_count = len(matched) + len(recovered_peers) + len(unmatched)
            self.console.print(f"[green]✓ Coordination server config includes {peer_count} peers[/green]")
            self.console.print(f"  • {len(matched)} matched (with client configs)")
            self.console.print(f"  • {len(unmatched)} preserved (coordination server-only)")
            if recovered_peers:
                self.console.print(f"  • {len(recovered_peers)} recovered (rotated keys)\n")
            else:
                self.console.print("")

            # Verify coordination server config
            self._verify_single_config(
                original=coordinator_config,
                config_yaml=config,
                matched=matched,
                recovered=recovered_peers,
                unmatched=unmatched,
                config_type="coordination server"
            )

            # Handle subnet router config if present
            if subnet_router_config:
                subnet_config_text = self._build_subnet_router_config_string(config, subnet_router_config)
                subnet_output_path = output_dir / 'subnet-router.conf'
                subnet_output_path.write_text(subnet_config_text)
                subnet_output_path.chmod(0o600)

                # Show FULL subnet router config
                self.console.print("\n[bold]Generated Subnet Router Config:[/bold]")
                self.console.print(f"[dim]Saved to: {subnet_output_path}[/dim]")
                self.console.print(f"[dim]Note: PrivateKey masked in preview - actual file has real key from original[/dim]\n")
                self.console.print("[dim]" + "─" * 60 + "[/dim]")
                self._display_config_with_syntax(subnet_config_text)
                self.console.print("[dim]" + "─" * 60 + "[/dim]\n")

                # Verify subnet router
                self._verify_subnet_router_config(
                    original=subnet_router_config,
                    config_yaml=config
                )

            self.console.print(f"\n[bold green]✓ All generated configs saved to {output_dir}/[/bold green]")

        except Exception as e:
            self.console.print(f"[yellow]Warning: Could not verify import: {e}[/yellow]")
            import traceback
            traceback.print_exc()

    def _display_config_with_syntax(self, config_text: str):
        """Display config with basic syntax highlighting (PrivateKey masked for preview only)"""
        for line in config_text.split('\n'):
            line_stripped = line.strip()
            if line_stripped.startswith('['):
                self.console.print(f"[bold magenta]{line}[/bold magenta]")
            elif line_stripped.startswith('#'):
                self.console.print(f"[dim]{line}[/dim]")
            elif '=' in line_stripped:
                key, value = line_stripped.split('=', 1)
                # Mask PrivateKey in preview only (actual file has real key)
                if 'PrivateKey' in key:
                    self.console.print(f"[cyan]{key}[/cyan]=[yellow] ******* [/yellow][dim](masked in preview)[/dim]")
                else:
                    self.console.print(f"[cyan]{key}[/cyan]=[yellow]{value}[/yellow]")
            elif not line_stripped:
                self.console.print("")
            else:
                self.console.print(line)

    def _build_subnet_router_config_string(self, config: Dict, original: ParsedConfig) -> str:
        """Build subnet router config preserving original structure"""
        lines = []

        # Build Interface section from original
        interface = original.interface
        lines.append("[Interface]")

        # Handle Address (can be multiple lines)
        address_val = interface.get('Address', '')
        if isinstance(address_val, list):
            for addr in address_val:
                lines.append(f"Address = {addr}")
        else:
            lines.append(f"Address = {address_val}")

        # Add other interface fields
        if 'ListenPort' in interface:
            lines.append(f"ListenPort = {interface['ListenPort']}")
        if 'MTU' in interface:
            lines.append(f"MTU = {interface['MTU']}")

        # PRESERVE original PrivateKey - DO NOT SUBSTITUTE
        lines.append(f"PrivateKey = {interface.get('PrivateKey', '<PRIVATE_KEY_ON_SERVER>')}")

        lines.append("")

        # Add PostUp/PostDown rules (PRESERVED EXACTLY from original!)
        postup_rules = interface.get('PostUp', [])
        if isinstance(postup_rules, str):
            postup_rules = [postup_rules]
        for rule in postup_rules:
            lines.append(f"PostUp = {rule}")

        postdown_rules = interface.get('PostDown', [])
        if isinstance(postdown_rules, str):
            postdown_rules = [postdown_rules]
        for rule in postdown_rules:
            lines.append(f"PostDown = {rule}")

        # Add peer(s) from original
        for peer in original.peers:
            lines.append("")
            lines.append("[Peer]")

            # Handle multi-line comments
            if peer.get('comment'):
                for comment_line in peer['comment'].split('\n'):
                    if comment_line.strip():
                        lines.append(f"# {comment_line}")

            # Add peer fields in standard order
            peer_keys_order = ['PublicKey', 'PresharedKey', 'AllowedIPs', 'Endpoint', 'PersistentKeepalive']
            for key in peer_keys_order:
                if key in peer:
                    lines.append(f"{key} = {peer[key]}")

        lines.append("")
        return '\n'.join(lines)

    def _verify_single_config(self, original: ParsedConfig, config_yaml: Dict,
                              matched: List, recovered: List, unmatched: List,
                              config_type: str):
        """Verify a single config file"""
        self.console.print(f"[bold]Verifying {config_type}:[/bold] {original.file_path.name}")

        # Build config as string
        if config_type == "coordination server":
            exported_config = self._build_coordinator_config_string(config_yaml, matched, recovered, unmatched, original)
        else:
            return  # Subnet router verification handled separately

        # Read original config
        original_config = original.file_path.read_text()

        # Create diff
        diff = list(difflib.unified_diff(
            original_config.splitlines(keepends=False),
            exported_config.splitlines(keepends=False),
            fromfile=f'Original: {original.file_path.name}',
            tofile=f'Generated {config_type}',
            lineterm=''
        ))

        if not diff:
            self.console.print("[bold green]  ✓ Perfect match![/bold green] Generated config is identical to original.\n")
            return

        # Analyze diff for 4-color display
        self._display_colored_diff(diff)

    def _verify_subnet_router_config(self, original: ParsedConfig, config_yaml: Dict):
        """Verify subnet router config preservation"""
        self.console.print(f"[bold]Verifying subnet router:[/bold] {original.file_path.name}")

        # Build what we would generate for subnet router
        subnet_router = config_yaml.get('subnet_router', {})
        if not subnet_router:
            self.console.print("[yellow]  ⚠️  No subnet router section in config.yaml[/yellow]\n")
            return

        # For subnet router, we mainly care that PostUp/PostDown rules are preserved
        original_postup = []
        original_postdown = []
        for key, value in original.interface.items():
            if key == 'PostUp':
                if isinstance(value, list):
                    original_postup.extend(value)
                else:
                    original_postup.append(value)
            elif key == 'PostDown':
                if isinstance(value, list):
                    original_postdown.extend(value)
                else:
                    original_postdown.append(value)

        yaml_postup = subnet_router.get('postup', [])
        yaml_postdown = subnet_router.get('postdown', [])

        if original_postup == yaml_postup and original_postdown == yaml_postdown:
            self.console.print("[bold green]  ✓ PostUp/PostDown rules preserved![/bold green]\n")
        else:
            self.console.print("[yellow]  ⚠️  PostUp/PostDown rules may differ[/yellow]")
            self.console.print(f"    Original: {len(original_postup)} PostUp, {len(original_postdown)} PostDown")
            self.console.print(f"    Imported: {len(yaml_postup)} PostUp, {len(yaml_postdown)} PostDown\n")

    def _display_colored_diff(self, diff: List[str]):
        """Display diff with 4-color system: red=removed, orange=repositioned, grey=unchanged, green=added"""
        # Separate additions and removals (without the +/- prefix for comparison)
        additions = {}  # content -> original line
        removals = {}   # content -> original line

        for line in diff:
            if line.startswith('+') and not line.startswith('+++'):
                content = line[1:]  # Remove the '+' prefix
                additions[content] = line
            elif line.startswith('-') and not line.startswith('---'):
                content = line[1:]  # Remove the '-' prefix
                removals[content] = line

        # Find repositioned lines (appear in both additions and removals)
        repositioned = set(additions.keys()) & set(removals.keys())

        # Count actual changes (excluding repositioned)
        actual_removals = len(removals) - len(repositioned)
        actual_additions = len(additions) - len(repositioned)

        if repositioned:
            self.console.print(f"[bold yellow]  Changes:[/bold yellow] {actual_removals} removed, {actual_additions} added, {len(repositioned)} repositioned\n")
        else:
            self.console.print(f"[bold yellow]  Changes:[/bold yellow] {actual_removals} removed, {actual_additions} added\n")

        # Display diff with colors
        for line in diff:
            if line.startswith('+++') or line.startswith('---'):
                self.console.print(f"[bold]{line}[/bold]")
            elif line.startswith('@@'):
                self.console.print(f"[cyan]{line}[/cyan]")
            elif line.startswith('+'):
                # Check if this line was repositioned
                content = line[1:]
                if content in repositioned:
                    self.console.print(f"[blue]{line}[/blue]")  # Blue for repositioned
                else:
                    self.console.print(f"[green]{line}[/green]")  # Green for truly added
            elif line.startswith('-'):
                # Check if this line was repositioned
                content = line[1:]
                if content in repositioned:
                    self.console.print(f"[blue]{line}[/blue]")  # Blue for repositioned
                else:
                    self.console.print(f"[red]{line}[/red]")  # Red for truly removed
            elif line.startswith(' '):
                # Unchanged lines in grey
                self.console.print(f"[dim]{line}[/dim]")
            else:
                self.console.print(line)

        self.console.print("\n[bold]Legend:[/bold]")
        self.console.print("  [red]- Red[/red] = Removed")
        self.console.print("  [blue]± Blue[/blue] = Repositioned (moved)")
        self.console.print("  [green]+ Green[/green] = Added")
        self.console.print("  [dim]  Grey[/dim] = Unchanged\n")

    def _build_coordinator_config_string(self, config: Dict, matched: List, recovered: List, unmatched: List, original: ParsedConfig) -> str:
        """Build coordination server config PRESERVING original structure and order"""
        lines = []
        interface = original.interface

        # Build Interface section - preserve original structure
        lines.append("[Interface]")

        # Handle Address (can be multiple lines)
        address_val = interface.get('Address', '')
        if isinstance(address_val, list):
            for addr in address_val:
                lines.append(f"Address = {addr}")
        else:
            lines.append(f"Address = {address_val}")

        # Add other interface fields
        if 'ListenPort' in interface:
            lines.append(f"ListenPort = {interface['ListenPort']}")
        if 'MTU' in interface:
            lines.append(f"MTU = {interface['MTU']}")

        # PRESERVE original PrivateKey - DO NOT SUBSTITUTE
        lines.append(f"PrivateKey = {interface.get('PrivateKey', '<PRIVATE_KEY_ON_SERVER>')}")
        lines.append("")

        # PRESERVE interface comments (like "# Update PostUp/PostDown..." and "# To allow postgres...")
        if 'comments' in interface:
            for comment in interface['comments']:
                lines.append(f"# {comment}")

        # Add PostUp/PostDown rules in original order
        postup_rules = interface.get('PostUp', [])
        if isinstance(postup_rules, str):
            postup_rules = [postup_rules]
        for rule in postup_rules:
            lines.append(f"PostUp = {rule}")

        postdown_rules = interface.get('PostDown', [])
        if isinstance(postdown_rules, str):
            postdown_rules = [postdown_rules]
        for rule in postdown_rules:
            lines.append(f"PostDown = {rule}")

        # Build lookup of peers by public key for matching
        matched_keys = {m['coord_peer'].get('PublicKey'): m for m in matched}
        recovered_keys = {r.get('metadata', {}).get('public_key'): r for r in recovered if r.get('action') == 'rotated'}

        # Output peers in ORIGINAL order from coordination server
        for peer in original.peers:
            pubkey = peer.get('PublicKey', '')

            lines.append("")
            lines.append("[Peer]")

            # Handle multi-line comments
            if peer.get('comment'):
                for comment_line in peer['comment'].split('\n'):
                    if comment_line.strip():
                        lines.append(f"# {comment_line}")

            # Output peer fields in standard order
            if 'PublicKey' in peer:
                lines.append(f"PublicKey = {peer['PublicKey']}")
            if 'PresharedKey' in peer:
                lines.append(f"PresharedKey = {peer['PresharedKey']}")
            if 'AllowedIPs' in peer:
                lines.append(f"AllowedIPs = {peer['AllowedIPs']}")
            if 'Endpoint' in peer:
                lines.append(f"Endpoint = {peer['Endpoint']}")
            if 'PersistentKeepalive' in peer:
                lines.append(f"PersistentKeepalive = {peer['PersistentKeepalive']}")

        lines.append("")
        return '\n'.join(lines)

    def show_import_summary(self, matched: List, recovered: List, config_path: Path):
        """Display import summary"""
        self.console.print(f"\n[bold green]{'═' * 60}[/bold green]")
        self.console.print("[bold green]🎉 Import Complete![/bold green]")
        self.console.print(f"[bold green]{'═' * 60}[/bold green]\n")

        self.console.print(f"[bold]Imported:[/bold]")
        self.console.print(f"  ✓ Matched peers: {len(matched)}")

        rotated = [p for p in recovered if p.get('action') == 'rotated']
        metadata_only = [p for p in recovered if p.get('action') == 'metadata_only']

        if rotated:
            self.console.print(f"  ✓ Recovered (rotated keys): {len(rotated)}")
        if metadata_only:
            self.console.print(f"  ℹ️  Metadata-only: {len(metadata_only)}")

        self.console.print(f"\n[bold]Generated:[/bold]")
        self.console.print(f"  ✓ Config: {config_path}")
        self.console.print(f"  ✓ Database: {config_path.parent / 'peers.db'}")

        if rotated:
            self.console.print(f"  ✓ Client configs: ~/.wg-friend/configs/ ({len(rotated)} files)")
            self.console.print(f"  ✓ QR codes: ~/.wg-friend/qr-codes/ ({len(rotated)} images)")

        self.console.print(f"\n[green]✓ Configuration complete![/green]")
        self.console.print(f"  All values extracted from your configs and confirmed.")
        self.console.print(f"\n[dim]Optional: Review {config_path} to customize peer templates or settings.[/dim]")

        if rotated:
            self.console.print(f"\n[bold]Next Steps:[/bold]")
            self.console.print(f"  1. Update rotated peers on coordination server:")
            self.console.print(f"     [cyan]# SSH to coordination server and update wg0.conf[/cyan]")
            self.console.print(f"  2. Deploy new client configs:")
            for peer in rotated[:3]:
                self.console.print(f"     • {peer['peer'].name}: {peer['qr_path']}")
            if len(rotated) > 3:
                self.console.print(f"     ... and {len(rotated) - 3} more")

        self.console.print(f"\n[bold]Ready to use:[/bold]")
        self.console.print(f"  [cyan]./wg-friend.py tui[/cyan]\n")


def main():
    parser = argparse.ArgumentParser(
        description='wg-friend Onboarding - Import configs or setup from scratch',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Setup from scratch (interactive wizard)
  ./wg-friend-onboard.py --wizard

  # Import existing configs (place .conf files in ./import/ first)
  ./wg-friend-onboard.py --scan ./import

  # Import and recover missing peer configs
  ./wg-friend-onboard.py --scan ./import --recover
        """
    )

    parser.add_argument(
        '--wizard',
        action='store_true',
        help='Run interactive setup wizard (from scratch)'
    )

    parser.add_argument(
        '--scan',
        type=Path,
        help='Scan directory for existing WireGuard configs (e.g., ./import)'
    )

    parser.add_argument(
        '--recover',
        action='store_true',
        help='Recover/rotate peers found only on coordinator'
    )

    args = parser.parse_args()

    # Determine mode
    if args.wizard or (not args.scan):
        # Wizard mode
        wizard = WizardSetup()
        wizard.run()
    elif args.scan:
        # Import mode
        importer = ImportOrchestrator(args.scan, args.recover)
        importer.run()
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
