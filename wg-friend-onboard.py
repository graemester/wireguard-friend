#!/usr/bin/env python3
"""
wg-friend Onboarding Script
Import existing WireGuard configs or setup from scratch with wizard
"""

import argparse
import sys
import yaml
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

# Import wg-friend components
sys.path.insert(0, str(Path(__file__).parent / 'src'))
from keygen import generate_keypair, derive_public_key
from peer_manager import WireGuardPeerManager
from config_builder import WireGuardConfigBuilder
from metadata_db import PeerDatabase
from ssh_client import SSHClient
from qr_generator import generate_qr_code


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
        """Parse a WireGuard config file"""
        try:
            with open(config_path) as f:
                content = f.read()

            interface = {}
            peers = []
            current_section = None
            current_peer = {}
            current_comment = None

            for line in content.split('\n'):
                line_stripped = line.strip()

                # Skip empty lines
                if not line_stripped:
                    continue

                # Comments
                if line_stripped.startswith('#'):
                    current_comment = line_stripped.lstrip('#').strip()
                    continue

                # Section headers
                if line_stripped.startswith('[Interface]'):
                    current_section = 'interface'
                    continue
                elif line_stripped.startswith('[Peer]'):
                    # Save previous peer
                    if current_peer:
                        peers.append(current_peer)

                    current_section = 'peer'
                    current_peer = {}

                    # Check for inline comment
                    if '#' in line:
                        current_comment = line.split('#')[1].strip()

                    if current_comment:
                        current_peer['comment'] = current_comment
                        current_comment = None
                    continue

                # Key-value pairs
                if '=' in line_stripped:
                    key, value = line_stripped.split('=', 1)
                    key = key.strip()
                    value = value.strip()

                    if current_section == 'interface':
                        interface[key] = value
                    elif current_section == 'peer':
                        current_peer[key] = value

            # Add last peer
            if current_peer:
                peers.append(current_peer)

            return ParsedConfig(
                file_path=config_path,
                interface=interface,
                peers=peers
            )

        except Exception as e:
            console.print(f"[yellow]Warning: Failed to parse {config_path}: {e}[/yellow]")
            return None

    def detect_config_type(self, config: ParsedConfig) -> str:
        """Detect if config is coordinator, subnet_router, or client"""
        interface = config.interface
        peers = config.peers

        has_listen_port = 'ListenPort' in interface
        has_multiple_peers = len(peers) > 3
        has_postup = 'PostUp' in interface
        has_nat_rules = has_postup and 'MASQUERADE' in interface.get('PostUp', '')

        if has_listen_port and has_multiple_peers and not peers:
            return 'coordinator'
        elif has_listen_port and has_nat_rules:
            return 'subnet_router'
        elif not has_listen_port and len(peers) == 1:
            return 'client'
        elif has_listen_port and len(peers) > 0:
            # Could be coordinator or subnet router
            if has_nat_rules:
                return 'subnet_router'
            else:
                return 'coordinator'
        else:
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
        self.console.print("\n[bold]═" * 30)
        self.console.print(" Step 1/6: Coordinator Server")
        self.console.print("═" * 30 + "[/bold]\n")

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
        self.console.print("\n[bold]═" * 30)
        self.console.print(" Step 2/6: Network Configuration")
        self.console.print("═" * 30 + "[/bold]\n")

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
        self.console.print("\n[bold]═" * 30)
        self.console.print(" Step 3/6: Subnet Router (Optional)")
        self.console.print("═" * 30 + "[/bold]\n")

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
        self.console.print("\n[bold]═" * 30)
        self.console.print(" Step 4/6: DNS Configuration")
        self.console.print("═" * 30 + "[/bold]\n")

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
        self.console.print("\n[bold]═" * 30)
        self.console.print(" Step 5/6: Peer Templates")
        self.console.print("═" * 30 + "[/bold]\n")

        self.console.print("Peer templates define configurations for different device types.\n")

        templates = {}

        # Mobile client template
        self.console.print("[bold cyan]Creating template: mobile_client[/bold cyan]")
        self.console.print("  Description: Mobile/desktop devices with full network access\n")

        keepalive = IntPrompt.ask("  PersistentKeepalive", default=25)
        mtu = IntPrompt.ask("  MTU", default=1280)

        allowed_ips = [network['ipv4'], network['ipv6']]
        if subnet_router:
            for subnet in subnet_router['subnets']:
                allowed_ips.append(subnet)

        self.console.print(f"\n  [green]Access:[/green]")
        self.console.print(f"    ✓ VPN mesh ({network['ipv4']}, {network['ipv6']})")
        if subnet_router:
            for subnet in subnet_router['subnets']:
                self.console.print(f"    ✓ Home LAN ({subnet})")

        if Confirm.ask("\n  Looks good?", default=True):
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

        keepalive = IntPrompt.ask("  PersistentKeepalive", default=25)

        self.console.print(f"\n  [green]Access:[/green]")
        self.console.print(f"    ✓ VPN mesh only")

        if Confirm.ask("\n  Looks good?", default=True):
            templates['mesh_only'] = {
                'description': 'VPN mesh only, no LAN access',
                'persistent_keepalive': keepalive,
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
        self.console.print("\n[bold]═" * 30)
        self.console.print(" Step 6/6: Review Configuration")
        self.console.print("═" * 30 + "[/bold]\n")

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
        self.console.print("\n[bold]═" * 30)
        self.console.print(" Optional: Initialize Infrastructure")
        self.console.print("═" * 30 + "[/bold]\n")

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

    def run(self) -> bool:
        """Run import process"""
        self.console.print(f"\n[bold cyan]🔍 Scanning {self.scan_path} for configs...[/bold cyan]\n")

        # Find configs
        config_files = self.scanner.find_configs()

        if not config_files:
            self.console.print("[red]No .conf files found![/red]")
            return False

        # Parse all configs
        parsed_configs = []
        for config_file in config_files:
            parsed = self.scanner.parse_config(config_file)
            if parsed:
                parsed.config_type = self.scanner.detect_config_type(parsed)
                parsed_configs.append(parsed)

        # Find coordinator
        coordinator_config = None
        client_configs = []
        subnet_router_config = None

        for config in parsed_configs:
            if config.config_type == 'coordinator':
                coordinator_config = config
            elif config.config_type == 'subnet_router':
                if 'MASQUERADE' in str(config.interface):
                    subnet_router_config = config
                else:
                    coordinator_config = config
            elif config.config_type == 'client':
                client_configs.append(config)

        if not coordinator_config:
            self.console.print("[yellow]⚠️  No coordinator config found[/yellow]")
            self.console.print("Using --wizard might be better for your setup")
            return False

        # Display findings
        self.display_scan_results(coordinator_config, client_configs, subnet_router_config)

        # Ask to proceed
        if not Confirm.ask("\nProceed with import?", default=True):
            return False

        # Extract coordinator info to build config
        coord_info = self.extract_coordinator_info(coordinator_config)

        # Match peers
        matched, unmatched = self.match_peers(coordinator_config, client_configs)

        self.console.print(f"\n[bold]📊 Matching Results:[/bold]")
        self.console.print(f"  ✓ Matched (with client configs): {len(matched)}")
        self.console.print(f"  ⚠️  Coordinator-only: {len(unmatched)}")

        # Handle recovery if requested
        recovered_peers = []
        if self.recover and unmatched:
            self.console.print(f"\n[bold cyan]━" * 30)
            self.console.print(" Recovery Mode")
            self.console.print("━" * 30 + "[/bold cyan]")
            recovered_peers = self.handle_recovery(unmatched, coord_info)

        # Generate config.yaml
        config_yaml_path = self.generate_config_yaml(coord_info, subnet_router_config)

        # Save to database
        db_path = Path(config_yaml_path).parent / 'peers.db'
        self.save_to_database(matched, recovered_peers, db_path)

        # Show summary
        self.show_import_summary(matched, recovered_peers, config_yaml_path)

        return True

    def display_scan_results(self, coordinator: ParsedConfig, clients: List[ParsedConfig],
                             subnet_router: Optional[ParsedConfig] = None):
        """Display what was found"""
        self.console.print(f"[bold green]Found coordinator:[/bold green] {coordinator.file_path.name}")
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

    def extract_coordinator_info(self, coordinator: ParsedConfig) -> Dict:
        """Extract coordinator information for config generation"""
        interface = coordinator.interface

        # Extract network from first peer's AllowedIPs
        first_peer = coordinator.peers[0] if coordinator.peers else {}
        allowed_ips = first_peer.get('AllowedIPs', '10.66.0.0/24')
        ipv4_network = [ip for ip in allowed_ips.split(',') if '.' in ip][0].strip() if ',' in allowed_ips else allowed_ips

        # Parse network to get coordinator IP (usually .1)
        network_base = '.'.join(ipv4_network.split('.')[:3])
        coordinator_ip = f"{network_base}.1"

        return {
            'address': interface.get('Address', coordinator_ip),
            'listen_port': interface.get('ListenPort', '51820'),
            'network_ipv4': ipv4_network.split('/')[0],
            'network_ipv6': 'fd66:6666::/64',  # Default
            'coordinator_ipv4': coordinator_ip,
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
                except:
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
        name = peer.get('comment', 'unknown')
        if '(' in name:
            name = name.split('(')[0].strip()

        allowed_ips = peer.get('AllowedIPs', '').split(',')
        ipv4 = None
        ipv6 = None

        for ip in allowed_ips:
            ip = ip.strip()
            if '.' in ip:
                ipv4 = ip.split('/')[0]
            elif ':' in ip:
                ipv6 = ip.split('/')[0]

        # Extract creation date from comment
        created = None
        import re
        comment = peer.get('comment', '')
        date_match = re.search(r'(\d{4}-\d{2}-\d{2})', comment)
        if date_match:
            try:
                created = datetime.strptime(date_match.group(1), '%Y-%m-%d')
            except:
                pass

        return CoordinatorPeer(
            name=name,
            public_key=peer.get('PublicKey', ''),
            ipv4=ipv4 or 'unknown',
            ipv6=ipv6 or 'unknown',
            allowed_ips=[ip.strip() for ip in allowed_ips],
            comment=peer.get('comment', ''),
            created=created
        )

    def handle_recovery(self, unmatched_peers: List[CoordinatorPeer], coord_info: Dict) -> List:
        """Handle recovery of coordinator-only peers"""
        recovered = []

        self.console.print(f"\n[yellow]Found {len(unmatched_peers)} coordinator-only peers[/yellow]")
        self.console.print("These peers exist on the coordinator but have no client config.\n")

        # Ask handling preference
        choice = Prompt.ask(
            "How to handle these peers?",
            choices=["individual", "skip-all"],
            default="individual"
        )

        if choice == "skip-all":
            self.console.print("[dim]Skipping all coordinator-only peers[/dim]")
            return []

        # Individual handling
        for peer in unmatched_peers:
            self.console.print(f"\n[bold cyan]━" * 60)
            self.console.print(f"\nPeer: [bold]{peer.name}[/bold] ({peer.ipv4})")
            if peer.created:
                age_days = (datetime.now() - peer.created).days
                self.console.print(f"  Created: {peer.created.strftime('%Y-%m-%d')} ({age_days} days ago)")

            self.console.print("\nOptions:")
            self.console.print("  [green]r)[/green] Rotate keys (generate new keypair, update coordinator)")
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

    def generate_config_yaml(self, coord_info: Dict, subnet_router: Optional[ParsedConfig]) -> Path:
        """Generate config.yaml from imported data"""
        config_path = Path('~/.wg-friend/config.yaml').expanduser()
        config_path.parent.mkdir(parents=True, exist_ok=True)

        # Build basic config
        config = {
            'data_dir': '~/.wg-friend',
            'metadata_db': '~/.wg-friend/peers.db',
            'ssh': {
                'key_path': '~/.ssh/id_ed25519',
                'timeout': 10
            },
            'coordinator': {
                'name': 'coordinator',  # User should update
                'host': 'coordinator.example.com',  # User should update
                'port': 22,
                'user': 'username',  # User should update
                'config_path': '/etc/wireguard/wg0.conf',
                'interface': 'wg0',
                'endpoint': 'coordinator.example.com:51820',
                'public_key': 'UPDATE_ME',
                'network': {
                    'ipv4': coord_info['network_ipv4'],
                    'ipv6': coord_info['network_ipv6']
                },
                'coordinator_ip': {
                    'ipv4': coord_info['coordinator_ipv4'],
                    'ipv6': 'fd66:6666::1'
                }
            },
            'peer_templates': {
                'mobile_client': {
                    'description': 'Mobile/desktop devices with full access',
                    'persistent_keepalive': 25,
                    'dns': coord_info['coordinator_ipv4'],
                    'allowed_ips': [coord_info['network_ipv4'], coord_info['network_ipv6']],
                    'mtu': 1280
                },
                'mesh_only': {
                    'description': 'VPN mesh only',
                    'persistent_keepalive': 25,
                    'dns': coord_info['coordinator_ipv4'],
                    'allowed_ips': [coord_info['network_ipv4'], coord_info['network_ipv6']],
                    'mtu': 1280
                }
            },
            'ip_allocation': {
                'start_ipv4': '10.66.0.50',
                'end_ipv4': '10.66.0.254',
                'reserved': [coord_info['coordinator_ipv4']]
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

        # Add subnet router if found
        if subnet_router:
            config['subnet_router'] = {
                'name': 'subnet_router',
                'host': '192.168.1.1',  # User should update
                'user': 'username',
                'vpn_ip': {'ipv4': '10.66.0.20'},
                'routed_subnets': ['192.168.1.0/24'],
                'dns': '192.168.1.1'
            }

        with open(config_path, 'w') as f:
            f.write(f"# wg-friend configuration\n")
            f.write(f"# Generated from import on {datetime.now().strftime('%Y-%m-%d')}\n")
            f.write(f"# IMPORTANT: Update coordinator host, SSH details, and public key!\n\n")
            yaml.dump(config, f, default_flow_style=False, sort_keys=False)

        return config_path

    def save_to_database(self, matched: List, recovered: List, db_path: Path):
        """Save imported peers to database"""
        with PeerDatabase(db_path) as db:
            # Save matched peers
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
                        ipv4 = ip.split('/')[0]
                    elif ':' in ip:
                        ipv6 = ip.split('/')[0]

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

            # Save recovered peers
            for recovered_peer in recovered:
                if recovered_peer.get('action') == 'rotated':
                    metadata = recovered_peer['metadata']
                    metadata['config_path'] = str(recovered_peer['config_path'])
                    metadata['qr_code_path'] = str(recovered_peer['qr_path'])
                    db.save_peer(metadata)

    def show_import_summary(self, matched: List, recovered: List, config_path: Path):
        """Display import summary"""
        self.console.print(f"\n[bold green]{'═' * 60}")
        self.console.print("🎉 Import Complete!")
        self.console.print(f"{'═' * 60}[/bold green]\n")

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

        self.console.print(f"\n[yellow]⚠️  IMPORTANT:[/yellow]")
        self.console.print(f"  Edit {config_path} and update:")
        self.console.print(f"    • coordinator.host (SSH hostname)")
        self.console.print(f"    • coordinator.user (SSH username)")
        self.console.print(f"    • coordinator.public_key")
        self.console.print(f"    • coordinator.endpoint")

        if rotated:
            self.console.print(f"\n[bold]Next Steps:[/bold]")
            self.console.print(f"  1. Update rotated peers on coordinator:")
            self.console.print(f"     [cyan]# SSH to coordinator and update wg0.conf[/cyan]")
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

  # Import existing configs
  ./wg-friend-onboard.py --scan /etc/wireguard

  # Import and recover missing peer configs
  ./wg-friend-onboard.py --scan ~/wireguard-backup --recover
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
        help='Scan directory for existing WireGuard configs'
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
