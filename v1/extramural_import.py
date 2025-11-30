"""
Extramural Config Import

Import external WireGuard configurations from sponsor-provided .conf files.

This module:
1. Parses sponsor-provided WireGuard configs
2. Extracts interface and peer details
3. Prompts for sponsor and local peer info
4. Stores everything in the extramural database
"""

import re
import logging
from pathlib import Path
from typing import Optional, List, Dict, Tuple
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class ParsedExtramuralConfig:
    """Parsed extramural WireGuard configuration"""
    # Interface section (required fields first)
    private_key: str
    addresses: List[str]  # Can have both IPv4 and IPv6
    peer_public_key: str  # Peer section - required
    peer_allowed_ips: str  # Peer section - required

    # Optional interface fields
    dns_servers: Optional[str] = None
    listen_port: Optional[int] = None
    mtu: Optional[int] = None
    table: Optional[str] = None

    # Optional peer fields
    peer_endpoint: Optional[str] = None
    peer_preshared_key: Optional[str] = None
    peer_persistent_keepalive: Optional[int] = None

    # PostUp/PostDown commands (if any)
    postup_commands: List[str] = None
    postdown_commands: List[str] = None

    def __post_init__(self):
        if self.postup_commands is None:
            self.postup_commands = []
        if self.postdown_commands is None:
            self.postdown_commands = []


class ExtramuralConfigParser:
    """Parser for sponsor-provided WireGuard configs"""

    def __init__(self):
        self.interface_fields = {}
        self.peers = []
        self.current_section = None

    def parse_file(self, config_path: Path) -> ParsedExtramuralConfig:
        """
        Parse a WireGuard config file from a sponsor.

        Args:
            config_path: Path to the .conf file

        Returns:
            ParsedExtramuralConfig with all extracted data

        Raises:
            ValueError: If config is invalid or missing required fields
        """
        if not config_path.exists():
            raise ValueError(f"Config file not found: {config_path}")

        with open(config_path, 'r') as f:
            lines = f.readlines()

        self.interface_fields = {}
        self.peers = []
        self.current_section = None

        for line in lines:
            line = line.strip()

            # Skip empty lines and comments
            if not line or line.startswith('#') or line.startswith(';'):
                continue

            # Section headers
            if line.startswith('['):
                section = line.strip('[]').lower()
                if section == 'interface':
                    self.current_section = 'interface'
                elif section == 'peer':
                    self.current_section = 'peer'
                    self.peers.append({})
                continue

            # Parse key-value pairs
            if '=' in line:
                key, value = line.split('=', 1)
                key = key.strip()
                value = value.strip()

                if self.current_section == 'interface':
                    if key in self.interface_fields:
                        # Handle multiple values (like Address, DNS, PostUp, PostDown)
                        if isinstance(self.interface_fields[key], list):
                            self.interface_fields[key].append(value)
                        else:
                            self.interface_fields[key] = [self.interface_fields[key], value]
                    else:
                        # PostUp and PostDown can appear multiple times
                        if key in ['PostUp', 'PostDown']:
                            self.interface_fields[key] = [value]
                        else:
                            self.interface_fields[key] = value
                elif self.current_section == 'peer' and self.peers:
                    self.peers[-1][key] = value

        # Validate required fields
        if not self.interface_fields.get('PrivateKey'):
            raise ValueError("Missing required field: PrivateKey in [Interface]")

        if not self.interface_fields.get('Address'):
            raise ValueError("Missing required field: Address in [Interface]")

        if not self.peers:
            raise ValueError("No [Peer] section found")

        if not self.peers[0].get('PublicKey'):
            raise ValueError("Missing required field: PublicKey in [Peer]")

        if not self.peers[0].get('AllowedIPs'):
            raise ValueError("Missing required field: AllowedIPs in [Peer]")

        # Handle multiple address values
        addresses = self.interface_fields['Address']
        if not isinstance(addresses, list):
            addresses = [addresses]

        # Handle comma-separated addresses in single line
        expanded_addresses = []
        for addr in addresses:
            if ',' in addr:
                expanded_addresses.extend([a.strip() for a in addr.split(',')])
            else:
                expanded_addresses.append(addr.strip())
        addresses = expanded_addresses

        # Handle multiple DNS values
        dns_servers = self.interface_fields.get('DNS')
        if isinstance(dns_servers, list):
            dns_servers = ', '.join(dns_servers)

        # Handle PostUp/PostDown
        postup_commands = []
        postdown_commands = []

        if 'PostUp' in self.interface_fields:
            postup = self.interface_fields['PostUp']
            postup_commands = postup if isinstance(postup, list) else [postup]

        if 'PostDown' in self.interface_fields:
            postdown = self.interface_fields['PostDown']
            postdown_commands = postdown if isinstance(postdown, list) else [postdown]

        # Use first peer (extramural configs typically have one peer)
        peer = self.peers[0]

        # Parse ListenPort and MTU as integers
        listen_port = None
        if 'ListenPort' in self.interface_fields:
            try:
                listen_port = int(self.interface_fields['ListenPort'])
            except ValueError:
                logger.warning(f"Invalid ListenPort value: {self.interface_fields['ListenPort']}")

        mtu = None
        if 'MTU' in self.interface_fields:
            try:
                mtu = int(self.interface_fields['MTU'])
            except ValueError:
                logger.warning(f"Invalid MTU value: {self.interface_fields['MTU']}")

        persistent_keepalive = None
        if 'PersistentKeepalive' in peer:
            try:
                persistent_keepalive = int(peer['PersistentKeepalive'])
            except ValueError:
                logger.warning(f"Invalid PersistentKeepalive value: {peer['PersistentKeepalive']}")

        return ParsedExtramuralConfig(
            private_key=self.interface_fields['PrivateKey'],
            addresses=addresses,
            peer_public_key=peer['PublicKey'],
            peer_allowed_ips=peer['AllowedIPs'],
            dns_servers=dns_servers,
            listen_port=listen_port,
            mtu=mtu,
            table=self.interface_fields.get('Table'),
            peer_endpoint=peer.get('Endpoint'),
            peer_preshared_key=peer.get('PresharedKey'),
            peer_persistent_keepalive=persistent_keepalive,
            postup_commands=postup_commands,
            postdown_commands=postdown_commands
        )

    @staticmethod
    def derive_public_key(private_key: str) -> str:
        """Derive public key from private key using wg command"""
        import subprocess

        try:
            public_key = subprocess.check_output(
                ["wg", "pubkey"],
                input=private_key,
                text=True
            ).strip()
            return public_key
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to derive public key: {e}")
        except FileNotFoundError:
            raise RuntimeError("WireGuard tools (wg) not found. Please install wireguard-tools.")


def import_extramural_config(
    db_path: Path,
    config_path: Path,
    sponsor_name: str,
    local_peer_name: str,
    interface_name: Optional[str] = None,
    sponsor_website: Optional[str] = None,
    sponsor_support_url: Optional[str] = None,
    peer_endpoint_name: Optional[str] = None,
    create_missing: bool = True
) -> Tuple[int, int, int]:
    """
    Import an extramural config from a sponsor-provided .conf file.

    Args:
        db_path: Path to database
        config_path: Path to sponsor's .conf file
        sponsor_name: Name of the sponsor (e.g., "Mullvad VPN")
        local_peer_name: Name of your device (e.g., "my-laptop")
        interface_name: Interface name (e.g., "wg-mullvad")
        sponsor_website: Optional website URL
        sponsor_support_url: Optional support URL
        peer_endpoint_name: Optional name for the peer endpoint (e.g., "us-east")
        create_missing: Create sponsor/peer if they don't exist

    Returns:
        Tuple of (config_id, sponsor_id, local_peer_id)

    Raises:
        ValueError: If config is invalid or entities don't exist
    """
    from v1.extramural_ops import ExtramuralOps
    from v1.extramural_schema import ExtramuralDB

    # Initialize database
    ExtramuralDB(db_path)
    ops = ExtramuralOps(db_path)

    # Parse config file
    parser = ExtramuralConfigParser()
    parsed = parser.parse_file(config_path)

    # Derive public key
    public_key = parser.derive_public_key(parsed.private_key)

    # Get or create sponsor
    sponsor = ops.get_sponsor_by_name(sponsor_name)
    if not sponsor:
        if not create_missing:
            raise ValueError(f"Sponsor '{sponsor_name}' not found and create_missing=False")

        sponsor_id = ops.add_sponsor(
            name=sponsor_name,
            website=sponsor_website,
            support_url=sponsor_support_url
        )
        logger.info(f"Created sponsor: {sponsor_name} (ID: {sponsor_id})")
    else:
        sponsor_id = sponsor.id
        logger.info(f"Using existing sponsor: {sponsor_name} (ID: {sponsor_id})")

    # Get or create local peer
    local_peer = ops.get_local_peer_by_name(local_peer_name)
    if not local_peer:
        if not create_missing:
            raise ValueError(f"Local peer '{local_peer_name}' not found and create_missing=False")

        local_peer_id = ops.add_local_peer(
            name=local_peer_name,
            permanent_guid=public_key,  # Use public key as GUID
            notes=f"Imported from {config_path.name}"
        )
        logger.info(f"Created local peer: {local_peer_name} (ID: {local_peer_id})")
    else:
        local_peer_id = local_peer.id
        logger.info(f"Using existing local peer: {local_peer_name} (ID: {local_peer_id})")

    # Determine interface name
    if not interface_name:
        interface_name = config_path.stem  # Use filename without extension

    # Extract IPv4 and IPv6 addresses
    ipv4_addr = None
    ipv6_addr = None

    for addr in parsed.addresses:
        if ':' in addr:
            ipv6_addr = addr
        else:
            ipv4_addr = addr

    # Create config
    config_id = ops.add_extramural_config(
        local_peer_id=local_peer_id,
        sponsor_id=sponsor_id,
        local_private_key=parsed.private_key,
        local_public_key=public_key,
        permanent_guid=public_key,  # Use public key as permanent identifier
        interface_name=interface_name,
        assigned_ipv4=ipv4_addr,
        assigned_ipv6=ipv6_addr,
        dns_servers=parsed.dns_servers,
        listen_port=parsed.listen_port,
        mtu=parsed.mtu,
        table_setting=parsed.table,
        config_path=str(config_path),
        notes=f"Imported from {config_path}"
    )

    logger.info(f"Created extramural config (ID: {config_id})")

    # Add peer (sponsor's server endpoint)
    if not peer_endpoint_name:
        # Try to derive name from endpoint
        if parsed.peer_endpoint:
            # Extract hostname from endpoint (e.g., "us1.mullvad.net:51820" -> "us1")
            endpoint_host = parsed.peer_endpoint.split(':')[0]
            peer_endpoint_name = endpoint_host.split('.')[0]
        else:
            peer_endpoint_name = "default"

    peer_id = ops.add_extramural_peer(
        config_id=config_id,
        name=peer_endpoint_name,
        public_key=parsed.peer_public_key,
        endpoint=parsed.peer_endpoint,
        allowed_ips=parsed.peer_allowed_ips,
        preshared_key=parsed.peer_preshared_key,
        persistent_keepalive=parsed.peer_persistent_keepalive,
        is_active=True  # First peer is active by default
    )

    logger.info(f"Added sponsor peer: {peer_endpoint_name} (ID: {peer_id})")

    # TODO: Handle PostUp/PostDown commands (store in command_pair table)
    if parsed.postup_commands or parsed.postdown_commands:
        logger.warning("PostUp/PostDown commands found but not yet implemented for storage")

    return config_id, sponsor_id, local_peer_id


if __name__ == "__main__":
    # Demo usage
    import tempfile

    # Create a sample config file
    sample_config = """[Interface]
PrivateKey = cNHEd4BbAPdJbqCWzXGDqVYLW0iYjJjx3B5M9k4DE3Q=
Address = 10.64.1.1/32, fc00:bbbb:bbbb:bb01::1/128
DNS = 10.64.0.1

[Peer]
PublicKey = SponsorServerPublicKey123456789abcdefghij=
Endpoint = us1.mullvad.net:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
"""

    with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
        f.write(sample_config)
        config_file = Path(f.name)

    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
        db_file = Path(f.name)

    print(f"Sample config file: {config_file}")
    print(f"Database file: {db_file}\n")

    try:
        # Test parsing
        parser = ExtramuralConfigParser()
        parsed = parser.parse_file(config_file)

        print("=== Parsed Config ===")
        print(f"Addresses: {parsed.addresses}")
        print(f"DNS: {parsed.dns_servers}")
        print(f"Peer endpoint: {parsed.peer_endpoint}")
        print(f"Peer allowed IPs: {parsed.peer_allowed_ips}")
        print(f"Persistent keepalive: {parsed.peer_persistent_keepalive}")

        # Test import (requires wg tools, may fail)
        print("\n=== Attempting Import ===")
        try:
            config_id, sponsor_id, peer_id = import_extramural_config(
                db_path=db_file,
                config_path=config_file,
                sponsor_name="Mullvad VPN",
                local_peer_name="my-laptop",
                interface_name="wg-mullvad",
                sponsor_website="https://mullvad.net"
            )

            print(f"Success! Config ID: {config_id}, Sponsor ID: {sponsor_id}, Peer ID: {peer_id}")

        except RuntimeError as e:
            print(f"Import requires wg tools: {e}")

    finally:
        config_file.unlink()
        print(f"\nCleaned up config file: {config_file}")
        print(f"Database remains at: {db_file}")
