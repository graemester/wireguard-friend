"""
WireGuard Config Parser - Full Fidelity

Parses WireGuard configs into complete AST with:
- All fields (known and unknown)
- Comments with positioning
- Formatting preferences
- PostUp/PostDown as structured commands
- Complete provenance tracking

This parser can extract EVERYTHING from a config, making raw blocks unnecessary.
"""

import re
import hashlib
import logging
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Any
from dataclasses import dataclass, field

from v1.comment_system import CommentExtractor, Comment, EntityType, CommentPosition
from v1.formatting import FormattingDetector, FormattingProfile
from v1.shell_parser import ShellCommandParser, ParsedCommand
from v1.unknown_fields import UnknownFieldHandler, FieldCategory, ValidationMode

logger = logging.getLogger(__name__)


@dataclass
class InterfaceData:
    """Complete interface section data"""
    # Known fields
    addresses: List[str] = field(default_factory=list)
    private_key: Optional[str] = None
    listen_port: Optional[int] = None
    mtu: Optional[int] = None
    dns: List[str] = field(default_factory=list)
    table: Optional[str] = None

    # Shell commands (parsed)
    preup_commands: List[ParsedCommand] = field(default_factory=list)
    postup_commands: List[ParsedCommand] = field(default_factory=list)
    predown_commands: List[ParsedCommand] = field(default_factory=list)
    postdown_commands: List[ParsedCommand] = field(default_factory=list)

    # Unknown fields
    unknown_fields: Dict[str, str] = field(default_factory=dict)

    # Provenance
    source_line_start: int = 0
    source_line_end: int = 0


@dataclass
class PeerData:
    """Complete peer section data"""
    # Known fields
    public_key: str = ""
    preshared_key: Optional[str] = None
    allowed_ips: List[str] = field(default_factory=list)
    endpoint: Optional[str] = None
    persistent_keepalive: Optional[int] = None

    # Unknown fields
    unknown_fields: Dict[str, str] = field(default_factory=dict)

    # Provenance
    source_line_start: int = 0
    source_line_end: int = 0
    peer_index: int = 0  # Order in original file


@dataclass
class ParsedConfig:
    """Complete parsed WireGuard configuration"""
    # Source file metadata
    source_file: Path
    file_size: int
    checksum: str  # SHA256

    # Main data
    interface: InterfaceData
    peers: List[PeerData]

    # Comments
    comments: List[Comment]

    # Formatting
    formatting: FormattingProfile

    # Statistics
    total_lines: int = 0
    total_peers: int = 0


class WireGuardParser:
    """Full-fidelity parser for WireGuard configurations"""

    def __init__(self, validation_mode: ValidationMode = ValidationMode.PERMISSIVE):
        self.unknown_handler = UnknownFieldHandler(validation_mode)
        self.comment_extractor = CommentExtractor()
        self.formatting_detector = FormattingDetector()
        self.shell_parser = ShellCommandParser()

    def parse_file(self, config_path: Path) -> ParsedConfig:
        """
        Parse a WireGuard config file with full fidelity.

        Args:
            config_path: Path to .conf file

        Returns:
            ParsedConfig with complete AST
        """
        # Read file
        with open(config_path, 'r') as f:
            content = f.read()

        lines = content.split('\n')

        # Calculate checksum
        checksum = hashlib.sha256(content.encode()).hexdigest()
        file_size = len(content)

        # Extract components
        comments = self.comment_extractor.extract_comments(lines)
        formatting = self.formatting_detector.detect_profile(lines)
        interface, peers = self._parse_sections(lines)

        return ParsedConfig(
            source_file=config_path,
            file_size=file_size,
            checksum=checksum,
            interface=interface,
            peers=peers,
            comments=comments,
            formatting=formatting,
            total_lines=len(lines),
            total_peers=len(peers)
        )

    def _parse_sections(self, lines: List[str]) -> Tuple[InterfaceData, List[PeerData]]:
        """
        Parse Interface and Peer sections.

        Returns:
            (interface_data, list_of_peer_data)
        """
        interface = InterfaceData()
        peers: List[PeerData] = []

        current_section = None
        current_peer = None
        section_start_line = 0

        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()

            # Section headers
            if stripped == '[Interface]':
                current_section = 'interface'
                section_start_line = line_num
                interface.source_line_start = line_num
                continue

            elif stripped == '[Peer]':
                # Save previous peer if exists
                if current_peer is not None:
                    current_peer.source_line_end = line_num - 1
                    peers.append(current_peer)

                # Start new peer
                current_section = 'peer'
                current_peer = PeerData(
                    source_line_start=line_num,
                    peer_index=len(peers)
                )
                continue

            # Skip empty lines and comments
            if not stripped or stripped.startswith('#'):
                continue

            # Parse field
            if '=' in stripped:
                # Remove inline comments for parsing
                field_line = stripped.split('#', 1)[0].strip()
                parts = field_line.split('=', 1)
                if len(parts) != 2:
                    continue

                field_name = parts[0].strip()
                field_value = parts[1].strip()

                # Parse based on section
                if current_section == 'interface':
                    self._parse_interface_field(
                        interface,
                        field_name,
                        field_value,
                        line_num
                    )
                elif current_section == 'peer' and current_peer is not None:
                    self._parse_peer_field(
                        current_peer,
                        field_name,
                        field_value,
                        line_num
                    )

        # Save last peer
        if current_peer is not None:
            current_peer.source_line_end = len(lines)
            peers.append(current_peer)

        # Set interface end line
        if peers:
            interface.source_line_end = peers[0].source_line_start - 1
        else:
            interface.source_line_end = len(lines)

        return interface, peers

    def _parse_interface_field(
        self,
        interface: InterfaceData,
        field_name: str,
        field_value: str,
        line_num: int
    ):
        """Parse a field in the Interface section"""
        field_lower = field_name.lower()

        if field_lower == 'address':
            # Can be comma-separated
            addrs = [a.strip() for a in field_value.split(',')]
            interface.addresses.extend(addrs)

        elif field_lower == 'privatekey':
            interface.private_key = field_value

        elif field_lower == 'listenport':
            try:
                interface.listen_port = int(field_value)
            except ValueError:
                logger.warning(f"Invalid ListenPort value at line {line_num}: {field_value}")

        elif field_lower == 'mtu':
            try:
                interface.mtu = int(field_value)
            except ValueError:
                logger.warning(f"Invalid MTU value at line {line_num}: {field_value}")

        elif field_lower == 'dns':
            dns_servers = [d.strip() for d in field_value.split(',')]
            interface.dns.extend(dns_servers)

        elif field_lower == 'table':
            interface.table = field_value

        elif field_lower == 'preup':
            parsed = self.shell_parser.parse_command(field_value)
            interface.preup_commands.append(parsed)

        elif field_lower == 'postup':
            parsed = self.shell_parser.parse_command(field_value)
            interface.postup_commands.append(parsed)

        elif field_lower == 'predown':
            parsed = self.shell_parser.parse_command(field_value)
            interface.predown_commands.append(parsed)

        elif field_lower == 'postdown':
            parsed = self.shell_parser.parse_command(field_value)
            interface.postdown_commands.append(parsed)

        else:
            # Unknown field - check with handler
            accepted = self.unknown_handler.check_field(
                FieldCategory.INTERFACE,
                field_name,
                field_value,
                entity_id=0,  # Will be updated when stored in DB
                source_line=line_num
            )
            if accepted:
                interface.unknown_fields[field_name] = field_value

    def _parse_peer_field(
        self,
        peer: PeerData,
        field_name: str,
        field_value: str,
        line_num: int
    ):
        """Parse a field in a Peer section"""
        field_lower = field_name.lower()

        if field_lower == 'publickey':
            peer.public_key = field_value

        elif field_lower == 'presharedkey':
            peer.preshared_key = field_value

        elif field_lower == 'allowedips':
            # Comma-separated list
            ips = [ip.strip() for ip in field_value.split(',')]
            peer.allowed_ips.extend(ips)

        elif field_lower == 'endpoint':
            peer.endpoint = field_value

        elif field_lower == 'persistentkeepalive':
            try:
                peer.persistent_keepalive = int(field_value)
            except ValueError:
                logger.warning(f"Invalid PersistentKeepalive at line {line_num}: {field_value}")

        else:
            # Unknown field
            accepted = self.unknown_handler.check_field(
                FieldCategory.PEER,
                field_name,
                field_value,
                entity_id=peer.peer_index,
                source_line=line_num
            )
            if accepted:
                peer.unknown_fields[field_name] = field_value

    def get_statistics(self, parsed: ParsedConfig) -> Dict[str, Any]:
        """Generate parsing statistics"""
        stats = {
            'file': str(parsed.source_file),
            'size_bytes': parsed.file_size,
            'checksum': parsed.checksum[:16] + '...',
            'total_lines': parsed.total_lines,
            'total_peers': parsed.total_peers,
            'total_comments': len(parsed.comments),
            'unknown_fields': self.unknown_handler.get_summary(),
            'formatting': {
                'indent_style': parsed.formatting.indent_style.value,
                'indent_width': parsed.formatting.indent_width,
                'peer_spacing': parsed.formatting.blank_lines_between_peers,
            }
        }

        # Count shell commands
        total_commands = (
            len(parsed.interface.preup_commands) +
            len(parsed.interface.postup_commands) +
            len(parsed.interface.predown_commands) +
            len(parsed.interface.postdown_commands)
        )
        stats['total_shell_commands'] = total_commands

        return stats


def demonstrate_parser():
    """Demonstrate full-fidelity parsing"""
    sample_config = """# WireGuard Configuration for VPN Server
[Interface]
# VPN network addresses
Address = 10.66.0.1/24, fd66::1/64
PrivateKey = SERVER_PRIVATE_KEY_HERE
ListenPort = 51820  # Standard WireGuard port
MTU = 1420

# Enable forwarding and NAT
PostUp = iptables -t nat -A POSTROUTING -s 10.66.0.0/24 -o eth0 -j MASQUERADE
PostUp = sysctl -w net.ipv4.ip_forward=1
PostDown = iptables -t nat -D POSTROUTING -s 10.66.0.0/24 -o eth0 -j MASQUERADE

[Peer]
# Mobile device - Alice's phone
PublicKey = ALICE_PUBLIC_KEY
AllowedIPs = 10.66.0.20/32
PersistentKeepalive = 25

[Peer]
# Laptop - Bob's work laptop
PublicKey = BOB_PUBLIC_KEY
AllowedIPs = 10.66.0.30/32
Endpoint = bob.example.com:51821
"""

    # Write to temp file
    import tempfile
    with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
        f.write(sample_config)
        temp_path = Path(f.name)

    try:
        # Parse
        parser = WireGuardParser(ValidationMode.PERMISSIVE)
        parsed = parser.parse_file(temp_path)

        # Show results
        print("=== Full-Fidelity Parser Demo ===\n")

        stats = parser.get_statistics(parsed)
        print("Statistics:")
        for key, value in stats.items():
            print(f"  {key}: {value}")

        print(f"\nInterface:")
        print(f"  Addresses: {parsed.interface.addresses}")
        print(f"  Listen Port: {parsed.interface.listen_port}")
        print(f"  MTU: {parsed.interface.mtu}")
        print(f"  PostUp commands: {len(parsed.interface.postup_commands)}")

        print(f"\nPeers: {len(parsed.peers)}")
        for i, peer in enumerate(parsed.peers, 1):
            print(f"  Peer {i}:")
            print(f"    Public Key: {peer.public_key[:20]}...")
            print(f"    Allowed IPs: {peer.allowed_ips}")
            if peer.endpoint:
                print(f"    Endpoint: {peer.endpoint}")

        print(f"\nComments: {len(parsed.comments)}")
        for comment in parsed.comments[:5]:  # Show first 5
            print(f"  Line {comment.original_line_number}: '{comment.text}' ({comment.position.value})")

        print(f"\nFormatting:")
        print(f"  Indent: {parsed.formatting.indent_style.value} (width: {parsed.formatting.indent_width})")
        print(f"  Peer spacing: {parsed.formatting.blank_lines_between_peers} blank lines")

    finally:
        temp_path.unlink()


if __name__ == "__main__":
    demonstrate_parser()
