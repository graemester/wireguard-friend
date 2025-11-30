"""
V2 Round-Trip Fidelity Test - Fixed Version

Fixes:
1. Ironclad comment-to-peer association via public keys
2. DNS field parsing
3. Better comment placement
4. Compound command handling
5. Canonical field ordering
"""

import json
import logging
import ipaddress
import base64
from pathlib import Path
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass, field

from v1.patterns import PatternRecognizer, CommandPair, CommandSingleton
from v1.comments import CommentCategorizer, SemanticComment, CommentCategory

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class InterfaceSection:
    """Parsed Interface section"""
    addresses: List[str]
    private_key: str
    listen_port: Optional[int]
    mtu: Optional[int]
    dns: List[str] = field(default_factory=list)

    # Commands (semantically recognized)
    command_pairs: List[CommandPair] = field(default_factory=list)
    command_singletons: List[CommandSingleton] = field(default_factory=list)
    unrecognized_commands: List[str] = field(default_factory=list)

    # Comments (before commands)
    comments: List[SemanticComment] = field(default_factory=list)


@dataclass
class PeerSection:
    """Parsed Peer section - KEYED BY PUBLIC KEY"""
    public_key: str  # The immutable identifier

    # Fields
    preshared_key: Optional[str]
    allowed_ips: List[str]
    endpoint: Optional[str]
    persistent_keepalive: Optional[int]

    # Comments that appeared WITH this public key
    comments: List[SemanticComment] = field(default_factory=list)

    # Derived from comments
    hostname: Optional[str] = None  # From hostname comment
    role_type: Optional[str] = None  # From role comment


@dataclass
class ParsedConfig:
    """Complete parsed config"""
    source_file: Path
    interface: InterfaceSection
    peers: List[PeerSection]  # Each peer keyed by public_key


class SemanticParser:
    """Parser with ironclad comment-to-peer association"""

    def __init__(self):
        self.pattern_recognizer = PatternRecognizer()
        self.comment_categorizer = CommentCategorizer()

    def parse_file(self, config_path: Path) -> ParsedConfig:
        """Parse config file"""
        with open(config_path, 'r') as f:
            content = f.read()

        lines = content.split('\n')

        # Parse interface and peers
        interface = self._parse_interface(lines)
        peers = self._parse_peers(lines)

        return ParsedConfig(
            source_file=config_path,
            interface=interface,
            peers=peers
        )

    def _parse_interface(self, lines: List[str]) -> InterfaceSection:
        """Parse Interface section"""
        in_interface = False
        addresses = []
        private_key = None
        listen_port = None
        mtu = None
        dns = []
        postup_lines = []
        postdown_lines = []
        comments = []

        for line in lines:
            stripped = line.strip()

            if stripped == '[Interface]':
                in_interface = True
                continue

            if stripped == '[Peer]':
                break

            if not in_interface:
                continue

            if not stripped:
                continue

            # Comments
            if stripped.startswith('#'):
                text = stripped[1:].strip()
                comments.append(text)
                continue

            # Fields
            if '=' in stripped:
                field_part = stripped.split('#')[0].strip()
                parts = field_part.split('=', 1)
                if len(parts) != 2:
                    continue

                key = parts[0].strip()
                value = parts[1].strip()

                if key.lower() == 'address':
                    addrs = [a.strip() for a in value.split(',')]
                    addresses.extend(addrs)
                elif key.lower() == 'privatekey':
                    private_key = value
                elif key.lower() == 'listenport':
                    listen_port = int(value)
                elif key.lower() == 'mtu':
                    mtu = int(value)
                elif key.lower() == 'dns':
                    dns_servers = [d.strip() for d in value.split(',')]
                    dns.extend(dns_servers)
                elif key.lower() == 'postup':
                    # Handle compound commands (semicolon-separated)
                    if ';' in value:
                        postup_lines.extend([c.strip() for c in value.split(';')])
                    else:
                        postup_lines.append(value)
                elif key.lower() == 'postdown':
                    if ';' in value:
                        postdown_lines.extend([c.strip() for c in value.split(';')])
                    else:
                        postdown_lines.append(value)

        # Recognize patterns
        pairs, singletons, unrecognized = self.pattern_recognizer.recognize_pairs(
            postup_lines,
            postdown_lines
        )

        # Categorize comments
        categorized = [
            self.comment_categorizer.categorize(text, 'interface')
            for text in comments
        ]

        return InterfaceSection(
            addresses=addresses,
            private_key=private_key,
            listen_port=listen_port,
            mtu=mtu,
            dns=dns,
            command_pairs=pairs,
            command_singletons=singletons,
            unrecognized_commands=unrecognized,
            comments=categorized
        )

    def _parse_peers(self, lines: List[str]) -> List[PeerSection]:
        """Parse all Peer sections with ironclad comment association"""
        peers = []
        current_peer = None
        current_comments = []
        in_peer = False

        for line in lines:
            stripped = line.strip()

            if stripped == '[Peer]':
                # Save previous peer
                if current_peer:
                    peers.append(current_peer)

                # Start new peer
                current_peer = None
                current_comments = []
                in_peer = True
                continue

            if not in_peer:
                continue

            if not stripped:
                continue

            # Comments BEFORE we see PublicKey belong to upcoming peer
            if stripped.startswith('#'):
                text = stripped[1:].strip()
                current_comments.append(text)
                continue

            # Fields
            if '=' in stripped:
                field_part = stripped.split('#')[0].strip()
                parts = field_part.split('=', 1)
                if len(parts) != 2:
                    continue

                key = parts[0].strip()
                value = parts[1].strip()

                # When we see PublicKey, CREATE the peer object
                # All comments collected so far belong to THIS peer
                if key.lower() == 'publickey':
                    # Categorize comments
                    categorized = [
                        self.comment_categorizer.categorize(text, 'peer')
                        for text in current_comments
                    ]

                    # Extract hostname and role from comments
                    hostname = None
                    role_type = None

                    for comment in categorized:
                        if comment.category == CommentCategory.HOSTNAME:
                            hostname = comment.text
                        elif comment.category == CommentCategory.ROLE:
                            role_type = comment.role_type

                    # Create peer KEYED BY PUBLIC KEY
                    current_peer = PeerSection(
                        public_key=value,
                        preshared_key=None,
                        allowed_ips=[],
                        endpoint=None,
                        persistent_keepalive=None,
                        comments=categorized,
                        hostname=hostname,
                        role_type=role_type
                    )
                    current_comments = []  # Reset for any comments after
                    continue

                # Add to current peer
                if current_peer:
                    if key.lower() == 'presharedkey':
                        current_peer.preshared_key = value
                    elif key.lower() == 'allowedips':
                        ips = [ip.strip() for ip in value.split(',')]
                        current_peer.allowed_ips.extend(ips)
                    elif key.lower() == 'endpoint':
                        current_peer.endpoint = value
                    elif key.lower() == 'persistentkeepalive':
                        current_peer.persistent_keepalive = int(value)

        # Save last peer
        if current_peer:
            peers.append(current_peer)

        return peers


class ConfigGenerator:
    """Generate config with proper ordering and comment placement"""

    def generate(self, parsed: ParsedConfig) -> str:
        """Generate config from parsed data"""
        lines = []

        # [Interface]
        lines.append('[Interface]')

        # Canonical field order (no comments yet)
        for addr in parsed.interface.addresses:
            lines.append(f"Address = {addr}")

        if parsed.interface.private_key:
            lines.append(f"PrivateKey = {parsed.interface.private_key}")

        if parsed.interface.listen_port:
            lines.append(f"ListenPort = {parsed.interface.listen_port}")

        if parsed.interface.mtu:
            lines.append(f"MTU = {parsed.interface.mtu}")

        if parsed.interface.dns:
            lines.append(f"DNS = {', '.join(parsed.interface.dns)}")

        # Blank line before commands
        if parsed.interface.command_pairs or parsed.interface.command_singletons:
            lines.append("")

        # Commands with rationale comments BEFORE them
        rationale_comments = [
            c for c in parsed.interface.comments
            if c.category == CommentCategory.RATIONALE
        ]

        # Group commands by rationale
        # For now, just output all rationale comments, then all commands
        for comment in rationale_comments:
            lines.append(f"# {comment.text}")

        # PostUp
        for singleton in parsed.interface.command_singletons:
            cmds = singleton.up_commands if isinstance(singleton.up_commands, list) else [singleton.up_commands]
            for cmd in cmds:
                lines.append(f"PostUp = {cmd}")

        for pair in parsed.interface.command_pairs:
            cmds = pair.up_commands if isinstance(pair.up_commands, list) else [pair.up_commands]
            for cmd in cmds:
                lines.append(f"PostUp = {cmd}")

        for cmd in parsed.interface.unrecognized_commands:
            lines.append(f"PostUp = {cmd}")

        # PostDown
        for pair in parsed.interface.command_pairs:
            cmds = pair.down_commands if isinstance(pair.down_commands, list) else [pair.down_commands]
            for cmd in cmds:
                lines.append(f"PostDown = {cmd}")

        # Peers
        for peer in parsed.peers:
            lines.append("")
            lines.append('[Peer]')

            # Comments BEFORE fields (hostname, role)
            for comment in sorted(peer.comments, key=lambda c: c.display_order):
                if comment.category in (CommentCategory.HOSTNAME, CommentCategory.ROLE, CommentCategory.UNCLASSIFIED):
                    lines.append(f"# {comment.text}")

            # Fields in canonical order
            lines.append(f"PublicKey = {peer.public_key}")

            if peer.preshared_key:
                lines.append(f"PresharedKey = {peer.preshared_key}")

            if peer.allowed_ips:
                lines.append(f"AllowedIPs = {', '.join(peer.allowed_ips)}")

            if peer.endpoint:
                lines.append(f"Endpoint = {peer.endpoint}")

            if peer.persistent_keepalive:
                lines.append(f"PersistentKeepalive = {peer.persistent_keepalive}")

            # Comments AFTER fields (custom)
            for comment in sorted(peer.comments, key=lambda c: c.display_order):
                if comment.category == CommentCategory.CUSTOM:
                    lines.append(f"# {comment.text}")

        return '\n'.join(lines) + '\n'


def verify_comment_associations(parsed: ParsedConfig):
    """Verify comments are associated with correct peers via public keys"""
    print("\n   COMMENT-TO-PEER ASSOCIATION VERIFICATION:")

    for i, peer in enumerate(parsed.peers, 1):
        print(f"\n   Peer {i}:")
        print(f"     PublicKey: {peer.public_key[:20]}...")

        if peer.hostname:
            print(f"     Hostname: {peer.hostname}")

        if peer.role_type:
            print(f"     Role: {peer.role_type}")

        if peer.comments:
            print(f"     Comments ({len(peer.comments)}):")
            for c in peer.comments:
                print(f"       - [{c.category.value}] {c.text}")

        # Verify this is correct by showing which IPs this peer has
        if peer.allowed_ips:
            print(f"     AllowedIPs: {peer.allowed_ips[0]}")


def test_roundtrip():
    """Test with comment association verification"""
    print("=" * 80)
    print("V2 ROUND-TRIP TEST - WITH COMMENT VERIFICATION")
    print("=" * 80)

    import_dir = Path("/home/ged/wireguard-friend/import")

    # Test on coordination.conf (has many peers with comments)
    config_path = import_dir / "coordination.conf"

    if not config_path.exists():
        print("✗ coordination.conf not found")
        return

    print(f"\nTesting: {config_path.name}")
    print("=" * 80)

    parser = SemanticParser()
    generator = ConfigGenerator()

    # Parse
    print("\n1. PARSING")
    parsed = parser.parse_file(config_path)
    print(f"   ✓ Parsed {len(parsed.peers)} peers")

    # Verify comment associations
    verify_comment_associations(parsed)

    # Generate
    print("\n2. GENERATION")
    generated = generator.generate(parsed)

    # Show first peer from generated output
    print("\n   First peer in generated output:")
    gen_lines = generated.split('\n')
    in_first_peer = False
    peer_lines = []
    for line in gen_lines:
        if line.strip() == '[Peer]' and not in_first_peer:
            in_first_peer = True
            peer_lines.append(line)
        elif in_first_peer:
            if line.strip() == '[Peer]':
                break
            peer_lines.append(line)

    for line in peer_lines[:8]:
        print(f"     {line}")

    # Compare
    print("\n3. COMPARISON")
    original = config_path.read_text()

    orig_lines = [l.rstrip() for l in original.split('\n') if l.strip()]
    gen_lines = [l.rstrip() for l in generated.split('\n') if l.strip()]

    print(f"   Original lines:  {len(orig_lines)}")
    print(f"   Generated lines: {len(gen_lines)}")

    # Show a few peer comparisons from original
    print("\n   Original first peer:")
    orig_in_peer = False
    count = 0
    for line in original.split('\n'):
        if '[Peer]' in line and not orig_in_peer:
            orig_in_peer = True
            print(f"     {line}")
            count += 1
        elif orig_in_peer:
            if '[Peer]' in line:
                break
            if line.strip():
                print(f"     {line}")
                count += 1
                if count >= 8:
                    break


if __name__ == "__main__":
    test_roundtrip()
