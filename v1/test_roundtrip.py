"""
V2 Round-Trip Fidelity Test

Prove v2 can achieve same fidelity as v1's raw blocks,
but using only semantic attributes.

Test:
1. Import real configs (coordination.conf, wg0.conf, iphone16.conf)
2. Parse with pattern recognizer + comment categorizer
3. Store in semantic database
4. Retrieve and regenerate configs
5. Compare: line-for-line with originals

Acceptable differences:
- Row repositioning (comments before/after)
- Whitespace normalization
- Field reordering (to canonical order)

Validations:
- IP addresses (valid CIDR)
- Keys (valid base64, correct length)
- Ports (valid range)
"""

import json
import logging
import ipaddress
import base64
from pathlib import Path
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass

from v1.patterns import PatternRecognizer, CommandPair, CommandSingleton
from v1.comments import CommentCategorizer, SemanticComment, CommentCategory

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class InterfaceSection:
    """Parsed Interface section with semantic attributes"""
    addresses: List[str]
    private_key: str
    listen_port: Optional[int]
    mtu: Optional[int]

    # Commands (semantically recognized)
    command_pairs: List[CommandPair]
    command_singletons: List[CommandSingleton]
    unrecognized_commands: List[str]

    # Comments (semantically categorized)
    comments: List[SemanticComment]


@dataclass
class PeerSection:
    """Parsed Peer section with semantic attributes"""
    public_key: str
    preshared_key: Optional[str]
    allowed_ips: List[str]
    endpoint: Optional[str]
    persistent_keepalive: Optional[int]

    # Comments (semantically categorized)
    comments: List[SemanticComment]


@dataclass
class ParsedConfig:
    """Complete parsed config with semantic attributes"""
    source_file: Path
    interface: InterfaceSection
    peers: List[PeerSection]


class SemanticParser:
    """Parser that uses pattern recognizer and comment categorizer"""

    def __init__(self):
        self.pattern_recognizer = PatternRecognizer()
        self.comment_categorizer = CommentCategorizer()

    def parse_file(self, config_path: Path) -> ParsedConfig:
        """Parse config file with semantic recognition"""
        with open(config_path, 'r') as f:
            lines = f.readlines()

        # Split into sections
        interface_lines, peer_sections = self._split_sections(lines)

        # Parse interface
        interface = self._parse_interface(interface_lines)

        # Parse peers
        peers = [self._parse_peer(peer_lines) for peer_lines in peer_sections]

        return ParsedConfig(
            source_file=config_path,
            interface=interface,
            peers=peers
        )

    def _split_sections(self, lines: List[str]) -> Tuple[List[str], List[List[str]]]:
        """Split config into interface and peer sections"""
        interface_lines = []
        peer_sections = []
        current_section = None
        current_lines = []

        for line in lines:
            stripped = line.strip()

            if stripped == '[Interface]':
                current_section = 'interface'
                current_lines = [line]
            elif stripped == '[Peer]':
                if current_section == 'interface':
                    interface_lines = current_lines
                elif current_section == 'peer':
                    peer_sections.append(current_lines)
                current_section = 'peer'
                current_lines = [line]
            else:
                current_lines.append(line)

        # Save last section
        if current_section == 'peer':
            peer_sections.append(current_lines)

        return interface_lines, peer_sections

    def _parse_interface(self, lines: List[str]) -> InterfaceSection:
        """Parse Interface section with semantic recognition"""
        addresses = []
        private_key = None
        listen_port = None
        mtu = None
        postup_lines = []
        postdown_lines = []
        comment_lines = []

        for line in lines:
            stripped = line.strip()

            # Skip section header and empty lines
            if not stripped or stripped == '[Interface]':
                continue

            # Comments
            if stripped.startswith('#'):
                comment_text = stripped[1:].strip()
                comment_lines.append(comment_text)
                continue

            # Fields
            if '=' in stripped:
                # Remove inline comments
                field_part = stripped.split('#')[0].strip()
                parts = field_part.split('=', 1)
                if len(parts) != 2:
                    continue

                key = parts[0].strip()
                value = parts[1].strip()

                if key.lower() == 'address':
                    # Can be comma-separated
                    addrs = [a.strip() for a in value.split(',')]
                    addresses.extend(addrs)
                elif key.lower() == 'privatekey':
                    private_key = value
                elif key.lower() == 'listenport':
                    listen_port = int(value)
                elif key.lower() == 'mtu':
                    mtu = int(value)
                elif key.lower() == 'postup':
                    postup_lines.append(value)
                elif key.lower() == 'postdown':
                    postdown_lines.append(value)

        # Recognize command patterns
        pairs, singletons, unrecognized = self.pattern_recognizer.recognize_pairs(
            postup_lines,
            postdown_lines
        )

        # Categorize comments
        comments = [
            self.comment_categorizer.categorize(text, context='interface')
            for text in comment_lines
        ]

        return InterfaceSection(
            addresses=addresses,
            private_key=private_key,
            listen_port=listen_port,
            mtu=mtu,
            command_pairs=pairs,
            command_singletons=singletons,
            unrecognized_commands=unrecognized,
            comments=comments
        )

    def _parse_peer(self, lines: List[str]) -> PeerSection:
        """Parse Peer section with semantic recognition"""
        public_key = None
        preshared_key = None
        allowed_ips = []
        endpoint = None
        persistent_keepalive = None
        comment_lines = []

        for line in lines:
            stripped = line.strip()

            # Skip section header and empty lines
            if not stripped or stripped == '[Peer]':
                continue

            # Comments
            if stripped.startswith('#'):
                comment_text = stripped[1:].strip()
                comment_lines.append(comment_text)
                continue

            # Fields
            if '=' in stripped:
                field_part = stripped.split('#')[0].strip()
                parts = field_part.split('=', 1)
                if len(parts) != 2:
                    continue

                key = parts[0].strip()
                value = parts[1].strip()

                if key.lower() == 'publickey':
                    public_key = value
                elif key.lower() == 'presharedkey':
                    preshared_key = value
                elif key.lower() == 'allowedips':
                    ips = [ip.strip() for ip in value.split(',')]
                    allowed_ips.extend(ips)
                elif key.lower() == 'endpoint':
                    endpoint = value
                elif key.lower() == 'persistentkeepalive':
                    persistent_keepalive = int(value)

        # Categorize comments
        comments = [
            self.comment_categorizer.categorize(text, context='peer')
            for text in comment_lines
        ]

        return PeerSection(
            public_key=public_key,
            preshared_key=preshared_key,
            allowed_ips=allowed_ips,
            endpoint=endpoint,
            persistent_keepalive=persistent_keepalive,
            comments=comments
        )


class ConfigGenerator:
    """Generate config from semantic attributes"""

    def generate(self, parsed: ParsedConfig) -> str:
        """Generate config text from parsed semantic data"""
        lines = []

        # Interface section
        lines.append('[Interface]')

        # Interface comments (rationale type, before fields)
        rationale_comments = [
            c for c in parsed.interface.comments
            if c.category == CommentCategory.RATIONALE
        ]
        for comment in sorted(rationale_comments, key=lambda c: c.display_order):
            lines.append(f"# {comment.text}")

        # Address (can be multiple)
        for addr in parsed.interface.addresses:
            lines.append(f"Address = {addr}")

        # PrivateKey
        if parsed.interface.private_key:
            lines.append(f"PrivateKey = {parsed.interface.private_key}")

        # ListenPort
        if parsed.interface.listen_port:
            lines.append(f"ListenPort = {parsed.interface.listen_port}")

        # MTU
        if parsed.interface.mtu:
            lines.append(f"MTU = {parsed.interface.mtu}")

        lines.append("")  # Blank line after interface fields

        # PostUp/PostDown commands (from semantic pairs)
        for pair in parsed.interface.command_pairs:
            cmds = pair.up_commands if isinstance(pair.up_commands, list) else json.loads(pair.up_commands)
            for cmd in cmds:
                lines.append(f"PostUp = {cmd}")

        for singleton in parsed.interface.command_singletons:
            cmds = singleton.up_commands if isinstance(singleton.up_commands, list) else json.loads(singleton.up_commands)
            for cmd in cmds:
                lines.append(f"PostUp = {cmd}")

        # Unrecognized commands (fallback)
        for cmd in parsed.interface.unrecognized_commands:
            lines.append(f"PostUp = {cmd}")

        # PostDown
        for pair in parsed.interface.command_pairs:
            cmds = pair.down_commands if isinstance(pair.down_commands, list) else json.loads(pair.down_commands)
            for cmd in cmds:
                lines.append(f"PostDown = {cmd}")

        # Peers
        for peer in parsed.peers:
            lines.append("")  # Blank line before peer
            lines.append('[Peer]')

            # Peer comments (hostname and role, before fields)
            before_comments = [
                c for c in peer.comments
                if c.category in (CommentCategory.HOSTNAME, CommentCategory.ROLE, CommentCategory.UNCLASSIFIED)
            ]
            for comment in sorted(before_comments, key=lambda c: c.display_order):
                lines.append(f"# {comment.text}")

            # PublicKey
            if peer.public_key:
                lines.append(f"PublicKey = {peer.public_key}")

            # PresharedKey
            if peer.preshared_key:
                lines.append(f"PresharedKey = {peer.preshared_key}")

            # AllowedIPs
            if peer.allowed_ips:
                lines.append(f"AllowedIPs = {', '.join(peer.allowed_ips)}")

            # Endpoint
            if peer.endpoint:
                lines.append(f"Endpoint = {peer.endpoint}")

            # PersistentKeepalive
            if peer.persistent_keepalive:
                lines.append(f"PersistentKeepalive = {peer.persistent_keepalive}")

            # Custom comments (after fields)
            after_comments = [
                c for c in peer.comments
                if c.category == CommentCategory.CUSTOM
            ]
            for comment in sorted(after_comments, key=lambda c: c.display_order):
                lines.append(f"# {comment.text}")

        return '\n'.join(lines) + '\n'


class Validator:
    """Validate parsed data"""

    @staticmethod
    def validate_ip_address(addr: str) -> Tuple[bool, str]:
        """Validate IP address or CIDR"""
        try:
            ipaddress.ip_network(addr, strict=False)
            return True, "Valid"
        except ValueError as e:
            return False, str(e)

    @staticmethod
    def validate_key(key: str, expected_len: int = 44) -> Tuple[bool, str]:
        """Validate WireGuard key (base64, correct length)"""
        if len(key) != expected_len:
            return False, f"Wrong length: {len(key)} (expected {expected_len})"

        try:
            decoded = base64.b64decode(key)
            if len(decoded) != 32:
                return False, f"Decoded length wrong: {len(decoded)} bytes"
            return True, "Valid"
        except Exception as e:
            return False, f"Invalid base64: {e}"

    @staticmethod
    def validate_port(port: int) -> Tuple[bool, str]:
        """Validate port number"""
        if 1 <= port <= 65535:
            return True, "Valid"
        return False, f"Out of range: {port}"


def compare_configs(original: str, generated: str) -> Dict:
    """Compare original and generated configs"""
    orig_lines = [l.rstrip() for l in original.split('\n') if l.strip()]
    gen_lines = [l.rstrip() for l in generated.split('\n') if l.strip()]

    # Exact match?
    exact_match = orig_lines == gen_lines

    # Count differences
    differences = []
    max_len = max(len(orig_lines), len(gen_lines))

    for i in range(max_len):
        orig = orig_lines[i] if i < len(orig_lines) else "<missing>"
        gen = gen_lines[i] if i < len(gen_lines) else "<missing>"

        if orig != gen:
            differences.append({
                'line': i + 1,
                'original': orig,
                'generated': gen
            })

    return {
        'exact_match': exact_match,
        'original_lines': len(orig_lines),
        'generated_lines': len(gen_lines),
        'differences': differences
    }


def test_roundtrip():
    """Complete round-trip test on real configs"""
    print("=" * 80)
    print("V2 ROUND-TRIP FIDELITY TEST")
    print("=" * 80)
    print()

    import_dir = Path("/home/ged/wireguard-friend/import")
    configs = list(import_dir.glob("*.conf"))

    if not configs:
        print("✗ No configs found in import/")
        return

    parser = SemanticParser()
    generator = ConfigGenerator()
    validator = Validator()

    total_exact = 0
    total_configs = 0

    for config_path in sorted(configs):
        total_configs += 1
        print(f"\n{'=' * 80}")
        print(f"CONFIG: {config_path.name}")
        print('=' * 80)

        # Read original
        original = config_path.read_text()

        # Parse with semantic recognition
        print("\n1. PARSING (with semantic recognition)")
        parsed = parser.parse_file(config_path)

        print(f"   ✓ Addresses: {len(parsed.interface.addresses)}")
        print(f"   ✓ Command pairs: {len(parsed.interface.command_pairs)}")
        print(f"   ✓ Command singletons: {len(parsed.interface.command_singletons)}")
        print(f"   ✓ Unrecognized commands: {len(parsed.interface.unrecognized_commands)}")
        print(f"   ✓ Interface comments: {len(parsed.interface.comments)}")
        print(f"   ✓ Peers: {len(parsed.peers)}")

        # Show recognized patterns
        if parsed.interface.command_pairs:
            print("\n   Recognized patterns:")
            for pair in parsed.interface.command_pairs:
                print(f"     - {pair.pattern_name}: {pair.rationale}")
                if pair.variables:
                    vars_dict = json.loads(pair.variables) if isinstance(pair.variables, str) else pair.variables
                    print(f"       Variables: {vars_dict}")

        # Show categorized comments
        if parsed.interface.comments:
            print("\n   Interface comments:")
            for c in parsed.interface.comments:
                print(f"     - [{c.category.value}] {c.text}")

        # Validate
        print("\n2. VALIDATION")
        all_valid = True

        # Validate addresses
        for addr in parsed.interface.addresses:
            valid, msg = validator.validate_ip_address(addr)
            status = "✓" if valid else "✗"
            print(f"   {status} Address {addr}: {msg}")
            all_valid = all_valid and valid

        # Validate private key
        if parsed.interface.private_key:
            valid, msg = validator.validate_key(parsed.interface.private_key)
            status = "✓" if valid else "✗"
            print(f"   {status} PrivateKey: {msg}")
            all_valid = all_valid and valid

        # Validate port
        if parsed.interface.listen_port:
            valid, msg = validator.validate_port(parsed.interface.listen_port)
            status = "✓" if valid else "✗"
            print(f"   {status} ListenPort {parsed.interface.listen_port}: {msg}")
            all_valid = all_valid and valid

        # Validate peer keys and IPs
        for i, peer in enumerate(parsed.peers, 1):
            if peer.public_key:
                valid, msg = validator.validate_key(peer.public_key)
                status = "✓" if valid else "✗"
                print(f"   {status} Peer {i} PublicKey: {msg}")
                all_valid = all_valid and valid

            for ip in peer.allowed_ips:
                valid, msg = validator.validate_ip_address(ip)
                status = "✓" if valid else "✗"
                print(f"   {status} Peer {i} AllowedIP {ip}: {msg}")
                all_valid = all_valid and valid

        print(f"\n   Overall validation: {'✓ PASS' if all_valid else '✗ FAIL'}")

        # Generate
        print("\n3. GENERATION (from semantic attributes)")
        generated = generator.generate(parsed)
        print(f"   ✓ Generated {len(generated)} bytes")

        # Compare
        print("\n4. COMPARISON")
        comparison = compare_configs(original, generated)

        print(f"   Original lines:  {comparison['original_lines']}")
        print(f"   Generated lines: {comparison['generated_lines']}")
        print(f"   Exact match: {'✓ YES' if comparison['exact_match'] else '✗ NO'}")

        if comparison['exact_match']:
            total_exact += 1

        if comparison['differences']:
            print(f"\n   Differences: {len(comparison['differences'])}")
            for diff in comparison['differences'][:10]:  # Show first 10
                print(f"\n   Line {diff['line']}:")
                print(f"     Original:  {diff['original']}")
                print(f"     Generated: {diff['generated']}")

            if len(comparison['differences']) > 10:
                print(f"\n   ... and {len(comparison['differences']) - 10} more differences")

    # Summary
    print(f"\n{'=' * 80}")
    print("SUMMARY")
    print('=' * 80)
    print(f"Total configs: {total_configs}")
    print(f"Exact matches: {total_exact}")
    print(f"Success rate: {total_exact / total_configs * 100:.1f}%")
    print()

    if total_exact == total_configs:
        print("✓ PERFECT FIDELITY - All configs reproduced exactly!")
    else:
        print("WARNING: PARTIAL FIDELITY - Some differences found")
        print("  (This may be acceptable if only comment/whitespace repositioning)")


if __name__ == "__main__":
    test_roundtrip()
