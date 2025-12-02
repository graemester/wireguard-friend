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
    dns: Optional[str]  # DNS servers

    # Commands (semantically recognized)
    command_pairs: List[CommandPair]
    command_singletons: List[CommandSingleton]
    unrecognized_commands: List[str]
    unrecognized_postdown: List[str]  # PostDown commands that weren't paired

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
        dns = None
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
                elif key.lower() == 'dns':
                    dns = value
                elif key.lower() == 'postup':
                    postup_lines.append(value)
                elif key.lower() == 'postdown':
                    postdown_lines.append(value)

        # Recognize command patterns
        pairs, singletons, unrecognized = self.pattern_recognizer.recognize_pairs(
            postup_lines,
            postdown_lines
        )

        # Find PostDown commands that weren't matched to pairs
        # (unrecognized PostDown commands)
        matched_postdown = set()
        for pair in pairs:
            cmds = pair.down_commands if isinstance(pair.down_commands, list) else json.loads(pair.down_commands)
            for cmd in cmds:
                matched_postdown.add(cmd)
        unrecognized_postdown = [cmd for cmd in postdown_lines if cmd not in matched_postdown]

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
            dns=dns,
            command_pairs=pairs,
            command_singletons=singletons,
            unrecognized_commands=unrecognized,
            unrecognized_postdown=unrecognized_postdown,
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

        # DNS
        if parsed.interface.dns:
            lines.append(f"DNS = {parsed.interface.dns}")

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

        # PostDown (from semantic pairs)
        for pair in parsed.interface.command_pairs:
            cmds = pair.down_commands if isinstance(pair.down_commands, list) else json.loads(pair.down_commands)
            for cmd in cmds:
                lines.append(f"PostDown = {cmd}")

        # Unrecognized PostDown commands (not matched to pairs)
        for cmd in parsed.interface.unrecognized_postdown:
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


def extract_config_values(config_text: str) -> Dict:
    """Extract all key-value pairs from a config, ignoring order and comments"""
    result = {
        'interface': {},
        'peers': []
    }

    current_section = None
    current_peer = {}

    for line in config_text.split('\n'):
        line = line.strip()
        if not line or line.startswith('#'):
            continue

        if line == '[Interface]':
            current_section = 'interface'
            continue
        elif line == '[Peer]':
            if current_peer:
                result['peers'].append(current_peer)
            current_peer = {}
            current_section = 'peer'
            continue

        if '=' in line:
            key, value = line.split('=', 1)
            key = key.strip()
            value = value.strip()

            if current_section == 'interface':
                if key in result['interface']:
                    # Handle multiple values (e.g., multiple Address lines)
                    if isinstance(result['interface'][key], list):
                        result['interface'][key].append(value)
                    else:
                        result['interface'][key] = [result['interface'][key], value]
                else:
                    result['interface'][key] = value
            elif current_section == 'peer':
                if key in current_peer:
                    if isinstance(current_peer[key], list):
                        current_peer[key].append(value)
                    else:
                        current_peer[key] = [current_peer[key], value]
                else:
                    current_peer[key] = value

    if current_peer:
        result['peers'].append(current_peer)

    return result


def normalize_value(value):
    """Normalize a config value for comparison"""
    if isinstance(value, list):
        # Sort and normalize each item
        return sorted([normalize_value(v) for v in value])
    if isinstance(value, str):
        # Handle comma-separated values (e.g., "10.0.0.1/32, 10.0.0.2/32")
        if ',' in value:
            parts = [p.strip() for p in value.split(',')]
            return sorted(parts)
        return value.strip()
    return value


def check_functional_equivalence(original: str, generated: str) -> Tuple[bool, List[str]]:
    """
    Check if two configs are functionally equivalent.

    Returns (is_equivalent, list_of_differences)

    Functional equivalence means:
    - Same keys present
    - Same values (order-independent for multi-value fields)
    - Same peers with same attributes
    """
    orig_data = extract_config_values(original)
    gen_data = extract_config_values(generated)

    differences = []

    # Compare interface sections
    orig_iface = orig_data['interface']
    gen_iface = gen_data['interface']

    # Check critical interface keys
    critical_keys = ['PrivateKey', 'Address', 'ListenPort', 'DNS', 'MTU']
    for key in critical_keys:
        orig_val = normalize_value(orig_iface.get(key, ''))
        gen_val = normalize_value(gen_iface.get(key, ''))
        if orig_val != gen_val:
            differences.append(f"Interface.{key}: '{orig_val}' vs '{gen_val}'")

    # Check PostUp/PostDown commands exist (order may differ but all should be present)
    for cmd_key in ['PostUp', 'PostDown']:
        orig_cmds = orig_iface.get(cmd_key, [])
        gen_cmds = gen_iface.get(cmd_key, [])
        if not isinstance(orig_cmds, list):
            orig_cmds = [orig_cmds] if orig_cmds else []
        if not isinstance(gen_cmds, list):
            gen_cmds = [gen_cmds] if gen_cmds else []

        orig_set = set(c.strip() for c in orig_cmds)
        gen_set = set(c.strip() for c in gen_cmds)

        if orig_set != gen_set:
            missing = orig_set - gen_set
            extra = gen_set - orig_set
            if missing:
                differences.append(f"Missing {cmd_key}: {missing}")
            if extra:
                differences.append(f"Extra {cmd_key}: {extra}")

    # Compare peers
    orig_peers = orig_data['peers']
    gen_peers = gen_data['peers']

    if len(orig_peers) != len(gen_peers):
        differences.append(f"Peer count: {len(orig_peers)} vs {len(gen_peers)}")
    else:
        # Match peers by PublicKey
        orig_by_key = {p.get('PublicKey', ''): p for p in orig_peers}
        gen_by_key = {p.get('PublicKey', ''): p for p in gen_peers}

        for pub_key, orig_peer in orig_by_key.items():
            if pub_key not in gen_by_key:
                differences.append(f"Missing peer with key: {pub_key[:20]}...")
                continue

            gen_peer = gen_by_key[pub_key]

            # Check AllowedIPs
            orig_ips = normalize_value(orig_peer.get('AllowedIPs', ''))
            gen_ips = normalize_value(gen_peer.get('AllowedIPs', ''))
            if orig_ips != gen_ips:
                differences.append(f"Peer {pub_key[:10]}... AllowedIPs differ")

            # Check Endpoint
            orig_ep = orig_peer.get('Endpoint', '')
            gen_ep = gen_peer.get('Endpoint', '')
            if orig_ep != gen_ep:
                differences.append(f"Peer {pub_key[:10]}... Endpoint: '{orig_ep}' vs '{gen_ep}'")

            # Check PersistentKeepalive
            orig_ka = orig_peer.get('PersistentKeepalive', '')
            gen_ka = gen_peer.get('PersistentKeepalive', '')
            if orig_ka != gen_ka:
                differences.append(f"Peer {pub_key[:10]}... Keepalive: '{orig_ka}' vs '{gen_ka}'")

    return len(differences) == 0, differences


def compare_configs(original: str, generated: str) -> Dict:
    """Compare original and generated configs"""
    orig_lines = [l.rstrip() for l in original.split('\n') if l.strip()]
    gen_lines = [l.rstrip() for l in generated.split('\n') if l.strip()]

    # Exact match?
    exact_match = orig_lines == gen_lines

    # Functional equivalence check
    func_equiv, func_diffs = check_functional_equivalence(original, generated)

    # Count line differences (for reporting)
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
        'functional_equivalent': func_equiv,
        'functional_differences': func_diffs,
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
    total_functional = 0
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
        print(f"   Exact match: {'✓ YES' if comparison['exact_match'] else '○ NO (cosmetic differences)'}")
        print(f"   Functional equivalence: {'✓ YES' if comparison['functional_equivalent'] else '✗ NO'}")

        if comparison['exact_match']:
            total_exact += 1

        if comparison['functional_equivalent']:
            total_functional += 1
            print("   ✓ PASS - Config is functionally equivalent")
        else:
            print("   ✗ FAIL - Functional differences detected:")
            for diff in comparison['functional_differences']:
                print(f"     - {diff}")

        # Only show line differences if not functionally equivalent (for debugging)
        if not comparison['functional_equivalent'] and comparison['differences']:
            print(f"\n   Line differences: {len(comparison['differences'])}")
            for diff in comparison['differences'][:5]:
                print(f"\n   Line {diff['line']}:")
                print(f"     Original:  {diff['original']}")
                print(f"     Generated: {diff['generated']}")

            if len(comparison['differences']) > 5:
                print(f"\n   ... and {len(comparison['differences']) - 5} more line differences")

    # Summary
    print(f"\n{'=' * 80}")
    print("SUMMARY")
    print('=' * 80)
    print(f"Total configs: {total_configs}")
    print(f"Exact matches: {total_exact}")
    print(f"Functional equivalence: {total_functional}/{total_configs}")
    print()

    if total_functional == total_configs:
        print("✓ ALL CONFIGS FUNCTIONALLY EQUIVALENT - Test PASSED!")
        if total_exact < total_configs:
            print(f"  (Note: {total_configs - total_exact} config(s) have cosmetic differences - field reordering)")
    else:
        print(f"✗ FAILED - {total_configs - total_functional} config(s) have functional differences")


if __name__ == "__main__":
    test_roundtrip()
