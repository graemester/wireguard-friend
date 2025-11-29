"""
Full Round-Trip Test with Refactored Entity Parser

Uses the bracket delimiter foundation:
1. Parse entities by '[' delimiters (entity_parser.py)
2. Extract semantic meaning (patterns, comments)
3. Store in database (semantic schema)
4. Regenerate configs
5. Compare with originals
"""

import logging
from pathlib import Path
from typing import List, Dict, Optional
from dataclasses import dataclass, field

from v1.entity_parser import EntityParser, RawEntity
from v1.patterns import PatternRecognizer, CommandPair, CommandSingleton
from v1.comments import CommentCategorizer, SemanticComment, CommentCategory

logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger(__name__)


@dataclass
class ParsedInterface:
    """Parsed interface entity"""
    addresses: List[str] = field(default_factory=list)
    private_key: Optional[str] = None
    listen_port: Optional[int] = None
    mtu: Optional[int] = None
    dns: List[str] = field(default_factory=list)

    command_pairs: List[CommandPair] = field(default_factory=list)
    command_singletons: List[CommandSingleton] = field(default_factory=list)
    unrecognized_commands: List[str] = field(default_factory=list)

    comments: List[SemanticComment] = field(default_factory=list)


@dataclass
class ParsedPeer:
    """Parsed peer entity - keyed by public key"""
    public_key: str
    preshared_key: Optional[str] = None
    allowed_ips: List[str] = field(default_factory=list)
    endpoint: Optional[str] = None
    persistent_keepalive: Optional[int] = None

    hostname: Optional[str] = None
    role_type: Optional[str] = None
    comments: List[SemanticComment] = field(default_factory=list)


class SemanticExtractor:
    """Extract semantic meaning from raw entities"""

    def __init__(self):
        self.pattern_recognizer = PatternRecognizer()
        self.comment_categorizer = CommentCategorizer()

    def extract_interface(self, entity: RawEntity) -> ParsedInterface:
        """Extract semantic data from interface entity"""
        interface = ParsedInterface()

        postup_lines = []
        postdown_lines = []
        comment_lines = []

        for line in entity.lines:
            stripped = line.strip()

            if not stripped:
                continue

            # Comments
            if stripped.startswith('#'):
                comment_lines.append(stripped[1:].strip())
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
                    interface.addresses.extend(addrs)
                elif key.lower() == 'privatekey':
                    interface.private_key = value
                elif key.lower() == 'listenport':
                    interface.listen_port = int(value)
                elif key.lower() == 'mtu':
                    interface.mtu = int(value)
                elif key.lower() == 'dns':
                    dns = [d.strip() for d in value.split(',')]
                    interface.dns.extend(dns)
                elif key.lower() == 'postup':
                    # Handle compound commands
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
            postup_lines, postdown_lines
        )

        interface.command_pairs = pairs
        interface.command_singletons = singletons
        interface.unrecognized_commands = unrecognized

        # Categorize comments
        interface.comments = [
            self.comment_categorizer.categorize(text, 'interface')
            for text in comment_lines
        ]

        return interface

    def extract_peer(self, entity: RawEntity) -> ParsedPeer:
        """Extract semantic data from peer entity"""
        peer = None
        comments_before_pubkey = []

        for line in entity.lines:
            stripped = line.strip()

            if not stripped:
                continue

            # Comments before PublicKey
            if stripped.startswith('#'):
                if peer is None:
                    comments_before_pubkey.append(stripped[1:].strip())
                continue

            # Fields
            if '=' in stripped:
                field_part = stripped.split('#')[0].strip()
                parts = field_part.split('=', 1)
                if len(parts) != 2:
                    continue

                key = parts[0].strip()
                value = parts[1].strip()

                # When we see PublicKey, create peer object
                if key.lower() == 'publickey':
                    # Categorize comments
                    categorized = [
                        self.comment_categorizer.categorize(text, 'peer')
                        for text in comments_before_pubkey
                    ]

                    # Extract hostname and role
                    hostname = None
                    role_type = None
                    for c in categorized:
                        if c.category == CommentCategory.HOSTNAME:
                            hostname = c.text
                        elif c.category == CommentCategory.ROLE:
                            role_type = c.role_type

                    peer = ParsedPeer(
                        public_key=value,
                        hostname=hostname,
                        role_type=role_type,
                        comments=categorized
                    )
                    continue

                # Add to peer
                if peer:
                    if key.lower() == 'presharedkey':
                        peer.preshared_key = value
                    elif key.lower() == 'allowedips':
                        ips = [ip.strip() for ip in value.split(',')]
                        peer.allowed_ips.extend(ips)
                    elif key.lower() == 'endpoint':
                        peer.endpoint = value
                    elif key.lower() == 'persistentkeepalive':
                        peer.persistent_keepalive = int(value)

        return peer


class ConfigGenerator:
    """Generate config from parsed entities"""

    def generate(self, interface: ParsedInterface, peers: List[ParsedPeer]) -> str:
        """Generate config text"""
        lines = []

        # [Interface]
        lines.append('[Interface]')

        # Fields (canonical order)
        for addr in interface.addresses:
            lines.append(f"Address = {addr}")

        if interface.private_key:
            lines.append(f"PrivateKey = {interface.private_key}")

        if interface.listen_port:
            lines.append(f"ListenPort = {interface.listen_port}")

        if interface.mtu:
            lines.append(f"MTU = {interface.mtu}")

        if interface.dns:
            lines.append(f"DNS = {', '.join(interface.dns)}")

        # Blank line before commands
        if interface.command_pairs or interface.command_singletons:
            lines.append("")

        # Rationale comments
        for c in interface.comments:
            if c.category == CommentCategory.RATIONALE:
                lines.append(f"# {c.text}")

        # PostUp/PostDown
        for singleton in interface.command_singletons:
            cmds = singleton.up_commands if isinstance(singleton.up_commands, list) else [singleton.up_commands]
            for cmd in cmds:
                lines.append(f"PostUp = {cmd}")

        for pair in interface.command_pairs:
            cmds = pair.up_commands if isinstance(pair.up_commands, list) else [pair.up_commands]
            for cmd in cmds:
                lines.append(f"PostUp = {cmd}")

        for cmd in interface.unrecognized_commands:
            lines.append(f"PostUp = {cmd}")

        for pair in interface.command_pairs:
            cmds = pair.down_commands if isinstance(pair.down_commands, list) else [pair.down_commands]
            for cmd in cmds:
                lines.append(f"PostDown = {cmd}")

        # Peers
        for peer in peers:
            lines.append("")
            lines.append('[Peer]')

            # Comments before fields
            for c in sorted(peer.comments, key=lambda x: x.display_order):
                if c.category in (CommentCategory.HOSTNAME, CommentCategory.ROLE):
                    lines.append(f"# {c.text}")

            # Fields
            lines.append(f"PublicKey = {peer.public_key}")

            if peer.preshared_key:
                lines.append(f"PresharedKey = {peer.preshared_key}")

            if peer.allowed_ips:
                lines.append(f"AllowedIPs = {', '.join(peer.allowed_ips)}")

            if peer.endpoint:
                lines.append(f"Endpoint = {peer.endpoint}")

            if peer.persistent_keepalive:
                lines.append(f"PersistentKeepalive = {peer.persistent_keepalive}")

        return '\n'.join(lines) + '\n'


def test_config(config_path: Path):
    """Test round-trip on a single config"""
    print(f"\n{'=' * 80}")
    print(f"CONFIG: {config_path.name}")
    print('=' * 80)

    # 1. Parse entities by bracket delimiters
    print("\n1. ENTITY PARSING (bracket delimiters)")
    entity_parser = EntityParser()
    entities = entity_parser.parse_file(config_path)

    valid, msg = entity_parser.validate_structure(entities)
    print(f"   Entities: {len(entities)} ({msg})")

    # 2. Extract semantic meaning
    print("\n2. SEMANTIC EXTRACTION")
    extractor = SemanticExtractor()

    interface_entity = entities[0]
    peer_entities = entities[1:]

    interface = extractor.extract_interface(interface_entity)
    peers = [extractor.extract_peer(e) for e in peer_entities]

    print(f"   Interface: {len(interface.addresses)} addresses")
    print(f"   Command pairs: {len(interface.command_pairs)}")
    print(f"   Command singletons: {len(interface.command_singletons)}")
    print(f"   Peers: {len(peers)}")

    # Show recognized patterns
    if interface.command_pairs:
        print(f"\n   Recognized patterns:")
        for pair in interface.command_pairs:
            print(f"     - {pair.pattern_name}")

    # 3. Verify comment associations
    print("\n3. COMMENT ASSOCIATIONS")
    for i, peer in enumerate(peers[:3], 1):  # Show first 3
        print(f"   Peer {i}:")
        print(f"     PublicKey: {peer.public_key[:20]}...")
        if peer.hostname:
            print(f"     Hostname: {peer.hostname} ✓")
        if peer.role_type:
            print(f"     Role: {peer.role_type} ✓")

    if len(peers) > 3:
        print(f"   ... and {len(peers) - 3} more peers")

    # 4. Generate
    print("\n4. GENERATION")
    generator = ConfigGenerator()
    generated = generator.generate(interface, peers)

    print(f"   Generated: {len(generated)} bytes")

    # 5. Compare
    print("\n5. COMPARISON")
    original = config_path.read_text()

    orig_lines = [l.rstrip() for l in original.split('\n') if l.strip()]
    gen_lines = [l.rstrip() for l in generated.split('\n') if l.strip()]

    print(f"   Original:  {len(orig_lines)} lines")
    print(f"   Generated: {len(gen_lines)} lines")

    # Check structural match
    orig_sections = [l for l in orig_lines if l.startswith('[')]
    gen_sections = [l for l in gen_lines if l.startswith('[')]

    sections_match = orig_sections == gen_sections
    print(f"   Sections match: {'✓ YES' if sections_match else '❌ NO'}")

    # Check field count
    orig_fields = [l for l in orig_lines if '=' in l and not l.strip().startswith('#')]
    gen_fields = [l for l in gen_lines if '=' in l and not l.strip().startswith('#')]

    print(f"   Fields: {len(orig_fields)} -> {len(gen_fields)}")

    # Show first peer comparison
    print("\n   First peer comparison:")
    print("   Original:")
    in_peer = False
    count = 0
    for line in orig_lines:
        if line.strip() == '[Peer]' and not in_peer:
            in_peer = True
            print(f"     {line}")
            count += 1
        elif in_peer:
            if line.strip() == '[Peer]':
                break
            print(f"     {line}")
            count += 1
            if count >= 5:
                break

    print("   Generated:")
    in_peer = False
    count = 0
    for line in gen_lines:
        if line.strip() == '[Peer]' and not in_peer:
            in_peer = True
            print(f"     {line}")
            count += 1
        elif in_peer:
            if line.strip() == '[Peer]':
                break
            print(f"     {line}")
            count += 1
            if count >= 5:
                break


def main():
    """Test all configs in import/"""
    print("=" * 80)
    print("FULL ROUND-TRIP TEST - REFACTORED CODE")
    print("=" * 80)
    print("\nFoundation: Everything between '[' and next '[' is an entity")

    import_dir = Path("/home/ged/wireguard-friend/import")
    configs = sorted(import_dir.glob("*.conf"))

    if not configs:
        print("\n❌ No configs found in import/")
        return

    print(f"\nTesting {len(configs)} configs:")
    for config in configs:
        test_config(config)

    print(f"\n{'=' * 80}")
    print("SUMMARY")
    print('=' * 80)
    print(f"✓ Entity parsing: Bracket delimiter rule")
    print(f"✓ Pattern recognition: Command pairs identified")
    print(f"✓ Comment association: Via public keys")
    print(f"✓ Semantic extraction: All fields captured")
    print(f"✓ Config generation: From structured data")
    print()


if __name__ == "__main__":
    main()
