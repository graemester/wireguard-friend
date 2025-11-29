"""
WireGuard Config Generator

Generates WireGuard configs from structured AST data.
This is the inverse of the parser - proving we can reconstruct
the original file from the database.

Goals:
- Byte-for-byte reconstruction when possible
- Respect formatting preferences
- Include all comments in correct positions
- Render shell commands from AST
- Include unknown fields
"""

import logging
from typing import List, Dict, Optional
from pathlib import Path

from v1.parser import ParsedConfig, InterfaceData, PeerData
from v1.comment_system import Comment, CommentPosition, CommentRenderer, EntityType
from v1.formatting import FormattingProfile, FormattingApplier
from v1.shell_parser import ParsedCommand, IptablesCommand, SysctlCommand, IpCommand, CustomCommand

logger = logging.getLogger(__name__)


class ConfigGenerator:
    """Generate WireGuard config from AST"""

    def __init__(self, formatting: FormattingProfile):
        self.formatting = formatting
        self.applier = FormattingApplier(formatting)
        self.comment_renderer = CommentRenderer()

    def generate(self, parsed: ParsedConfig) -> str:
        """
        Generate complete config text from parsed data.

        Args:
            parsed: ParsedConfig with complete AST

        Returns:
            Config file content as string
        """
        lines = []

        # File-level comments (before everything)
        file_comments = [
            c for c in parsed.comments
            if c.entity_type == EntityType.FILE and c.position == CommentPosition.BEFORE
        ]
        for comment in file_comments:
            lines.append(self._format_comment(comment))

        # Interface section
        if file_comments:
            lines.append('')  # Blank line after file comments

        interface_lines = self._generate_interface(parsed.interface, parsed.comments)
        lines.extend(interface_lines)

        # Spacing after interface
        spacing = self.applier.format_section_spacing('interface', 'after')
        if spacing:
            lines.append(spacing.rstrip())

        # Peer sections
        for i, peer in enumerate(parsed.peers):
            if i > 0:
                # Spacing between peers
                spacing = self.applier.format_peer_spacing()
                if spacing:
                    lines.append(spacing.rstrip())

            peer_lines = self._generate_peer(peer, parsed.comments, i)
            lines.extend(peer_lines)

        # File-level comments (after everything)
        end_comments = [
            c for c in parsed.comments
            if c.entity_type == EntityType.FILE and c.position == CommentPosition.AFTER
        ]
        if end_comments:
            lines.append('')
            for comment in end_comments:
                lines.append(self._format_comment(comment))

        # Join with newlines
        config_text = '\n'.join(lines)

        # Add trailing newline if configured
        if self.formatting.trailing_newline and not config_text.endswith('\n'):
            config_text += '\n'

        return config_text

    def _generate_interface(self, interface: InterfaceData, all_comments: List[Comment]) -> List[str]:
        """Generate Interface section"""
        lines = []

        # Comments before [Interface]
        before_comments = [
            c for c in all_comments
            if c.entity_type == EntityType.INTERFACE and c.position == CommentPosition.BEFORE
        ]
        for comment in before_comments:
            lines.append(self._format_comment(comment))

        # Section header
        lines.append('[Interface]')

        # Generate fields with inline comments
        interface_comments = self.comment_renderer.render_comments(
            all_comments,
            EntityType.INTERFACE,
            None
        )

        # Address field
        if interface.addresses:
            addr_line = f"Address = {', '.join(interface.addresses)}"
            if 1 in interface_comments.get('inline', {}):
                addr_line += f"  # {interface_comments['inline'][1]}"
            lines.append(addr_line)

        # PrivateKey
        if interface.private_key:
            lines.append(f"PrivateKey = {interface.private_key}")

        # ListenPort
        if interface.listen_port:
            port_line = f"ListenPort = {interface.listen_port}"
            # Check for inline comment (this is simplified - would need line mapping)
            lines.append(port_line)

        # MTU
        if interface.mtu:
            lines.append(f"MTU = {interface.mtu}")

        # DNS
        if interface.dns:
            lines.append(f"DNS = {', '.join(interface.dns)}")

        # Table
        if interface.table:
            lines.append(f"Table = {interface.table}")

        # Shell commands
        for cmd in interface.preup_commands:
            lines.append(f"PreUp = {self._render_command(cmd)}")

        for cmd in interface.postup_commands:
            lines.append(f"PostUp = {self._render_command(cmd)}")

        for cmd in interface.predown_commands:
            lines.append(f"PreDown = {self._render_command(cmd)}")

        for cmd in interface.postdown_commands:
            lines.append(f"PostDown = {self._render_command(cmd)}")

        # Unknown fields
        for field_name, field_value in interface.unknown_fields.items():
            lines.append(f"{field_name} = {field_value}")

        # Comments after interface
        after_comments = [
            c for c in all_comments
            if c.entity_type == EntityType.INTERFACE and c.position == CommentPosition.AFTER
        ]
        for comment in after_comments:
            lines.append(self._format_comment(comment))

        return lines

    def _generate_peer(self, peer: PeerData, all_comments: List[Comment], peer_index: int) -> List[str]:
        """Generate Peer section"""
        lines = []

        # Comments before [Peer]
        before_comments = [
            c for c in all_comments
            if c.entity_type == EntityType.PEER
            and c.position == CommentPosition.BEFORE
            and c.line_offset == peer.source_line_start
        ]
        for comment in before_comments:
            lines.append(self._format_comment(comment))

        # Section header
        lines.append('[Peer]')

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

        # Unknown fields
        for field_name, field_value in peer.unknown_fields.items():
            lines.append(f"{field_name} = {field_value}")

        return lines

    def _render_command(self, cmd: ParsedCommand) -> str:
        """Render a shell command from its AST"""
        if isinstance(cmd, IptablesCommand):
            return self._render_iptables(cmd)
        elif isinstance(cmd, SysctlCommand):
            return self._render_sysctl(cmd)
        elif isinstance(cmd, IpCommand):
            return self._render_ip(cmd)
        elif isinstance(cmd, CustomCommand):
            return cmd.original_text
        else:
            return cmd.original_text

    def _render_iptables(self, cmd: IptablesCommand) -> str:
        """Reconstruct iptables command from AST"""
        parts = ['iptables']

        # Table (if not default 'filter')
        if cmd.table != 'filter':
            parts.extend(['-t', cmd.table])

        # Action and chain
        parts.extend([cmd.action, cmd.chain])

        # Components (match rules, target, etc.)
        for flag, value in cmd.components:
            if value is not None:
                parts.extend([flag, value])
            else:
                parts.append(flag)

        return ' '.join(parts)

    def _render_sysctl(self, cmd: SysctlCommand) -> str:
        """Reconstruct sysctl command from AST"""
        parts = ['sysctl']

        if cmd.write_flag:
            parts.append('-w')

        parts.append(f"{cmd.parameter}={cmd.value}")

        return ' '.join(parts)

    def _render_ip(self, cmd: IpCommand) -> str:
        """Reconstruct ip command from AST"""
        parts = ['ip', cmd.subcommand, cmd.action]

        # Add parameters
        for key, value in cmd.parameters.items():
            if key == 'target':
                # Positional argument(s)
                if isinstance(value, list):
                    parts.extend(value)
                else:
                    parts.append(value)
            elif isinstance(value, bool) and value:
                # Boolean flag (e.g., 'up')
                parts.append(key)
            else:
                # Key-value pair
                parts.extend([key, str(value)])

        return ' '.join(parts)

    def _format_comment(self, comment: Comment) -> str:
        """Format a comment with proper indentation"""
        indent = ' ' * comment.indent_level
        return f"{indent}# {comment.text}"


def demonstrate_generator():
    """Demonstrate round-trip: parse -> generate"""
    from v1.parser import WireGuardParser
    from v1.unknown_fields import ValidationMode
    import tempfile

    sample_config = """# Server configuration
[Interface]
Address = 10.66.0.1/24
PrivateKey = SERVER_KEY
ListenPort = 51820  # Main port
PostUp = iptables -t nat -A POSTROUTING -s 10.66.0.0/24 -o eth0 -j MASQUERADE
PostUp = sysctl -w net.ipv4.ip_forward=1

[Peer]
# Alice's device
PublicKey = ALICE_KEY
AllowedIPs = 10.66.0.20/32
PersistentKeepalive = 25

[Peer]
# Bob's device
PublicKey = BOB_KEY
AllowedIPs = 10.66.0.30/32
"""

    print("=== Config Generator Demo (Round-Trip) ===\n")

    # Write original
    with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
        f.write(sample_config)
        temp_path = Path(f.name)

    try:
        # Parse
        parser = WireGuardParser(ValidationMode.PERMISSIVE)
        parsed = parser.parse_file(temp_path)

        print("Original config:")
        print("-" * 50)
        print(sample_config)
        print("-" * 50)

        # Generate
        generator = ConfigGenerator(parsed.formatting)
        regenerated = generator.generate(parsed)

        print("\nRegenerated config:")
        print("-" * 50)
        print(regenerated)
        print("-" * 50)

        # Compare
        original_lines = sample_config.strip().split('\n')
        regen_lines = regenerated.strip().split('\n')

        print(f"\nComparison:")
        print(f"  Original lines: {len(original_lines)}")
        print(f"  Regenerated lines: {len(regen_lines)}")
        print(f"  Match: {original_lines == regen_lines}")

        # Show differences
        if original_lines != regen_lines:
            print("\n  Differences:")
            for i, (orig, regen) in enumerate(zip(original_lines, regen_lines), 1):
                if orig != regen:
                    print(f"    Line {i}:")
                    print(f"      Original:    '{orig}'")
                    print(f"      Regenerated: '{regen}'")

    finally:
        temp_path.unlink()


if __name__ == "__main__":
    demonstrate_generator()
