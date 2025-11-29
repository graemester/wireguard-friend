"""
Formatting Preference System

Captures user's style preferences explicitly so we can reconstruct
configs that look exactly like the original.

Categories:
- Spacing: blank lines between sections, between peers
- Indentation: spaces vs tabs, indent width
- Ordering: field order within sections, peer order
- Alignment: comment alignment, value alignment
- Line breaks: where to break long lines
"""

import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class IndentStyle(Enum):
    """How indentation is done"""
    SPACES = "spaces"
    TABS = "tabs"
    MIXED = "mixed"  # Detected but discouraged


class FieldOrdering(Enum):
    """How fields are ordered within sections"""
    ORIGINAL = "original"  # Keep original order
    ALPHABETICAL = "alphabetical"
    CANONICAL = "canonical"  # Standard WireGuard order


class CommentAlignment(Enum):
    """How inline comments are aligned"""
    NONE = "none"  # No alignment, comment right after value
    COLUMN = "column"  # Align to specific column
    RELATIVE = "relative"  # Consistent spacing from value


@dataclass
class FormattingProfile:
    """Complete formatting profile for a config"""
    name: str = "default"

    # Spacing preferences
    blank_lines_before_interface: int = 0
    blank_lines_after_interface: int = 1
    blank_lines_before_peer: int = 1
    blank_lines_after_peer: int = 0
    blank_lines_between_peers: int = 1

    # Indentation
    indent_style: IndentStyle = IndentStyle.SPACES
    indent_width: int = 4
    indent_section_headers: bool = False  # Indent [Interface], [Peer]?

    # Field ordering
    interface_field_order: FieldOrdering = FieldOrdering.ORIGINAL
    peer_field_order: FieldOrdering = FieldOrdering.ORIGINAL

    # Comments
    inline_comment_alignment: CommentAlignment = CommentAlignment.RELATIVE
    inline_comment_spacing: int = 2  # Spaces between value and #
    inline_comment_column: int = 40  # For COLUMN alignment

    # Line breaks
    max_line_length: Optional[int] = None  # None = no limit
    wrap_long_values: bool = False

    # Other
    trailing_newline: bool = True
    preserve_empty_lines: bool = True

    # Custom overrides per entity
    entity_overrides: Dict[str, Dict[str, Any]] = field(default_factory=dict)


class FormattingDetector:
    """Detect formatting preferences from existing config"""

    def detect_profile(self, lines: List[str]) -> FormattingProfile:
        """
        Analyze config lines and detect formatting preferences.

        Args:
            lines: Config file lines

        Returns:
            FormattingProfile with detected preferences
        """
        profile = FormattingProfile()

        # Detect indentation
        profile.indent_style, profile.indent_width = self._detect_indentation(lines)

        # Detect spacing
        profile.blank_lines_between_peers = self._detect_peer_spacing(lines)
        profile.blank_lines_after_interface = self._detect_interface_spacing(lines)

        # Detect comment alignment
        profile.inline_comment_alignment, profile.inline_comment_spacing = self._detect_comment_alignment(lines)

        # Detect trailing newline
        profile.trailing_newline = self._has_trailing_newline(lines)

        return profile

    def _detect_indentation(self, lines: List[str]) -> tuple[IndentStyle, int]:
        """
        Detect indentation style and width.

        Returns:
            (indent_style, indent_width)
        """
        space_indents = []
        tab_indents = []

        for line in lines:
            if not line or line.lstrip() == line:
                continue

            # Count leading whitespace
            indent = len(line) - len(line.lstrip())
            if indent == 0:
                continue

            # Check what kind of whitespace
            if line[0] == ' ':
                space_indents.append(indent)
            elif line[0] == '\t':
                tab_indents.append(1)

        # Determine style
        if tab_indents and not space_indents:
            return IndentStyle.TABS, 1
        elif space_indents and not tab_indents:
            # Find most common indent width
            if space_indents:
                # Use GCD-like approach to find indent unit
                from math import gcd
                from functools import reduce
                indent_width = reduce(gcd, space_indents)
                return IndentStyle.SPACES, max(indent_width, 1)
            return IndentStyle.SPACES, 4
        elif tab_indents and space_indents:
            return IndentStyle.MIXED, 4
        else:
            return IndentStyle.SPACES, 4

    def _detect_peer_spacing(self, lines: List[str]) -> int:
        """Detect number of blank lines between peer sections"""
        peer_indices = [i for i, line in enumerate(lines) if line.strip().startswith('[Peer]')]

        if len(peer_indices) < 2:
            return 1  # Default

        # Count blank lines between consecutive peers
        spacings = []
        for i in range(len(peer_indices) - 1):
            # Find end of current peer (next peer or EOF)
            current_peer_end = peer_indices[i]
            next_peer_start = peer_indices[i + 1]

            # Count blank lines between them
            blank_count = 0
            for j in range(current_peer_end + 1, next_peer_start):
                if not lines[j].strip():
                    blank_count += 1
                elif lines[j].strip().startswith('[Peer]'):
                    break
                else:
                    # Non-blank content, reset counter
                    blank_count = 0

            spacings.append(blank_count)

        # Return most common spacing
        if spacings:
            return max(set(spacings), key=spacings.count)
        return 1

    def _detect_interface_spacing(self, lines: List[str]) -> int:
        """Detect blank lines after [Interface] section"""
        interface_idx = None
        for i, line in enumerate(lines):
            if line.strip().startswith('[Interface]'):
                interface_idx = i
                break

        if interface_idx is None:
            return 1

        # Find first [Peer]
        peer_idx = None
        for i in range(interface_idx + 1, len(lines)):
            if lines[i].strip().startswith('[Peer]'):
                peer_idx = i
                break

        if peer_idx is None:
            return 1

        # Count blank lines between Interface section end and first Peer
        blank_count = 0
        for i in range(peer_idx - 1, interface_idx, -1):
            if not lines[i].strip():
                blank_count += 1
            else:
                break

        return blank_count

    def _detect_comment_alignment(self, lines: List[str]) -> tuple[CommentAlignment, int]:
        """
        Detect inline comment alignment style.

        Returns:
            (alignment_style, spacing)
        """
        # Find lines with inline comments
        inline_comments = []
        for line in lines:
            if '=' in line and '#' in line:
                parts = line.split('#', 1)
                if parts[0].strip():  # Has content before #
                    # Measure spacing before #
                    content_end = len(parts[0].rstrip())
                    comment_start = len(parts[0])
                    spacing = comment_start - content_end
                    inline_comments.append((content_end, spacing))

        if not inline_comments:
            return CommentAlignment.RELATIVE, 2

        # Check if comments align to a column
        comment_positions = [pos[0] + pos[1] for pos in inline_comments]
        if len(set(comment_positions)) == 1:
            # All comments at same column
            return CommentAlignment.COLUMN, comment_positions[0]

        # Check if spacing is consistent
        spacings = [pos[1] for pos in inline_comments]
        if len(set(spacings)) == 1:
            return CommentAlignment.RELATIVE, spacings[0]

        # Mixed - use most common spacing
        if spacings:
            most_common = max(set(spacings), key=spacings.count)
            return CommentAlignment.RELATIVE, most_common

        return CommentAlignment.RELATIVE, 2

    def _has_trailing_newline(self, lines: List[str]) -> bool:
        """Check if file ends with newline"""
        if not lines:
            return True
        return lines[-1] == '' or lines[-1].endswith('\n')


class FormattingApplier:
    """Apply formatting profile to generate config text"""

    def __init__(self, profile: FormattingProfile):
        self.profile = profile

    def format_section_spacing(self, section_type: str, position: str) -> str:
        """
        Generate blank lines for section spacing.

        Args:
            section_type: 'interface', 'peer'
            position: 'before', 'after'

        Returns:
            String of newlines
        """
        if section_type == 'interface':
            if position == 'before':
                count = self.profile.blank_lines_before_interface
            else:
                count = self.profile.blank_lines_after_interface
        elif section_type == 'peer':
            if position == 'before':
                count = self.profile.blank_lines_before_peer
            else:
                count = self.profile.blank_lines_after_peer
        else:
            count = 0

        return '\n' * count

    def format_peer_spacing(self) -> str:
        """Generate blank lines between peers"""
        return '\n' * self.profile.blank_lines_between_peers

    def format_indent(self, level: int = 1) -> str:
        """Generate indentation string"""
        if self.profile.indent_style == IndentStyle.TABS:
            return '\t' * level
        else:
            return ' ' * (self.profile.indent_width * level)

    def format_inline_comment(self, value: str, comment: str) -> str:
        """
        Format a field with inline comment.

        Args:
            value: The field value
            comment: The comment text

        Returns:
            Formatted string with comment
        """
        if self.profile.inline_comment_alignment == CommentAlignment.COLUMN:
            # Pad to column
            total_len = len(value)
            padding_needed = max(self.profile.inline_comment_column - total_len, 1)
            return f"{value}{' ' * padding_needed}# {comment}"
        else:
            # Relative spacing
            spacing = ' ' * self.profile.inline_comment_spacing
            return f"{value}{spacing}# {comment}"


def demonstrate_formatting():
    """Demonstrate formatting detection and application"""
    sample_config = """[Interface]
Address = 10.66.0.1/24
PrivateKey = abc123
ListenPort = 51820  # Main port

[Peer]
PublicKey = xyz789
AllowedIPs = 10.66.0.20/32

[Peer]
PublicKey = def456
AllowedIPs = 10.66.0.30/32
"""

    lines = sample_config.split('\n')

    detector = FormattingDetector()
    profile = detector.detect_profile(lines)

    print("=== Formatting Detection Demo ===\n")
    print(f"Indent Style: {profile.indent_style.value}")
    print(f"Indent Width: {profile.indent_width}")
    print(f"Blank Lines Between Peers: {profile.blank_lines_between_peers}")
    print(f"Blank Lines After Interface: {profile.blank_lines_after_interface}")
    print(f"Comment Alignment: {profile.inline_comment_alignment.value}")
    print(f"Comment Spacing: {profile.inline_comment_spacing}")
    print(f"Trailing Newline: {profile.trailing_newline}")


if __name__ == "__main__":
    demonstrate_formatting()
