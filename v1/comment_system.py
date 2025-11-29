"""
Comment Preservation System

Comments are first-class entities with precise positioning metadata.
This allows perfect reconstruction of the original config file.

Comment positions:
- before: Comment appears before the entity entirely
- after: Comment appears after the entity entirely
- inline: Comment appears on the same line as an entity field
- above: Comment appears inside an entity, above a specific line
- below: Comment appears inside an entity, below a specific line
- standalone: File-level comment not attached to any entity
"""

import re
import logging
from typing import List, Optional, Dict, Tuple
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class CommentPosition(Enum):
    """Where a comment appears relative to its entity"""
    BEFORE = "before"  # Comment before entity starts
    AFTER = "after"  # Comment after entity ends
    INLINE = "inline"  # Comment on same line as field
    ABOVE = "above"  # Comment inside entity, above a field
    BELOW = "below"  # Comment inside entity, below a field
    STANDALONE = "standalone"  # File-level, no attachment


class EntityType(Enum):
    """Type of entity a comment can attach to"""
    FILE = "file"
    INTERFACE = "interface"
    PEER = "peer"
    COMMAND = "command"


@dataclass
class Comment:
    """A comment with complete positioning metadata"""
    text: str
    entity_type: EntityType
    entity_id: Optional[int]  # None for file-level comments
    position: CommentPosition
    line_offset: int  # For multi-line entities, which line?
    indent_level: int  # Number of spaces/tabs
    original_line_number: int  # Line number in source file


@dataclass
class CommentBlock:
    """A multi-line comment block"""
    comments: List[Comment]
    start_line: int
    end_line: int


class CommentExtractor:
    """Extract comments from WireGuard config with positioning metadata"""

    def __init__(self):
        self.comments: List[Comment] = []

    def extract_comments(self, lines: List[str]) -> List[Comment]:
        """
        Extract all comments from config lines with positioning.

        Args:
            lines: Config file lines (with line numbers implicit)

        Returns:
            List of Comment objects with positioning metadata
        """
        comments = []
        current_section = EntityType.FILE
        entity_id = None
        section_start_line = 0

        for line_num, line in enumerate(lines, start=1):
            # Detect section changes
            if line.strip().startswith('[Interface]'):
                current_section = EntityType.INTERFACE
                section_start_line = line_num
                entity_id = None  # Will be set when entity is created
                continue
            elif line.strip().startswith('[Peer]'):
                current_section = EntityType.PEER
                section_start_line = line_num
                entity_id = None
                continue

            # Extract comments
            inline_comment = self._extract_inline_comment(line, line_num)
            if inline_comment:
                comment = Comment(
                    text=inline_comment,
                    entity_type=current_section,
                    entity_id=entity_id,
                    position=CommentPosition.INLINE,
                    line_offset=line_num - section_start_line,
                    indent_level=self._get_indent_level(line),
                    original_line_number=line_num
                )
                comments.append(comment)

            # Full line comments
            if line.strip().startswith('#'):
                comment_text = line.strip()[1:].strip()
                comment = Comment(
                    text=comment_text,
                    entity_type=current_section,
                    entity_id=entity_id,
                    position=self._determine_position(line_num, lines, current_section),
                    line_offset=line_num - section_start_line,
                    indent_level=self._get_indent_level(line),
                    original_line_number=line_num
                )
                comments.append(comment)

        return comments

    def _extract_inline_comment(self, line: str, line_num: int) -> Optional[str]:
        """
        Extract inline comment from a line.

        Example:
            ListenPort = 51820  # Main WireGuard port
            Returns: "Main WireGuard port"
        """
        # Simple approach: look for # outside of quotes
        # TODO: Handle # inside quoted strings properly
        parts = line.split('#', 1)
        if len(parts) > 1:
            # Make sure there's actual content before the #
            if parts[0].strip():
                return parts[1].strip()
        return None

    def _get_indent_level(self, line: str) -> int:
        """Calculate indentation level (number of leading spaces)"""
        original_len = len(line)
        stripped_len = len(line.lstrip())
        return original_len - stripped_len

    def _determine_position(self, line_num: int, lines: List[str], section: EntityType) -> CommentPosition:
        """
        Determine if comment is before, after, above, or below an entity.

        Strategy:
        - Look at surrounding lines
        - If next non-blank line is a field (Key = Value), comment is ABOVE
        - If previous non-blank line is a field, comment is BELOW
        - If next non-blank line is a section header, comment is BEFORE
        - If at end of section, comment is AFTER
        """
        # Look ahead
        next_content_line = self._find_next_content_line(line_num, lines)
        if next_content_line:
            if next_content_line.strip().startswith('['):
                return CommentPosition.BEFORE
            elif '=' in next_content_line:
                return CommentPosition.ABOVE

        # Look behind
        prev_content_line = self._find_prev_content_line(line_num, lines)
        if prev_content_line:
            if '=' in prev_content_line:
                return CommentPosition.BELOW

        # Default to standalone
        return CommentPosition.STANDALONE

    def _find_next_content_line(self, line_num: int, lines: List[str]) -> Optional[str]:
        """Find next non-empty, non-comment line"""
        for i in range(line_num, len(lines)):
            line = lines[i].strip()
            if line and not line.startswith('#'):
                return line
        return None

    def _find_prev_content_line(self, line_num: int, lines: List[str]) -> Optional[str]:
        """Find previous non-empty, non-comment line"""
        for i in range(line_num - 2, -1, -1):  # line_num is 1-indexed
            line = lines[i].strip()
            if line and not line.startswith('#'):
                return line
        return None


class CommentRenderer:
    """Render comments back into config text with proper positioning"""

    def render_comments(
        self,
        comments: List[Comment],
        entity_type: EntityType,
        entity_id: Optional[int]
    ) -> Dict[str, List[str]]:
        """
        Organize comments by position for rendering.

        Args:
            comments: All comments in the system
            entity_type: Type of entity we're rendering
            entity_id: Specific entity ID

        Returns:
            Dict mapping position to list of comment texts
        """
        organized = {
            'before': [],
            'after': [],
            'inline': {},  # Map of line_offset -> comment
            'above': {},  # Map of line_offset -> comments
            'below': {}  # Map of line_offset -> comments
        }

        for comment in comments:
            if comment.entity_type != entity_type:
                continue
            if comment.entity_id != entity_id:
                continue

            if comment.position == CommentPosition.BEFORE:
                organized['before'].append(self._format_comment(comment))
            elif comment.position == CommentPosition.AFTER:
                organized['after'].append(self._format_comment(comment))
            elif comment.position == CommentPosition.INLINE:
                organized['inline'][comment.line_offset] = comment.text
            elif comment.position == CommentPosition.ABOVE:
                if comment.line_offset not in organized['above']:
                    organized['above'][comment.line_offset] = []
                organized['above'][comment.line_offset].append(self._format_comment(comment))
            elif comment.position == CommentPosition.BELOW:
                if comment.line_offset not in organized['below']:
                    organized['below'][comment.line_offset] = []
                organized['below'][comment.line_offset].append(self._format_comment(comment))

        return organized

    def _format_comment(self, comment: Comment) -> str:
        """Format comment with proper indentation"""
        indent = ' ' * comment.indent_level
        return f"{indent}# {comment.text}"


def demonstrate_comments():
    """Demonstrate comment extraction and rendering"""
    sample_config = """# Top level comment
[Interface]
# Interface comment 1
Address = 10.66.0.1/24  # Inline comment for Address
PrivateKey = abc123
# Comment above ListenPort
ListenPort = 51820
# Comment below ListenPort

[Peer]
# Peer comment
PublicKey = xyz789  # Inline peer comment
AllowedIPs = 10.66.0.20/32
# End comment
"""

    lines = sample_config.strip().split('\n')

    extractor = CommentExtractor()
    comments = extractor.extract_comments(lines)

    print("=== Comment Extraction Demo ===\n")
    for comment in comments:
        print(f"Line {comment.original_line_number}: '{comment.text}'")
        print(f"  Entity: {comment.entity_type.value}")
        print(f"  Position: {comment.position.value}")
        print(f"  Line Offset: {comment.line_offset}")
        print(f"  Indent: {comment.indent_level}")
        print()


if __name__ == "__main__":
    demonstrate_comments()
