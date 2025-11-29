"""
V2 Semantic Comment System

Comments are entity attributes with semantic categories:

1. HOSTNAME - Enforced human-readable unique ID (BEFORE peer)
2. ROLE - Function/characteristics of the entity (BEFORE peer)
3. RATIONALE - Why command pairs exist (BEFORE commands)
4. CUSTOM - Personal admin notes (AFTER peer)

Order: hostname → role → entity → custom
"""

import re
import logging
from typing import List, Optional, Dict
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class CommentCategory(Enum):
    """Semantic categories of comments"""
    HOSTNAME = "hostname"      # Human-readable unique ID (enforced)
    ROLE = "role"              # Function/characteristics
    PERMANENT_GUID = "permanent_guid"  # Reference to immutable GUID (after key rotation)
    RATIONALE = "rationale"    # Why commands exist
    CUSTOM = "custom"          # Personal admin notes
    UNCLASSIFIED = "unclassified"  # Can't determine category yet


@dataclass
class SemanticComment:
    """A comment with semantic meaning"""
    category: CommentCategory
    text: str
    display_order: int  # Lower = earlier

    # For ROLE comments
    role_type: Optional[str] = None  # "dynamic_endpoint", "initiates_only", etc.

    # For RATIONALE comments
    applies_to_command_pair: Optional[str] = None  # pattern_name

    # For PERMANENT_GUID comments (after key rotation)
    guid_reference: Optional[str] = None  # The permanent GUID being referenced


class CommentCategorizer:
    """Categorizes comments based on semantic meaning"""

    # Known role patterns from real configs
    ROLE_PATTERNS = {
        "initiates_only": [
            r"no endpoint.*behind CGNAT.*initiates connection",
            r"behind NAT.*initiates only",
            r"initiates.*no endpoint"
        ],
        "dynamic_endpoint": [
            r"[Ee]ndpoint will be dynamic",
            r"mobile device",
            r"dynamic IP"
        ],
        "static_endpoint": [
            r"static IP",
            r"fixed endpoint"
        ]
    }

    # Command rationale patterns (from comments in configs)
    RATIONALE_PATTERNS = {
        "ipv4_ipv6_support": [
            r"Update.*to handle.*IPv4.*IPv6",
            r"both IPv4 and IPv6"
        ],
        "service_access": [
            r"[Tt]o allow.*connections",
            r"[Aa]llow.*over wg0"
        ],
        "enable_forwarding": [
            r"[Ee]nable.*forwarding"
        ],
        "forwarding_rules": [
            r"[Ff]orwarding rules"
        ],
        "mss_clamping": [
            r"MSS clamping.*fragmentation"
        ],
        "cleanup": [
            r"[Cc]leanup"
        ]
    }

    def categorize(self, comment_text: str, context: str = "peer") -> SemanticComment:
        """
        Categorize a comment based on its content and context.

        Args:
            comment_text: The comment text (without leading #)
            context: Where the comment appears ("peer", "interface")

        Returns:
            SemanticComment with category and metadata
        """
        text = comment_text.strip()

        # Check if it's a hostname (simple single-word or hyphenated identifier)
        if context == "peer" and self._is_hostname(text):
            return SemanticComment(
                category=CommentCategory.HOSTNAME,
                text=text,
                display_order=1  # Always first
            )

        # Check for permanent_guid reference (after key rotation)
        guid_ref = self._detect_permanent_guid(text)
        if guid_ref:
            return SemanticComment(
                category=CommentCategory.PERMANENT_GUID,
                text=text,
                display_order=3,  # After role, before entity
                guid_reference=guid_ref
            )

        # Check for role patterns
        role_type = self._detect_role(text)
        if role_type:
            return SemanticComment(
                category=CommentCategory.ROLE,
                text=text,
                display_order=2,  # After hostname, before entity
                role_type=role_type
            )

        # Check for rationale patterns (command explanations)
        if context == "interface":
            rationale_type = self._detect_rationale(text)
            if rationale_type:
                return SemanticComment(
                    category=CommentCategory.RATIONALE,
                    text=text,
                    display_order=1,  # Before commands
                    applies_to_command_pair=rationale_type
                )

        # Check if it's a custom comment (personal notes)
        if self._is_custom(text):
            return SemanticComment(
                category=CommentCategory.CUSTOM,
                text=text,
                display_order=999  # Always last
            )

        # Default: unclassified
        return SemanticComment(
            category=CommentCategory.UNCLASSIFIED,
            text=text,
            display_order=500  # Middle
        )

    def _is_hostname(self, text: str) -> bool:
        """
        Check if comment looks like a hostname.

        Characteristics:
        - Single word or hyphenated
        - Short (< 30 chars)
        - No punctuation except hyphens
        - Alphanumeric
        """
        # Remove common prefixes
        cleaned = text.lower()

        # Hostname pattern: alphanumeric with hyphens, reasonable length
        if re.fullmatch(r'[a-z0-9][-a-z0-9]{0,28}[a-z0-9]', cleaned):
            return True

        return False

    def _detect_permanent_guid(self, text: str) -> Optional[str]:
        """
        Detect if comment is a permanent_guid reference.

        Format: "permanent_guid: <base64_key>" or "GUID: <base64_key>"

        WireGuard public keys are 44 characters (32 bytes base64-encoded).
        """
        # Pattern: "permanent_guid:" followed by base64-looking string (WireGuard key length)
        pattern = r'permanent_guid:\s*([A-Za-z0-9+/=]{43,45})'
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            return match.group(1)  # Return the GUID
        return None

    def _detect_role(self, text: str) -> Optional[str]:
        """Detect if comment describes a role/function"""
        for role_type, patterns in self.ROLE_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    return role_type
        return None

    def _detect_rationale(self, text: str) -> Optional[str]:
        """Detect if comment explains command rationale"""
        for rationale_type, patterns in self.RATIONALE_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    return rationale_type
        return None

    def _is_custom(self, text: str) -> bool:
        """
        Check if comment is a custom/personal note.

        Characteristics:
        - First person ("I rotate", "I added")
        - Temporal references ("Sundays", "when")
        - Personal context ("brother", "discovered")
        """
        custom_indicators = [
            r'\bI\b',  # First person
            r'\bmy\b',
            r'[Ss]unday',
            r'when\b',
            r'rotate',
            r'added.*when',
            r'discovered'
        ]

        for pattern in custom_indicators:
            if re.search(pattern, text):
                return True

        return False

    def organize_comments(
        self,
        comments: List[SemanticComment]
    ) -> Dict[str, List[SemanticComment]]:
        """
        Organize comments by category in display order.

        Returns:
            Dict mapping category to sorted list of comments
        """
        organized = {
            'before_entity': [],  # hostname, role
            'after_entity': [],   # custom
            'interface': []       # rationale (for commands)
        }

        for comment in sorted(comments, key=lambda c: c.display_order):
            if comment.category in (CommentCategory.HOSTNAME, CommentCategory.ROLE, CommentCategory.PERMANENT_GUID):
                organized['before_entity'].append(comment)
            elif comment.category == CommentCategory.CUSTOM:
                organized['after_entity'].append(comment)
            elif comment.category == CommentCategory.RATIONALE:
                organized['interface'].append(comment)
            else:
                # Unclassified - treat as before entity for now
                organized['before_entity'].append(comment)

        return organized


def demonstrate_comment_categorization():
    """Demonstrate comment categorization on real examples"""

    # Real comments from coordination.conf
    peer_comments = [
        ("icculus", "peer"),
        ("no endpoint == behind CGNAT == initiates connection", "peer"),
        ("mba15m2", "peer"),
        ("Endpoint will be dynamic (mobile device)", "peer"),
        ("iphone16pro", "peer"),
        ("m2mini", "peer"),
    ]

    # Real comments from wg0.conf
    interface_comments = [
        ("Enable IP forwarding", "interface"),
        ("Forwarding rules", "interface"),
        ("MSS clamping to fix fragmentation issues", "interface"),
        ("Cleanup", "interface"),
    ]

    # Example custom comments (from user's description)
    custom_comments = [
        ("I rotate this key on Sundays of months where there are five Sundays", "peer"),
        ("I added the preshared key here when I discovered my brother was trying to spoof this device", "peer"),
    ]

    categorizer = CommentCategorizer()

    print("=== Comment Categorization Demo ===\n")

    print("Peer Comments:")
    for text, context in peer_comments:
        result = categorizer.categorize(text, context)
        print(f"  '{text}'")
        print(f"    → {result.category.value} (order={result.display_order})")
        if result.role_type:
            print(f"    → role_type: {result.role_type}")
        print()

    print("Interface Comments:")
    for text, context in interface_comments:
        result = categorizer.categorize(text, context)
        print(f"  '{text}'")
        print(f"    → {result.category.value} (order={result.display_order})")
        if result.applies_to_command_pair:
            print(f"    → applies_to: {result.applies_to_command_pair}")
        print()

    print("Custom Comments:")
    for text, context in custom_comments:
        result = categorizer.categorize(text, context)
        print(f"  '{text}'")
        print(f"    → {result.category.value} (order={result.display_order})")
        print()

    # Demonstrate organization
    print("Comment Organization:")
    all_comments = [
        categorizer.categorize(text, context)
        for text, context in peer_comments + custom_comments
    ]
    organized = categorizer.organize_comments(all_comments)

    print("\n  Before Entity:")
    for comment in organized['before_entity']:
        print(f"    - [{comment.category.value}] {comment.text}")

    print("\n  After Entity:")
    for comment in organized['after_entity']:
        print(f"    - [{comment.category.value}] {comment.text}")


if __name__ == "__main__":
    demonstrate_comment_categorization()
