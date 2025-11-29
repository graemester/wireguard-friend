"""
Unknown Field Preservation System

Handles WireGuard configuration fields we don't know about yet.
This provides forward compatibility when WireGuard adds new features.

Validation modes:
- strict: Reject unknown fields (fail import)
- permissive: Accept and preserve unknown fields (default)
- ignore: Silently discard unknown fields
"""

import logging
from typing import Dict, List, Set, Optional
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class ValidationMode(Enum):
    """How to handle unknown fields"""
    STRICT = "strict"  # Fail on unknown fields
    PERMISSIVE = "permissive"  # Accept and preserve
    IGNORE = "ignore"  # Silently discard


class FieldCategory(Enum):
    """Where the field appears"""
    INTERFACE = "interface"
    PEER = "peer"


@dataclass
class UnknownField:
    """An unrecognized field from a config"""
    category: FieldCategory
    entity_id: int
    field_name: str
    field_value: str
    source_line: int


# Known WireGuard fields (as of 2025)
KNOWN_INTERFACE_FIELDS = {
    'Address',
    'PrivateKey',
    'ListenPort',
    'MTU',
    'DNS',
    'Table',
    'PreUp',
    'PostUp',
    'PreDown',
    'PostDown',
    'SaveConfig',
}

KNOWN_PEER_FIELDS = {
    'PublicKey',
    'PresharedKey',
    'AllowedIPs',
    'Endpoint',
    'PersistentKeepalive',
}


class UnknownFieldHandler:
    """Handle unknown fields according to validation mode"""

    def __init__(self, mode: ValidationMode = ValidationMode.PERMISSIVE):
        self.mode = mode
        self.unknown_fields: List[UnknownField] = []

    def check_field(
        self,
        category: FieldCategory,
        field_name: str,
        field_value: str,
        entity_id: int,
        source_line: int
    ) -> bool:
        """
        Check if a field is known, handle if unknown.

        Args:
            category: Interface or Peer
            field_name: Field name (e.g., "Address")
            field_value: Field value
            entity_id: Database entity ID
            source_line: Line number in source file

        Returns:
            True if field is known or accepted, False if rejected

        Raises:
            ValueError: If mode is STRICT and field is unknown
        """
        # Check if field is known
        if category == FieldCategory.INTERFACE:
            known_fields = KNOWN_INTERFACE_FIELDS
        else:
            known_fields = KNOWN_PEER_FIELDS

        # Normalize field name (WireGuard is case-insensitive for field names)
        normalized_name = field_name.strip()

        # Check against known fields (case-insensitive)
        is_known = any(
            normalized_name.lower() == known.lower()
            for known in known_fields
        )

        if is_known:
            return True

        # Unknown field - handle according to mode
        unknown = UnknownField(
            category=category,
            entity_id=entity_id,
            field_name=normalized_name,
            field_value=field_value,
            source_line=source_line
        )

        if self.mode == ValidationMode.STRICT:
            raise ValueError(
                f"Unknown {category.value} field '{field_name}' at line {source_line}. "
                f"Use permissive mode to accept unknown fields."
            )
        elif self.mode == ValidationMode.PERMISSIVE:
            logger.warning(
                f"Unknown {category.value} field '{field_name}' at line {source_line} - preserving"
            )
            self.unknown_fields.append(unknown)
            return True
        else:  # IGNORE
            logger.debug(
                f"Unknown {category.value} field '{field_name}' at line {source_line} - ignoring"
            )
            return False

    def get_unknown_fields(
        self,
        category: Optional[FieldCategory] = None,
        entity_id: Optional[int] = None
    ) -> List[UnknownField]:
        """
        Get unknown fields, optionally filtered.

        Args:
            category: Filter by category (Interface/Peer)
            entity_id: Filter by entity ID

        Returns:
            List of unknown fields matching filters
        """
        filtered = self.unknown_fields

        if category is not None:
            filtered = [f for f in filtered if f.category == category]

        if entity_id is not None:
            filtered = [f for f in filtered if f.entity_id == entity_id]

        return filtered

    def has_unknown_fields(self) -> bool:
        """Check if any unknown fields were encountered"""
        return len(self.unknown_fields) > 0

    def get_summary(self) -> Dict[str, int]:
        """
        Get summary of unknown fields.

        Returns:
            Dict with counts by category
        """
        summary = {
            'interface': 0,
            'peer': 0,
            'total': len(self.unknown_fields)
        }

        for field in self.unknown_fields:
            if field.category == FieldCategory.INTERFACE:
                summary['interface'] += 1
            else:
                summary['peer'] += 1

        return summary


class UnknownFieldRegistry:
    """
    Global registry of unknown fields discovered across imports.

    This helps track new WireGuard features as they emerge.
    """

    def __init__(self):
        self.registry: Dict[str, List[UnknownField]] = {}

    def register(self, field: UnknownField):
        """Add an unknown field to the registry"""
        key = f"{field.category.value}:{field.field_name}"

        if key not in self.registry:
            self.registry[key] = []

        self.registry[key].append(field)

    def get_all_unknown_field_names(self) -> Set[str]:
        """Get set of all unknown field names encountered"""
        return {
            field.field_name
            for fields in self.registry.values()
            for field in fields
        }

    def get_frequency(self, field_name: str, category: FieldCategory) -> int:
        """Get how many times a field has been encountered"""
        key = f"{category.value}:{field_name}"
        return len(self.registry.get(key, []))

    def report(self) -> str:
        """Generate a report of unknown fields"""
        if not self.registry:
            return "No unknown fields encountered"

        lines = ["Unknown Field Report:", "=" * 50]

        for key, fields in sorted(self.registry.items()):
            category, field_name = key.split(':', 1)
            lines.append(f"\n{field_name} ({category}): {len(fields)} occurrences")

            # Show sample values
            sample_values = list(set(f.field_value for f in fields[:5]))
            for value in sample_values[:3]:
                lines.append(f"  Sample: {value}")

        return '\n'.join(lines)


def demonstrate_unknown_fields():
    """Demonstrate unknown field handling"""
    print("=== Unknown Field Handler Demo ===\n")

    # Test permissive mode
    print("1. PERMISSIVE mode (accept and preserve):")
    handler = UnknownFieldHandler(ValidationMode.PERMISSIVE)

    # Known field
    result = handler.check_field(
        FieldCategory.INTERFACE,
        "Address",
        "10.0.0.1/24",
        entity_id=1,
        source_line=5
    )
    print(f"  Known field 'Address': {result}")

    # Unknown field
    result = handler.check_field(
        FieldCategory.INTERFACE,
        "FutureFeature",
        "some_value",
        entity_id=1,
        source_line=10
    )
    print(f"  Unknown field 'FutureFeature': {result}")
    print(f"  Unknown fields stored: {len(handler.unknown_fields)}")

    # Test strict mode
    print("\n2. STRICT mode (reject unknown):")
    strict_handler = UnknownFieldHandler(ValidationMode.STRICT)

    try:
        strict_handler.check_field(
            FieldCategory.PEER,
            "UnknownPeerField",
            "test",
            entity_id=2,
            source_line=20
        )
    except ValueError as e:
        print(f"  Rejected: {e}")

    # Test registry
    print("\n3. Field Registry:")
    registry = UnknownFieldRegistry()

    for field in handler.unknown_fields:
        registry.register(field)

    print(f"  Total unknown field types: {len(registry.get_all_unknown_field_names())}")
    print(f"  Frequency of 'FutureFeature': {registry.get_frequency('FutureFeature', FieldCategory.INTERFACE)}")


if __name__ == "__main__":
    demonstrate_unknown_fields()
