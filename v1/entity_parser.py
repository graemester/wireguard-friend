"""
Entity Parser - Direct Implementation of Bracket Delimiter Rule

Fundamental principle:
  Everything between a '[' and the next '[' is an entity.

This is the universal structure of WireGuard configs.
Everything else (comments, fields, semantics) is built on this foundation.
"""

import logging
from pathlib import Path
from typing import List, Tuple, Dict, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class RawEntity:
    """An entity as delimited by brackets - before any parsing"""
    entity_type: str  # '[Interface]' or '[Peer]'
    lines: List[str]  # Everything between this [ and the next [
    start_line: int   # Line number in source file
    end_line: int


class EntityParser:
    """Parse WireGuard config by bracket delimiters"""

    def parse_file(self, config_path: Path) -> List[RawEntity]:
        """
        Parse config into entities using bracket delimiter rule.

        Returns list of RawEntity objects, each containing everything
        between one '[' and the next '['.
        """
        with open(config_path, 'r') as f:
            lines = f.readlines()

        return self.parse_lines(lines)

    def parse_lines(self, lines: List[str]) -> List[RawEntity]:
        """
        Parse lines into entities.

        Algorithm:
          1. When we see a line starting with '[', start new entity
          2. Collect all subsequent lines into that entity
          3. When we see another '[', save previous entity and start new one
          4. At EOF, save last entity

        This directly implements: "Everything between '[' and next '[' is an entity"
        """
        entities = []
        current_type = None
        current_lines = []
        start_line = 0

        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()

            # Bracket delimiter - marks entity boundary
            if stripped.startswith('['):
                # Save previous entity (if any)
                if current_type is not None:
                    entities.append(RawEntity(
                        entity_type=current_type,
                        lines=current_lines,
                        start_line=start_line,
                        end_line=line_num - 1
                    ))

                # Start new entity
                current_type = stripped  # '[Interface]' or '[Peer]'
                current_lines = []
                start_line = line_num

            else:
                # Everything else belongs to current entity
                if current_type is not None:
                    current_lines.append(line)

        # Save last entity
        if current_type is not None:
            entities.append(RawEntity(
                entity_type=current_type,
                lines=current_lines,
                start_line=start_line,
                end_line=len(lines)
            ))

        return entities

    def validate_structure(self, entities: List[RawEntity]) -> Tuple[bool, str]:
        """
        Validate entity structure.

        WireGuard configs must have:
          - Exactly one [Interface]
          - Zero or more [Peer] sections
          - [Interface] must come first
        """
        if not entities:
            return False, "No entities found"

        # First must be [Interface]
        if entities[0].entity_type != '[Interface]':
            return False, f"First entity must be [Interface], got {entities[0].entity_type}"

        # Count interfaces
        interface_count = sum(1 for e in entities if e.entity_type == '[Interface]')
        if interface_count != 1:
            return False, f"Must have exactly 1 [Interface], found {interface_count}"

        # All others must be [Peer]
        for i, entity in enumerate(entities[1:], start=2):
            if entity.entity_type != '[Peer]':
                return False, f"Entity {i} must be [Peer], got {entity.entity_type}"

        return True, "Valid structure"


def demonstrate_entity_parsing():
    """Demonstrate bracket delimiter parsing"""
    sample_config = """[Interface]
Address = 10.66.0.1/24
PrivateKey = abc123
ListenPort = 51820

# Comment in interface
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT

[Peer]
# Comment for peer 1
PublicKey = peer1key
AllowedIPs = 10.66.0.10/32

[Peer]
# Comment for peer 2
PublicKey = peer2key
AllowedIPs = 10.66.0.20/32
Endpoint = peer2.example.com:51820

[Peer]
PublicKey = peer3key
AllowedIPs = 10.66.0.30/32
"""

    print("=" * 80)
    print("ENTITY PARSER - BRACKET DELIMITER RULE")
    print("=" * 80)
    print()
    print("Principle: Everything between '[' and next '[' is an entity")
    print()

    parser = EntityParser()
    entities = parser.parse_lines(sample_config.split('\n'))

    print(f"Found {len(entities)} entities:")
    print()

    for i, entity in enumerate(entities, start=1):
        print(f"Entity {i}: {entity.entity_type}")
        print(f"  Lines {entity.start_line}-{entity.end_line} ({len(entity.lines)} lines)")
        print(f"  Content:")
        for line in entity.lines[:5]:  # Show first 5 lines
            print(f"    {line.rstrip()}")
        if len(entity.lines) > 5:
            print(f"    ... and {len(entity.lines) - 5} more lines")
        print()

    # Validate structure
    valid, msg = parser.validate_structure(entities)
    print(f"Structure validation: {'✓ VALID' if valid else '❌ INVALID'}")
    print(f"  {msg}")
    print()

    # Show the rule in action
    print("=" * 80)
    print("THE RULE IN ACTION")
    print("=" * 80)
    print()
    print("Config text:")
    print("-" * 40)
    for line_num, line in enumerate(sample_config.split('\n'), start=1):
        marker = "  "
        if line.strip().startswith('['):
            marker = "← "  # Entity boundary
        print(f"{line_num:3} {marker} {line}")
    print()
    print("Entity boundaries marked with ←")
    print()
    print("Everything between boundaries belongs to that entity.")
    print("No ambiguity. 100% reliable.")


if __name__ == "__main__":
    demonstrate_entity_parsing()
