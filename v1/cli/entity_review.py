"""
Entity Review Flow

Interactive review of detected entities after import detection.
Allows user to confirm/change classification and set friendly names.
"""

import sys
from pathlib import Path
from typing import List, Tuple, Optional

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from v1.entity_parser import EntityParser
from v1.keygen import derive_public_key


class DetectedEntity:
    """Represents a detected config file with its classification"""

    def __init__(self, path: Path, config_type: str, peer_count: int):
        self.path = path
        self.config_type = config_type  # coordination_server, subnet_router, client
        self.peer_count = peer_count
        self.friendly_name = path.stem  # Default to filename without .conf
        self.confirmed = False

        # Extracted data (populated during review)
        self.addresses = []
        self.endpoint = None
        self.private_key = None
        self.public_key = None

    @property
    def type_display(self) -> str:
        """Human-readable type name"""
        return {
            'coordination_server': 'Coordination Server',
            'subnet_router': 'Subnet Router',
            'client': 'Remote Client'
        }.get(self.config_type, self.config_type)

    @property
    def type_short(self) -> str:
        """Short type code"""
        return {
            'coordination_server': 'CS',
            'subnet_router': 'SNR',
            'client': 'Remote'
        }.get(self.config_type, '?')


def extract_entity_details(entity: DetectedEntity) -> None:
    """Extract additional details from config file"""
    parser = EntityParser()
    entities = parser.parse_file(entity.path)

    if not entities:
        return

    interface = entities[0]

    for line in interface.lines:
        stripped = line.strip()
        if '=' not in stripped:
            continue

        key, value = stripped.split('=', 1)
        key = key.strip().lower()
        value = value.strip()

        if key == 'address':
            entity.addresses = [a.strip() for a in value.split(',')]
        elif key == 'privatekey':
            entity.private_key = value
            try:
                entity.public_key = derive_public_key(value)
            except:
                pass

    # Look for endpoint in first peer (for clients)
    if len(entities) > 1:
        peer = entities[1]
        for line in peer.lines:
            stripped = line.strip()
            if stripped.lower().startswith('endpoint'):
                if '=' in stripped:
                    entity.endpoint = stripped.split('=', 1)[1].strip()


def print_entity_summary(entity: DetectedEntity, index: int) -> None:
    """Print a summary of the detected entity"""
    print(f"\n{'─' * 60}")
    print(f"  [{index}] {entity.path.name}")
    print(f"{'─' * 60}")
    print(f"  Detected as: {entity.type_display}")
    print(f"  Peer count:  {entity.peer_count}")

    if entity.addresses:
        print(f"  Addresses:   {', '.join(entity.addresses)}")

    if entity.endpoint:
        print(f"  Endpoint:    {entity.endpoint}")

    if entity.public_key:
        print(f"  Public Key:  {entity.public_key[:20]}...")


def prompt_entity_review(entity: DetectedEntity, index: int, total: int) -> bool:
    """
    Interactive review of a single entity.

    Returns:
        True if user confirms, False if user wants to skip/cancel
    """
    print(f"\n{'=' * 60}")
    print(f"  REVIEW ENTITY {index}/{total}")
    print(f"{'=' * 60}")

    # Extract details first
    extract_entity_details(entity)

    # Show current detection
    print(f"\n  File: {entity.path.name}")
    print(f"  Detected as: {entity.type_display}")

    if entity.addresses:
        print(f"  Addresses: {', '.join(entity.addresses)}")

    if entity.endpoint:
        print(f"  Connects to: {entity.endpoint}")

    if entity.peer_count > 0:
        print(f"  Peers: {entity.peer_count}")

    # Prompt for classification confirmation
    # Build list of alternative types (excluding current)
    all_types = [
        ('coordination_server', 'Coordination Server'),
        ('subnet_router', 'Subnet Router'),
        ('client', 'Remote Client')
    ]
    alternatives = [(t, name) for t, name in all_types if t != entity.config_type]

    print(f"\n  Is this classification correct?")
    print(f"    1. Yes, this is a {entity.type_display}")
    for i, (_, name) in enumerate(alternatives, 2):
        print(f"    {i}. No, this is a {name}")
    print(f"    s. Skip this config")
    print()

    while True:
        choice = input("  Choice [1]: ").strip().lower()

        if choice == '' or choice == '1':
            # Keep current classification
            break
        elif choice == '2' and len(alternatives) >= 1:
            entity.config_type = alternatives[0][0]
            print(f"  -> Changed to: {alternatives[0][1]}")
            break
        elif choice == '3' and len(alternatives) >= 2:
            entity.config_type = alternatives[1][0]
            print(f"  -> Changed to: {alternatives[1][1]}")
            break
        elif choice == 's':
            print("  -> Skipping this config")
            return False
        else:
            print("  Invalid choice. Enter 1-3 or 's' to skip.")

    # Prompt for friendly name
    default_name = entity.friendly_name

    # Suggest better names based on type
    if entity.config_type == 'coordination_server':
        if default_name in ('wg0', 'coordination', 'server'):
            default_name = 'coordination-server'

    print(f"\n  Enter a friendly name for this {entity.type_short}.")
    print(f"  This will be used to identify it in the database and generated configs.")
    print()

    name = input(f"  Friendly name [{default_name}]: ").strip()
    if name:
        entity.friendly_name = name
    else:
        entity.friendly_name = default_name

    print(f"  -> Name: {entity.friendly_name}")

    entity.confirmed = True
    return True


def review_detected_entities(
    classified_configs: List[Tuple[Path, str, int]]
) -> List[DetectedEntity]:
    """
    Interactive review of all detected entities.

    Args:
        classified_configs: List of (path, config_type, peer_count) tuples

    Returns:
        List of confirmed DetectedEntity objects
    """
    print()
    print("=" * 60)
    print("  ENTITY REVIEW")
    print("=" * 60)
    print()
    print("  Let's review each detected config to confirm the")
    print("  classification and set friendly names.")
    print()

    # Create entity objects
    entities = [
        DetectedEntity(path, config_type, peer_count)
        for path, config_type, peer_count in classified_configs
    ]

    # Sort: coordination_server first, then subnet_router, then client
    type_order = {'coordination_server': 0, 'subnet_router': 1, 'client': 2}
    entities.sort(key=lambda e: type_order.get(e.config_type, 99))

    confirmed = []
    total = len(entities)

    for i, entity in enumerate(entities, 1):
        if prompt_entity_review(entity, i, total):
            confirmed.append(entity)

    # Summary
    print()
    print("=" * 60)
    print("  REVIEW COMPLETE")
    print("=" * 60)
    print()

    if not confirmed:
        print("  No entities confirmed for import.")
        return []

    # Count by type
    cs_count = sum(1 for e in confirmed if e.config_type == 'coordination_server')
    snr_count = sum(1 for e in confirmed if e.config_type == 'subnet_router')
    client_count = sum(1 for e in confirmed if e.config_type == 'client')

    print(f"  Confirmed {len(confirmed)} entities:")
    if cs_count:
        print(f"    - {cs_count} Coordination Server(s)")
    if snr_count:
        print(f"    - {snr_count} Subnet Router(s)")
    if client_count:
        print(f"    - {client_count} Remote Client(s)")
    print()

    # List them
    for entity in confirmed:
        print(f"    [{entity.type_short:6}] {entity.friendly_name} ({entity.path.name})")
    print()

    # Validate: must have exactly one CS
    if cs_count == 0:
        print("  WARNING: No coordination server selected!")
        print("  You need at least one coordination server to import.")
        print()
        return []
    elif cs_count > 1:
        print("  WARNING: Multiple coordination servers selected!")
        print("  Only one coordination server is supported. Please re-run and select only one.")
        print()
        return []

    return confirmed


def get_cs_entity(entities: List[DetectedEntity]) -> Optional[DetectedEntity]:
    """Get the coordination server entity from the list"""
    for entity in entities:
        if entity.config_type == 'coordination_server':
            return entity
    return None


if __name__ == '__main__':
    # Test the review flow
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('configs', nargs='+', help='Config files to review')
    args = parser.parse_args()

    from v1.config_detector import ConfigDetector

    detector = ConfigDetector()
    classified = []

    for config_path in args.configs:
        path = Path(config_path)
        if path.exists():
            config_type, peer_count = detector.detect_type(path)
            classified.append((path, config_type, peer_count))

    if classified:
        confirmed = review_detected_entities(classified)
        print(f"\nConfirmed {len(confirmed)} entities")
