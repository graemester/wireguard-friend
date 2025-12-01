"""
Entity Review Flow

Interactive review of detected entities after import detection.
Allows user to confirm/change classification and set friendly names.

Phase 1: Parse and classify configs
Phase 2: Review each entity
"""

import sys
from pathlib import Path
from typing import List, Tuple, Optional

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

# Rich imports for enhanced UI
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.prompt import Prompt, Confirm, IntPrompt
    from rich import box
    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False
    console = None
    Prompt = Confirm = IntPrompt = None

from v1.entity_parser import EntityParser
from v1.keygen import derive_public_key


def rprint(msg: str = "", style: str = None):
    """Print with Rich if available, else plain print"""
    if RICH_AVAILABLE:
        if style:
            console.print(f"[{style}]{msg}[/{style}]")
        else:
            console.print(msg)
    else:
        import re
        plain = re.sub(r'\[/?[^\]]+\]', '', msg)
        print(plain)


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
    if RICH_AVAILABLE:
        # Build summary table
        table = Table(show_header=False, box=box.SIMPLE)
        table.add_column("Property", style="bold")
        table.add_column("Value")

        table.add_row("Detected as", f"[cyan]{entity.type_display}[/cyan]")
        table.add_row("Peer count", str(entity.peer_count))

        if entity.addresses:
            table.add_row("Addresses", f"[green]{', '.join(entity.addresses)}[/green]")

        if entity.endpoint:
            table.add_row("Endpoint", f"[yellow]{entity.endpoint}[/yellow]")

        if entity.public_key:
            table.add_row("Public Key", f"[dim]{entity.public_key[:20]}...[/dim]")

        console.print(Panel(
            table,
            title=f"[bold][{index}] {entity.path.name}[/bold]",
            border_style="cyan"
        ))
    else:
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
    # Extract details first
    extract_entity_details(entity)

    if RICH_AVAILABLE:
        console.print()
        console.print(Panel.fit(
            f"[bold]Review Entity {index}/{total}[/bold]",
            border_style="cyan"
        ))

        # Build info table
        table = Table(show_header=False, box=box.SIMPLE)
        table.add_column("Property", style="bold")
        table.add_column("Value")

        table.add_row("File", f"[cyan]{entity.path.name}[/cyan]")
        table.add_row("Detected as", f"[yellow]{entity.type_display}[/yellow]")

        if entity.addresses:
            table.add_row("Addresses", f"[green]{', '.join(entity.addresses)}[/green]")

        if entity.endpoint:
            table.add_row("Connects to", f"[magenta]{entity.endpoint}[/magenta]")

        if entity.peer_count > 0:
            table.add_row("Peers", str(entity.peer_count))

        console.print(table)
    else:
        print(f"\n{'=' * 60}")
        print(f"  REVIEW ENTITY {index}/{total}")
        print(f"{'=' * 60}")

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

    rprint()
    rprint("[bold]Is this classification correct?[/bold]")
    rprint(f"  [1] Yes, this is a {entity.type_display}")
    for i, (_, name) in enumerate(alternatives, 2):
        rprint(f"  [{i}] No, this is a {name}")
    rprint(f"  [s] Skip this config")
    rprint()

    while True:
        if RICH_AVAILABLE:
            choice = Prompt.ask("Choice", default="1").strip().lower()
        else:
            choice = input("  Choice [1]: ").strip().lower()

        if choice == '' or choice == '1':
            # Keep current classification
            break
        elif choice == '2' and len(alternatives) >= 1:
            entity.config_type = alternatives[0][0]
            rprint(f"  [green]-> Changed to: {alternatives[0][1]}[/green]")
            break
        elif choice == '3' and len(alternatives) >= 2:
            entity.config_type = alternatives[1][0]
            rprint(f"  [green]-> Changed to: {alternatives[1][1]}[/green]")
            break
        elif choice == 's':
            rprint("  [dim]-> Skipping this config[/dim]")
            return False
        else:
            rprint("  [red]Invalid choice. Enter 1-3 or 's' to skip.[/red]")

    # Prompt for friendly name
    default_name = entity.friendly_name

    # Suggest better names based on type
    if entity.config_type == 'coordination_server':
        if default_name in ('wg0', 'coordination', 'server'):
            default_name = 'coordination-server'

    rprint()
    rprint(f"[bold]Enter a friendly name for this {entity.type_short}.[/bold]")
    rprint("[dim]This will be used to identify it in the database and generated configs.[/dim]")
    rprint()

    if RICH_AVAILABLE:
        name = Prompt.ask("Friendly name", default=default_name).strip()
    else:
        name = input(f"  Friendly name [{default_name}]: ").strip()

    if name:
        entity.friendly_name = name
    else:
        entity.friendly_name = default_name

    rprint(f"  [green]-> Name: {entity.friendly_name}[/green]")

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
    if RICH_AVAILABLE:
        console.print()
        console.print(Panel.fit(
            "[bold cyan]Phase 1: Entity Review[/bold cyan]\n\n"
            "Review each detected config to confirm classification\n"
            "and set friendly names.",
            border_style="cyan"
        ))
    else:
        print()
        print("=" * 60)
        print("  PHASE 1: ENTITY REVIEW")
        print("=" * 60)
        print()
        print("  Review each detected config to confirm the")
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
    if RICH_AVAILABLE:
        console.print()

        if not confirmed:
            console.print(Panel(
                "[yellow]No entities confirmed for import.[/yellow]",
                title="[bold]Review Complete[/bold]",
                border_style="yellow"
            ))
            return []

        # Count by type
        cs_count = sum(1 for e in confirmed if e.config_type == 'coordination_server')
        snr_count = sum(1 for e in confirmed if e.config_type == 'subnet_router')
        client_count = sum(1 for e in confirmed if e.config_type == 'client')

        # Build summary table
        summary_table = Table(title="Confirmed Entities", box=box.ROUNDED)
        summary_table.add_column("Type", style="bold")
        summary_table.add_column("Name", style="cyan")
        summary_table.add_column("File", style="dim")

        for entity in confirmed:
            type_style = {
                'coordination_server': 'green',
                'subnet_router': 'magenta',
                'client': 'blue'
            }.get(entity.config_type, 'white')
            summary_table.add_row(
                f"[{type_style}]{entity.type_short}[/{type_style}]",
                entity.friendly_name,
                entity.path.name
            )

        console.print(summary_table)
        console.print()
    else:
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

        for entity in confirmed:
            print(f"    [{entity.type_short:6}] {entity.friendly_name} ({entity.path.name})")
        print()

    # Validate: must have exactly one CS
    if cs_count == 0:
        rprint("[red]WARNING: No coordination server selected![/red]")
        rprint("You need at least one coordination server to import.")
        rprint()
        return []
    elif cs_count > 1:
        rprint("[red]WARNING: Multiple coordination servers selected![/red]")
        rprint("Only one coordination server is supported. Please re-run and select only one.")
        rprint()
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
