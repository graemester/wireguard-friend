"""
Extramural CLI Commands

Command-line interface for managing external WireGuard configurations.

Commands:
- list: List configs by sponsor or local peer
- show: Show detailed config information
- import: Import config from sponsor .conf file
- generate: Generate .conf file from database
- add-sponsor: Add a new sponsor
- add-peer: Add a new local peer (device)
- add-ssh-host: Add a new SSH host configuration
- switch-peer: Switch active server endpoint
- update: Update config with new details from sponsor
- deploy: Deploy config via SSH
"""

import sys
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


def list_configs(db_path: Path, sponsor: Optional[str] = None, peer: Optional[str] = None):
    """List extramural configs"""
    from v1.extramural_ops import ExtramuralOps

    ops = ExtramuralOps(db_path)

    # Get filter IDs
    sponsor_id = None
    peer_id = None

    if sponsor:
        sponsor_obj = ops.get_sponsor_by_name(sponsor)
        if not sponsor_obj:
            print(f"Error: Sponsor '{sponsor}' not found")
            return 1
        sponsor_id = sponsor_obj.id

    if peer:
        peer_obj = ops.get_local_peer_by_name(peer)
        if not peer_obj:
            print(f"Error: Local peer '{peer}' not found")
            return 1
        peer_id = peer_obj.id

    # List configs
    configs = ops.list_extramural_configs(
        local_peer_id=peer_id,
        sponsor_id=sponsor_id
    )

    if not configs:
        print("No extramural configs found")
        return 0

    print(f"\n{'=' * 80}")
    print(f"EXTRAMURAL CONFIGS ({len(configs)})")
    print(f"{'=' * 80}\n")

    for config in configs:
        peer_obj = ops.get_local_peer(config.local_peer_id)
        sponsor_obj = ops.get_sponsor(config.sponsor_id)
        active_peer = ops.get_active_peer(config.id)

        print(f"Config ID: {config.id}")
        print(f"  Local Peer: {peer_obj.name if peer_obj else 'Unknown'}")
        print(f"  Sponsor: {sponsor_obj.name if sponsor_obj else 'Unknown'}")
        print(f"  Interface: {config.interface_name or 'N/A'}")
        print(f"  Addresses: {', '.join(filter(None, [config.assigned_ipv4, config.assigned_ipv6]))}")
        print(f"  Active Endpoint: {active_peer.endpoint if active_peer else 'None'}")

        if config.pending_remote_update:
            print(f"  ⚠️  PENDING REMOTE UPDATE - New public key: {config.local_public_key[:32]}...")

        if config.last_deployed_at:
            print(f"  Last Deployed: {config.last_deployed_at}")

        print()

    return 0


def show_config(db_path: Path, config_spec: str):
    """Show detailed config information"""
    from v1.extramural_ops import ExtramuralOps
    from v1.extramural_generator import ExtramuralConfigGenerator

    ops = ExtramuralOps(db_path)
    gen = ExtramuralConfigGenerator(db_path)

    # Parse config_spec (peer/sponsor or config_id)
    if '/' in config_spec:
        peer_name, sponsor_name = config_spec.split('/', 1)
        peer_obj = ops.get_local_peer_by_name(peer_name)
        sponsor_obj = ops.get_sponsor_by_name(sponsor_name)

        if not peer_obj:
            print(f"Error: Local peer '{peer_name}' not found")
            return 1
        if not sponsor_obj:
            print(f"Error: Sponsor '{sponsor_name}' not found")
            return 1

        config = ops.get_extramural_config_by_peer_sponsor(peer_obj.id, sponsor_obj.id)
    else:
        try:
            config_id = int(config_spec)
            config = ops.get_extramural_config(config_id)
        except ValueError:
            print(f"Error: Invalid config spec '{config_spec}'. Use 'peer/sponsor' or config_id")
            return 1

    if not config:
        print("Config not found")
        return 1

    # Get related entities
    peer = ops.get_local_peer(config.local_peer_id)
    sponsor = ops.get_sponsor(config.sponsor_id)
    peers = ops.list_extramural_peers(config.id)
    active_peer = ops.get_active_peer(config.id)

    # Display detailed info
    print(f"\n{'=' * 80}")
    print(f"EXTRAMURAL CONFIG DETAILS")
    print(f"{'=' * 80}\n")

    print(f"Config ID: {config.id}")
    print(f"Permanent GUID: {config.permanent_guid}")
    print(f"\nLocal Peer: {peer.name if peer else 'Unknown'}")
    print(f"Sponsor: {sponsor.name if sponsor else 'Unknown'}")
    if sponsor and sponsor.website:
        print(f"  Website: {sponsor.website}")
    if sponsor and sponsor.support_url:
        print(f"  Support: {sponsor.support_url}")

    print(f"\nInterface Configuration:")
    print(f"  Name: {config.interface_name or 'N/A'}")
    print(f"  IPv4: {config.assigned_ipv4 or 'N/A'}")
    print(f"  IPv6: {config.assigned_ipv6 or 'N/A'}")
    print(f"  DNS: {config.dns_servers or 'N/A'}")
    print(f"  MTU: {config.mtu or 'default'}")
    print(f"  Listen Port: {config.listen_port or 'N/A'}")
    print(f"  Table: {config.table_setting or 'auto'}")

    print(f"\nKeys:")
    print(f"  Public Key: {config.local_public_key}")
    print(f"  Private Key: {config.local_private_key[:20]}...")

    print(f"\nPeer Endpoints ({len(peers)}):")
    for p in peers:
        active_mark = "  [ACTIVE]" if p.is_active else ""
        print(f"  - {p.name or 'unnamed'}{active_mark}")
        print(f"      Public Key: {p.public_key}")
        print(f"      Endpoint: {p.endpoint or 'N/A'}")
        print(f"      Allowed IPs: {p.allowed_ips}")
        if p.persistent_keepalive:
            print(f"      Keepalive: {p.persistent_keepalive}s")

    print(f"\nStatus:")
    if config.pending_remote_update:
        print(f"  ⚠️  PENDING REMOTE UPDATE")
        print(f"  You rotated your local key. Update your public key at sponsor:")
        print(f"  New public key: {config.local_public_key}")
    else:
        print(f"  ✓ Up to date")

    if config.last_deployed_at:
        print(f"\n  Last deployed: {config.last_deployed_at}")
    else:
        print(f"\n  Never deployed")

    if config.last_key_rotation_at:
        print(f"  Last key rotation: {config.last_key_rotation_at}")

    print()
    return 0


def import_config(
    db_path: Path,
    config_file: Path,
    sponsor: str,
    peer: str,
    interface: Optional[str] = None,
    website: Optional[str] = None,
    support_url: Optional[str] = None
):
    """Import config from sponsor .conf file"""
    from v1.extramural_import import import_extramural_config

    try:
        config_id, sponsor_id, peer_id = import_extramural_config(
            db_path=db_path,
            config_path=config_file,
            sponsor_name=sponsor,
            local_peer_name=peer,
            interface_name=interface,
            sponsor_website=website,
            sponsor_support_url=support_url
        )

        print(f"\n✓ Successfully imported config")
        print(f"  Config ID: {config_id}")
        print(f"  Sponsor: {sponsor} (ID: {sponsor_id})")
        print(f"  Local Peer: {peer} (ID: {peer_id})")
        print(f"\nUse 'wg-friend extramural show {peer}/{sponsor}' to view details")

        return 0

    except Exception as e:
        print(f"Error importing config: {e}")
        logger.exception("Import failed")
        return 1


def generate_config(db_path: Path, config_spec: str, output: Optional[Path] = None):
    """Generate .conf file from database"""
    from v1.extramural_ops import ExtramuralOps
    from v1.extramural_generator import ExtramuralConfigGenerator

    ops = ExtramuralOps(db_path)
    gen = ExtramuralConfigGenerator(db_path)

    # Parse config_spec
    if '/' in config_spec:
        peer_name, sponsor_name = config_spec.split('/', 1)
        peer = ops.get_local_peer_by_name(peer_name)
        sponsor = ops.get_sponsor_by_name(sponsor_name)

        if not peer or not sponsor:
            print(f"Error: Peer or sponsor not found")
            return 1

        config = ops.get_extramural_config_by_peer_sponsor(peer.id, sponsor.id)
    else:
        try:
            config_id = int(config_spec)
            config = ops.get_extramural_config(config_id)
        except ValueError:
            print(f"Error: Invalid config spec")
            return 1

    if not config:
        print("Config not found")
        return 1

    # Generate config
    try:
        content = gen.generate_config(config.id, output)

        if output:
            print(f"✓ Config written to: {output}")
        else:
            print(content)

        return 0

    except Exception as e:
        print(f"Error generating config: {e}")
        logger.exception("Generation failed")
        return 1


def add_sponsor(
    db_path: Path,
    name: str,
    website: Optional[str] = None,
    support_url: Optional[str] = None,
    notes: Optional[str] = None
):
    """Add a new sponsor"""
    from v1.extramural_ops import ExtramuralOps

    ops = ExtramuralOps(db_path)

    try:
        sponsor_id = ops.add_sponsor(
            name=name,
            website=website,
            support_url=support_url,
            notes=notes
        )

        print(f"✓ Added sponsor: {name} (ID: {sponsor_id})")
        return 0

    except Exception as e:
        print(f"Error adding sponsor: {e}")
        logger.exception("Add sponsor failed")
        return 1


def add_local_peer(
    db_path: Path,
    name: str,
    ssh_host: Optional[str] = None,
    notes: Optional[str] = None
):
    """Add a new local peer"""
    from v1.extramural_ops import ExtramuralOps

    ops = ExtramuralOps(db_path)

    # Get SSH host ID if specified
    ssh_host_id = None
    if ssh_host:
        host = ops.get_ssh_host_by_name(ssh_host)
        if not host:
            print(f"Error: SSH host '{ssh_host}' not found")
            print("Create it first with: wg-friend extramural add-ssh-host")
            return 1
        ssh_host_id = host.id

    try:
        peer_id = ops.add_local_peer(
            name=name,
            ssh_host_id=ssh_host_id,
            notes=notes
        )

        print(f"✓ Added local peer: {name} (ID: {peer_id})")
        return 0

    except Exception as e:
        print(f"Error adding local peer: {e}")
        logger.exception("Add peer failed")
        return 1


def add_ssh_host(
    db_path: Path,
    name: str,
    host: str,
    port: int = 22,
    user: Optional[str] = None,
    key_path: Optional[str] = None,
    config_dir: str = "/etc/wireguard",
    notes: Optional[str] = None
):
    """Add a new SSH host"""
    from v1.extramural_ops import ExtramuralOps

    ops = ExtramuralOps(db_path)

    try:
        host_id = ops.add_ssh_host(
            name=name,
            ssh_host=host,
            ssh_port=port,
            ssh_user=user,
            ssh_key_path=key_path,
            config_directory=config_dir,
            notes=notes
        )

        print(f"✓ Added SSH host: {name} (ID: {host_id})")
        return 0

    except Exception as e:
        print(f"Error adding SSH host: {e}")
        logger.exception("Add SSH host failed")
        return 1


def switch_active_peer(db_path: Path, config_spec: str, peer_name: str):
    """Switch active server endpoint"""
    from v1.extramural_ops import ExtramuralOps

    ops = ExtramuralOps(db_path)

    # Get config
    if '/' in config_spec:
        local_peer_name, sponsor_name = config_spec.split('/', 1)
        local_peer = ops.get_local_peer_by_name(local_peer_name)
        sponsor = ops.get_sponsor_by_name(sponsor_name)

        if not local_peer or not sponsor:
            print("Error: Peer or sponsor not found")
            return 1

        config = ops.get_extramural_config_by_peer_sponsor(local_peer.id, sponsor.id)
    else:
        try:
            config_id = int(config_spec)
            config = ops.get_extramural_config(config_id)
        except ValueError:
            print(f"Error: Invalid config spec")
            return 1

    if not config:
        print("Config not found")
        return 1

    # Find peer by name
    peers = ops.list_extramural_peers(config.id)
    target_peer = None

    for p in peers:
        if p.name == peer_name:
            target_peer = p
            break

    if not target_peer:
        print(f"Error: Peer '{peer_name}' not found in config")
        print(f"\nAvailable peers:")
        for p in peers:
            active = "  [ACTIVE]" if p.is_active else ""
            print(f"  - {p.name}{active}")
        return 1

    # Switch active peer
    try:
        ops.set_active_peer(target_peer.id)
        print(f"✓ Switched active peer to: {peer_name}")
        print(f"  Endpoint: {target_peer.endpoint}")
        print(f"\nRegenerate and deploy config to apply changes:")
        print(f"  wg-friend extramural generate {config_spec}")
        print(f"  wg-friend extramural deploy {config_spec}")

        return 0

    except Exception as e:
        print(f"Error switching peer: {e}")
        logger.exception("Switch peer failed")
        return 1


if __name__ == "__main__":
    # Demo usage
    print("Extramural CLI Module")
    print("\nAvailable commands:")
    print("  - list [--sponsor NAME] [--peer NAME]")
    print("  - show <peer/sponsor>")
    print("  - import <config.conf> --sponsor NAME --peer NAME")
    print("  - generate <peer/sponsor> [--output FILE]")
    print("  - add-sponsor NAME [--website URL] [--support URL]")
    print("  - add-peer NAME [--ssh-host NAME]")
    print("  - add-ssh-host NAME --host HOST [--user USER] [--port PORT]")
    print("  - switch-peer <peer/sponsor> PEER_NAME")
