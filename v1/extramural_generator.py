"""
Extramural Config Generator

Generate WireGuard .conf files from extramural database entries.

This module:
1. Queries the database for extramural configs
2. Generates valid WireGuard .conf files
3. Includes only the active peer endpoint
4. Properly formats all fields
"""

import logging
from pathlib import Path
from typing import Optional, List

logger = logging.getLogger(__name__)


class ExtramuralConfigGenerator:
    """Generate WireGuard configs from extramural database"""

    def __init__(self, db_path: Path):
        from v1.extramural_ops import ExtramuralOps
        self.ops = ExtramuralOps(db_path)
        self.db_path = db_path

    def _get_commands(self, config_id: int) -> tuple:
        """
        Retrieve PostUp/PostDown commands for an extramural config.

        Args:
            config_id: ID of the extramural config

        Returns:
            Tuple of (postup_commands, postdown_commands) lists
        """
        import json
        import sqlite3

        postup_commands = []
        postdown_commands = []

        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute("""
                SELECT up_commands, down_commands
                FROM command_pair
                WHERE extramural_config_id = ?
                ORDER BY execution_order
            """, (config_id,))

            for row in cursor.fetchall():
                up = json.loads(row['up_commands']) if row['up_commands'] else []
                down = json.loads(row['down_commands']) if row['down_commands'] else []
                postup_commands.extend(up)
                postdown_commands.extend(down)

        return postup_commands, postdown_commands

    def generate_config(
        self,
        config_id: int,
        output_path: Optional[Path] = None
    ) -> str:
        """
        Generate a WireGuard .conf file for an extramural config.

        Args:
            config_id: ID of the extramural config
            output_path: Optional path to write the config file

        Returns:
            String content of the generated config

        Raises:
            ValueError: If config not found or no active peer
        """
        # Get config
        config = self.ops.get_extramural_config(config_id)
        if not config:
            raise ValueError(f"Extramural config {config_id} not found")

        # Get active peer
        active_peer = self.ops.get_active_peer(config_id)
        if not active_peer:
            raise ValueError(f"No active peer for config {config_id}")

        # Build config content
        lines = []

        # [Interface] section
        lines.append("[Interface]")
        lines.append(f"PrivateKey = {config.local_private_key}")

        # Address
        addresses = []
        if config.assigned_ipv4:
            addresses.append(config.assigned_ipv4)
        if config.assigned_ipv6:
            addresses.append(config.assigned_ipv6)

        if addresses:
            lines.append(f"Address = {', '.join(addresses)}")

        # DNS
        if config.dns_servers:
            lines.append(f"DNS = {config.dns_servers}")

        # ListenPort
        if config.listen_port:
            lines.append(f"ListenPort = {config.listen_port}")

        # MTU
        if config.mtu:
            lines.append(f"MTU = {config.mtu}")

        # Table
        if config.table_setting:
            lines.append(f"Table = {config.table_setting}")

        # Add PostUp/PostDown from command_pair table
        postup_commands, postdown_commands = self._get_commands(config_id)
        for cmd in postup_commands:
            lines.append(f"PostUp = {cmd}")
        for cmd in postdown_commands:
            lines.append(f"PostDown = {cmd}")

        # Empty line before peer section
        lines.append("")

        # [Peer] section
        lines.append("[Peer]")
        lines.append(f"PublicKey = {active_peer.public_key}")

        if active_peer.preshared_key:
            lines.append(f"PresharedKey = {active_peer.preshared_key}")

        if active_peer.endpoint:
            lines.append(f"Endpoint = {active_peer.endpoint}")

        lines.append(f"AllowedIPs = {active_peer.allowed_ips}")

        if active_peer.persistent_keepalive:
            lines.append(f"PersistentKeepalive = {active_peer.persistent_keepalive}")

        # Join all lines
        content = "\n".join(lines) + "\n"

        # Write to file if requested
        if output_path:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'w') as f:
                f.write(content)
            logger.info(f"Wrote config to {output_path}")

        return content

    def generate_all_configs(
        self,
        output_dir: Path,
        local_peer_id: Optional[int] = None,
        sponsor_id: Optional[int] = None
    ) -> List[Path]:
        """
        Generate all extramural configs, optionally filtered.

        Args:
            output_dir: Directory to write config files
            local_peer_id: Optional filter by local peer
            sponsor_id: Optional filter by sponsor

        Returns:
            List of generated file paths
        """
        output_dir.mkdir(parents=True, exist_ok=True)
        generated = []

        configs = self.ops.list_extramural_configs(
            local_peer_id=local_peer_id,
            sponsor_id=sponsor_id
        )

        from datetime import datetime

        for config in configs:
            # Get peer and sponsor names for filename
            peer = self.ops.get_local_peer(config.local_peer_id)
            sponsor = self.ops.get_sponsor(config.sponsor_id)

            if not peer or not sponsor:
                logger.warning(f"Skipping config {config.id}: missing peer or sponsor")
                continue

            # Determine filename: [Sponsor]-[hostname]-date.conf
            sponsor_slug = sponsor.name.lower().replace(' ', '-')
            peer_slug = peer.name.lower().replace(' ', '-')
            date_str = datetime.now().strftime('%Y%m%d')
            filename = f"{sponsor_slug}-{peer_slug}-{date_str}.conf"

            output_path = output_dir / filename

            try:
                self.generate_config(config.id, output_path)
                generated.append(output_path)
            except ValueError as e:
                logger.error(f"Failed to generate config {config.id}: {e}")

        logger.info(f"Generated {len(generated)} config file(s)")
        return generated

    def get_config_summary(self, config_id: int) -> dict:
        """Get a summary of a config (for display/validation)"""
        config = self.ops.get_extramural_config(config_id)
        if not config:
            raise ValueError(f"Config {config_id} not found")

        peer = self.ops.get_local_peer(config.local_peer_id)
        sponsor = self.ops.get_sponsor(config.sponsor_id)
        active_peer = self.ops.get_active_peer(config_id)
        all_peers = self.ops.list_extramural_peers(config_id)

        return {
            'config_id': config.id,
            'local_peer': peer.name if peer else 'Unknown',
            'sponsor': sponsor.name if sponsor else 'Unknown',
            'interface_name': config.interface_name,
            'addresses': [a for a in [config.assigned_ipv4, config.assigned_ipv6] if a],
            'dns': config.dns_servers,
            'active_peer': active_peer.name if active_peer else None,
            'active_endpoint': active_peer.endpoint if active_peer else None,
            'total_peers': len(all_peers),
            'pending_remote_update': config.pending_remote_update,
            'last_deployed': config.last_deployed_at,
            'config_path': config.config_path
        }


if __name__ == "__main__":
    # Demo usage
    import tempfile
    from v1.extramural_schema import ExtramuralDB
    from v1.extramural_ops import ExtramuralOps

    # Create demo database
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
        db_path = Path(f.name)

    print(f"Creating demo database at {db_path}\n")

    # Initialize
    ExtramuralDB(db_path)
    ops = ExtramuralOps(db_path)

    # Add entities
    print("=== Setting up demo data ===")
    ssh_id = ops.add_ssh_host("laptop", "laptop.local", ssh_user="user")
    sponsor_id = ops.add_sponsor("Mullvad VPN", website="https://mullvad.net")
    peer_id = ops.add_local_peer("my-laptop", ssh_host_id=ssh_id)

    # Generate keypair
    try:
        from v1.extramural_ops import generate_wireguard_keypair
        private_key, public_key = generate_wireguard_keypair()

        # Add config
        config_id = ops.add_extramural_config(
            local_peer_id=peer_id,
            sponsor_id=sponsor_id,
            local_private_key=private_key,
            local_public_key=public_key,
            interface_name="wg-mullvad",
            assigned_ipv4="10.64.1.1/32",
            assigned_ipv6="fc00:bbbb:bbbb:bb01::1/128",
            dns_servers="10.64.0.1"
        )

        # Add peer
        ops.add_extramural_peer(
            config_id=config_id,
            name="us-east-1",
            public_key="SponsorPublicKey123456789abcdefg=",
            endpoint="us1.mullvad.net:51820",
            allowed_ips="0.0.0.0/0, ::/0",
            persistent_keepalive=25,
            is_active=True
        )

        print(f"Created config ID: {config_id}\n")

        # Generate config
        print("=== Generating Config ===")
        generator = ExtramuralConfigGenerator(db_path)

        content = generator.generate_config(config_id)
        print(content)

        # Get summary
        print("=== Config Summary ===")
        summary = generator.get_config_summary(config_id)
        for key, value in summary.items():
            print(f"{key}: {value}")

        # Generate to file
        print("\n=== Writing to file ===")
        output_dir = Path("/tmp/extramural-configs")
        files = generator.generate_all_configs(output_dir)
        print(f"Generated files: {files}")

    except RuntimeError as e:
        print(f"Skipping test (requires wg tools): {e}")

    print(f"\nDatabase available at: {db_path}")
