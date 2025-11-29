"""WireGuard peer management and status tracking"""

import re
import logging
from pathlib import Path
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, field
from .ssh_client import SSHClient


logger = logging.getLogger(__name__)


@dataclass
class WireGuardPeerStatus:
    """WireGuard peer with runtime status from 'wg show'"""
    public_key: str
    name: Optional[str] = None
    endpoint: Optional[str] = None
    allowed_ips: List[str] = field(default_factory=list)
    latest_handshake: Optional[datetime] = None
    transfer_rx: int = 0
    transfer_tx: int = 0
    persistent_keepalive: Optional[int] = None
    created: Optional[datetime] = None
    ipv4: Optional[str] = None
    ipv6: Optional[str] = None

    @property
    def is_online(self) -> bool:
        """Check if peer is online (handshake within last 3 minutes)"""
        if not self.latest_handshake:
            return False
        return (datetime.now() - self.latest_handshake) < timedelta(minutes=3)

    @property
    def is_old(self) -> bool:
        """Check if config is older than 6 months"""
        if not self.created:
            return False
        return (datetime.now() - self.created) > timedelta(days=180)

    @property
    def status_icon(self) -> str:
        """Get status icon"""
        return "●" if self.is_online else "○"

    @property
    def status_color(self) -> str:
        """Get status color"""
        return "green" if self.is_online else "grey50"

    @property
    def age_flag(self) -> str:
        """Get age warning flag"""
        return "⚠ " if self.is_old else ""


class WireGuardPeerManager:
    """Manager for WireGuard peers on coordinator"""

    def __init__(self, config: Dict):
        """
        Initialize peer manager

        Args:
            config: Loaded config.yaml dictionary
        """
        self.coordinator = config['coordinator']
        self.ssh_config = config['ssh']
        self.host = self.coordinator['host']
        self.port = self.coordinator.get('port', 22)
        self.user = self.coordinator['user']
        self.config_path = self.coordinator['config_path']
        self.interface = self.coordinator['interface']
        self.config = config  # Store full config for PostUp/PostDown rules

    def get_current_peers_from_wg_show(self) -> List[WireGuardPeerStatus]:
        """
        Get current peer status from 'wg show' command

        Returns:
            List of WireGuardPeerStatus objects
        """
        peers = []

        try:
            with SSHClient(
                self.host,
                self.user,
                self.ssh_config['key_path'],
                self.port
            ) as ssh:
                if not ssh.client:
                    logger.error("Failed to connect to coordinator")
                    return peers

                # Run wg show
                exit_code, stdout, stderr = ssh.execute_command(
                    f"wg show {self.interface}",
                    use_sudo=True
                )

                if exit_code != 0:
                    logger.error(f"Failed to run wg show: {stderr}")
                    return peers

                # Parse wg show output
                peers = self._parse_wg_show(stdout)

                logger.info(f"Retrieved {len(peers)} peers from wg show")

        except Exception as e:
            logger.error(f"Failed to get peer status: {e}")

        return peers

    def _parse_wg_show(self, wg_show_output: str) -> List[WireGuardPeerStatus]:
        """Parse 'wg show' output into peer status objects"""
        peers = []
        current_peer = None

        for line in wg_show_output.split('\n'):
            line = line.strip()

            if line.startswith('peer:'):
                # Save previous peer if exists
                if current_peer:
                    peers.append(current_peer)

                # Start new peer
                public_key = line.split('peer:')[1].strip()
                current_peer = WireGuardPeerStatus(public_key=public_key)

            elif current_peer:
                if line.startswith('endpoint:'):
                    current_peer.endpoint = line.split('endpoint:')[1].strip()

                elif line.startswith('allowed ips:'):
                    ips_str = line.split('allowed ips:')[1].strip()
                    current_peer.allowed_ips = [ip.strip() for ip in ips_str.split(',')]

                    # Extract IPv4 and IPv6
                    for ip in current_peer.allowed_ips:
                        if '.' in ip and '/' in ip:
                            current_peer.ipv4 = ip.split('/')[0]
                        elif ':' in ip and '/' in ip:
                            current_peer.ipv6 = ip.split('/')[0]

                elif line.startswith('latest handshake:'):
                    handshake_str = line.split('latest handshake:')[1].strip()
                    current_peer.latest_handshake = self._parse_handshake_time(handshake_str)

                elif line.startswith('transfer:'):
                    transfer_str = line.split('transfer:')[1].strip()
                    rx, tx = self._parse_transfer(transfer_str)
                    current_peer.transfer_rx = rx
                    current_peer.transfer_tx = tx

                elif line.startswith('persistent keepalive:'):
                    ka_str = line.split('persistent keepalive:')[1].strip()
                    if 'every' in ka_str:
                        seconds = re.search(r'(\d+)', ka_str)
                        if seconds:
                            current_peer.persistent_keepalive = int(seconds.group(1))

        # Add last peer
        if current_peer:
            peers.append(current_peer)

        return peers

    def _parse_handshake_time(self, handshake_str: str) -> Optional[datetime]:
        """Parse handshake time string to datetime"""
        if not handshake_str or handshake_str == '(never)':
            return None

        now = datetime.now()
        total_seconds = 0

        # Extract time components
        time_parts = re.findall(r'(\d+)\s+(second|minute|hour|day)s?', handshake_str)

        for value, unit in time_parts:
            value = int(value)
            if unit == 'second':
                total_seconds += value
            elif unit == 'minute':
                total_seconds += value * 60
            elif unit == 'hour':
                total_seconds += value * 3600
            elif unit == 'day':
                total_seconds += value * 86400

        return now - timedelta(seconds=total_seconds)

    def _parse_transfer(self, transfer_str: str) -> Tuple[int, int]:
        """Parse transfer string to bytes"""
        rx, tx = 0, 0

        # Extract received
        rx_match = re.search(r'([\d.]+)\s+(B|KiB|MiB|GiB|TiB)\s+received', transfer_str)
        if rx_match:
            rx = self._convert_to_bytes(float(rx_match.group(1)), rx_match.group(2))

        # Extract sent
        tx_match = re.search(r'([\d.]+)\s+(B|KiB|MiB|GiB|TiB)\s+sent', transfer_str)
        if tx_match:
            tx = self._convert_to_bytes(float(tx_match.group(1)), tx_match.group(2))

        return rx, tx

    def _convert_to_bytes(self, value: float, unit: str) -> int:
        """Convert size with unit to bytes"""
        units = {
            'B': 1,
            'KiB': 1024,
            'MiB': 1024 ** 2,
            'GiB': 1024 ** 3,
            'TiB': 1024 ** 4,
        }
        return int(value * units.get(unit, 1))

    def parse_coordinator_config(self) -> List[WireGuardPeerStatus]:
        """
        Parse coordinator wg0.conf to extract peer configurations

        Returns:
            List of WireGuardPeerStatus with names from comments
        """
        peers = []

        try:
            with SSHClient(
                self.host,
                self.user,
                self.ssh_config['key_path'],
                self.port
            ) as ssh:
                if not ssh.client:
                    return peers

                # Read config file
                config_text = ssh.read_file(self.config_path, use_sudo=True)

                if not config_text:
                    return peers

                # Parse config
                peers = self._parse_wg_config(config_text)

        except Exception as e:
            logger.error(f"Failed to parse coordinator config: {e}")

        return peers

    def _parse_wg_config(self, config_text: str) -> List[WireGuardPeerStatus]:
        """Parse wg0.conf file"""
        peers = []
        current_peer = None
        current_comment = None

        for line in config_text.split('\n'):
            line = line.strip()

            if line.startswith('#') and '[Peer]' not in line:
                # Comment before peer block
                current_comment = line.lstrip('#').strip()

            elif line.startswith('[Peer]'):
                # Start new peer
                if '#' in line:
                    # Comment on same line
                    current_comment = line.split('#')[1].strip()
                current_peer = WireGuardPeerStatus(public_key='')

            elif current_peer:
                if line.startswith('PublicKey'):
                    current_peer.public_key = line.split('=')[1].strip()

                elif line.startswith('AllowedIPs'):
                    ips_str = line.split('=')[1].strip()
                    current_peer.allowed_ips = [ip.strip() for ip in ips_str.split(',')]

                    # Extract IPv4 and IPv6
                    for ip in current_peer.allowed_ips:
                        if '.' in ip and '/' in ip:
                            current_peer.ipv4 = ip.split('/')[0]
                        elif ':' in ip and '/' in ip:
                            current_peer.ipv6 = ip.split('/')[0]

                elif line.startswith('PersistentKeepalive'):
                    current_peer.persistent_keepalive = int(line.split('=')[1].strip())

                elif line == '' or line.startswith('['):
                    # End of peer block
                    if current_peer and current_peer.public_key:
                        # Parse name and date from comment
                        if current_comment:
                            current_peer.name = self._extract_name_from_comment(current_comment)
                            created = self._extract_date_from_comment(current_comment)
                            if created:
                                current_peer.created = created

                        peers.append(current_peer)

                    current_peer = None
                    current_comment = None

        # Add last peer
        if current_peer and current_peer.public_key:
            if current_comment:
                current_peer.name = self._extract_name_from_comment(current_comment)
                created = self._extract_date_from_comment(current_comment)
                if created:
                    current_peer.created = created
            peers.append(current_peer)

        return peers

    def _extract_name_from_comment(self, comment: str) -> str:
        """Extract peer name from comment"""
        # Remove date part if present
        if '(' in comment:
            name = comment.split('(')[0].strip()
        else:
            name = comment.strip()
        return name

    def _extract_date_from_comment(self, comment: str) -> Optional[datetime]:
        """Extract creation date from comment"""
        # Look for date pattern YYYY-MM-DD
        date_match = re.search(r'(\d{4}-\d{2}-\d{2})', comment)
        if date_match:
            try:
                return datetime.strptime(date_match.group(1), '%Y-%m-%d')
            except ValueError:
                pass
        return None

    def merge_status_with_config(
        self,
        wg_show_peers: List[WireGuardPeerStatus],
        config_peers: List[WireGuardPeerStatus]
    ) -> List[WireGuardPeerStatus]:
        """
        Merge runtime status from wg show with config metadata

        Args:
            wg_show_peers: Peers from 'wg show' with runtime status
            config_peers: Peers from config file with names and dates

        Returns:
            Merged list of peers with both status and metadata
        """
        merged = []

        # Create lookup by public key
        config_by_key = {p.public_key: p for p in config_peers}

        for status_peer in wg_show_peers:
            # Get config metadata if exists
            config_peer = config_by_key.get(status_peer.public_key)

            if config_peer:
                # Merge: status from wg show, metadata from config
                status_peer.name = config_peer.name
                status_peer.created = config_peer.created

            merged.append(status_peer)

        # Add config peers not in wg show (offline peers)
        status_keys = {p.public_key for p in wg_show_peers}
        for config_peer in config_peers:
            if config_peer.public_key not in status_keys:
                # Peer in config but not in wg show
                merged.append(config_peer)

        return merged

    def update_peer_in_config(
        self,
        old_public_key: str,
        new_peer_block: str
    ) -> bool:
        """
        Update an existing peer in coordinator's wg0.conf (key rotation)

        Args:
            old_public_key: Public key of peer to replace
            new_peer_block: New [Peer] block to insert

        Returns:
            True if successful
        """
        try:
            with SSHClient(
                self.host,
                self.user,
                self.ssh_config['key_path'],
                self.port
            ) as ssh:
                if not ssh.client:
                    return False

                # Read current config
                config_text = ssh.read_file(self.config_path, use_sudo=True)

                if not config_text:
                    return False

                # Remove old peer block
                new_config = self._remove_peer_from_config(config_text, old_public_key)

                # Append new peer block
                new_config = new_config.rstrip() + '\n\n' + new_peer_block + '\n'

                # Write back to coordinator
                if not ssh.write_file(self.config_path, new_config, use_sudo=True, mode="600"):
                    return False

                # Restart WireGuard
                if not ssh.restart_wireguard(self.interface):
                    return False

                logger.info(f"Updated peer in coordinator config and restarted WireGuard")
                return True

        except Exception as e:
            logger.error(f"Failed to update peer in config: {e}")
            return False

    def revoke_peer(
        self,
        public_key: str,
        peer_name: Optional[str] = None
    ) -> bool:
        """
        Revoke a peer by removing it from coordinator's wg0.conf

        Args:
            public_key: Public key of peer to revoke
            peer_name: Optional name for logging

        Returns:
            True if successful
        """
        try:
            with SSHClient(
                self.host,
                self.user,
                self.ssh_config['key_path'],
                self.port
            ) as ssh:
                if not ssh.client:
                    logger.error("Failed to connect to coordinator")
                    return False

                # Read current config
                config_text = ssh.read_file(self.config_path, use_sudo=True)

                if not config_text:
                    logger.error("Failed to read config")
                    return False

                # Remove peer block
                new_config = self._remove_peer_from_config(config_text, public_key)

                # Check if anything changed
                if new_config == config_text:
                    logger.warning(f"Peer not found in config: {public_key[:16]}...")
                    return False

                # Write back to coordinator
                if not ssh.write_file(self.config_path, new_config, use_sudo=True, mode="600"):
                    logger.error("Failed to write updated config")
                    return False

                # Restart WireGuard
                if not ssh.restart_wireguard(self.interface):
                    logger.error("Failed to restart WireGuard")
                    return False

                peer_display = peer_name if peer_name else public_key[:16] + "..."
                logger.info(f"Revoked peer '{peer_display}' from coordinator")
                return True

        except Exception as e:
            logger.error(f"Failed to revoke peer: {e}")
            return False

    def _remove_peer_from_config(self, config_text: str, public_key: str) -> str:
        """Remove a peer block from config by public key"""
        lines = config_text.split('\n')
        new_lines = []
        in_peer_block = False
        skip_peer = False

        for line in lines:
            if line.strip().startswith('[Peer]'):
                in_peer_block = True
                skip_peer = False
                peer_start_line = line

            elif in_peer_block and line.strip().startswith('PublicKey'):
                # Check if this is the peer to remove
                peer_key = line.split('=')[1].strip()
                if peer_key == public_key:
                    skip_peer = True
                else:
                    # Add the [Peer] line for peers we're keeping
                    new_lines.append(peer_start_line)
                    new_lines.append(line)

            elif in_peer_block and (line.strip() == '' or line.strip().startswith('[')):
                # End of peer block
                in_peer_block = False
                if not skip_peer:
                    new_lines.append(line)

            elif not (in_peer_block and skip_peer):
                # Add lines that aren't part of the removed peer
                new_lines.append(line)

        return '\n'.join(new_lines)

    def add_peer_to_config(self, peer_block: str) -> bool:
        """
        Add a new peer to coordinator config

        Args:
            peer_block: Complete [Peer] block to add

        Returns:
            True if successful
        """
        try:
            with SSHClient(
                self.host,
                self.user,
                self.ssh_config['key_path'],
                self.port
            ) as ssh:
                if not ssh.client:
                    return False

                # Read current config
                config_text = ssh.read_file(self.config_path, use_sudo=True)

                if config_text is None:
                    return False

                # Append new peer
                new_config = config_text.rstrip() + '\n\n' + peer_block + '\n'

                # Write back
                if not ssh.write_file(self.config_path, new_config, use_sudo=True, mode="600"):
                    return False

                # Restart WireGuard
                if not ssh.restart_wireguard(self.interface):
                    return False

                logger.info("Added peer to coordinator config")
                return True

        except Exception as e:
            logger.error(f"Failed to add peer: {e}")
            return False

    def export_coordinator_config(self, metadata_db, output_path: Path) -> bool:
        """
        Export full coordinator config with all active peers from database

        This generates a complete wg0.conf ready for deployment to the coordinator.
        It builds the Interface section from config.yaml (preserving PostUp/PostDown)
        and Peer blocks from the database.

        Args:
            metadata_db: MetadataDB instance with peer data
            output_path: Local path to save exported config

        Returns:
            True if successful
        """
        try:
            # Build Interface section from config.yaml
            interface_section = self._build_interface_section()

            # Get all active peers from database
            active_peers = metadata_db.get_active_peers()

            if not active_peers:
                logger.warning("No active peers found in database")

            # Build full config
            config_lines = [interface_section, ""]

            for peer in active_peers:
                # Build peer block
                peer_block = self._build_peer_block(peer)
                config_lines.append(peer_block)
                config_lines.append("")

            # Write to output file
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text('\n'.join(config_lines))
            output_path.chmod(0o600)

            logger.info(f"Exported coordinator config to {output_path}")
            logger.info(f"Included {len(active_peers)} active peers")
            return True

        except Exception as e:
            logger.error(f"Failed to export coordinator config: {e}")
            return False

    def _build_interface_section(self) -> str:
        """Build [Interface] section from config.yaml"""
        lines = ["[Interface]"]

        # Add Address
        ipv4 = self.coordinator['network']['ipv4']
        ipv6 = self.coordinator['network']['ipv6']
        lines.append(f"Address = {ipv4}")
        lines.append(f"Address = {ipv6}")

        # Add ListenPort
        listen_port = self.coordinator.get('listen_port', 51820)
        lines.append(f"ListenPort = {listen_port}")

        # Add MTU if specified
        mtu = self.coordinator.get('mtu', 1280)
        lines.append(f"MTU = {mtu}")

        # Add PrivateKey placeholder (should be manually set on server)
        lines.append("PrivateKey = <UPDATE_ON_SERVER>")
        lines.append("")

        # Add PostUp rules from config.yaml (PRESERVED FROM IMPORT!)
        postup_rules = self.coordinator.get('postup', [])
        if postup_rules:
            if isinstance(postup_rules, str):
                postup_rules = [postup_rules]
            for rule in postup_rules:
                lines.append(f"PostUp = {rule}")

        # Add PostDown rules from config.yaml (PRESERVED FROM IMPORT!)
        postdown_rules = self.coordinator.get('postdown', [])
        if postdown_rules:
            if isinstance(postdown_rules, str):
                postdown_rules = [postdown_rules]
            for rule in postdown_rules:
                lines.append(f"PostDown = {rule}")

        return '\n'.join(lines)

    def _extract_interface_section(self, config_text: str) -> str:
        """Extract [Interface] section from config (legacy method)"""
        lines = []
        in_interface = False

        for line in config_text.split('\n'):
            if line.strip().startswith('[Interface]'):
                in_interface = True
                lines.append(line)
            elif in_interface:
                if line.strip().startswith('[Peer]'):
                    # End of Interface section
                    break
                lines.append(line)

        return '\n'.join(lines).rstrip()

    def _build_peer_block(self, peer: Dict) -> str:
        """Build [Peer] block from database peer record"""
        name = peer.get('name', 'unknown')
        public_key = peer.get('public_key', '')
        allowed_ips = peer.get('allowed_ips', '')
        comment = peer.get('comment', '')
        created_at = peer.get('created_at', '')

        # Format creation date
        date_str = created_at.split('T')[0] if 'T' in created_at else created_at.split()[0]

        # Build comment line
        if comment:
            comment_line = f"# {name} - {comment} (added {date_str})"
        else:
            comment_line = f"# {name} (added {date_str})"

        # Build peer block
        lines = [
            comment_line,
            "[Peer]",
            f"PublicKey = {public_key}",
            f"AllowedIPs = {allowed_ips}"
        ]

        return '\n'.join(lines)
