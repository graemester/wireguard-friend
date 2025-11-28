"""WireGuard configuration builder using templates"""

import logging
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict
from .templates import get_client_template, get_coordinator_peer_template
from .keygen import generate_keypair, derive_public_key


logger = logging.getLogger(__name__)


class WireGuardConfigBuilder:
    """Builder for WireGuard client configurations"""

    def __init__(self, config: Dict):
        """
        Initialize with configuration

        Args:
            config: Loaded config.yaml as dictionary
        """
        self.coordinator = config['coordinator']
        self.peer_templates = config['peer_templates']
        self.ip_allocation = config.get('ip_allocation', {})

    def build_client_config(
        self,
        client_name: str,
        client_ipv4: str,
        client_ipv6: str,
        peer_type: str = "mobile_client",
        private_key: Optional[str] = None,
        public_key: Optional[str] = None,
        custom_allowed_ips: Optional[str] = None,
        comment: Optional[str] = None
    ) -> Dict:
        """
        Build a complete WireGuard client configuration

        Args:
            client_name: Name for this client (e.g., "iphone-alice")
            client_ipv4: IPv4 address for client (e.g., "10.20.0.50")
            client_ipv6: IPv6 address for client (e.g., "fd20::50")
            peer_type: Template type (mobile_client, mesh_only, restricted_external, server_peer)
            private_key: Use existing private key, or None to generate
            public_key: Use existing public key, or None to derive/generate
            custom_allowed_ips: Custom AllowedIPs (overrides template)
            comment: Optional comment for this client

        Returns:
            Dictionary with 'client_config', 'coordinator_peer', 'metadata'
        """
        # Get peer template settings
        if peer_type not in self.peer_templates:
            logger.warning(f"Unknown peer type '{peer_type}', using 'mobile_client'")
            peer_type = "mobile_client"

        template = self.peer_templates[peer_type]

        # Generate or validate keys
        if private_key is None:
            logger.info(f"Generating new keypair for {client_name}")
            private_key, public_key = generate_keypair()
        elif public_key is None:
            # Derive public key from provided private key
            public_key = derive_public_key(private_key)

        # Determine AllowedIPs
        if custom_allowed_ips:
            allowed_ips = custom_allowed_ips
        else:
            allowed_ips = ', '.join(template['allowed_ips'])

        # Build client config using template
        client_config = get_client_template(
            address_ipv4=f"{client_ipv4}/24",
            address_ipv6=f"{client_ipv6}/64",
            private_key=private_key,
            dns=template.get('dns', self.coordinator.get('coordinator_ip', {}).get('ipv4', '10.20.0.1')),
            peer_public_key=self.coordinator['public_key'],
            peer_endpoint=self.coordinator['endpoint'],
            peer_allowed_ips=allowed_ips,
            persistent_keepalive=template.get('persistent_keepalive', 25),
            mtu=template.get('mtu', 1280),
        )

        # Build coordinator peer entry
        timestamp = datetime.now().strftime("%Y-%m-%d")
        peer_comment = comment or f"{client_name} (added {timestamp})"

        coordinator_peer = get_coordinator_peer_template(
            client_name=client_name,
            public_key=public_key,
            allowed_ip_v4=f"{client_ipv4}/32",
            allowed_ip_v6=f"{client_ipv6}/128",
            comment=peer_comment,
        )

        metadata = {
            'name': client_name,
            'ipv4': client_ipv4,
            'ipv6': client_ipv6,
            'public_key': public_key,
            'private_key': private_key,
            'peer_type': peer_type,
            'allowed_ips': allowed_ips,
            'comment': peer_comment,
            'created_at': datetime.now().isoformat(),
        }

        logger.info(f"Built WireGuard config for {client_name} (type: {peer_type})")

        return {
            'client_config': client_config,
            'coordinator_peer': coordinator_peer,
            'metadata': metadata,
        }

    def save_client_config(
        self,
        client_name: str,
        client_config: str,
        output_dir: Path
    ) -> Path:
        """
        Save client config to file

        Args:
            client_name: Client name
            client_config: Config text
            output_dir: Output directory

        Returns:
            Path to saved config file
        """
        output_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        config_file = output_dir / f"{client_name}-{timestamp}.conf"

        with open(config_file, 'w') as f:
            f.write(client_config)

        # Set restrictive permissions (600 - owner read/write only)
        config_file.chmod(0o600)

        logger.info(f"Saved client config to {config_file}")
        return config_file

    def ipv6_from_ipv4(self, ipv4: str) -> str:
        """
        Derive IPv6 address from IPv4

        Args:
            ipv4: IPv4 address (e.g., "10.20.0.50")

        Returns:
            Corresponding IPv6 address (e.g., "fd20::50")
        """
        # Extract last octet from IPv4
        last_octet = ipv4.split('.')[-1]

        # Build IPv6 using coordinator network prefix
        ipv6_base = self.coordinator['network']['ipv6'].split('/')[0].rstrip(':')
        ipv6 = f"{ipv6_base}:{last_octet}"

        logger.debug(f"Derived IPv6 {ipv6} from IPv4 {ipv4}")
        return ipv6
