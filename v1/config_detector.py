"""
Config Type Detection

Detect whether a WireGuard config is a coordination server, subnet router, or client.
Uses v1's proven detection logic.
"""

from pathlib import Path
from typing import Tuple, Optional
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

from v1.entity_parser import EntityParser, RawEntity


class ConfigDetector:
    """Detect configuration type based on config structure"""

    def __init__(self):
        self.parser = EntityParser()

    def detect_type(self, config_path: Path) -> Tuple[str, int]:
        """
        Detect config type: coordination_server, subnet_router, or client

        Priority (from v1):
        1. Peer count: 3+ peers = coordination_server
        2. Forwarding rules: PostUp with iptables FORWARD = coordination_server or subnet_router
        3. Endpoint presence: Has endpoint = client

        Args:
            config_path: Path to WireGuard config file

        Returns:
            (config_type, peer_count)
            config_type is one of: 'coordination_server', 'subnet_router', 'client'
        """
        entities = self.parser.parse_file(config_path)

        if not entities:
            raise ValueError(f"No entities found in {config_path}")

        # First entity should be [Interface]
        interface = entities[0]
        if not any('[Interface]' in line for line in interface.lines):
            raise ValueError(f"First entity is not [Interface] in {config_path}")

        # Count peers
        peers = entities[1:]
        peer_count = len(peers)

        # Extract PostUp rules from Interface
        postup_rules = []
        for line in interface.lines:
            stripped = line.strip()
            if stripped.startswith('PostUp'):
                # Extract value after '='
                if '=' in stripped:
                    value = stripped.split('=', 1)[1].strip()
                    postup_rules.append(value)

        # Check for forwarding rules
        has_forwarding = False
        for rule in postup_rules:
            if 'FORWARD' in rule or 'POSTROUTING' in rule:
                has_forwarding = True
                break

        # Check if first peer has endpoint (for client detection)
        first_peer_has_endpoint = False
        if peers:
            for line in peers[0].lines:
                stripped = line.strip()
                if stripped.startswith('Endpoint'):
                    first_peer_has_endpoint = True
                    break

        # Detection logic (from v1)
        if peer_count >= 3:
            return 'coordination_server', peer_count
        elif has_forwarding:
            # Could be coordination_server or subnet_router
            if peer_count == 1:
                return 'subnet_router', peer_count
            else:
                return 'coordination_server', peer_count
        elif peer_count == 1 and first_peer_has_endpoint:
            return 'client', peer_count
        elif peer_count == 1:
            # Single peer, no endpoint = probably subnet_router
            return 'subnet_router', peer_count
        else:
            return 'client', peer_count


def detect_config_type(config_path: Path) -> str:
    """
    Helper function to detect config type.

    Args:
        config_path: Path to WireGuard config file

    Returns:
        'coordination_server', 'subnet_router', or 'client'
    """
    detector = ConfigDetector()
    config_type, _ = detector.detect_type(config_path)
    return config_type


if __name__ == '__main__':
    """Test the detector"""
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('config', help='Config file to analyze')
    args = parser.parse_args()

    config_path = Path(args.config)
    if not config_path.exists():
        print(f"Error: {config_path} not found")
        sys.exit(1)

    detector = ConfigDetector()
    config_type, peer_count = detector.detect_type(config_path)

    print(f"Config: {config_path.name}")
    print(f"Type: {config_type}")
    print(f"Peers: {peer_count}")
