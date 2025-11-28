"""Raw block extraction and structured data parsing for WireGuard configs"""

import logging
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class RawInterfaceBlock:
    """Raw Interface block with structured data extracted"""
    raw_text: str  # EXACT text from file
    # Structured data extracted for logic
    addresses: List[str]  # e.g., ["10.20.0.1/24", "fd20::1/64"]
    private_key: Optional[str]
    listen_port: Optional[int]
    mtu: Optional[int]
    postup_rules: List[str]
    postdown_rules: List[str]


@dataclass
class RawPeerBlock:
    """Raw Peer block with structured data extracted"""
    raw_text: str  # EXACT text from file
    # Structured data extracted for logic
    public_key: str
    preshared_key: Optional[str]
    allowed_ips: str  # e.g., "10.20.0.20/32, 192.168.12.0/24, fd20::20/128"
    endpoint: Optional[str]
    persistent_keepalive: Optional[int]
    comment_lines: List[str]  # Multi-line comments preserved


@dataclass
class ParsedWireGuardConfig:
    """Complete parsed WireGuard configuration"""
    file_path: Path
    interface: RawInterfaceBlock
    peers: List[RawPeerBlock]


class RawBlockParser:
    """Parser that extracts raw blocks + structured data"""

    def parse_file(self, config_path: Path) -> ParsedWireGuardConfig:
        """Parse WireGuard config file"""
        with open(config_path, 'r') as f:
            content = f.read()

        interface = self._extract_interface_block(content)
        peers = self._extract_peer_blocks(content)

        return ParsedWireGuardConfig(
            file_path=config_path,
            interface=interface,
            peers=peers
        )

    def _extract_interface_block(self, content: str) -> RawInterfaceBlock:
        """Extract raw Interface block and parse structured data"""
        lines = content.split('\n')

        # Find Interface section start
        interface_start = None
        for i, line in enumerate(lines):
            if line.strip().startswith('[Interface]'):
                interface_start = i
                break

        if interface_start is None:
            raise ValueError("No [Interface] section found")

        # Find where Interface section ends (first [Peer] or EOF)
        interface_end = len(lines)
        for i in range(interface_start + 1, len(lines)):
            if lines[i].strip().startswith('[Peer]'):
                interface_end = i
                break

        # Extract raw text (including [Interface] header)
        raw_lines = lines[interface_start:interface_end]
        raw_text = '\n'.join(raw_lines).rstrip()

        # Parse structured data
        addresses = []
        private_key = None
        listen_port = None
        mtu = None
        postup_rules = []
        postdown_rules = []

        for line in raw_lines[1:]:  # Skip [Interface] header
            line_stripped = line.strip()

            if not line_stripped or line_stripped.startswith('#'):
                continue

            if '=' not in line_stripped:
                continue

            key, value = line_stripped.split('=', 1)
            key = key.strip()
            value = value.strip()

            if key == 'Address':
                addresses.append(value)
            elif key == 'PrivateKey':
                private_key = value
            elif key == 'ListenPort':
                listen_port = int(value)
            elif key == 'MTU':
                mtu = int(value)
            elif key == 'PostUp':
                postup_rules.append(value)
            elif key == 'PostDown':
                postdown_rules.append(value)

        return RawInterfaceBlock(
            raw_text=raw_text,
            addresses=addresses,
            private_key=private_key,
            listen_port=listen_port,
            mtu=mtu,
            postup_rules=postup_rules,
            postdown_rules=postdown_rules
        )

    def _extract_peer_blocks(self, content: str) -> List[RawPeerBlock]:
        """Extract raw Peer blocks and parse structured data"""
        lines = content.split('\n')
        peers = []

        # Find all [Peer] section starts
        peer_starts = []
        for i, line in enumerate(lines):
            if line.strip().startswith('[Peer]'):
                peer_starts.append(i)

        if not peer_starts:
            return []

        # Extract each peer block
        for i, start in enumerate(peer_starts):
            # Determine end of this peer block (next [Peer] or EOF)
            if i + 1 < len(peer_starts):
                end = peer_starts[i + 1]
            else:
                end = len(lines)

            # Extract raw text
            raw_lines = lines[start:end]
            raw_text = '\n'.join(raw_lines).rstrip()

            # Parse structured data
            public_key = None
            preshared_key = None
            allowed_ips = None
            endpoint = None
            persistent_keepalive = None
            comment_lines = []

            for line in raw_lines[1:]:  # Skip [Peer] header
                line_stripped = line.strip()

                if not line_stripped:
                    continue

                if line_stripped.startswith('#'):
                    comment = line_stripped.lstrip('#').strip()
                    if comment:  # Don't add empty comments
                        comment_lines.append(comment)
                    continue

                if '=' not in line_stripped:
                    continue

                key, value = line_stripped.split('=', 1)
                key = key.strip()
                value = value.strip()

                if key == 'PublicKey':
                    public_key = value
                elif key == 'PresharedKey':
                    preshared_key = value
                elif key == 'AllowedIPs':
                    allowed_ips = value
                elif key == 'Endpoint':
                    endpoint = value
                elif key == 'PersistentKeepalive':
                    persistent_keepalive = int(value)

            if public_key:  # Valid peer must have PublicKey
                peers.append(RawPeerBlock(
                    raw_text=raw_text,
                    public_key=public_key,
                    preshared_key=preshared_key,
                    allowed_ips=allowed_ips or '',
                    endpoint=endpoint,
                    persistent_keepalive=persistent_keepalive,
                    comment_lines=comment_lines
                ))

        return peers


class ConfigDetector:
    """Detect configuration type"""

    @staticmethod
    def detect_type(parsed: ParsedWireGuardConfig) -> str:
        """
        Detect config type: coordination_server, subnet_router, or client

        Priority:
        1. Peer count: 3+ peers = coordination_server
        2. Forwarding rules: PostUp with iptables FORWARD = coordination_server or subnet_router
        3. Endpoint presence: Has endpoint = client
        """
        peer_count = len(parsed.peers)
        interface = parsed.interface

        # Check for forwarding rules in PostUp
        has_forwarding = False
        for rule in interface.postup_rules:
            if 'FORWARD' in rule or 'POSTROUTING' in rule:
                has_forwarding = True
                break

        # Detection logic
        if peer_count >= 3:
            return 'coordination_server'
        elif has_forwarding:
            # Could be coordination_server or subnet_router
            # If it has peers with /24 or /64 networks (not just /32 or /128), likely subnet_router
            # But for simplicity, if peer_count < 3, assume subnet_router
            if peer_count == 1:
                return 'subnet_router'
            else:
                return 'coordination_server'
        elif peer_count == 1 and parsed.peers[0].endpoint:
            return 'client'
        elif peer_count == 1:
            # Single peer, no endpoint = probably subnet_router
            return 'subnet_router'
        else:
            return 'client'


class StructuredDataExtractor:
    """Extract structured data for specific use cases"""

    @staticmethod
    def extract_network_info(interface: RawInterfaceBlock) -> Dict:
        """Extract network information from Interface"""
        # Parse addresses to get network ranges
        ipv4_address = None
        ipv6_address = None
        network_ipv4 = None
        network_ipv6 = None

        for addr in interface.addresses:
            if '.' in addr:  # IPv4
                # e.g., "10.20.0.1/24" -> address=10.20.0.1, network=10.20.0.0/24
                parts = addr.split('/')
                ipv4_address = parts[0]
                if len(parts) > 1:
                    prefix = parts[1]
                    # Convert to network (simple approach - assumes last octet is 0 for /24)
                    octets = ipv4_address.split('.')
                    if prefix == '24':
                        network_ipv4 = f"{octets[0]}.{octets[1]}.{octets[2]}.0/{prefix}"
                    elif prefix == '32':
                        network_ipv4 = addr
                    else:
                        network_ipv4 = addr  # Keep as-is for other prefixes
            elif ':' in addr:  # IPv6
                # e.g., "fd20::1/64" -> address=fd20::1, network=fd20::/64
                parts = addr.split('/')
                ipv6_address = parts[0]
                if len(parts) > 1:
                    prefix = parts[1]
                    # Extract network prefix (everything before last ::)
                    if '::' in ipv6_address:
                        network_part = ipv6_address.split('::')[0]
                        network_ipv6 = f"{network_part}::/{prefix}"
                    else:
                        network_ipv6 = addr

        return {
            'ipv4_address': ipv4_address,
            'ipv6_address': ipv6_address,
            'network_ipv4': network_ipv4,
            'network_ipv6': network_ipv6,
        }

    @staticmethod
    def extract_peer_addresses(peer: RawPeerBlock) -> Dict:
        """Extract IPv4/IPv6 addresses from peer AllowedIPs"""
        ipv4_address = None
        ipv6_address = None

        # Parse AllowedIPs to find /32 (IPv4) and /128 (IPv6)
        for allowed_ip in peer.allowed_ips.split(','):
            allowed_ip = allowed_ip.strip()
            if allowed_ip.endswith('/32'):
                # IPv4 address
                ipv4_address = allowed_ip.replace('/32', '')
            elif allowed_ip.endswith('/128'):
                # IPv6 address
                ipv6_address = allowed_ip.replace('/128', '')

        return {
            'ipv4_address': ipv4_address,
            'ipv6_address': ipv6_address,
        }

    @staticmethod
    def extract_lan_networks(peer: RawPeerBlock) -> List[str]:
        """Extract LAN networks from peer AllowedIPs (not /32 or /128)"""
        lan_networks = []

        for allowed_ip in peer.allowed_ips.split(','):
            allowed_ip = allowed_ip.strip()
            # Skip /32 and /128 (those are individual addresses, not networks)
            if allowed_ip.endswith('/32') or allowed_ip.endswith('/128'):
                continue
            # Skip common VPN networks - check if it's a /24 or /64 CIDR
            # This heuristic assumes VPN network is the /24 or /64, LAN networks have different sizes
            if '/24' in allowed_ip or '/64' in allowed_ip:
                continue
            if allowed_ip:
                lan_networks.append(allowed_ip)

        return lan_networks

    @staticmethod
    def derive_public_key_from_private(private_key: str) -> str:
        """Derive public key from private key using wg command"""
        import subprocess
        try:
            # wg pubkey reads from stdin and outputs to stdout
            result = subprocess.run(
                ['wg', 'pubkey'],
                input=private_key.strip() + '\n',
                capture_output=True,
                text=True,
                check=True
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to derive public key: {e}")
            raise
        except FileNotFoundError:
            logger.error("'wg' command not found - is WireGuard installed?")
            raise
