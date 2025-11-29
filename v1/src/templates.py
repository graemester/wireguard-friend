"""WireGuard configuration templates"""

from typing import Optional


def get_client_template(
    address_ipv4: str,
    address_ipv6: str,
    private_key: str,
    dns: str,
    peer_public_key: str,
    peer_endpoint: str,
    peer_allowed_ips: str,
    persistent_keepalive: int = 25,
    mtu: int = 1280,
) -> str:
    """
    Generate WireGuard client configuration

    Args:
        address_ipv4: Client IPv4 address with CIDR (e.g., "10.20.0.50/24")
        address_ipv6: Client IPv6 address with CIDR (e.g., "fd20::50/64")
        private_key: Client private key
        dns: DNS server (e.g., "192.168.10.20" for Pi-hole)
        peer_public_key: Coordinator public key
        peer_endpoint: Coordinator endpoint (e.g., "your.vpshost.com:51820")
        peer_allowed_ips: Allowed IPs for routing
        persistent_keepalive: Keepalive interval in seconds
        mtu: MTU size (default 1280 for mobile compatibility)

    Returns:
        Complete WireGuard client config text
    """
    config = f"""[Interface]
Address = {address_ipv4}, {address_ipv6}
PrivateKey = {private_key}
DNS = {dns}
MTU = {mtu}

[Peer]
PublicKey = {peer_public_key}
Endpoint = {peer_endpoint}
AllowedIPs = {peer_allowed_ips}
PersistentKeepalive = {persistent_keepalive}
"""
    return config


def get_coordinator_peer_template(
    client_name: str,
    public_key: str,
    allowed_ip_v4: str,
    allowed_ip_v6: str,
    comment: Optional[str] = None,
) -> str:
    """
    Generate peer block to add to coordinator

    Args:
        client_name: Name of the client
        public_key: Client's public key
        allowed_ip_v4: IPv4 with /32 CIDR (e.g., "10.20.0.50/32")
        allowed_ip_v6: IPv6 with /128 CIDR (e.g., "fd20::50/128")
        comment: Optional comment

    Returns:
        Peer block text to add to coordinator's wg0.conf
    """
    from datetime import datetime

    if comment is None:
        comment = f"{client_name} (added {datetime.now().strftime('%Y-%m-%d')})"

    peer_block = f"""[Peer]  # {comment}
PublicKey = {public_key}
AllowedIPs = {allowed_ip_v4}, {allowed_ip_v6}
"""
    return peer_block
