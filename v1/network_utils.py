"""
Network Utilities

Helper functions for network operations.
"""

import socket
from typing import List


def is_local_host(host: str) -> bool:
    """
    Check if a hostname/IP refers to the local machine.

    Args:
        host: Hostname or IP address

    Returns:
        True if host is the local machine

    Examples:
        >>> is_local_host('localhost')
        True
        >>> is_local_host('127.0.0.1')
        True
        >>> is_local_host('example.com')
        False
    """
    try:
        # Check for localhost variants
        if host in ['localhost', '127.0.0.1', '::1']:
            return True

        # Get local hostname
        local_hostname = socket.gethostname()
        local_fqdn = socket.getfqdn()

        if host in [local_hostname, local_fqdn]:
            return True

        # Compare IP addresses
        try:
            host_ip = socket.gethostbyname(host)
            local_ip = socket.gethostbyname(local_hostname)

            if host_ip == local_ip:
                return True

            # Check if it's a local IP (127.x.x.x)
            if host_ip.startswith('127.'):
                return True

        except socket.error:
            pass

        return False

    except Exception:
        return False


def get_local_ips() -> List[str]:
    """
    Get all local IP addresses.

    Returns:
        List of local IP addresses
    """
    ips = []

    try:
        # Get hostname
        hostname = socket.gethostname()

        # Get all addresses for hostname
        addr_info = socket.getaddrinfo(hostname, None)

        for info in addr_info:
            ip = info[4][0]
            if ip not in ips:
                ips.append(ip)

    except Exception:
        pass

    # Always include localhost
    if '127.0.0.1' not in ips:
        ips.append('127.0.0.1')

    return ips


if __name__ == '__main__':
    """Test the utilities"""
    print("Local hostname:", socket.gethostname())
    print("Local FQDN:", socket.getfqdn())
    print("Local IPs:", get_local_ips())
    print()

    # Test localhost detection
    test_hosts = ['localhost', '127.0.0.1', '::1', socket.gethostname(), 'google.com']

    for host in test_hosts:
        result = is_local_host(host)
        print(f"is_local_host('{host}'): {result}")
