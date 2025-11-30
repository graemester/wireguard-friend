"""
SSH Setup Wizard

Interactive wizard to set up SSH key authentication for WireGuard servers.
Helps users configure passwordless SSH access to coordination server and subnet routers.
"""

import sys
import subprocess
from pathlib import Path
from typing import List, Dict, Optional

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from v1.schema_semantic import WireGuardDBv2
from v1.network_utils import is_local_host


def prompt_yes_no(question: str, default: bool = False) -> bool:
    """Prompt for yes/no"""
    default_str = "Y/n" if default else "y/N"
    response = input(f"{question} [{default_str}]: ").strip().lower()

    if not response:
        return default
    return response in ('y', 'yes')


def check_ssh_key() -> Optional[Path]:
    """
    Check if SSH key exists.

    Returns:
        Path to private key if it exists, None otherwise
    """
    ssh_dir = Path.home() / '.ssh'
    common_keys = ['id_rsa', 'id_ed25519', 'id_ecdsa']

    for key_name in common_keys:
        private_key = ssh_dir / key_name
        if private_key.exists():
            return private_key

    return None


def generate_ssh_key(key_type: str = 'ed25519') -> Optional[Path]:
    """
    Generate SSH keypair.

    Args:
        key_type: Type of key (ed25519, rsa, ecdsa)

    Returns:
        Path to private key if successful, None otherwise
    """
    ssh_dir = Path.home() / '.ssh'
    ssh_dir.mkdir(mode=0o700, exist_ok=True)

    key_path = ssh_dir / f'id_{key_type}'

    print(f"\nGenerating {key_type.upper()} keypair...")
    print(f"  Location: {key_path}")
    print()

    try:
        cmd = [
            'ssh-keygen',
            '-t', key_type,
            '-f', str(key_path),
            '-N', '',  # No passphrase
            '-C', f'wireguard-friend-{key_type}'
        ]

        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode != 0:
            print(f"Error generating SSH key: {result.stderr}")
            return None

        print(f"✓ SSH keypair generated: {key_path}")
        return key_path

    except FileNotFoundError:
        print("Error: ssh-keygen command not found")
        return None
    except Exception as e:
        print(f"Error: {e}")
        return None


def install_ssh_key(host: str, public_key_path: Path, user: str = 'root') -> bool:
    """
    Install SSH public key to remote host.

    Args:
        host: Hostname or IP
        public_key_path: Path to public key file
        user: SSH user

    Returns:
        True if successful, False otherwise
    """
    if not public_key_path.exists():
        print(f"Error: Public key not found: {public_key_path}")
        return False

    # Read public key
    public_key = public_key_path.read_text().strip()

    print(f"\nInstalling SSH key to {user}@{host}...")

    # Use ssh-copy-id if available
    try:
        result = subprocess.run(
            ['ssh-copy-id', '-i', str(public_key_path), f'{user}@{host}'],
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode == 0:
            print(f"✓ SSH key installed to {user}@{host}")
            return True
        else:
            print(f"Error: {result.stderr}")
            return False

    except FileNotFoundError:
        # Fallback: manual installation
        print("  ssh-copy-id not found, trying manual installation...")

        try:
            # Create .ssh directory and add key
            cmd = f'mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo "{public_key}" >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys'

            result = subprocess.run(
                ['ssh', f'{user}@{host}', cmd],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0:
                print(f"✓ SSH key installed to {user}@{host}")
                return True
            else:
                print(f"Error: {result.stderr}")
                return False

        except Exception as e:
            print(f"Error: {e}")
            return False

    except subprocess.TimeoutExpired:
        print("Error: SSH connection timed out")
        return False
    except Exception as e:
        print(f"Error: {e}")
        return False


def test_ssh_connection(host: str, user: str = 'root') -> bool:
    """
    Test SSH connection to host.

    Args:
        host: Hostname or IP
        user: SSH user

    Returns:
        True if connection successful, False otherwise
    """
    print(f"\nTesting SSH connection to {user}@{host}...")

    try:
        result = subprocess.run(
            ['ssh', '-o', 'ConnectTimeout=10', '-o', 'BatchMode=yes',
             f'{user}@{host}', 'echo "Connection successful"'],
            capture_output=True,
            text=True,
            timeout=15
        )

        if result.returncode == 0 and 'Connection successful' in result.stdout:
            print(f"✓ SSH connection to {user}@{host} successful")
            return True
        else:
            print(f"✗ SSH connection failed")
            print(f"  Error: {result.stderr}")
            return False

    except subprocess.TimeoutExpired:
        print(f"✗ SSH connection timed out")
        return False
    except Exception as e:
        print(f"✗ Error: {e}")
        return False


def run_ssh_setup_wizard(db: WireGuardDBv2, user: str = 'root') -> int:
    """
    Interactive SSH setup wizard.

    Args:
        db: Database connection
        user: SSH user for servers

    Returns:
        0 on success, 1 on error
    """
    print("\n" + "=" * 70)
    print("SSH SETUP WIZARD")
    print("=" * 70)
    print()
    print("This wizard will help you set up SSH key authentication to your")
    print("WireGuard servers (coordination server and subnet routers).")
    print()
    print("This allows wg-friend to deploy configs automatically without")
    print("prompting for passwords.")
    print()

    # Get servers from database
    servers = []

    with db._connection() as conn:
        cursor = conn.cursor()

        # Coordination server
        cursor.execute("""
            SELECT hostname, endpoint
            FROM coordination_server
        """)
        row = cursor.fetchone()
        if row:
            hostname, endpoint = row
            if endpoint and endpoint != 'UNKNOWN':
                servers.append(('Coordination Server', hostname, endpoint))

        # Subnet routers
        cursor.execute("""
            SELECT hostname, endpoint
            FROM subnet_router
            WHERE endpoint IS NOT NULL AND endpoint != ''
            ORDER BY hostname
        """)
        for hostname, endpoint in cursor.fetchall():
            servers.append(('Subnet Router', hostname, endpoint))

    if not servers:
        print("WARNING:  No servers with endpoints found in database.")
        print("Add servers with endpoints first, then run this wizard.")
        return 1

    # Filter out localhost servers (don't need SSH)
    remote_servers = []
    local_servers = []

    for server_type, hostname, endpoint in servers:
        host = endpoint.split(':')[0]
        if is_local_host(host):
            local_servers.append((server_type, hostname, endpoint))
        else:
            remote_servers.append((server_type, hostname, endpoint))

    if local_servers:
        print("Localhost servers (no SSH needed):")
        for server_type, hostname, endpoint in local_servers:
            print(f"  • {hostname} ({server_type}) - {endpoint}")
        print()

    if not remote_servers:
        print("✓ All servers are localhost - SSH setup not needed!")
        return 0

    print(f"Remote servers to configure ({len(remote_servers)}):")
    for server_type, hostname, endpoint in remote_servers:
        print(f"  • {hostname} ({server_type}) - {endpoint}")
    print()

    if not prompt_yes_no("Continue with SSH setup?", default=True):
        print("Cancelled.")
        return 0

    # Check for existing SSH key
    print("\n" + "─" * 70)
    print("Step 1: SSH Key")
    print("─" * 70)

    existing_key = check_ssh_key()

    if existing_key:
        print(f"\n✓ Found existing SSH key: {existing_key}")
        public_key_path = existing_key.with_suffix('.pub')

        if not public_key_path.exists():
            print(f"WARNING:  Public key not found: {public_key_path}")
            print("Generating new keypair...")
            private_key = generate_ssh_key()
            if not private_key:
                return 1
            public_key_path = private_key.with_suffix('.pub')
        else:
            private_key = existing_key

        if prompt_yes_no("Use this key?", default=True):
            pass
        else:
            print("\nGenerating new SSH key...")
            key_type = input("Key type [ed25519/rsa/ecdsa] (default: ed25519): ").strip() or 'ed25519'
            private_key = generate_ssh_key(key_type)
            if not private_key:
                return 1
            public_key_path = private_key.with_suffix('.pub')
    else:
        print("\nNo SSH key found. Let's generate one.")
        key_type = input("Key type [ed25519/rsa/ecdsa] (default: ed25519): ").strip() or 'ed25519'
        private_key = generate_ssh_key(key_type)
        if not private_key:
            return 1
        public_key_path = private_key.with_suffix('.pub')

    # Install keys to remote servers
    print("\n" + "─" * 70)
    print("Step 2: Install Keys to Servers")
    print("─" * 70)
    print()
    print("You'll be prompted for the server password for each host.")
    print("After installation, SSH will use key authentication (no password).")
    print()

    failed_servers = []

    for server_type, hostname, endpoint in remote_servers:
        host = endpoint.split(':')[0]

        print(f"\n• {hostname} ({host})")

        if not prompt_yes_no(f"  Install SSH key to {user}@{host}?", default=True):
            print("  Skipped.")
            continue

        success = install_ssh_key(host, public_key_path, user=user)
        if not success:
            failed_servers.append((hostname, host))

    # Test connections
    print("\n" + "─" * 70)
    print("Step 3: Test Connections")
    print("─" * 70)

    test_results = []

    for server_type, hostname, endpoint in remote_servers:
        host = endpoint.split(':')[0]
        success = test_ssh_connection(host, user=user)
        test_results.append((hostname, host, success))

    # Summary
    print("\n" + "=" * 70)
    print("SSH SETUP SUMMARY")
    print("=" * 70)

    successful = sum(1 for _, _, success in test_results if success)
    failed = len(test_results) - successful

    print(f"\nTotal servers: {len(remote_servers)}")
    print(f"Setup: {successful}")
    print(f"Failed: {failed}")
    print()

    if failed > 0:
        print("Failed servers:")
        for hostname, host, success in test_results:
            if not success:
                print(f"  • {hostname} ({host})")
        print()
        print("You can:")
        print("  1. Check that SSH is enabled on the server")
        print("  2. Verify the hostname/IP is correct")
        print("  3. Run this wizard again")
        print()

    if successful == len(remote_servers):
        print("✓ All servers configured")
        print()
        print("You can now deploy configs without passwords:")
        print("  wg-friend deploy")
        print()

    return 0 if failed == 0 else 1


def ssh_setup(args) -> int:
    """CLI handler for 'wg-friend ssh-setup' command"""
    db = WireGuardDBv2(args.db)
    user = getattr(args, 'user', 'root')

    return run_ssh_setup_wizard(db, user=user)


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('--db', default='wireguard.db')
    parser.add_argument('--user', default='root', help='SSH user for servers')

    args = parser.parse_args()
    sys.exit(ssh_setup(args))
