#!/usr/bin/env python3
"""
wg-friend-deploy.py - Automated WireGuard config deployment

Securely deploys updated WireGuard configurations to coordinator and subnet router.
Automatically detects local vs remote hosts and deploys accordingly!

Usage:
    ./wg-friend-deploy.py --setup              # One-time SSH key setup
    ./wg-friend-deploy.py                      # Deploy to both endpoints
    sudo ./wg-friend-deploy.py                 # Deploy if running on coordinator/subnet
    ./wg-friend-deploy.py --coordinator-only   # Deploy to coordinator only
    ./wg-friend-deploy.py --subnet-only        # Deploy to subnet router only
    ./wg-friend-deploy.py --dry-run            # Show what would be deployed
    ./wg-friend-deploy.py --no-restart         # Upload only, skip restart

Local vs Remote Detection:
    - If running ON coordinator/subnet router: Uses local deployment (requires sudo)
    - If running from another machine: Uses SSH deployment (no sudo needed)
    - Hybrid mode: Local for one, SSH for the other (mixed environments)
"""

import argparse
import getpass
import os
import shutil
import socket
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, Tuple

import paramiko
import yaml
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table

console = Console()


class DeploymentError(Exception):
    """Raised when deployment fails"""
    pass


def is_local_host(host: str) -> bool:
    """
    Detect if we're running on the specified host

    Checks:
    - Exact hostname match
    - Localhost/127.0.0.1 variants
    - Local IP addresses

    Args:
        host: Hostname or IP to check

    Returns:
        True if host is the local machine
    """
    try:
        # Get current hostname
        local_hostname = socket.gethostname()
        local_fqdn = socket.getfqdn()

        # Check for exact match
        if host in [local_hostname, local_fqdn]:
            return True

        # Check for localhost variants
        if host in ['localhost', '127.0.0.1', '::1']:
            return True

        # Check local IP addresses
        try:
            host_ip = socket.gethostbyname(host)

            # Get all local IPs
            local_ips = []
            hostname = socket.gethostname()
            local_ips.append(socket.gethostbyname(hostname))

            # Try to get all network interfaces
            import netifaces
            for interface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(interface)
                if netifaces.AF_INET in addrs:
                    for addr in addrs[netifaces.AF_INET]:
                        local_ips.append(addr['addr'])

            if host_ip in local_ips:
                return True

        except (ImportError, socket.error):
            # netifaces not available or DNS lookup failed
            # Fall back to basic check
            try:
                # Try to resolve and compare
                host_ip = socket.gethostbyname(host)
                local_ip = socket.gethostbyname(socket.gethostname())
                if host_ip == local_ip:
                    return True
            except socket.error:
                pass

        return False

    except Exception:
        return False


def check_sudo() -> bool:
    """Check if running with sudo/root privileges"""
    return os.geteuid() == 0


def deploy_locally(local_config: str, remote_path: str, interface: str,
                   dry_run: bool = False, restart: bool = True) -> bool:
    """
    Deploy config locally (no SSH needed)

    Must be run with sudo!

    Args:
        local_config: Path to local config file
        remote_path: Destination path (e.g., /etc/wireguard/wg0.conf)
        interface: WireGuard interface name
        dry_run: If True, only show what would be done
        restart: If True, restart WireGuard after deployment

    Returns:
        True if successful
    """
    try:
        console.print("[cyan]🏠 Deploying locally (no SSH needed)[/cyan]")

        if not check_sudo():
            console.print("[red]✗ Local deployment requires sudo privileges[/red]")
            console.print("[yellow]Run with: sudo ./wg-friend-deploy.py[/yellow]")
            return False

        if dry_run:
            console.print(f"[yellow]DRY RUN - Would deploy {local_config} → {remote_path}[/yellow]")
            return True

        # Backup existing config
        remote_path_obj = Path(remote_path)
        if remote_path_obj.exists():
            backup_path = f"{remote_path}.backup.{datetime.now().strftime('%Y%m%d-%H%M%S')}"
            shutil.copy2(remote_path, backup_path)
            console.print(f"[green]✓ Backed up to: {backup_path}[/green]")

        # Copy new config
        shutil.copy2(local_config, remote_path)
        os.chmod(remote_path, 0o600)
        console.print(f"[green]✓ Copied to: {remote_path}[/green]")

        # Restart WireGuard
        if restart:
            console.print(f"[cyan]🔄 Restarting wg-quick@{interface}...[/cyan]")
            result = subprocess.run(
                ['systemctl', 'restart', f'wg-quick@{interface}'],
                capture_output=True,
                text=True
            )

            if result.returncode == 0:
                console.print("[green]✓ WireGuard restarted[/green]")
            else:
                console.print(f"[red]✗ Restart failed: {result.stderr}[/red]")
                return False

            # Verify
            console.print(f"[cyan]🔍 Verifying WireGuard status...[/cyan]")
            result = subprocess.run(
                ['wg', 'show', interface],
                capture_output=True,
                text=True
            )

            if result.returncode == 0:
                console.print("[green]✓ WireGuard is running[/green]")
            else:
                console.print("[red]✗ WireGuard not running[/red]")
                return False

        return True

    except Exception as e:
        console.print(f"[red]✗ Local deployment failed: {e}[/red]")
        return False


def check_ip_forwarding(ssh: Optional[paramiko.SSHClient] = None) -> Tuple[bool, bool]:
    """
    Check if IP forwarding is enabled

    Args:
        ssh: SSH client for remote check, None for local

    Returns:
        (ipv4_enabled, ipv6_enabled)
    """
    try:
        if ssh:
            # Remote check
            stdin, stdout, stderr = ssh.exec_command("sysctl net.ipv4.ip_forward net.ipv6.conf.all.forwarding")
            output = stdout.read().decode()
        else:
            # Local check
            result = subprocess.run(
                ['sysctl', 'net.ipv4.ip_forward', 'net.ipv6.conf.all.forwarding'],
                capture_output=True,
                text=True
            )
            output = result.stdout

        ipv4_enabled = 'net.ipv4.ip_forward = 1' in output
        ipv6_enabled = 'net.ipv6.conf.all.forwarding = 1' in output

        return ipv4_enabled, ipv6_enabled

    except Exception:
        return False, False


def enable_ip_forwarding(ssh: Optional[paramiko.SSHClient] = None) -> bool:
    """
    Enable IP forwarding (runtime + persistent)

    Args:
        ssh: SSH client for remote enable, None for local

    Returns:
        True if successful
    """
    try:
        console.print("[cyan]🔧 Enabling IP forwarding...[/cyan]")

        # Commands to run
        commands = [
            # Enable runtime
            "sysctl -w net.ipv4.ip_forward=1",
            "sysctl -w net.ipv6.conf.all.forwarding=1",
            # Make persistent
            "grep -q '^net.ipv4.ip_forward=1' /etc/sysctl.conf || echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf",
            "grep -q '^net.ipv6.conf.all.forwarding=1' /etc/sysctl.conf || echo 'net.ipv6.conf.all.forwarding=1' >> /etc/sysctl.conf",
        ]

        if ssh:
            # Remote execution
            for cmd in commands:
                stdin, stdout, stderr = ssh.exec_command(f"sudo {cmd}")
                exit_status = stdout.channel.recv_exit_status()
                if exit_status != 0:
                    console.print(f"[red]✗ Failed: {cmd}[/red]")
                    return False
        else:
            # Local execution (already have sudo)
            for cmd in commands:
                result = subprocess.run(
                    cmd,
                    shell=True,
                    capture_output=True,
                    text=True
                )
                if result.returncode != 0:
                    console.print(f"[red]✗ Failed: {cmd}[/red]")
                    return False

        console.print("[green]✓ IP forwarding enabled (runtime + persistent)[/green]")
        return True

    except Exception as e:
        console.print(f"[red]✗ Failed to enable IP forwarding: {e}[/red]")
        return False


def check_postup_rules(config_path: str, ssh: Optional[paramiko.SSHClient] = None) -> Tuple[bool, list]:
    """
    Check if PostUp/PostDown rules exist in WireGuard config

    Args:
        config_path: Path to wg0.conf
        ssh: SSH client for remote read, None for local

    Returns:
        (has_rules, rules_list)
    """
    try:
        if ssh:
            # Remote read
            stdin, stdout, stderr = ssh.exec_command(f"sudo cat {config_path}")
            config_text = stdout.read().decode()
        else:
            # Local read
            with open(config_path, 'r') as f:
                config_text = f.read()

        # Extract PostUp/PostDown lines
        rules = []
        for line in config_text.split('\n'):
            line = line.strip()
            if line.startswith('PostUp') or line.startswith('PostDown'):
                rules.append(line)

        has_rules = len(rules) > 0
        return has_rules, rules

    except Exception:
        return False, []


def configure_subnet_router_system(config: dict, key_manager: SSHKeyManager) -> bool:
    """
    Configure subnet router system settings (IP forwarding, PostUp rules)

    Args:
        config: Config dictionary
        key_manager: SSH key manager

    Returns:
        True if successful or skipped
    """
    subnet_config = config.get('subnet_router')
    if not subnet_config:
        return True

    host = subnet_config.get('host')
    port = subnet_config.get('port', 22)
    user = subnet_config.get('user', 'root')
    config_path = subnet_config.get('config_path', '/etc/wireguard/wg0.conf')

    console.print(Panel.fit(
        "[bold]Subnet Router System Configuration[/bold]\n\n"
        "Checking IP forwarding and routing rules...",
        border_style="cyan"
    ))

    # Check if local or remote
    is_local = is_local_host(host)
    ssh = None

    try:
        if not is_local:
            # Connect via SSH
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            private_key = paramiko.Ed25519Key.from_private_key_file(str(key_manager.private_key_path))
            ssh_client.connect(hostname=host, port=port, username=user, pkey=private_key, timeout=10)
            ssh = ssh_client

        # 1. Check PostUp/PostDown rules first
        has_rules, existing_rules = check_postup_rules(config_path, ssh)

        # Check if IP forwarding is handled in PostUp rules
        ipv4_in_postup = any('sysctl' in rule and 'ipv4.ip_forward' in rule for rule in existing_rules)
        ipv6_in_postup = any('sysctl' in rule and 'ipv6.conf.all.forwarding' in rule for rule in existing_rules)

        # Only check system-level if NOT in PostUp
        if ipv4_in_postup and ipv6_in_postup:
            console.print("[green]✓ IP forwarding configured in PostUp rules (best practice!)[/green]")
        else:
            # Check system-level sysctl
            ipv4_enabled, ipv6_enabled = check_ip_forwarding(ssh)

            if ipv4_enabled and ipv6_enabled:
                console.print("[green]✓ IP forwarding enabled at system level[/green]")
            elif ipv4_in_postup or ipv6_in_postup:
                console.print("[green]✓ IP forwarding partially in PostUp, partially system-level[/green]")
            else:
                console.print(f"[yellow]⚠ IP forwarding status:[/yellow]")
                console.print(f"  IPv4: {'enabled' if ipv4_enabled else 'DISABLED'}")
                console.print(f"  IPv6: {'enabled' if ipv6_enabled else 'DISABLED'}")
                console.print(f"\n[cyan]You can enable IP forwarding either:[/cyan]")
                console.print(f"  1. In PostUp rules (recommended - only active when VPN up)")
                console.print(f"  2. System-wide in /etc/sysctl.conf")

                choice = Prompt.ask("\nHow to enable", choices=['postup', 'system', 'skip'], default='postup')

                if choice == 'system':
                    if not enable_ip_forwarding(ssh):
                        console.print("[red]✗ Failed to enable IP forwarding[/red]")
                        if ssh:
                            ssh.close()
                        return False
                elif choice == 'postup':
                    console.print("[cyan]Will add IP forwarding to PostUp rules below...[/cyan]")
                    # This will be added with the MASQUERADE rules

        # 2. Check for routing rules (MASQUERADE, FORWARD, etc.)
        has_masquerade = any('MASQUERADE' in rule or 'FORWARD' in rule for rule in existing_rules)

        if has_rules:
            console.print(f"\n[green]✓ Found {len(existing_rules)} PostUp/PostDown rules in config:[/green]")
            for rule in existing_rules:
                console.print(f"  {rule}")

            if not Confirm.ask("\nAre these rules correct for your setup?", default=True):
                console.print("\n[yellow]⚠ Please manually edit the WireGuard config:[/yellow]")
                console.print(f"  Config: {config_path}")
                console.print("\n[cyan]Standard subnet router rules (example):[/cyan]")
                console.print("  PostUp = iptables -A FORWARD -i %i -j ACCEPT")
                console.print("  PostUp = iptables -A FORWARD -o %i -j ACCEPT")
                console.print("  PostUp = iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE")
                console.print("  PostDown = iptables -D FORWARD -i %i -j ACCEPT")
                console.print("  PostDown = iptables -D FORWARD -o %i -j ACCEPT")
                console.print("  PostDown = iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE")
                console.print("\n[yellow]Note: Replace 'eth0' with your WAN interface[/yellow]")
        elif not has_masquerade:
            console.print("\n[yellow]⚠ No routing rules (MASQUERADE/FORWARD) found in config[/yellow]")

            if Confirm.ask("\nAdd standard routing rules?", default=True):
                # Ask for WAN interface
                wan_interface = Prompt.ask("WAN interface name", default="eth0")

                # Build rules - include IP forwarding if needed
                rules_lines = ["# Routing rules (added by wg-friend)"]

                # Add IP forwarding if not already handled
                if not ipv4_in_postup and not ipv6_in_postup:
                    if not (ipv4_enabled and ipv6_enabled):
                        rules_lines.extend([
                            "# Enable IP forwarding",
                            "PostUp = sysctl -w net.ipv4.ip_forward=1",
                            "PostUp = sysctl -w net.ipv6.conf.all.forwarding=1",
                            ""
                        ])

                # Add forwarding and MASQUERADE rules
                rules_lines.extend([
                    "# Forwarding rules",
                    "PostUp = iptables -A FORWARD -i %i -j ACCEPT",
                    "PostUp = iptables -A FORWARD -o %i -j ACCEPT",
                    f"PostUp = iptables -t nat -A POSTROUTING -o {wan_interface} -j MASQUERADE",
                    "PostDown = iptables -D FORWARD -i %i -j ACCEPT",
                    "PostDown = iptables -D FORWARD -o %i -j ACCEPT",
                    f"PostDown = iptables -t nat -D POSTROUTING -o {wan_interface} -j MASQUERADE"
                ])

                rules_to_add = "\n".join(rules_lines) + "\n"

                console.print("\n[cyan]Will add these rules to [Interface] section:[/cyan]")
                console.print(rules_to_add)

                if Confirm.ask("\nProceed?", default=True):
                    try:
                        if ssh:
                            # Read config
                            stdin, stdout, stderr = ssh.exec_command(f"sudo cat {config_path}")
                            config_text = stdout.read().decode()

                            # Add rules after [Interface] section
                            lines = config_text.split('\n')
                            new_lines = []
                            for line in lines:
                                new_lines.append(line)
                                if line.strip() == '[Interface]' or (line.strip().startswith('PrivateKey') and '[Interface]' in '\n'.join(new_lines[-10:])):
                                    # Insert rules after Interface or PrivateKey (whichever comes last in Interface section)
                                    if '[Peer]' not in '\n'.join(lines[lines.index(line)+1:lines.index(line)+5]):
                                        continue
                                elif line.strip().startswith('[Peer]'):
                                    # Insert before first Peer
                                    new_lines.insert(-1, rules_to_add)
                                    break

                            new_config = '\n'.join(new_lines)

                            # Write back
                            temp_file = f"/tmp/wg-config-{datetime.now().strftime('%Y%m%d%H%M%S')}.conf"
                            sftp = ssh.open_sftp()
                            with sftp.file(temp_file, 'w') as f:
                                f.write(new_config)
                            sftp.close()

                            ssh.exec_command(f"sudo mv {temp_file} {config_path} && sudo chmod 600 {config_path}")
                            console.print("[green]✓ PostUp rules added to config[/green]")
                        else:
                            # Local edit
                            with open(config_path, 'r') as f:
                                config_text = f.read()

                            # Simple append before first [Peer]
                            if '[Peer]' in config_text:
                                config_text = config_text.replace('[Peer]', f"{rules_to_add}\n[Peer]", 1)
                            else:
                                config_text += rules_to_add

                            with open(config_path, 'w') as f:
                                f.write(config_text)
                            os.chmod(config_path, 0o600)
                            console.print("[green]✓ PostUp rules added to config[/green]")

                    except Exception as e:
                        console.print(f"[red]✗ Failed to add rules: {e}[/red]")
                        console.print("[yellow]Please add them manually[/yellow]")
            else:
                console.print("\n[yellow]⚠ Remember to add PostUp/PostDown rules manually for routing to work![/yellow]")

        if ssh:
            ssh.close()

        console.print("\n[bold green]✓ Subnet router system configuration complete![/bold green]")
        return True

    except Exception as e:
        console.print(f"[red]✗ System configuration failed: {e}[/red]")
        if ssh:
            try:
                ssh.close()
            except:
                pass
        return False


class SSHKeyManager:
    """Manages SSH key generation and installation for wg-friend"""

    def __init__(self, key_dir: Path):
        self.key_dir = key_dir
        self.key_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.private_key_path = self.key_dir / "wg-friend-deploy"
        self.public_key_path = self.key_dir / "wg-friend-deploy.pub"

    def key_exists(self) -> bool:
        """Check if SSH key already exists"""
        return self.private_key_path.exists() and self.public_key_path.exists()

    def generate_keypair(self) -> bool:
        """Generate new SSH keypair for wg-friend deployments"""
        try:
            console.print("\n[bold cyan]🔑 Generating SSH keypair for wg-friend...[/bold cyan]")

            # Use ssh-keygen for best compatibility
            cmd = [
                "ssh-keygen",
                "-t", "ed25519",
                "-f", str(self.private_key_path),
                "-N", "",  # No passphrase
                "-C", f"wg-friend-deploy@{datetime.now().strftime('%Y%m%d')}"
            ]

            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.returncode != 0:
                console.print(f"[red]✗ Failed to generate key: {result.stderr}[/red]")
                return False

            # Ensure correct permissions
            self.private_key_path.chmod(0o600)
            self.public_key_path.chmod(0o644)

            console.print(f"[green]✓ SSH keypair generated:[/green]")
            console.print(f"  Private: {self.private_key_path}")
            console.print(f"  Public:  {self.public_key_path}")

            return True

        except Exception as e:
            console.print(f"[red]✗ Error generating keypair: {e}[/red]")
            return False

    def get_public_key(self) -> Optional[str]:
        """Read public key content"""
        if not self.public_key_path.exists():
            return None
        return self.public_key_path.read_text().strip()

    def install_key_to_remote(self, host: str, port: int, user: str, password: str) -> bool:
        """Install public key to remote host's authorized_keys"""
        try:
            console.print(f"\n[cyan]📤 Installing SSH key to {user}@{host}:{port}...[/cyan]")

            public_key = self.get_public_key()
            if not public_key:
                console.print("[red]✗ Public key not found[/red]")
                return False

            # Connect with password
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            ssh.connect(
                hostname=host,
                port=port,
                username=user,
                password=password,
                timeout=10
            )

            # Ensure .ssh directory exists
            ssh.exec_command("mkdir -p ~/.ssh && chmod 700 ~/.ssh")

            # Add public key to authorized_keys
            install_cmd = f'echo "{public_key}" >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys'
            stdin, stdout, stderr = ssh.exec_command(install_cmd)
            exit_status = stdout.channel.recv_exit_status()

            ssh.close()

            if exit_status == 0:
                console.print(f"[green]✓ SSH key installed successfully[/green]")
                return True
            else:
                error = stderr.read().decode()
                console.print(f"[red]✗ Failed to install key: {error}[/red]")
                return False

        except Exception as e:
            console.print(f"[red]✗ Error installing key: {e}[/red]")
            return False

    def test_key_auth(self, host: str, port: int, user: str) -> bool:
        """Test SSH key authentication"""
        try:
            console.print(f"[cyan]🔍 Testing key-based authentication to {user}@{host}:{port}...[/cyan]")

            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            # Load private key
            private_key = paramiko.Ed25519Key.from_private_key_file(str(self.private_key_path))

            ssh.connect(
                hostname=host,
                port=port,
                username=user,
                pkey=private_key,
                timeout=10
            )

            # Run test command
            stdin, stdout, stderr = ssh.exec_command("echo 'wg-friend test'")
            output = stdout.read().decode().strip()

            ssh.close()

            if output == "wg-friend test":
                console.print("[green]✓ Key authentication successful![/green]")
                return True
            else:
                console.print("[red]✗ Key authentication failed[/red]")
                return False

        except Exception as e:
            console.print(f"[red]✗ Authentication test failed: {e}[/red]")
            return False


class DeployManager:
    """Manages WireGuard config deployment to remote hosts"""

    def __init__(self, config_path: Path, ssh_key_path: Path):
        self.config_path = config_path
        self.ssh_key_path = ssh_key_path
        self.config = self._load_config()

    def _load_config(self) -> Dict:
        """Load wg-friend config.yaml"""
        if not self.config_path.exists():
            raise DeploymentError(f"Config not found: {self.config_path}")

        with open(self.config_path) as f:
            return yaml.safe_load(f)

    def _get_ssh_client(self, host: str, port: int, user: str) -> paramiko.SSHClient:
        """Create authenticated SSH client using private key"""
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # Load private key
        private_key = paramiko.Ed25519Key.from_private_key_file(str(self.ssh_key_path))

        ssh.connect(
            hostname=host,
            port=port,
            username=user,
            pkey=private_key,
            timeout=30
        )

        return ssh

    def _backup_remote_config(self, ssh: paramiko.SSHClient, remote_path: str) -> bool:
        """Backup existing config on remote host"""
        try:
            backup_path = f"{remote_path}.backup.{datetime.now().strftime('%Y%m%d-%H%M%S')}"
            cmd = f"sudo cp {remote_path} {backup_path}"

            stdin, stdout, stderr = ssh.exec_command(cmd)
            exit_status = stdout.channel.recv_exit_status()

            if exit_status == 0:
                console.print(f"[green]✓ Backed up to: {backup_path}[/green]")
                return True
            else:
                console.print(f"[yellow]⚠ Backup failed (might not exist yet)[/yellow]")
                return False

        except Exception as e:
            console.print(f"[yellow]⚠ Backup error: {e}[/yellow]")
            return False

    def _upload_config(self, ssh: paramiko.SSHClient, local_path: str, remote_path: str, use_sudo: bool = True) -> bool:
        """Upload config file to remote host"""
        try:
            sftp = ssh.open_sftp()

            # Upload to temp location first
            temp_path = f"/tmp/wg-friend-upload-{datetime.now().strftime('%Y%m%d%H%M%S')}.conf"
            sftp.put(local_path, temp_path)
            sftp.close()

            # Move to final location with sudo
            if use_sudo:
                cmd = f"sudo mv {temp_path} {remote_path} && sudo chmod 600 {remote_path}"
            else:
                cmd = f"mv {temp_path} {remote_path} && chmod 600 {remote_path}"

            stdin, stdout, stderr = ssh.exec_command(cmd)
            exit_status = stdout.channel.recv_exit_status()

            if exit_status == 0:
                console.print(f"[green]✓ Uploaded to: {remote_path}[/green]")
                return True
            else:
                error = stderr.read().decode()
                console.print(f"[red]✗ Upload failed: {error}[/red]")
                return False

        except Exception as e:
            console.print(f"[red]✗ Upload error: {e}[/red]")
            return False

    def _restart_wireguard(self, ssh: paramiko.SSHClient, interface: str = "wg0") -> bool:
        """Restart WireGuard interface"""
        try:
            console.print(f"[cyan]🔄 Restarting wg-quick@{interface}...[/cyan]")

            cmd = f"sudo systemctl restart wg-quick@{interface}"
            stdin, stdout, stderr = ssh.exec_command(cmd)
            exit_status = stdout.channel.recv_exit_status()

            if exit_status == 0:
                console.print(f"[green]✓ WireGuard restarted[/green]")
                return True
            else:
                error = stderr.read().decode()
                console.print(f"[red]✗ Restart failed: {error}[/red]")
                return False

        except Exception as e:
            console.print(f"[red]✗ Restart error: {e}[/red]")
            return False

    def _verify_wireguard(self, ssh: paramiko.SSHClient, interface: str = "wg0") -> bool:
        """Verify WireGuard is running"""
        try:
            console.print(f"[cyan]🔍 Verifying WireGuard status...[/cyan]")

            cmd = f"sudo wg show {interface}"
            stdin, stdout, stderr = ssh.exec_command(cmd)
            exit_status = stdout.channel.recv_exit_status()

            if exit_status == 0:
                output = stdout.read().decode()
                # Check if output contains interface info
                if "interface:" in output or "public key:" in output:
                    console.print(f"[green]✓ WireGuard is running[/green]")
                    return True
                else:
                    console.print(f"[yellow]⚠ WireGuard running but no peers[/yellow]")
                    return True
            else:
                console.print(f"[red]✗ WireGuard not running[/red]")
                return False

        except Exception as e:
            console.print(f"[red]✗ Verification error: {e}[/red]")
            return False

    def deploy_to_coordinator(self, dry_run: bool = False, restart: bool = True) -> bool:
        """Deploy config to coordinator server"""
        try:
            coord_config = self.config.get('coordinator')
            if not coord_config:
                console.print("[yellow]⚠ No coordinator configured, skipping[/yellow]")
                return True

            host = coord_config.get('host')
            port = coord_config.get('port', 22)
            user = coord_config.get('user', 'root')
            remote_path = coord_config.get('config_path', '/etc/wireguard/wg0.conf')
            interface = coord_config.get('interface', 'wg0')

            # Get local config path
            local_path = coord_config.get('local_config_path')
            if not local_path:
                # Try to find coordinator config
                local_path = str(Path.home() / '.wg-friend' / 'coordinator-wg0.conf')

            if not Path(local_path).exists():
                console.print(f"[red]✗ Local config not found: {local_path}[/red]")
                return False

            # Check if we're deploying locally
            if is_local_host(host):
                console.print(Panel(
                    f"[bold]Coordinator:[/bold] localhost (detected)\n"
                    f"[bold]Config:[/bold] {remote_path}\n"
                    f"[bold]Interface:[/bold] {interface}",
                    title="🌐 Deploying to Coordinator",
                    border_style="cyan"
                ))

                # Deploy locally
                success = deploy_locally(local_path, remote_path, interface, dry_run, restart)
                if success:
                    console.print("[bold green]✓ Coordinator deployment complete![/bold green]\n")
                return success

            # Remote deployment via SSH
            console.print(Panel(
                f"[bold]Coordinator:[/bold] {user}@{host}:{port}\n"
                f"[bold]Config:[/bold] {remote_path}\n"
                f"[bold]Interface:[/bold] {interface}",
                title="🌐 Deploying to Coordinator",
                border_style="cyan"
            ))

            if dry_run:
                console.print("[yellow]DRY RUN - No changes made[/yellow]")
                return True

            # Connect
            ssh = self._get_ssh_client(host, port, user)

            # Backup existing config
            self._backup_remote_config(ssh, remote_path)

            # Upload new config
            if not self._upload_config(ssh, local_path, remote_path):
                ssh.close()
                return False

            # Restart WireGuard
            if restart:
                if not self._restart_wireguard(ssh, interface):
                    ssh.close()
                    return False

                # Verify
                self._verify_wireguard(ssh, interface)

            ssh.close()
            console.print("[bold green]✓ Coordinator deployment complete![/bold green]\n")
            return True

        except Exception as e:
            console.print(f"[red]✗ Coordinator deployment failed: {e}[/red]")
            return False

    def deploy_to_subnet_router(self, dry_run: bool = False, restart: bool = True) -> bool:
        """Deploy config to subnet router"""
        try:
            subnet_config = self.config.get('subnet_router')
            if not subnet_config:
                console.print("[yellow]⚠ No subnet router configured, skipping[/yellow]")
                return True

            host = subnet_config.get('host')
            port = subnet_config.get('port', 22)
            user = subnet_config.get('user', 'root')
            remote_path = subnet_config.get('config_path', '/etc/wireguard/wg0.conf')
            interface = subnet_config.get('interface', 'wg0')

            # Get local config path
            local_path = subnet_config.get('local_config_path')
            if not local_path:
                # Try to find subnet router config
                local_path = str(Path.home() / '.wg-friend' / 'subnet-router-wg0.conf')

            if not Path(local_path).exists():
                console.print(f"[red]✗ Local config not found: {local_path}[/red]")
                return False

            # Check if we're deploying locally
            if is_local_host(host):
                console.print(Panel(
                    f"[bold]Subnet Router:[/bold] localhost (detected)\n"
                    f"[bold]Config:[/bold] {remote_path}\n"
                    f"[bold]Interface:[/bold] {interface}",
                    title="🏠 Deploying to Subnet Router",
                    border_style="cyan"
                ))

                # Deploy locally
                success = deploy_locally(local_path, remote_path, interface, dry_run, restart)
                if success:
                    console.print("[bold green]✓ Subnet router deployment complete![/bold green]\n")
                return success

            # Remote deployment via SSH
            console.print(Panel(
                f"[bold]Subnet Router:[/bold] {user}@{host}:{port}\n"
                f"[bold]Config:[/bold] {remote_path}\n"
                f"[bold]Interface:[/bold] {interface}",
                title="🏠 Deploying to Subnet Router",
                border_style="cyan"
            ))

            if dry_run:
                console.print("[yellow]DRY RUN - No changes made[/yellow]")
                return True

            # Connect
            ssh = self._get_ssh_client(host, port, user)

            # Backup existing config
            self._backup_remote_config(ssh, remote_path)

            # Upload new config
            if not self._upload_config(ssh, local_path, remote_path):
                ssh.close()
                return False

            # Restart WireGuard
            if restart:
                if not self._restart_wireguard(ssh, interface):
                    ssh.close()
                    return False

                # Verify
                self._verify_wireguard(ssh, interface)

            ssh.close()
            console.print("[bold green]✓ Subnet router deployment complete![/bold green]\n")
            return True

        except Exception as e:
            console.print(f"[red]✗ Subnet router deployment failed: {e}[/red]")
            return False


def setup_mode():
    """Interactive setup: generate SSH key and install to endpoints"""
    console.print(Panel.fit(
        "[bold cyan]wg-friend Deployment Setup[/bold cyan]\n\n"
        "This will:\n"
        "1. Generate a dedicated SSH keypair for wg-friend\n"
        "2. Install the public key to your coordinator\n"
        "3. Install the public key to your subnet router\n"
        "4. Test key-based authentication\n\n"
        "[yellow]You'll need to enter passwords once for each endpoint.[/yellow]",
        border_style="cyan"
    ))

    if not Confirm.ask("\nContinue with setup?", default=True):
        console.print("Setup cancelled.")
        return False

    # Setup paths
    wg_friend_dir = Path.home() / '.wg-friend'
    ssh_dir = wg_friend_dir / 'ssh'
    config_path = wg_friend_dir / 'config.yaml'

    # Generate SSH key
    key_manager = SSHKeyManager(ssh_dir)

    if key_manager.key_exists():
        console.print("\n[yellow]⚠ SSH key already exists![/yellow]")
        if not Confirm.ask("Overwrite existing key?", default=False):
            console.print("Using existing key...")
        else:
            if not key_manager.generate_keypair():
                return False
    else:
        if not key_manager.generate_keypair():
            return False

    # Load config to get endpoint details
    if not config_path.exists():
        console.print(f"\n[red]✗ Config not found: {config_path}[/red]")
        console.print("[yellow]Run wg-friend-onboard.py first to create config.yaml[/yellow]")
        return False

    with open(config_path) as f:
        config = yaml.safe_load(f)

    # Check which endpoints are remote
    coord_config = config.get('coordinator')
    subnet_config = config.get('subnet_router')

    coord_is_local = coord_config and is_local_host(coord_config.get('host'))
    subnet_is_local = subnet_config and is_local_host(subnet_config.get('host'))

    # If both are local, no SSH setup needed
    if coord_is_local and subnet_is_local:
        console.print(Panel.fit(
            "[bold green]✓ Setup Complete (No SSH needed)[/bold green]\n\n"
            "Both coordinator and subnet router are on localhost.\n"
            "Deployments will use local filesystem operations.\n\n"
            "[yellow]Run deployments with sudo:[/yellow]\n"
            "  [cyan]sudo ./wg-friend-deploy.py[/cyan]",
            border_style="green"
        ))
        return True

    # Install to coordinator (if remote)
    if coord_config:
        host = coord_config.get('host')

        if is_local_host(host):
            console.print(f"\n[green]✓ Coordinator is localhost, skipping SSH setup[/green]")
        else:
            console.print(Panel.fit(
                "[bold]Coordinator SSH Setup[/bold]",
                border_style="cyan"
            ))

            port = coord_config.get('port', 22)
            user = Prompt.ask(f"SSH user for {host}", default=coord_config.get('user', 'root'))

            console.print(f"\n[cyan]Enter password for {user}@{host}[/cyan]")
            password = getpass.getpass("Password: ")

            if key_manager.install_key_to_remote(host, port, user, password):
                if key_manager.test_key_auth(host, port, user):
                    console.print("[bold green]✓ Coordinator setup complete![/bold green]")
                else:
                    console.print("[red]✗ Key authentication test failed[/red]")
                    return False
            else:
                console.print("[red]✗ Failed to install key to coordinator[/red]")
                return False

    # Install to subnet router (if remote)
    if subnet_config:
        host = subnet_config.get('host')

        if is_local_host(host):
            console.print(f"\n[green]✓ Subnet router is localhost, skipping SSH setup[/green]")
        else:
            console.print(Panel.fit(
                "[bold]Subnet Router SSH Setup[/bold]",
                border_style="cyan"
            ))

            port = subnet_config.get('port', 22)
            user = Prompt.ask(f"SSH user for {host}", default=subnet_config.get('user', 'root'))

            console.print(f"\n[cyan]Enter password for {user}@{host}[/cyan]")
            password = getpass.getpass("Password: ")

            if key_manager.install_key_to_remote(host, port, user, password):
                if key_manager.test_key_auth(host, port, user):
                    console.print("[bold green]✓ Subnet router setup complete![/bold green]")
                else:
                    console.print("[red]✗ Key authentication test failed[/red]")
                    return False
            else:
                console.print("[red]✗ Failed to install key to subnet router[/red]")
                return False

    # Configure subnet router system settings
    console.print("\n")
    if not configure_subnet_router_system(config, key_manager):
        console.print("[yellow]⚠ System configuration incomplete, but you can still deploy[/yellow]")

    console.print(Panel.fit(
        "[bold green]🎉 Setup Complete![/bold green]\n\n"
        "SSH key-based authentication is now configured.\n"
        "System settings have been verified.\n\n"
        "You can deploy configs with:\n\n"
        "  [cyan]./wg-friend-deploy.py[/cyan]",
        border_style="green"
    ))

    return True


def deploy_mode(coordinator: bool, subnet: bool, dry_run: bool, no_restart: bool):
    """Deploy updated configs to endpoints"""
    wg_friend_dir = Path.home() / '.wg-friend'
    config_path = wg_friend_dir / 'config.yaml'
    ssh_key_path = wg_friend_dir / 'ssh' / 'wg-friend-deploy'

    # Check SSH key exists (only needed for remote deploys)
    # Local deploys don't need SSH keys
    with open(config_path) as f:
        config = yaml.safe_load(f)

    coord_config = config.get('coordinator')
    subnet_config = config.get('subnet_router')

    coord_is_local = coord_config and coordinator and is_local_host(coord_config.get('host'))
    subnet_is_local = subnet_config and subnet and is_local_host(subnet_config.get('host'))

    # Only require SSH key if we have remote deploys
    if not (coord_is_local and subnet_is_local):
        if not ssh_key_path.exists():
            console.print("[red]✗ SSH key not found. Run --setup first:[/red]")
            console.print("  [cyan]./wg-friend-deploy.py --setup[/cyan]")
            return False

    # Pre-flight checks for subnet router
    if subnet and subnet_config and not dry_run:
        console.print(Panel.fit(
            "[bold]Pre-flight Checks[/bold]\n\n"
            "Verifying subnet router system configuration...",
            border_style="cyan"
        ))

        host = subnet_config.get('host')
        port = subnet_config.get('port', 22)
        user = subnet_config.get('user', 'root')
        config_file = subnet_config.get('config_path', '/etc/wireguard/wg0.conf')

        is_local = is_local_host(host)
        ssh = None

        try:
            if not is_local:
                # Connect via SSH
                ssh_client = paramiko.SSHClient()
                ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                private_key = paramiko.Ed25519Key.from_private_key_file(str(ssh_key_path))
                ssh_client.connect(hostname=host, port=port, username=user, pkey=private_key, timeout=10)
                ssh = ssh_client

            # Check PostUp rules first
            has_rules, rules = check_postup_rules(config_file, ssh)

            # Check if IP forwarding is in PostUp rules
            ipv4_in_postup = any('sysctl' in rule and 'ipv4.ip_forward' in rule for rule in rules)
            ipv6_in_postup = any('sysctl' in rule and 'ipv6.conf.all.forwarding' in rule for rule in rules)

            # Check system-level only if NOT in PostUp
            if not (ipv4_in_postup and ipv6_in_postup):
                ipv4_enabled, ipv6_enabled = check_ip_forwarding(ssh)

                if not ipv4_enabled and not ipv4_in_postup:
                    console.print("[yellow]⚠ IPv4 forwarding is DISABLED on subnet router[/yellow]")
                    console.print("[yellow]  Option 1 (recommended): Add to PostUp rules[/yellow]")
                    console.print("[yellow]    PostUp = sysctl -w net.ipv4.ip_forward=1[/yellow]")
                    console.print("[yellow]  Option 2: Enable system-wide[/yellow]")
                    console.print("[yellow]    sudo sysctl -w net.ipv4.ip_forward=1[/yellow]")
                    console.print("[yellow]  Or run: ./wg-friend-deploy.py --setup[/yellow]\n")

            # Check for routing rules
            has_masquerade = any('MASQUERADE' in rule or 'FORWARD' in rule for rule in rules)

            if not has_masquerade:
                console.print("[yellow]⚠ No routing rules (MASQUERADE/FORWARD) found in subnet router config[/yellow]")
                console.print("[yellow]  Routing will not work without these rules![/yellow]")
                console.print("[yellow]  Run: ./wg-friend-deploy.py --setup (to configure)[/yellow]\n")

            if ssh:
                ssh.close()

        except Exception as e:
            console.print(f"[yellow]⚠ Pre-flight check failed: {e}[/yellow]")
            console.print("[yellow]  Continuing with deployment...[/yellow]\n")
            if ssh:
                try:
                    ssh.close()
                except:
                    pass

    # Deploy
    manager = DeployManager(config_path, ssh_key_path)

    success = True

    if coordinator:
        if not manager.deploy_to_coordinator(dry_run=dry_run, restart=not no_restart):
            success = False

    if subnet:
        if not manager.deploy_to_subnet_router(dry_run=dry_run, restart=not no_restart):
            success = False

    if success:
        console.print(Panel.fit(
            "[bold green]✓ Deployment Complete![/bold green]",
            border_style="green"
        ))
    else:
        console.print(Panel.fit(
            "[bold red]✗ Deployment had errors[/bold red]",
            border_style="red"
        ))

    return success


def main():
    parser = argparse.ArgumentParser(
        description="wg-friend deployment tool - Automated WireGuard config deployment",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --setup                    # One-time SSH key setup
  %(prog)s                            # Deploy to both endpoints
  %(prog)s --coordinator-only         # Deploy to coordinator only
  %(prog)s --subnet-only              # Deploy to subnet router only
  %(prog)s --dry-run                  # Show what would be deployed
  %(prog)s --no-restart               # Upload only, skip restart
        """
    )

    parser.add_argument('--setup', action='store_true',
                        help='Interactive setup: generate SSH key and install to endpoints')
    parser.add_argument('--coordinator-only', action='store_true',
                        help='Deploy to coordinator only')
    parser.add_argument('--subnet-only', action='store_true',
                        help='Deploy to subnet router only')
    parser.add_argument('--dry-run', action='store_true',
                        help='Show what would be deployed without making changes')
    parser.add_argument('--no-restart', action='store_true',
                        help='Upload configs without restarting WireGuard')

    args = parser.parse_args()

    try:
        if args.setup:
            success = setup_mode()
        else:
            # Default: deploy to both unless specific endpoint selected
            deploy_coordinator = not args.subnet_only
            deploy_subnet = not args.coordinator_only

            success = deploy_mode(
                coordinator=deploy_coordinator,
                subnet=deploy_subnet,
                dry_run=args.dry_run,
                no_restart=args.no_restart
            )

        sys.exit(0 if success else 1)

    except KeyboardInterrupt:
        console.print("\n[yellow]Cancelled by user[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[red]Error: {e}[/red]")
        sys.exit(1)


if __name__ == "__main__':
    main()
