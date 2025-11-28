#!/usr/bin/env python3
"""
wg-friend Maintenance Mode
Manage WireGuard configurations after import
"""

import argparse
import sys
import subprocess
from pathlib import Path
from typing import List, Dict, Optional
from datetime import datetime

from rich.console import Console
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.panel import Panel
from rich.table import Table
from rich import box
from rich.syntax import Syntax

from src.database import WireGuardDB
from src.keygen import generate_keypair, generate_preshared_key
from src.qr_generator import generate_qr_code
from src.ssh_client import SSHClient

import getpass

console = Console()


class WireGuardMaintainer:
    """Maintenance operations for WireGuard configs"""

    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        if not self.db_path.exists():
            console.print(f"[red]Database not found: {db_path}[/red]")
            console.print("[yellow]Run wg-friend-onboard-v2.py first to import configs[/yellow]")
            sys.exit(1)

        self.db = WireGuardDB(db_path)
        self.output_dir = Path("output")
        self.output_dir.mkdir(exist_ok=True)

        # SSH key path for deployments - use unique name to avoid conflicts
        self.ssh_key_dir = Path.home() / ".ssh"

        # Check if wg-friend key already exists, otherwise create new one with timestamp
        existing_keys = list(self.ssh_key_dir.glob("wg-friend-*"))
        if existing_keys:
            # Use the most recent wg-friend key
            self.ssh_key_path = sorted(existing_keys)[-1]
        else:
            # Create new key with timestamp
            import time
            timestamp = int(time.time())
            self.ssh_key_path = self.ssh_key_dir / f"wg-friend-{timestamp}"

    def run(self):
        """Run maintenance mode interactive menu"""
        console.print(Panel.fit(
            "[bold cyan]WireGuard Friend - Maintenance Mode[/bold cyan]\n"
            "Manage your WireGuard network",
            border_style="cyan"
        ))

        while True:
            console.print("\n[bold]Main Menu:[/bold]")
            console.print("  [1] Manage Coordination Server")
            console.print("  [2] Manage Subnet Routers")
            console.print("  [3] Manage Peers")
            console.print("  [4] Create New Peer")
            console.print("  [5] List All Entities")
            console.print("  [6] Deploy Configs")
            console.print("  [7] SSH Setup (Key Generation & Installation)")
            console.print("  [0] Exit")

            choice = Prompt.ask("\nSelect option", choices=["0", "1", "2", "3", "4", "5", "6", "7"], default="0")

            if choice == "0":
                console.print("[yellow]Goodbye![/yellow]")
                break
            elif choice == "1":
                self._manage_coordination_server()
            elif choice == "2":
                self._manage_subnet_routers()
            elif choice == "3":
                self._manage_peers()
            elif choice == "4":
                self._create_new_peer()
            elif choice == "5":
                self._list_all_entities()
            elif choice == "6":
                self._deploy_configs()
            elif choice == "7":
                self._ssh_setup_wizard()

    def _ssh_setup_wizard(self):
        """Interactive SSH key setup wizard"""
        console.print(Panel.fit(
            "[bold cyan]SSH Key Setup Wizard[/bold cyan]\n\n"
            "This wizard will help you set up SSH key-based authentication\n"
            "for deploying WireGuard configs to your servers.\n\n"
            "Steps:\n"
            "  1. Generate SSH keypair (if needed)\n"
            "  2. Install public key to coordination server\n"
            "  3. Install public key to subnet router(s)\n"
            "  4. Test authentication",
            border_style="cyan"
        ))

        if not Confirm.ask("\nContinue with SSH setup?", default=True):
            console.print("[yellow]Cancelled[/yellow]")
            return

        # Step 1: Generate or check SSH key
        console.print("\n[bold cyan]Step 1: SSH Keypair[/bold cyan]")

        if self.ssh_key_path.exists():
            console.print(f"[green]✓ SSH key already exists: {self.ssh_key_path}[/green]")

            if not Confirm.ask("Use existing key?", default=True):
                if not Confirm.ask("[yellow]Generate new key? (will overwrite existing)[/yellow]", default=False):
                    console.print("[yellow]Keeping existing key[/yellow]")
                else:
                    self._generate_ssh_key()
        else:
            console.print(f"[yellow]No SSH key found at: {self.ssh_key_path}[/yellow]")
            if Confirm.ask("Generate new SSH key?", default=True):
                self._generate_ssh_key()
            else:
                console.print("[red]Cannot proceed without SSH key[/red]")
                return

        # Step 2: Install to coordination server
        console.print("\n[bold cyan]Step 2: Coordination Server[/bold cyan]")
        cs = self.db.get_coordination_server()

        if cs:
            console.print(f"Target: {cs['ssh_user']}@{cs['ssh_host']}:{cs['ssh_port']}")

            if Confirm.ask("Install SSH key to coordination server?", default=True):
                self._install_ssh_key_to_host(
                    cs['ssh_host'],
                    cs['ssh_port'],
                    cs['ssh_user']
                )
        else:
            console.print("[yellow]No coordination server configured - skipping[/yellow]")

        # Step 3: Install to subnet routers
        console.print("\n[bold cyan]Step 3: Subnet Routers[/bold cyan]")

        if cs:
            sn_list = self.db.get_subnet_routers(cs['id'])

            if sn_list:
                console.print(f"Found {len(sn_list)} subnet router(s)")

                for sn in sn_list:
                    console.print(f"\n  • {sn['name']} ({sn['ipv4_address']})")

                    if Confirm.ask(f"    Install SSH key to {sn['name']}?", default=True):
                        # Prompt for SSH details
                        ssh_host = Prompt.ask("    SSH hostname/IP", default=sn.get('ipv4_address', ''))
                        ssh_port = int(Prompt.ask("    SSH port", default="22"))
                        ssh_user = Prompt.ask("    SSH username", default="root")

                        self._install_ssh_key_to_host(ssh_host, ssh_port, ssh_user)
            else:
                console.print("[yellow]No subnet routers configured - skipping[/yellow]")

        console.print("\n[bold green]✓ SSH setup complete![/bold green]")
        console.print("\n[cyan]You can now use deployment features in the main menu.[/cyan]")

    def _generate_ssh_key(self):
        """Generate SSH keypair"""
        try:
            console.print(f"\n[cyan]Generating ed25519 SSH keypair...[/cyan]")

            # Ensure .ssh directory exists
            self.ssh_key_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

            # Generate key using ssh-keygen
            result = subprocess.run(
                [
                    "ssh-keygen",
                    "-t", "ed25519",
                    "-f", str(self.ssh_key_path),
                    "-N", "",  # No passphrase
                    "-C", f"wg-friend@{datetime.now().strftime('%Y%m%d')}"
                ],
                capture_output=True,
                text=True
            )

            if result.returncode != 0:
                console.print(f"[red]✗ Failed to generate key: {result.stderr}[/red]")
                return False

            # Set permissions
            self.ssh_key_path.chmod(0o600)
            (self.ssh_key_path.parent / f"{self.ssh_key_path.name}.pub").chmod(0o644)

            console.print(f"[green]✓ SSH keypair generated:[/green]")
            console.print(f"  Private: {self.ssh_key_path}")
            console.print(f"  Public:  {self.ssh_key_path}.pub")

            return True

        except Exception as e:
            console.print(f"[red]✗ Error generating keypair: {e}[/red]")
            return False

    def _install_ssh_key_to_host(self, host: str, port: int, user: str):
        """Install SSH public key to remote host"""
        try:
            console.print(f"\n[cyan]Installing SSH key to {user}@{host}:{port}[/cyan]")

            # Read public key
            pub_key_path = Path(f"{self.ssh_key_path}.pub")
            if not pub_key_path.exists():
                console.print(f"[red]✗ Public key not found: {pub_key_path}[/red]")
                return False

            public_key = pub_key_path.read_text().strip()

            # Prompt for password
            console.print(f"[yellow]Enter password for {user}@{host}:[/yellow]")
            password = getpass.getpass("Password: ")

            # Connect with password and install key
            import paramiko
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            console.print("[cyan]Connecting...[/cyan]")
            ssh.connect(
                hostname=host,
                port=port,
                username=user,
                password=password,
                timeout=10
            )

            # Ensure .ssh directory exists
            console.print("[cyan]Setting up .ssh directory...[/cyan]")
            ssh.exec_command("mkdir -p ~/.ssh && chmod 700 ~/.ssh")

            # Add public key to authorized_keys
            console.print("[cyan]Installing public key...[/cyan]")
            install_cmd = f'echo "{public_key}" >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys'
            stdin, stdout, stderr = ssh.exec_command(install_cmd)
            exit_status = stdout.channel.recv_exit_status()

            ssh.close()

            if exit_status != 0:
                error = stderr.read().decode()
                console.print(f"[red]✗ Failed to install key: {error}[/red]")
                return False

            console.print(f"[green]✓ Public key installed successfully[/green]")

            # Test key authentication
            console.print("[cyan]Testing key-based authentication...[/cyan]")

            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            private_key = paramiko.Ed25519Key.from_private_key_file(str(self.ssh_key_path))

            ssh.connect(
                hostname=host,
                port=port,
                username=user,
                pkey=private_key,
                timeout=10
            )

            stdin, stdout, stderr = ssh.exec_command("echo 'wg-friend test'")
            output = stdout.read().decode().strip()

            ssh.close()

            if output == "wg-friend test":
                console.print("[green]✓ Key authentication successful![/green]")
                return True
            else:
                console.print("[red]✗ Key authentication failed[/red]")
                return False

        except paramiko.AuthenticationException:
            console.print(f"[red]✗ Authentication failed - incorrect password?[/red]")
            return False
        except Exception as e:
            console.print(f"[red]✗ Error installing key: {e}[/red]")
            import traceback
            console.print(f"[dim]{traceback.format_exc()}[/dim]")
            return False

    def _list_all_entities(self):
        """List all entities in the system"""
        console.print("\n[bold cyan]System Overview[/bold cyan]")

        # Coordination Server
        cs = self.db.get_coordination_server()
        if cs:
            console.print(f"\n[bold]Coordination Server:[/bold]")
            console.print(f"  Endpoint: {cs['endpoint']}")
            console.print(f"  Network: {cs['network_ipv4']}, {cs['network_ipv6']}")
            console.print(f"  SSH: {cs['ssh_user']}@{cs['ssh_host']}:{cs['ssh_port']}")

        # Subnet Routers
        if cs:
            sn_list = self.db.get_subnet_routers(cs['id'])
            if sn_list:
                console.print(f"\n[bold]Subnet Routers ({len(sn_list)}):[/bold]")
                table = Table(show_header=True, box=box.SIMPLE)
                table.add_column("Name", style="cyan")
                table.add_column("IPv4", style="yellow")
                table.add_column("IPv6", style="yellow")
                table.add_column("LANs", style="green")

                for sn in sn_list:
                    lans = self.db.get_sn_lan_networks(sn['id'])
                    lan_str = ", ".join(lans) if lans else "None"
                    table.add_row(sn['name'], sn['ipv4_address'], sn['ipv6_address'], lan_str)

                console.print(table)

        # Peers
        if cs:
            peers = self.db.get_peers(cs['id'])
            if peers:
                console.print(f"\n[bold]Peers ({len(peers)}):[/bold]")
                table = Table(show_header=True, box=box.SIMPLE)
                table.add_column("Name", style="cyan")
                table.add_column("IPv4", style="yellow")
                table.add_column("IPv6", style="yellow")
                table.add_column("Access", style="green")
                table.add_column("Client Config", style="magenta")

                for peer in peers:
                    has_config = "Yes" if peer['raw_interface_block'] else "No"
                    table.add_row(
                        peer['name'],
                        peer['ipv4_address'],
                        peer['ipv6_address'],
                        peer['access_level'],
                        has_config
                    )

                console.print(table)

    def _manage_coordination_server(self):
        """Manage coordination server"""
        cs = self.db.get_coordination_server()
        if not cs:
            console.print("[red]No coordination server found[/red]")
            return

        console.print(f"\n[bold cyan]Coordination Server: {cs['endpoint']}[/bold cyan]")
        console.print("\n[bold]Actions:[/bold]")
        console.print("  [1] View Current Config")
        console.print("  [2] Export Config to File")
        console.print("  [3] Deploy to Server")
        console.print("  [0] Back")

        choice = Prompt.ask("\nSelect action", choices=["0", "1", "2", "3"], default="0")

        if choice == "1":
            self._view_cs_config()
        elif choice == "2":
            self._export_cs_config()
        elif choice == "3":
            self._deploy_cs_config()

    def _view_cs_config(self):
        """View coordination server config"""
        config = self.db.reconstruct_cs_config()
        console.print(Panel(
            Syntax(config, "ini", theme="monokai", line_numbers=False),
            title="Coordination Server Config",
            border_style="green"
        ))

    def _export_cs_config(self):
        """Export CS config to file"""
        config = self.db.reconstruct_cs_config()
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        output_file = self.output_dir / f"coordination-{timestamp}.conf"

        with open(output_file, 'w') as f:
            f.write(config)
        output_file.chmod(0o600)

        console.print(f"[green]✓ Exported to {output_file}[/green]")

    def _deploy_cs_config(self):
        """Deploy CS config to server via SSH"""
        cs = self.db.get_coordination_server()
        config = self.db.reconstruct_cs_config()

        console.print(f"\n[bold yellow]Deploy to {cs['ssh_user']}@{cs['ssh_host']}:{cs['ssh_port']}[/bold yellow]")

        # Check SSH key
        if not self.ssh_key_path.exists():
            console.print(f"[red]✗ SSH key not found: {self.ssh_key_path}[/red]")
            console.print("[yellow]SSH key-based authentication is required for deployment.[/yellow]")

            if Confirm.ask("\nRun SSH setup wizard now?", default=True):
                self._ssh_setup_wizard()

                # Check again after wizard
                if not self.ssh_key_path.exists():
                    console.print("[red]✗ SSH setup incomplete - cannot deploy[/red]")
                    return
            else:
                console.print("[yellow]Deployment cancelled[/yellow]")
                return

        if not Confirm.ask("Continue with deployment?", default=False):
            console.print("[yellow]Cancelled[/yellow]")
            return

        # Create temporary file
        temp_file = self.output_dir / "coordination-deploy.conf"
        with open(temp_file, 'w') as f:
            f.write(config)
        temp_file.chmod(0o600)

        try:
            console.print("[cyan]Connecting to server...[/cyan]")
            ssh = SSHClient(
                hostname=cs['ssh_host'],
                username=cs['ssh_user'],
                ssh_key_path=str(self.ssh_key_path),
                port=cs['ssh_port']
            )

            if not ssh.connect():
                console.print("[red]✗ Failed to connect to server[/red]")
                return

            # Backup existing config
            console.print("[cyan]Creating backup of existing config...[/cyan]")
            backup_result = ssh.run_command(
                "cp /etc/wireguard/wg0.conf /etc/wireguard/wg0.conf.backup-$(date +%Y%m%d-%H%M%S)"
            )

            # Upload new config
            console.print("[cyan]Uploading new config...[/cyan]")
            ssh.upload_file(str(temp_file), "/tmp/wg0.conf", use_sudo=False, mode="600")

            # Move to proper location
            console.print("[cyan]Installing config...[/cyan]")
            ssh.run_command("mv /tmp/wg0.conf /etc/wireguard/wg0.conf")
            ssh.run_command("chmod 600 /etc/wireguard/wg0.conf")

            # Restart WireGuard
            if Confirm.ask("Restart WireGuard service?", default=True):
                console.print("[cyan]Restarting wg-quick@wg0...[/cyan]")
                restart_result = ssh.run_command("systemctl restart wg-quick@wg0")

                # Verify
                console.print("[cyan]Verifying WireGuard status...[/cyan]")
                verify_result = ssh.run_command("wg show wg0")
                if verify_result.strip():
                    console.print("[green]✓ WireGuard is running[/green]")
                else:
                    console.print("[yellow]⚠ WireGuard may not be running - check manually[/yellow]")

            ssh.disconnect()
            console.print("[bold green]✓ Deployment complete![/bold green]")

        except Exception as e:
            console.print(f"[red]✗ Deployment failed: {e}[/red]")
            import traceback
            console.print(f"[dim]{traceback.format_exc()}[/dim]")

    def _manage_subnet_routers(self):
        """Manage subnet routers"""
        cs = self.db.get_coordination_server()
        if not cs:
            console.print("[red]No coordination server found[/red]")
            return

        sn_list = self.db.get_subnet_routers(cs['id'])
        if not sn_list:
            console.print("[yellow]No subnet routers found[/yellow]")
            return

        # Display list
        console.print("\n[bold]Subnet Routers:[/bold]")
        for i, sn in enumerate(sn_list, 1):
            lans = self.db.get_sn_lan_networks(sn['id'])
            lan_str = ", ".join(lans) if lans else "None"
            console.print(f"  [{i}] {sn['name']} ({sn['ipv4_address']}) - LANs: {lan_str}")

        console.print(f"  [0] Back")

        choice = IntPrompt.ask("\nSelect subnet router", default=0)
        if choice == 0 or choice > len(sn_list):
            return

        selected_sn = sn_list[choice - 1]
        self._manage_single_subnet_router(selected_sn)

    def _manage_single_subnet_router(self, sn: Dict):
        """Manage a single subnet router"""
        console.print(f"\n[bold cyan]Subnet Router: {sn['name']}[/bold cyan]")
        console.print("\n[bold]Actions:[/bold]")
        console.print("  [1] View Client Config")
        console.print("  [2] Rotate Keys")
        console.print("  [3] Export Config to File")
        console.print("  [4] Deploy to Server")
        console.print("  [0] Back")

        choice = Prompt.ask("\nSelect action", choices=["0", "1", "2", "3", "4"], default="0")

        if choice == "1":
            self._view_sn_config(sn)
        elif choice == "2":
            self._rotate_sn_keys(sn)
        elif choice == "3":
            self._export_sn_config(sn)
        elif choice == "4":
            self._deploy_sn_config(sn)

    def _view_sn_config(self, sn: Dict):
        """View subnet router client config"""
        config = self.db.reconstruct_sn_config(sn['id'])

        # Reconstruct full config with peer section
        cs = self.db.get_coordination_server()
        full_config = config + "\n[Peer]\n"
        full_config += f"PublicKey = {cs['public_key']}\n"
        full_config += f"Endpoint = {cs['endpoint']}\n"
        full_config += f"AllowedIPs = {sn['allowed_ips']}\n"
        if sn.get('persistent_keepalive'):
            full_config += f"PersistentKeepalive = {sn['persistent_keepalive']}\n"

        console.print(Panel(
            Syntax(full_config, "ini", theme="monokai", line_numbers=False),
            title=f"Subnet Router Config: {sn['name']}",
            border_style="green"
        ))

    def _export_sn_config(self, sn: Dict):
        """Export subnet router config to file"""
        config = self.db.reconstruct_sn_config(sn['id'])

        # Add peer section
        cs = self.db.get_coordination_server()
        full_config = config + "\n[Peer]\n"
        full_config += f"PublicKey = {cs['public_key']}\n"
        full_config += f"Endpoint = {cs['endpoint']}\n"
        full_config += f"AllowedIPs = {sn['allowed_ips']}\n"
        if sn.get('persistent_keepalive'):
            full_config += f"PersistentKeepalive = {sn['persistent_keepalive']}\n"

        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        output_file = self.output_dir / f"{sn['name']}-{timestamp}.conf"

        with open(output_file, 'w') as f:
            f.write(full_config)
        output_file.chmod(0o600)

        console.print(f"[green]✓ Exported to {output_file}[/green]")

    def _deploy_sn_config(self, sn: Dict):
        """Deploy subnet router config to server via SSH"""
        config = self.db.reconstruct_sn_config(sn['id'])

        # Add peer section for full config
        cs = self.db.get_coordination_server()
        full_config = config + "\n[Peer]\n"
        full_config += f"PublicKey = {cs['public_key']}\n"
        full_config += f"Endpoint = {cs['endpoint']}\n"
        full_config += f"AllowedIPs = {sn['allowed_ips']}\n"
        if sn.get('persistent_keepalive'):
            full_config += f"PersistentKeepalive = {sn['persistent_keepalive']}\n"

        console.print(f"\n[bold yellow]Deploy config for {sn['name']}[/bold yellow]")
        console.print("\n[cyan]SSH Connection Details:[/cyan]")

        # Prompt for SSH details
        ssh_host = Prompt.ask("SSH hostname/IP", default=sn.get('ipv4_address', ''))
        ssh_port = int(Prompt.ask("SSH port", default="22"))
        ssh_user = Prompt.ask("SSH username", default="root")

        console.print(f"\n[bold yellow]Deploy to {ssh_user}@{ssh_host}:{ssh_port}[/bold yellow]")

        # Check SSH key
        if not self.ssh_key_path.exists():
            console.print(f"[red]✗ SSH key not found: {self.ssh_key_path}[/red]")
            console.print("[yellow]SSH key-based authentication is required for deployment.[/yellow]")

            if Confirm.ask("\nRun SSH setup wizard now?", default=True):
                self._ssh_setup_wizard()

                # Check again after wizard
                if not self.ssh_key_path.exists():
                    console.print("[red]✗ SSH setup incomplete - cannot deploy[/red]")
                    return
            else:
                console.print("[yellow]Deployment cancelled[/yellow]")
                return

        if not Confirm.ask("Continue with deployment?", default=False):
            console.print("[yellow]Cancelled[/yellow]")
            return

        # Create temporary file
        temp_file = self.output_dir / f"{sn['name']}-deploy.conf"
        with open(temp_file, 'w') as f:
            f.write(full_config)
        temp_file.chmod(0o600)

        try:
            console.print("[cyan]Connecting to server...[/cyan]")
            ssh = SSHClient(
                hostname=ssh_host,
                username=ssh_user,
                ssh_key_path=str(self.ssh_key_path),
                port=ssh_port
            )

            if not ssh.connect():
                console.print("[red]✗ Failed to connect to server[/red]")
                return

            # Backup existing config
            console.print("[cyan]Creating backup of existing config...[/cyan]")
            backup_result = ssh.run_command(
                "cp /etc/wireguard/wg0.conf /etc/wireguard/wg0.conf.backup-$(date +%Y%m%d-%H%M%S)"
            )

            # Upload new config
            console.print("[cyan]Uploading new config...[/cyan]")
            ssh.upload_file(str(temp_file), "/tmp/wg0.conf", use_sudo=False, mode="600")

            # Move to proper location
            console.print("[cyan]Installing config...[/cyan]")
            ssh.run_command("mv /tmp/wg0.conf /etc/wireguard/wg0.conf")
            ssh.run_command("chmod 600 /etc/wireguard/wg0.conf")

            # Restart WireGuard
            if Confirm.ask("Restart WireGuard service?", default=True):
                console.print("[cyan]Restarting wg-quick@wg0...[/cyan]")
                restart_result = ssh.run_command("systemctl restart wg-quick@wg0")

                # Verify
                console.print("[cyan]Verifying WireGuard status...[/cyan]")
                verify_result = ssh.run_command("wg show wg0")
                if verify_result.strip():
                    console.print("[green]✓ WireGuard is running[/green]")
                else:
                    console.print("[yellow]⚠ WireGuard may not be running - check manually[/yellow]")

            ssh.disconnect()
            console.print("[bold green]✓ Deployment complete![/bold green]")

        except Exception as e:
            console.print(f"[red]✗ Deployment failed: {e}[/red]")
            import traceback
            console.print(f"[dim]{traceback.format_exc()}[/dim]")

    def _rotate_sn_keys(self, sn: Dict):
        """Rotate subnet router keypair"""
        console.print(f"\n[bold yellow]Rotate keys for {sn['name']}[/bold yellow]")
        console.print("This will:")
        console.print("  1. Generate new keypair for subnet router")
        console.print("  2. Update subnet router config")
        console.print("  3. Update coordination server peer entry")

        if not Confirm.ask("\nContinue?", default=False):
            console.print("[yellow]Cancelled[/yellow]")
            return

        # Generate new keypair
        private_key, public_key = generate_keypair()
        console.print(f"[green]✓ Generated new keypair[/green]")

        # Update subnet router in database
        with self.db._connection() as conn:
            cursor = conn.cursor()

            # Update subnet_router table
            cursor.execute("""
                UPDATE subnet_router
                SET private_key = ?, public_key = ?, last_rotated = ?
                WHERE id = ?
            """, (private_key, public_key, datetime.now().isoformat(), sn['id']))

            # Update raw_interface_block (replace PrivateKey line)
            old_interface = sn['raw_interface_block']
            lines = old_interface.split('\n')
            new_lines = []
            for line in lines:
                if line.strip().startswith('PrivateKey'):
                    new_lines.append(f"PrivateKey = {private_key}")
                else:
                    new_lines.append(line)
            new_interface = '\n'.join(new_lines)

            cursor.execute("""
                UPDATE subnet_router
                SET raw_interface_block = ?
                WHERE id = ?
            """, (new_interface, sn['id']))

            # Update CS peer entry (raw_peer_block)
            old_peer = sn['raw_peer_block']
            peer_lines = old_peer.split('\n')
            new_peer_lines = []
            for line in peer_lines:
                if line.strip().startswith('PublicKey'):
                    new_peer_lines.append(f"PublicKey = {public_key}")
                else:
                    new_peer_lines.append(line)
            new_peer = '\n'.join(new_peer_lines)

            cursor.execute("""
                UPDATE subnet_router
                SET raw_peer_block = ?
                WHERE id = ?
            """, (new_peer, sn['id']))

        console.print(f"[green]✓ Keys rotated successfully![/green]")
        console.print(f"\n[bold]Next steps:[/bold]")
        console.print(f"  1. Export and deploy subnet router config to {sn['name']}")
        console.print(f"  2. Deploy updated coordination server config")

    def _manage_peers(self):
        """Manage peers"""
        cs = self.db.get_coordination_server()
        if not cs:
            console.print("[red]No coordination server found[/red]")
            return

        peers = self.db.get_peers(cs['id'])
        if not peers:
            console.print("[yellow]No peers found[/yellow]")
            return

        # Display list
        console.print("\n[bold]Peers:[/bold]")
        for i, peer in enumerate(peers, 1):
            has_config = "✓" if peer['raw_interface_block'] else "✗"
            console.print(f"  [{i}] {peer['name']} ({peer['ipv4_address']}) - Config: {has_config}")

        console.print(f"  [0] Back")

        choice = IntPrompt.ask("\nSelect peer", default=0)
        if choice == 0 or choice > len(peers):
            return

        selected_peer = peers[choice - 1]
        self._manage_single_peer(selected_peer)

    def _manage_single_peer(self, peer: Dict):
        """Manage a single peer"""
        console.print(f"\n[bold cyan]Peer: {peer['name']}[/bold cyan]")

        # Show current preshared key status
        has_psk = "Yes" if peer.get('preshared_key') else "No"
        console.print(f"  Preshared Key: {has_psk}")

        console.print("\n[bold]Actions:[/bold]")
        console.print("  [1] View Client Config")
        console.print("  [2] Generate QR Code")
        console.print("  [3] Rotate Keys")
        console.print("  [4] Export Config to File")
        console.print("  [5] Add/Update Preshared Key")
        console.print("  [6] Delete Peer")
        console.print("  [0] Back")

        choice = Prompt.ask("\nSelect action", choices=["0", "1", "2", "3", "4", "5", "6"], default="0")

        if choice == "1":
            self._view_peer_config(peer)
        elif choice == "2":
            self._generate_peer_qr(peer)
        elif choice == "3":
            self._rotate_peer_keys(peer)
        elif choice == "4":
            self._export_peer_config(peer)
        elif choice == "5":
            self._add_preshared_key(peer)
        elif choice == "6":
            self._delete_peer(peer)

    def _view_peer_config(self, peer: Dict):
        """View peer client config"""
        if not peer['raw_interface_block']:
            console.print("[yellow]No client config available for this peer[/yellow]")
            return

        config = self.db.reconstruct_peer_config(peer['id'])
        console.print(Panel(
            Syntax(config, "ini", theme="monokai", line_numbers=False),
            title=f"Peer Config: {peer['name']}",
            border_style="green"
        ))

    def _generate_peer_qr(self, peer: Dict):
        """Generate QR code for peer"""
        if not peer['raw_interface_block']:
            console.print("[yellow]No client config available for this peer[/yellow]")
            console.print("Create a client config first using key rotation")
            return

        config = self.db.reconstruct_peer_config(peer['id'])

        # Generate QR code (returns ASCII art)
        qr_file = self.output_dir / f"{peer['name']}-qr.png"
        qr_ascii = generate_qr_code(config, qr_file)

        console.print(f"[green]✓ QR code saved to {qr_file}[/green]")

        # Offer to display in terminal
        if Confirm.ask("\nDisplay QR code in terminal?", default=True):
            console.print("\n[dim]Note: Terminal display may not work in all terminal configurations.[/dim]")
            console.print("[dim]If scanning doesn't work, use the PNG file from output/ folder.[/dim]\n")
            console.print(qr_ascii)

    def _export_peer_config(self, peer: Dict):
        """Export peer config to file"""
        if not peer['raw_interface_block']:
            console.print("[yellow]No client config available for this peer[/yellow]")
            return

        config = self.db.reconstruct_peer_config(peer['id'])
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        output_file = self.output_dir / f"{peer['name']}-{timestamp}.conf"

        with open(output_file, 'w') as f:
            f.write(config)
        output_file.chmod(0o600)

        console.print(f"[green]✓ Exported to {output_file}[/green]")

    def _rotate_peer_keys(self, peer: Dict):
        """Rotate peer keypair"""
        console.print(f"\n[bold yellow]Rotate keys for {peer['name']}[/bold yellow]")
        console.print("This will:")
        console.print("  1. Generate new keypair for peer")
        console.print("  2. Update peer client config (if exists)")
        console.print("  3. Update coordination server peer entry")

        if not Confirm.ask("\nContinue?", default=False):
            console.print("[yellow]Cancelled[/yellow]")
            return

        # Generate new keypair
        private_key, public_key = generate_keypair()
        console.print(f"[green]✓ Generated new keypair[/green]")

        # Update peer in database
        with self.db._connection() as conn:
            cursor = conn.cursor()

            # Update peer table
            cursor.execute("""
                UPDATE peer
                SET private_key = ?, public_key = ?, last_rotated = ?
                WHERE id = ?
            """, (private_key, public_key, datetime.now().isoformat(), peer['id']))

            # Update raw_interface_block if it exists
            if peer['raw_interface_block']:
                old_interface = peer['raw_interface_block']
                lines = old_interface.split('\n')
                new_lines = []
                for line in lines:
                    if line.strip().startswith('PrivateKey'):
                        new_lines.append(f"PrivateKey = {private_key}")
                    else:
                        new_lines.append(line)
                new_interface = '\n'.join(new_lines)

                cursor.execute("""
                    UPDATE peer
                    SET raw_interface_block = ?
                    WHERE id = ?
                """, (new_interface, peer['id']))

            # Update CS peer entry (raw_peer_block)
            old_peer = peer['raw_peer_block']
            peer_lines = old_peer.split('\n')
            new_peer_lines = []
            for line in peer_lines:
                if line.strip().startswith('PublicKey'):
                    new_peer_lines.append(f"PublicKey = {public_key}")
                else:
                    new_peer_lines.append(line)
            new_peer = '\n'.join(new_peer_lines)

            cursor.execute("""
                UPDATE peer
                SET raw_peer_block = ?
                WHERE id = ?
            """, (new_peer, peer['id']))

        console.print(f"[green]✓ Keys rotated successfully![/green]")
        console.print(f"\n[bold]Next steps:[/bold]")
        console.print(f"  1. Generate QR code or export config for {peer['name']}")
        console.print(f"  2. Deploy updated coordination server config")

    def _add_preshared_key(self, peer: Dict):
        """Add or update preshared key for peer"""
        action = "Update" if peer.get('preshared_key') else "Add"
        console.print(f"\n[bold yellow]{action} preshared key for {peer['name']}[/bold yellow]")

        if peer.get('preshared_key'):
            console.print("[yellow]This peer already has a preshared key.[/yellow]")
            console.print("Continuing will replace it with a new one.")

        console.print("\nThis will:")
        console.print("  1. Generate new preshared key")
        console.print("  2. Update coordination server peer entry")
        console.print("  3. Update peer client config (if exists)")

        if not Confirm.ask("\nContinue?", default=False):
            console.print("[yellow]Cancelled[/yellow]")
            return

        # Generate preshared key
        preshared_key = generate_preshared_key()
        console.print(f"[green]✓ Generated preshared key[/green]")

        # Update peer in database
        with self.db._connection() as conn:
            cursor = conn.cursor()

            # Update preshared_key field
            cursor.execute("""
                UPDATE peer
                SET preshared_key = ?
                WHERE id = ?
            """, (preshared_key, peer['id']))

            # Update CS peer entry (raw_peer_block) - add/update PresharedKey line
            old_peer_block = peer['raw_peer_block']
            peer_lines = old_peer_block.split('\n')
            new_peer_lines = []
            psk_added = False

            for line in peer_lines:
                # Remove existing PresharedKey line if present
                if line.strip().startswith('PresharedKey'):
                    continue
                new_peer_lines.append(line)
                # Add PresharedKey after PublicKey
                if line.strip().startswith('PublicKey') and not psk_added:
                    new_peer_lines.append(f"PresharedKey = {preshared_key}")
                    psk_added = True

            new_peer_block = '\n'.join(new_peer_lines)

            cursor.execute("""
                UPDATE peer
                SET raw_peer_block = ?
                WHERE id = ?
            """, (new_peer_block, peer['id']))

            # Update client config (raw_interface_block) if it exists
            if peer['raw_interface_block']:
                old_interface = peer['raw_interface_block']
                interface_lines = old_interface.split('\n')
                new_interface_lines = []
                in_peer_section = False
                psk_added_client = False

                for line in interface_lines:
                    # Track if we're in [Peer] section
                    if line.strip().startswith('[Peer]'):
                        in_peer_section = True
                        new_interface_lines.append(line)
                        continue

                    # Remove existing PresharedKey line if present
                    if line.strip().startswith('PresharedKey'):
                        continue

                    new_interface_lines.append(line)

                    # Add PresharedKey after Endpoint in [Peer] section
                    if in_peer_section and line.strip().startswith('Endpoint') and not psk_added_client:
                        new_interface_lines.append(f"PresharedKey = {preshared_key}")
                        psk_added_client = True

                new_interface = '\n'.join(new_interface_lines)

                cursor.execute("""
                    UPDATE peer
                    SET raw_interface_block = ?
                    WHERE id = ?
                """, (new_interface, peer['id']))

        console.print(f"[green]✓ Preshared key {action.lower()}d successfully![/green]")
        console.print(f"\n[bold]Next steps:[/bold]")
        console.print(f"  1. Generate QR code or export config for {peer['name']}")
        console.print(f"  2. Deploy updated coordination server config")

    def _delete_peer(self, peer: Dict):
        """Delete a peer"""
        console.print(f"\n[bold red]Delete peer: {peer['name']}[/bold red]")
        console.print(f"  IPv4: {peer['ipv4_address']}")
        console.print(f"  IPv6: {peer['ipv6_address']}")

        console.print("\n[bold yellow]Warning:[/bold yellow]")
        console.print("  This will permanently delete the peer from the database.")
        console.print("  The peer will be removed from the coordination server config.")
        console.print("  This action cannot be undone.")

        if not Confirm.ask("\n[bold]Are you sure you want to delete this peer?[/bold]", default=False):
            console.print("[yellow]Cancelled[/yellow]")
            return

        # Double confirmation for destructive action
        confirm_name = Prompt.ask(f"Type the peer name '{peer['name']}' to confirm deletion")
        if confirm_name != peer['name']:
            console.print("[red]Name mismatch. Deletion cancelled.[/red]")
            return

        # Delete from database
        with self.db._connection() as conn:
            cursor = conn.cursor()

            # Delete from peer table
            cursor.execute("""
                DELETE FROM peer
                WHERE id = ?
            """, (peer['id'],))

            # Delete from cs_peer_order table
            cursor.execute("""
                DELETE FROM cs_peer_order
                WHERE cs_id = ? AND peer_public_key = ?
            """, (peer['cs_id'], peer['public_key']))

        console.print(f"[green]✓ Peer '{peer['name']}' deleted successfully[/green]")
        console.print(f"\n[bold]Next steps:[/bold]")
        console.print(f"  1. Deploy updated coordination server config to remove peer")
        console.print(f"  2. Revoke access on the physical device")

    def _create_new_peer(self):
        """Create a new peer"""
        console.print("\n[bold cyan]Create New Peer[/bold cyan]")

        cs = self.db.get_coordination_server()
        if not cs:
            console.print("[red]No coordination server found[/red]")
            return

        # Get peer details
        name = Prompt.ask("Peer name (e.g., 'alice-laptop')")

        # Allocate IP addresses
        existing_peers = self.db.get_peers(cs['id'])
        existing_sn = self.db.get_subnet_routers(cs['id'])

        # Extract used IPs
        used_ipv4 = set()
        used_ipv6 = set()

        # CS IPs
        used_ipv4.add(cs['ipv4_address'])
        used_ipv6.add(cs['ipv6_address'])

        # Peer IPs
        for p in existing_peers:
            if p['ipv4_address'] and p['ipv4_address'] != '0.0.0.0':
                used_ipv4.add(p['ipv4_address'])
            if p['ipv6_address'] and p['ipv6_address'] != '::':
                used_ipv6.add(p['ipv6_address'])

        # SN IPs
        for sn in existing_sn:
            used_ipv4.add(sn['ipv4_address'])
            used_ipv6.add(sn['ipv6_address'])

        # Find next available IP
        ipv4_base = ".".join(cs['ipv4_address'].split('.')[:-1])
        ipv6_base = cs['ipv6_address'].rsplit(':', 1)[0]

        next_ipv4 = None
        for i in range(2, 255):
            candidate = f"{ipv4_base}.{i}"
            if candidate not in used_ipv4:
                next_ipv4 = candidate
                break

        next_ipv6 = None
        for i in range(2, 65535):
            candidate = f"{ipv6_base}:{i:x}"
            if candidate not in used_ipv6:
                next_ipv6 = candidate
                break

        if not next_ipv4 or not next_ipv6:
            console.print("[red]No available IP addresses![/red]")
            return

        console.print(f"\n[green]Next available IPs:[/green]")
        console.print(f"  IPv4: {next_ipv4}")
        console.print(f"  IPv6: {next_ipv6}")

        ipv4 = Prompt.ask("IPv4 address", default=next_ipv4)
        ipv6 = Prompt.ask("IPv6 address", default=next_ipv6)

        # Access level
        console.print("\n[bold]Access Level:[/bold]")
        console.print("  [1] Full access")
        console.print("  [2] VPN only")
        console.print("  [3] LAN only")

        access_choice = IntPrompt.ask("Select", default=1)
        access_map = {1: 'full_access', 2: 'vpn_only', 3: 'lan_only'}
        access_level = access_map.get(access_choice, 'full_access')

        # Generate keypair
        private_key, public_key = generate_keypair()

        # Build peer entry for CS
        peer_block = f"[Peer]\n"
        peer_block += f"# {name}\n"
        peer_block += f"PublicKey = {public_key}\n"
        peer_block += f"AllowedIPs = {ipv4}/32, {ipv6}/128\n"

        # Build client config
        client_config = f"[Interface]\n"
        client_config += f"PrivateKey = {private_key}\n"
        client_config += f"Address = {ipv4}/24, {ipv6}/64\n"
        client_config += f"DNS = {cs['ipv4_address']}\n"
        if cs['mtu']:
            client_config += f"MTU = {cs['mtu']}\n"
        client_config += f"\n[Peer]\n"
        client_config += f"PublicKey = {cs['public_key']}\n"
        client_config += f"Endpoint = {cs['endpoint']}\n"

        # Set AllowedIPs based on access level
        if access_level == 'full_access':
            # Get all networks from subnet routers
            all_networks = [cs['network_ipv4'], cs['network_ipv6']]
            for sn in existing_sn:
                lans = self.db.get_sn_lan_networks(sn['id'])
                all_networks.extend(lans)
            allowed_ips = ", ".join(all_networks)
        elif access_level == 'vpn_only':
            allowed_ips = f"{cs['network_ipv4']}, {cs['network_ipv6']}"
        elif access_level == 'lan_only':
            # VPN + all LAN networks
            all_networks = [cs['network_ipv4'], cs['network_ipv6']]
            for sn in existing_sn:
                lans = self.db.get_sn_lan_networks(sn['id'])
                all_networks.extend(lans)
            allowed_ips = ", ".join(all_networks)

        client_config += f"AllowedIPs = {allowed_ips}\n"
        client_config += f"PersistentKeepalive = 25\n"

        # Save to database
        peer_id = self.db.save_peer(
            name=name,
            cs_id=cs['id'],
            public_key=public_key,
            ipv4_address=ipv4,
            ipv6_address=ipv6,
            access_level=access_level,
            raw_peer_block=peer_block,
            private_key=private_key,
            raw_interface_block=client_config,
            persistent_keepalive=25
        )

        # Add to peer order (at the end)
        peer_order = self.db.get_peer_order(cs['id'])
        next_position = len(peer_order) + 1
        self.db.save_peer_order(cs['id'], public_key, next_position, is_subnet_router=False)

        console.print(f"\n[green]✓ Peer '{name}' created successfully![/green]")
        console.print(f"\n[bold]Next steps:[/bold]")
        console.print(f"  1. Export client config or generate QR code")
        console.print(f"  2. Deploy updated coordination server config")

        # Offer to export now
        if Confirm.ask("\nExport client config now?", default=True):
            timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            output_file = self.output_dir / f"{name}-{timestamp}.conf"
            with open(output_file, 'w') as f:
                f.write(client_config)
            output_file.chmod(0o600)
            console.print(f"[green]✓ Exported to {output_file}[/green]")

        if Confirm.ask("Generate QR code?", default=True):
            qr_file = self.output_dir / f"{name}-qr.png"
            qr_ascii = generate_qr_code(client_config, qr_file)
            console.print(f"[green]✓ QR code saved to {qr_file}[/green]")

            if Confirm.ask("Display QR code in terminal?", default=True):
                console.print("\n[dim]Note: Terminal display may not work in all terminal configurations.[/dim]")
                console.print("[dim]If scanning doesn't work, use the PNG file from output/ folder.[/dim]\n")
                console.print(qr_ascii)

    def _deploy_configs(self):
        """Deploy all configs"""
        console.print("\n[bold cyan]Deploy Configurations[/bold cyan]")
        console.print("\nThis will deploy:")
        console.print("  • Coordination server config")
        console.print("  • All subnet router configs (if SSH info available)")

        if not Confirm.ask("\nContinue?", default=False):
            console.print("[yellow]Cancelled[/yellow]")
            return

        # Deploy CS
        self._deploy_cs_config()

        # TODO: Add subnet router deployment once we have SSH info for them


def main():
    parser = argparse.ArgumentParser(
        description="Maintenance mode for WireGuard Friend"
    )
    parser.add_argument(
        "--db",
        type=Path,
        default=Path("wg-friend.db"),
        help="SQLite database path"
    )

    args = parser.parse_args()

    maintainer = WireGuardMaintainer(args.db)
    maintainer.run()


if __name__ == "__main__":
    main()
