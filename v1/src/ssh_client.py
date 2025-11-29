"""SSH client for WireGuard configuration management"""

import logging
from pathlib import Path
from typing import Optional, Tuple
import paramiko
from paramiko import SSHClient as ParamikoSSHClient, AutoAddPolicy


logger = logging.getLogger(__name__)


class SSHClient:
    """Simplified SSH client for WireGuard operations"""

    def __init__(self, hostname: str, username: str, ssh_key_path: str, port: int = 22):
        self.hostname = hostname
        self.username = username
        self.ssh_key_path = Path(ssh_key_path).expanduser()
        self.port = port
        self.client: Optional[ParamikoSSHClient] = None

    def connect(self) -> bool:
        """Establish SSH connection"""
        try:
            self.client = ParamikoSSHClient()
            self.client.set_missing_host_key_policy(AutoAddPolicy())

            logger.info(f"Connecting to {self.hostname}:{self.port} as {self.username}")

            self.client.connect(
                hostname=self.hostname,
                port=self.port,
                username=self.username,
                key_filename=str(self.ssh_key_path),
                timeout=10,
                banner_timeout=30,
            )

            logger.info(f"Connected to {self.hostname}")
            return True

        except Exception as e:
            logger.error(f"Failed to connect to {self.hostname}: {e}")
            return False

    def disconnect(self):
        """Close SSH connection"""
        if self.client:
            self.client.close()
            logger.info(f"Disconnected from {self.hostname}")

    def execute_command(self, command: str, use_sudo: bool = False) -> Tuple[int, str, str]:
        """
        Execute command on remote host

        Args:
            command: Command to execute
            use_sudo: Prefix command with sudo

        Returns:
            (exit_code, stdout, stderr)
        """
        if not self.client:
            raise RuntimeError("Not connected to host")

        try:
            if use_sudo:
                command = f"sudo {command}"

            logger.debug(f"Executing: {command}")
            stdin, stdout, stderr = self.client.exec_command(command)

            exit_code = stdout.channel.recv_exit_status()
            stdout_text = stdout.read().decode('utf-8', errors='replace')
            stderr_text = stderr.read().decode('utf-8', errors='replace')

            return exit_code, stdout_text, stderr_text

        except Exception as e:
            logger.error(f"Command execution failed: {e}")
            return 1, "", str(e)

    def read_file(self, remote_path: str, use_sudo: bool = True) -> Optional[str]:
        """
        Read file contents from remote host

        Args:
            remote_path: Path to file on remote host
            use_sudo: Use sudo to read file (needed for /etc/wireguard/)

        Returns:
            File contents as string, or None on error
        """
        cmd = f"cat {remote_path}"
        exit_code, stdout, stderr = self.execute_command(cmd, use_sudo=use_sudo)

        if exit_code != 0:
            logger.error(f"Failed to read {remote_path}: {stderr}")
            return None

        return stdout

    def write_file(self, remote_path: str, content: str, use_sudo: bool = True, mode: str = "600") -> bool:
        """
        Write file to remote host

        Args:
            remote_path: Path to file on remote host
            content: File contents to write
            use_sudo: Use sudo to write file
            mode: File permissions (chmod format)

        Returns:
            True if successful
        """
        import tempfile
        import time

        try:
            # Create temp file on remote
            temp_path = f"/tmp/wg-friend-{int(time.time())}.tmp"

            # Write content to temp file
            cmd = f"cat > {temp_path} << 'EOFWGFRIEND'\n{content}\nEOFWGFRIEND"
            exit_code, _, stderr = self.execute_command(cmd, use_sudo=False)

            if exit_code != 0:
                logger.error(f"Failed to write temp file: {stderr}")
                return False

            # Move to final location with sudo
            exit_code, _, stderr = self.execute_command(
                f"cp {temp_path} {remote_path}",
                use_sudo=use_sudo
            )

            if exit_code != 0:
                logger.error(f"Failed to copy to {remote_path}: {stderr}")
                return False

            # Set permissions
            self.execute_command(f"chmod {mode} {remote_path}", use_sudo=use_sudo)

            # Clean up temp file
            self.execute_command(f"rm -f {temp_path}", use_sudo=False)

            logger.info(f"Wrote file to {remote_path}")
            return True

        except Exception as e:
            logger.error(f"Failed to write file: {e}")
            return False

    def restart_wireguard(self, interface: str = "wg0") -> bool:
        """
        Restart WireGuard interface

        Args:
            interface: WireGuard interface name (default: wg0)

        Returns:
            True if successful
        """
        exit_code, _, stderr = self.execute_command(
            f"systemctl restart wg-quick@{interface}",
            use_sudo=True
        )

        if exit_code != 0:
            logger.error(f"Failed to restart WireGuard: {stderr}")
            return False

        logger.info(f"Restarted WireGuard interface {interface}")
        return True

    def run_command(self, command: str, use_sudo: bool = True) -> str:
        """
        Alias for execute_command that returns stdout (for compatibility)

        Args:
            command: Command to execute
            use_sudo: Prefix command with sudo

        Returns:
            stdout output as string
        """
        exit_code, stdout, stderr = self.execute_command(command, use_sudo=use_sudo)

        if exit_code != 0:
            logger.warning(f"Command failed with exit code {exit_code}: {stderr}")

        return stdout

    def upload_file(self, local_path: str, remote_path: str, use_sudo: bool = False, mode: str = "644") -> bool:
        """
        Upload file to remote host

        Args:
            local_path: Path to local file
            remote_path: Destination path on remote host
            use_sudo: Use sudo for final move (not used for initial upload)
            mode: File permissions (default: 644)

        Returns:
            True if successful
        """
        try:
            # Read local file
            with open(local_path, 'r') as f:
                content = f.read()

            # Write to remote (write_file handles sudo internally)
            return self.write_file(remote_path, content, use_sudo=use_sudo, mode=mode)

        except Exception as e:
            logger.error(f"Failed to upload file: {e}")
            return False

    def __enter__(self):
        """Context manager entry"""
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.disconnect()
