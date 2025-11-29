"""
Shell Command Parser for PostUp/PostDown

Parses shell commands into structured AST for database storage.
This eliminates the need for raw text blocks.

Supported command types:
- iptables (full rule decomposition)
- ip (route, addr, link commands)
- sysctl (kernel parameters)
- Custom (fallback for unparseable commands)
"""

import re
import logging
import shlex
from typing import List, Dict, Optional, Tuple, Any
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class CommandKind(Enum):
    """Type of shell command"""
    IPTABLES = "iptables"
    IP6TABLES = "ip6tables"
    SYSCTL = "sysctl"
    IP = "ip"
    CUSTOM = "custom"


@dataclass
class ParsedCommand:
    """Base class for parsed commands"""
    kind: CommandKind
    original_text: str


@dataclass
class IptablesCommand(ParsedCommand):
    """Parsed iptables command"""
    table: str  # filter, nat, mangle, raw
    chain: str  # INPUT, FORWARD, POSTROUTING, etc.
    action: str  # -A, -I, -D, -R
    components: List[Tuple[str, Optional[str]]]  # [(flag, value), ...]

    def __init__(self, original_text: str, table: str, chain: str, action: str, components: List[Tuple[str, Optional[str]]]):
        super().__init__(CommandKind.IPTABLES, original_text)
        self.table = table
        self.chain = chain
        self.action = action
        self.components = components


@dataclass
class SysctlCommand(ParsedCommand):
    """Parsed sysctl command"""
    parameter: str
    value: str
    write_flag: bool

    def __init__(self, original_text: str, parameter: str, value: str, write_flag: bool):
        super().__init__(CommandKind.SYSCTL, original_text)
        self.parameter = parameter
        self.value = value
        self.write_flag = write_flag


@dataclass
class IpCommand(ParsedCommand):
    """Parsed ip command"""
    subcommand: str  # route, addr, link
    action: str  # add, del, show, set
    parameters: Dict[str, Any]

    def __init__(self, original_text: str, subcommand: str, action: str, parameters: Dict[str, Any]):
        super().__init__(CommandKind.IP, original_text)
        self.subcommand = subcommand
        self.action = action
        self.parameters = parameters


@dataclass
class CustomCommand(ParsedCommand):
    """Unparseable command stored as-is"""
    reason: str  # Why couldn't we parse it?

    def __init__(self, original_text: str, reason: str):
        super().__init__(CommandKind.CUSTOM, original_text)
        self.reason = reason


class ShellCommandParser:
    """Parse PostUp/PostDown shell commands into structured AST"""

    def parse_command(self, command_text: str) -> ParsedCommand:
        """
        Parse a shell command into structured form.

        Args:
            command_text: Raw shell command string

        Returns:
            ParsedCommand subclass based on command type
        """
        command_text = command_text.strip()

        # Try parsing as iptables
        if command_text.startswith(('iptables ', 'ip6tables ')):
            try:
                return self._parse_iptables(command_text)
            except Exception as e:
                logger.warning(f"Failed to parse iptables command: {e}")
                return CustomCommand(command_text, f"iptables parse error: {e}")

        # Try parsing as sysctl
        if command_text.startswith('sysctl '):
            try:
                return self._parse_sysctl(command_text)
            except Exception as e:
                logger.warning(f"Failed to parse sysctl command: {e}")
                return CustomCommand(command_text, f"sysctl parse error: {e}")

        # Try parsing as ip command
        if command_text.startswith('ip '):
            try:
                return self._parse_ip(command_text)
            except Exception as e:
                logger.warning(f"Failed to parse ip command: {e}")
                return CustomCommand(command_text, f"ip parse error: {e}")

        # Fallback: custom command
        return CustomCommand(command_text, "unrecognized command type")

    def _parse_iptables(self, command_text: str) -> IptablesCommand:
        """
        Parse iptables command into structured components.

        Example:
            iptables -t nat -A POSTROUTING -s 10.66.0.0/24 -o eth0 -j MASQUERADE

        Returns:
            IptablesCommand with table=nat, chain=POSTROUTING, action=-A, components=[...]
        """
        # Use shlex to handle quoted arguments
        try:
            tokens = shlex.split(command_text)
        except ValueError as e:
            raise ValueError(f"Failed to tokenize command: {e}")

        if not tokens or tokens[0] not in ('iptables', 'ip6tables'):
            raise ValueError("Not an iptables command")

        # Default table is 'filter'
        table = 'filter'
        chain = None
        action = None
        components = []

        i = 1  # Skip 'iptables'
        while i < len(tokens):
            token = tokens[i]

            # Table specification
            if token in ('-t', '--table'):
                if i + 1 >= len(tokens):
                    raise ValueError("Missing table name after -t")
                table = tokens[i + 1]
                i += 2
                continue

            # Chain action
            if token in ('-A', '--append', '-I', '--insert', '-D', '--delete', '-R', '--replace'):
                if i + 1 >= len(tokens):
                    raise ValueError(f"Missing chain name after {token}")
                action = token
                chain = tokens[i + 1]
                i += 2
                continue

            # Match options and targets
            if token.startswith('-'):
                # Some flags have values, some don't
                if i + 1 < len(tokens) and not tokens[i + 1].startswith('-'):
                    # Flag with value
                    components.append((token, tokens[i + 1]))
                    i += 2
                else:
                    # Flag without value (boolean flag)
                    components.append((token, None))
                    i += 1
            else:
                # Standalone value (shouldn't happen in well-formed iptables)
                components.append(('', token))
                i += 1

        if not chain or not action:
            raise ValueError("Missing chain or action in iptables command")

        return IptablesCommand(command_text, table, chain, action, components)

    def _parse_sysctl(self, command_text: str) -> SysctlCommand:
        """
        Parse sysctl command.

        Examples:
            sysctl -w net.ipv4.ip_forward=1
            sysctl net.ipv4.ip_forward=1
        """
        tokens = shlex.split(command_text)

        if not tokens or tokens[0] != 'sysctl':
            raise ValueError("Not a sysctl command")

        write_flag = False
        parameter = None
        value = None

        i = 1
        while i < len(tokens):
            token = tokens[i]

            if token in ('-w', '--write'):
                write_flag = True
                i += 1
                continue

            # Parameter=value format
            if '=' in token:
                parts = token.split('=', 1)
                parameter = parts[0]
                value = parts[1]
                i += 1
                continue

            # Parameter without value (for reading)
            if parameter is None:
                parameter = token
                i += 1
                continue

            i += 1

        if not parameter:
            raise ValueError("Missing parameter in sysctl command")

        # For write operations, value is required
        if write_flag and not value:
            raise ValueError("sysctl -w requires parameter=value format")

        return SysctlCommand(command_text, parameter, value or '', write_flag)

    def _parse_ip(self, command_text: str) -> IpCommand:
        """
        Parse ip command.

        Examples:
            ip route add 192.168.1.0/24 via 10.66.0.20
            ip addr add 10.66.0.1/24 dev wg0
            ip link set wg0 up
        """
        tokens = shlex.split(command_text)

        if not tokens or tokens[0] != 'ip':
            raise ValueError("Not an ip command")

        if len(tokens) < 3:
            raise ValueError("Incomplete ip command")

        subcommand = tokens[1]  # route, addr, link, etc.
        action = tokens[2]  # add, del, show, set, etc.

        # Parse remaining tokens into key-value pairs
        parameters = {}
        i = 3
        current_key = None

        while i < len(tokens):
            token = tokens[i]

            # Keywords that take values
            if token in ('via', 'dev', 'src', 'to', 'from', 'table', 'metric', 'scope'):
                current_key = token
                if i + 1 < len(tokens):
                    parameters[current_key] = tokens[i + 1]
                    i += 2
                else:
                    raise ValueError(f"Missing value for {token}")
            # Boolean flags
            elif token in ('up', 'down'):
                parameters[token] = True
                i += 1
            # Default: positional argument (usually the target)
            else:
                if 'target' not in parameters:
                    parameters['target'] = token
                else:
                    # Multiple positional args - store as list
                    if not isinstance(parameters['target'], list):
                        parameters['target'] = [parameters['target']]
                    parameters['target'].append(token)
                i += 1

        return IpCommand(command_text, subcommand, action, parameters)

    def parse_multiline(self, commands: List[str]) -> List[ParsedCommand]:
        """
        Parse multiple commands (e.g., all PostUp rules).

        Args:
            commands: List of command strings

        Returns:
            List of ParsedCommand objects
        """
        parsed = []
        for cmd in commands:
            cmd = cmd.strip()
            if cmd:
                parsed.append(self.parse_command(cmd))
        return parsed


def demonstrate_parser():
    """Demonstrate shell command parsing"""
    parser = ShellCommandParser()

    test_commands = [
        "iptables -t nat -A POSTROUTING -s 10.66.0.0/24 -o eth0 -j MASQUERADE",
        "iptables -A FORWARD -i wg0 -j ACCEPT",
        "iptables -A FORWARD -o wg0 -j ACCEPT",
        "sysctl -w net.ipv4.ip_forward=1",
        "ip route add 192.168.1.0/24 via 10.66.0.20",
        "ip link set wg0 up",
        "echo 'Hello World'",  # Should become CustomCommand
    ]

    print("=== Shell Command Parser Demo ===\n")

    for cmd in test_commands:
        print(f"Original: {cmd}")
        parsed = parser.parse_command(cmd)
        print(f"Type: {parsed.kind.value}")

        if isinstance(parsed, IptablesCommand):
            print(f"  Table: {parsed.table}")
            print(f"  Chain: {parsed.chain}")
            print(f"  Action: {parsed.action}")
            print(f"  Components: {parsed.components}")
        elif isinstance(parsed, SysctlCommand):
            print(f"  Parameter: {parsed.parameter}")
            print(f"  Value: {parsed.value}")
            print(f"  Write: {parsed.write_flag}")
        elif isinstance(parsed, IpCommand):
            print(f"  Subcommand: {parsed.subcommand}")
            print(f"  Action: {parsed.action}")
            print(f"  Parameters: {parsed.parameters}")
        elif isinstance(parsed, CustomCommand):
            print(f"  Reason: {parsed.reason}")

        print()


if __name__ == "__main__":
    demonstrate_parser()
