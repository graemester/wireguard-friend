"""
V2 Semantic Pattern Recognition

Recognizes standard PostUp/PostDown patterns from real-world configs.
Based on actual patterns from import/ directory.

Key insight: Most PostUp/PostDown are bog-standard and recognizable.
We build a library of known patterns and match against them.
"""

import re
import logging
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class CommandScope(Enum):
    """Scope of a command pair"""
    ENVIRONMENT_WIDE = "environment-wide"  # Affects all traffic
    PEER_SPECIFIC = "peer-specific"        # Specific to one peer


@dataclass
class CommandPair:
    """A semantically matched PostUp/PostDown pair"""
    pattern_name: str
    rationale: str
    scope: CommandScope
    up_commands: List[str]
    down_commands: List[str]
    variables: Dict[str, str]  # Extracted variables
    execution_order: int = 0


@dataclass
class CommandSingleton:
    """A PostUp command without a matching PostDown"""
    pattern_name: str
    rationale: str
    scope: CommandScope
    up_commands: List[str]
    variables: Dict[str, str]
    execution_order: int = 0


class PatternLibrary:
    """Library of known PostUp/PostDown patterns"""

    # Pattern definitions with regex templates
    PATTERNS = {
        "nat_masquerade_ipv4": {
            "rationale": "NAT for VPN subnet (IPv4)",
            "scope": CommandScope.ENVIRONMENT_WIDE,
            "up_regex": [
                r"iptables -A FORWARD -i wg0 -j ACCEPT",
                r"iptables -t nat -A POSTROUTING -o (?P<wan_iface>\S+) -j MASQUERADE"
            ],
            "down_regex": [
                r"iptables -D FORWARD -i wg0 -j ACCEPT",
                r"iptables -t nat -D POSTROUTING -o (?P<wan_iface>\S+) -j MASQUERADE"
            ]
        },

        "nat_masquerade_ipv6": {
            "rationale": "NAT for VPN subnet (IPv6)",
            "scope": CommandScope.ENVIRONMENT_WIDE,
            "up_regex": [
                r"ip6tables -A FORWARD -i wg0 -j ACCEPT",
                r"ip6tables -t nat -A POSTROUTING -o (?P<wan_iface>\S+) -j MASQUERADE"
            ],
            "down_regex": [
                r"ip6tables -D FORWARD -i wg0 -j ACCEPT",
                r"ip6tables -t nat -D POSTROUTING -o (?P<wan_iface>\S+) -j MASQUERADE"
            ]
        },

        "bidirectional_forwarding_ipv4": {
            "rationale": "Bidirectional forwarding and NAT for LAN interface (IPv4)",
            "scope": CommandScope.ENVIRONMENT_WIDE,
            "up_regex": [
                r"iptables -A FORWARD -i wg0 -o (?P<lan_iface>\S+) -j ACCEPT",
                r"iptables -A FORWARD -i (?P<lan_iface>\S+) -o wg0 -j ACCEPT",
                r"iptables -t nat -A POSTROUTING -o (?P<lan_iface>\S+) -s (?P<vpn_subnet>\S+) -j MASQUERADE"
            ],
            "down_regex": [
                r"iptables -D FORWARD -i wg0 -o (?P<lan_iface>\S+) -j ACCEPT",
                r"iptables -D FORWARD -i (?P<lan_iface>\S+) -o wg0 -j ACCEPT",
                r"iptables -t nat -D POSTROUTING -o (?P<lan_iface>\S+) -s (?P<vpn_subnet>\S+) -j MASQUERADE"
            ]
        },

        "bidirectional_forwarding_ipv6": {
            "rationale": "Bidirectional forwarding for LAN interface (IPv6)",
            "scope": CommandScope.ENVIRONMENT_WIDE,
            "up_regex": [
                r"ip6tables -A FORWARD -i wg0 -o (?P<lan_iface>\S+) -j ACCEPT",
                r"ip6tables -A FORWARD -i (?P<lan_iface>\S+) -o wg0 -j ACCEPT"
            ],
            "down_regex": [
                r"ip6tables -D FORWARD -i wg0 -o (?P<lan_iface>\S+) -j ACCEPT",
                r"ip6tables -D FORWARD -i (?P<lan_iface>\S+) -o wg0 -j ACCEPT"
            ]
        },

        "mss_clamping_ipv4": {
            "rationale": "MSS clamping to fix MTU/fragmentation issues (IPv4)",
            "scope": CommandScope.ENVIRONMENT_WIDE,
            "up_regex": [
                r"iptables -t mangle -A FORWARD -i wg0 -o (?P<iface>\S+) -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu",
                r"iptables -t mangle -A FORWARD -i (?P<iface>\S+) -o wg0 -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu"
            ],
            "down_regex": [
                r"iptables -t mangle -D FORWARD -i wg0 -o (?P<iface>\S+) -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu",
                r"iptables -t mangle -D FORWARD -i (?P<iface>\S+) -o wg0 -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu"
            ]
        },

        "mss_clamping_ipv6": {
            "rationale": "MSS clamping to fix MTU/fragmentation issues (IPv6)",
            "scope": CommandScope.ENVIRONMENT_WIDE,
            "up_regex": [
                r"ip6tables -t mangle -A FORWARD -i wg0 -o (?P<iface>\S+) -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu",
                r"ip6tables -t mangle -A FORWARD -i (?P<iface>\S+) -o wg0 -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu"
            ],
            "down_regex": [
                r"ip6tables -t mangle -D FORWARD -i wg0 -o (?P<iface>\S+) -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu",
                r"ip6tables -t mangle -D FORWARD -i (?P<iface>\S+) -o wg0 -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu"
            ]
        },

        "allow_service_port": {
            "rationale": "Allow service connections over WireGuard",
            "scope": CommandScope.ENVIRONMENT_WIDE,
            "up_regex": [
                r"iptables -I INPUT -i wg0 -p (?P<protocol>\S+) --dport (?P<port>\d+) -j ACCEPT"
            ],
            "down_regex": [
                r"iptables -D INPUT -i wg0 -p (?P<protocol>\S+) --dport (?P<port>\d+) -j ACCEPT"
            ]
        }
    }

    # Singleton patterns (no PostDown)
    SINGLETON_PATTERNS = {
        "enable_ip_forwarding": {
            "rationale": "Enable kernel IP forwarding",
            "scope": CommandScope.ENVIRONMENT_WIDE,
            "up_regex": [
                r"sysctl -w net\.ipv4\.ip_forward=1",
                r"sysctl -w net\.ipv6\.conf\.all\.forwarding=1"
            ]
        }
    }


class PatternRecognizer:
    """Recognizes command patterns and pairs PostUp with PostDown"""

    def __init__(self):
        self.library = PatternLibrary()

    def recognize_pairs(
        self,
        postup_lines: List[str],
        postdown_lines: List[str]
    ) -> Tuple[List[CommandPair], List[CommandSingleton], List[str]]:
        """
        Recognize command pairs and singletons from PostUp/PostDown lists.

        Args:
            postup_lines: List of PostUp commands
            postdown_lines: List of PostDown commands

        Returns:
            (pairs, singletons, unrecognized_commands)
        """
        pairs = []
        singletons = []
        unrecognized = []

        used_up = set()
        used_down = set()

        # Try to match each pattern
        for pattern_name, pattern_def in self.library.PATTERNS.items():
            # Try to find this pattern in the commands
            pair = self._match_pattern(
                pattern_name,
                pattern_def,
                postup_lines,
                postdown_lines
            )

            if pair:
                pairs.append(pair)
                # Mark commands as used
                for cmd in pair.up_commands:
                    used_up.add(cmd)
                for cmd in pair.down_commands:
                    used_down.add(cmd)

        # Check for singletons
        remaining_up = [cmd for cmd in postup_lines if cmd not in used_up]

        for pattern_name, pattern_def in self.library.SINGLETON_PATTERNS.items():
            singleton = self._match_singleton_pattern(
                pattern_name,
                pattern_def,
                remaining_up
            )

            if singleton:
                singletons.append(singleton)
                for cmd in singleton.up_commands:
                    used_up.add(cmd)

        # Anything left is unrecognized
        unrecognized = [cmd for cmd in postup_lines if cmd not in used_up]

        return pairs, singletons, unrecognized

    def _match_pattern(
        self,
        pattern_name: str,
        pattern_def: Dict,
        postup_lines: List[str],
        postdown_lines: List[str]
    ) -> Optional[CommandPair]:
        """Try to match a paired pattern"""
        up_regexes = pattern_def["up_regex"]
        down_regexes = pattern_def["down_regex"]

        # Try to find all up commands matching the pattern
        up_matches = []
        up_vars = {}

        for regex in up_regexes:
            found = False
            for cmd in postup_lines:
                match = re.fullmatch(regex, cmd.strip())
                if match:
                    up_matches.append(cmd.strip())
                    up_vars.update(match.groupdict())
                    found = True
                    break

            if not found:
                # This pattern doesn't match
                return None

        # Try to find matching down commands
        down_matches = []
        down_vars = {}

        for regex in down_regexes:
            found = False
            for cmd in postdown_lines:
                match = re.fullmatch(regex, cmd.strip())
                if match:
                    down_matches.append(cmd.strip())
                    down_vars.update(match.groupdict())
                    found = True
                    break

            if not found:
                # Pattern matched up but not down - incomplete pair
                return None

        # Check that variables are consistent
        if up_vars != down_vars:
            logger.warning(f"Variable mismatch in pattern {pattern_name}: {up_vars} != {down_vars}")

        # Success! Create the pair
        return CommandPair(
            pattern_name=pattern_name,
            rationale=pattern_def["rationale"],
            scope=pattern_def["scope"],
            up_commands=up_matches,
            down_commands=down_matches,
            variables=up_vars
        )

    def _match_singleton_pattern(
        self,
        pattern_name: str,
        pattern_def: Dict,
        postup_lines: List[str]
    ) -> Optional[CommandSingleton]:
        """Try to match a singleton pattern"""
        up_regexes = pattern_def["up_regex"]

        up_matches = []
        up_vars = {}

        for regex in up_regexes:
            found = False
            for cmd in postup_lines:
                match = re.fullmatch(regex, cmd.strip())
                if match:
                    up_matches.append(cmd.strip())
                    up_vars.update(match.groupdict())
                    found = True
                    break

            if not found:
                return None

        return CommandSingleton(
            pattern_name=pattern_name,
            rationale=pattern_def["rationale"],
            scope=pattern_def["scope"],
            up_commands=up_matches,
            variables=up_vars
        )


def demonstrate_patterns():
    """Demonstrate pattern recognition on real configs"""

    # From coordination.conf
    cs_postup = [
        "iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE",
        "ip6tables -A FORWARD -i wg0 -j ACCEPT; ip6tables -t nat -A POSTROUTING -o eth0 -j MASQUERADE",
        "iptables -I INPUT -i wg0 -p tcp --dport 5432 -j ACCEPT"
    ]

    cs_postdown = [
        "iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE",
        "ip6tables -D FORWARD -i wg0 -j ACCEPT; ip6tables -t nat -D POSTROUTING -o eth0 -j MASQUERADE",
        "iptables -D INPUT -i wg0 -p tcp --dport 5432 -j ACCEPT"
    ]

    # Split compound commands (semicolon-separated)
    cs_postup_split = []
    for cmd in cs_postup:
        cs_postup_split.extend([c.strip() for c in cmd.split(';')])

    cs_postdown_split = []
    for cmd in cs_postdown:
        cs_postdown_split.extend([c.strip() for c in cmd.split(';')])

    # From wg0.conf (subnet router)
    snr_postup = [
        "sysctl -w net.ipv4.ip_forward=1",
        "sysctl -w net.ipv6.conf.all.forwarding=1",
        "iptables -A FORWARD -i wg0 -o enp1s0 -j ACCEPT",
        "iptables -A FORWARD -i enp1s0 -o wg0 -j ACCEPT",
        "iptables -t nat -A POSTROUTING -o enp1s0 -s 10.66.0.0/24 -j MASQUERADE",
        "ip6tables -A FORWARD -i wg0 -o enp1s0 -j ACCEPT",
        "ip6tables -A FORWARD -i enp1s0 -o wg0 -j ACCEPT",
        "iptables -t mangle -A FORWARD -i wg0 -o enp1s0 -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu",
        "iptables -t mangle -A FORWARD -i enp1s0 -o wg0 -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu",
        "ip6tables -t mangle -A FORWARD -i wg0 -o enp1s0 -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu",
        "ip6tables -t mangle -A FORWARD -i enp1s0 -o wg0 -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu"
    ]

    snr_postdown = [
        "iptables -D FORWARD -i wg0 -o enp1s0 -j ACCEPT",
        "iptables -D FORWARD -i enp1s0 -o wg0 -j ACCEPT",
        "iptables -t nat -D POSTROUTING -o enp1s0 -s 10.66.0.0/24 -j MASQUERADE",
        "ip6tables -D FORWARD -i wg0 -o enp1s0 -j ACCEPT",
        "ip6tables -D FORWARD -i enp1s0 -o wg0 -j ACCEPT",
        "iptables -t mangle -D FORWARD -i wg0 -o enp1s0 -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu",
        "iptables -t mangle -D FORWARD -i enp1s0 -o wg0 -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu",
        "ip6tables -t mangle -D FORWARD -i wg0 -o enp1s0 -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu",
        "ip6tables -t mangle -D FORWARD -i enp1s0 -o wg0 -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu"
    ]

    recognizer = PatternRecognizer()

    print("=== Pattern Recognition Demo ===\n")

    print("Coordination Server:")
    pairs, singletons, unrecognized = recognizer.recognize_pairs(cs_postup_split, cs_postdown_split)
    print(f"  Pairs: {len(pairs)}")
    for pair in pairs:
        print(f"    - {pair.pattern_name}: {pair.rationale}")
        print(f"      Variables: {pair.variables}")
    print(f"  Unrecognized: {len(unrecognized)}")
    for cmd in unrecognized:
        print(f"    - {cmd}")

    print("\nSubnet Router:")
    pairs, singletons, unrecognized = recognizer.recognize_pairs(snr_postup, snr_postdown)
    print(f"  Pairs: {len(pairs)}")
    for pair in pairs:
        print(f"    - {pair.pattern_name}: {pair.rationale}")
        print(f"      Variables: {pair.variables}")
    print(f"  Singletons: {len(singletons)}")
    for singleton in singletons:
        print(f"    - {singleton.pattern_name}: {singleton.rationale}")
    print(f"  Unrecognized: {len(unrecognized)}")


if __name__ == "__main__":
    demonstrate_patterns()
