"""
WireGuard Friend Split DNS with Fallback

Provides intelligent DNS configuration with fallback chains for WireGuard peers.

Features:
- Primary and secondary DNS configuration per entity
- Domain-specific DNS overrides (e.g., internal domains to internal DNS)
- Automatic fallback configuration
- systemd-resolved integration (resolvectl)
- DNS leak prevention options

Schema Additions:
    CREATE TABLE dns_config (
        id INTEGER PRIMARY KEY,
        entity_type TEXT NOT NULL,      -- 'cs', 'sr', 'remote', 'exit'
        entity_id INTEGER NOT NULL,
        primary_dns TEXT,               -- Primary DNS server
        secondary_dns TEXT,             -- Fallback DNS server
        domain_overrides TEXT,          -- JSON: {"home.lan": "192.168.1.1"}
        dns_search_domains TEXT,        -- JSON: ["home.lan", "office.local"]
        prevent_leaks BOOLEAN DEFAULT 1,  -- Block non-tunnel DNS
        use_systemd_resolved BOOLEAN DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(entity_type, entity_id)
    );

Usage:
    from v1.split_dns import DNSManager

    dns = DNSManager(db_path)
    dns.set_dns_config('remote', 1, primary='10.66.0.1', secondary='1.1.1.1')
    dns.add_domain_override('remote', 1, 'home.lan', '192.168.1.1')

    # Generate config snippets
    dns_config = dns.generate_dns_config('remote', 1)
"""

import json
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Dict, List, Tuple
from enum import Enum


class DNSProvider(Enum):
    """Well-known DNS providers."""
    CLOUDFLARE = "1.1.1.1"
    CLOUDFLARE_IPV6 = "2606:4700:4700::1111"
    GOOGLE = "8.8.8.8"
    GOOGLE_IPV6 = "2001:4860:4860::8888"
    QUAD9 = "9.9.9.9"
    QUAD9_IPV6 = "2620:fe::fe"
    OPENDNS = "208.67.222.222"
    ADGUARD = "94.140.14.14"
    LOCAL = "127.0.0.1"


@dataclass
class DNSConfig:
    """DNS configuration for an entity."""
    entity_type: str
    entity_id: int
    primary_dns: Optional[str] = None
    secondary_dns: Optional[str] = None
    domain_overrides: Dict[str, str] = field(default_factory=dict)
    dns_search_domains: List[str] = field(default_factory=list)
    prevent_leaks: bool = True
    use_systemd_resolved: bool = False
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    def to_dict(self) -> Dict:
        return {
            'entity_type': self.entity_type,
            'entity_id': self.entity_id,
            'primary_dns': self.primary_dns,
            'secondary_dns': self.secondary_dns,
            'domain_overrides': self.domain_overrides,
            'dns_search_domains': self.dns_search_domains,
            'prevent_leaks': self.prevent_leaks,
            'use_systemd_resolved': self.use_systemd_resolved,
        }


@dataclass
class DNSGeneratedConfig:
    """Generated DNS configuration for WireGuard."""
    dns_line: str                       # DNS = x.x.x.x, y.y.y.y
    postup_commands: List[str]          # PostUp commands for advanced DNS
    postdown_commands: List[str]        # PostDown cleanup commands
    notes: List[str]                    # Explanatory notes

    def format_for_config(self) -> str:
        """Format for inclusion in WireGuard config."""
        lines = []
        if self.dns_line:
            lines.append(self.dns_line)
        for cmd in self.postup_commands:
            lines.append(f"PostUp = {cmd}")
        for cmd in self.postdown_commands:
            lines.append(f"PostDown = {cmd}")
        return '\n'.join(lines)


class DNSManager:
    """Manages DNS configurations for WireGuard entities."""

    DNS_CONFIG_TABLE = """
    CREATE TABLE IF NOT EXISTS dns_config (
        id INTEGER PRIMARY KEY,
        entity_type TEXT NOT NULL,
        entity_id INTEGER NOT NULL,
        primary_dns TEXT,
        secondary_dns TEXT,
        domain_overrides TEXT DEFAULT '{}',
        dns_search_domains TEXT DEFAULT '[]',
        prevent_leaks BOOLEAN DEFAULT 1,
        use_systemd_resolved BOOLEAN DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(entity_type, entity_id)
    )
    """

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._ensure_table()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _ensure_table(self) -> None:
        """Ensure DNS config table exists."""
        conn = self._get_conn()
        try:
            conn.execute(self.DNS_CONFIG_TABLE)
            conn.commit()
        finally:
            conn.close()

    def set_dns_config(
        self,
        entity_type: str,
        entity_id: int,
        primary: Optional[str] = None,
        secondary: Optional[str] = None,
        prevent_leaks: bool = True,
        use_systemd_resolved: bool = False,
    ) -> DNSConfig:
        """
        Set DNS configuration for an entity.

        Args:
            entity_type: Type of entity ('cs', 'sr', 'remote', 'exit')
            entity_id: ID of the entity
            primary: Primary DNS server IP
            secondary: Secondary/fallback DNS server IP
            prevent_leaks: Block DNS queries outside tunnel
            use_systemd_resolved: Use systemd-resolved for DNS

        Returns:
            DNSConfig object
        """
        conn = self._get_conn()
        try:
            # Check if config exists
            existing = conn.execute("""
                SELECT id, domain_overrides, dns_search_domains
                FROM dns_config
                WHERE entity_type = ? AND entity_id = ?
            """, (entity_type, entity_id)).fetchone()

            if existing:
                # Update existing
                conn.execute("""
                    UPDATE dns_config SET
                        primary_dns = ?,
                        secondary_dns = ?,
                        prevent_leaks = ?,
                        use_systemd_resolved = ?,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE entity_type = ? AND entity_id = ?
                """, (primary, secondary, prevent_leaks, use_systemd_resolved,
                      entity_type, entity_id))
                domain_overrides = json.loads(existing['domain_overrides'] or '{}')
                search_domains = json.loads(existing['dns_search_domains'] or '[]')
            else:
                # Insert new
                conn.execute("""
                    INSERT INTO dns_config
                    (entity_type, entity_id, primary_dns, secondary_dns,
                     prevent_leaks, use_systemd_resolved)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (entity_type, entity_id, primary, secondary,
                      prevent_leaks, use_systemd_resolved))
                domain_overrides = {}
                search_domains = []

            conn.commit()

            return DNSConfig(
                entity_type=entity_type,
                entity_id=entity_id,
                primary_dns=primary,
                secondary_dns=secondary,
                domain_overrides=domain_overrides,
                dns_search_domains=search_domains,
                prevent_leaks=prevent_leaks,
                use_systemd_resolved=use_systemd_resolved,
            )
        finally:
            conn.close()

    def get_dns_config(self, entity_type: str, entity_id: int) -> Optional[DNSConfig]:
        """Get DNS configuration for an entity."""
        conn = self._get_conn()
        try:
            row = conn.execute("""
                SELECT * FROM dns_config
                WHERE entity_type = ? AND entity_id = ?
            """, (entity_type, entity_id)).fetchone()

            if not row:
                return None

            return DNSConfig(
                entity_type=row['entity_type'],
                entity_id=row['entity_id'],
                primary_dns=row['primary_dns'],
                secondary_dns=row['secondary_dns'],
                domain_overrides=json.loads(row['domain_overrides'] or '{}'),
                dns_search_domains=json.loads(row['dns_search_domains'] or '[]'),
                prevent_leaks=bool(row['prevent_leaks']),
                use_systemd_resolved=bool(row['use_systemd_resolved']),
                created_at=row['created_at'],
                updated_at=row['updated_at'],
            )
        finally:
            conn.close()

    def add_domain_override(
        self,
        entity_type: str,
        entity_id: int,
        domain: str,
        dns_server: str
    ) -> None:
        """
        Add a domain-specific DNS override.

        Example: add_domain_override('remote', 1, 'home.lan', '192.168.1.1')
        Routes queries for *.home.lan to 192.168.1.1
        """
        conn = self._get_conn()
        try:
            row = conn.execute("""
                SELECT domain_overrides FROM dns_config
                WHERE entity_type = ? AND entity_id = ?
            """, (entity_type, entity_id)).fetchone()

            if row:
                overrides = json.loads(row['domain_overrides'] or '{}')
                overrides[domain] = dns_server
                conn.execute("""
                    UPDATE dns_config SET
                        domain_overrides = ?,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE entity_type = ? AND entity_id = ?
                """, (json.dumps(overrides), entity_type, entity_id))
            else:
                # Create new config with override
                conn.execute("""
                    INSERT INTO dns_config
                    (entity_type, entity_id, domain_overrides)
                    VALUES (?, ?, ?)
                """, (entity_type, entity_id, json.dumps({domain: dns_server})))

            conn.commit()
        finally:
            conn.close()

    def remove_domain_override(
        self,
        entity_type: str,
        entity_id: int,
        domain: str
    ) -> bool:
        """Remove a domain-specific DNS override."""
        conn = self._get_conn()
        try:
            row = conn.execute("""
                SELECT domain_overrides FROM dns_config
                WHERE entity_type = ? AND entity_id = ?
            """, (entity_type, entity_id)).fetchone()

            if not row:
                return False

            overrides = json.loads(row['domain_overrides'] or '{}')
            if domain not in overrides:
                return False

            del overrides[domain]
            conn.execute("""
                UPDATE dns_config SET
                    domain_overrides = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE entity_type = ? AND entity_id = ?
            """, (json.dumps(overrides), entity_type, entity_id))
            conn.commit()
            return True
        finally:
            conn.close()

    def set_search_domains(
        self,
        entity_type: str,
        entity_id: int,
        domains: List[str]
    ) -> None:
        """Set DNS search domains for an entity."""
        conn = self._get_conn()
        try:
            row = conn.execute("""
                SELECT id FROM dns_config
                WHERE entity_type = ? AND entity_id = ?
            """, (entity_type, entity_id)).fetchone()

            if row:
                conn.execute("""
                    UPDATE dns_config SET
                        dns_search_domains = ?,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE entity_type = ? AND entity_id = ?
                """, (json.dumps(domains), entity_type, entity_id))
            else:
                conn.execute("""
                    INSERT INTO dns_config
                    (entity_type, entity_id, dns_search_domains)
                    VALUES (?, ?, ?)
                """, (entity_type, entity_id, json.dumps(domains)))

            conn.commit()
        finally:
            conn.close()

    def generate_dns_config(
        self,
        entity_type: str,
        entity_id: int,
        interface_name: str = "wg0"
    ) -> DNSGeneratedConfig:
        """
        Generate DNS configuration for WireGuard config file.

        Returns DNSGeneratedConfig with:
        - DNS line for [Interface] section
        - PostUp/PostDown commands for advanced DNS routing
        - Notes explaining the configuration
        """
        config = self.get_dns_config(entity_type, entity_id)

        if not config:
            # Return default config
            return DNSGeneratedConfig(
                dns_line="DNS = 1.1.1.1, 8.8.8.8",
                postup_commands=[],
                postdown_commands=[],
                notes=["Using default Cloudflare + Google DNS fallback"]
            )

        dns_servers = []
        postup = []
        postdown = []
        notes = []

        # Build DNS server list
        if config.primary_dns:
            dns_servers.append(config.primary_dns)
            notes.append(f"Primary DNS: {config.primary_dns}")

        if config.secondary_dns:
            dns_servers.append(config.secondary_dns)
            notes.append(f"Fallback DNS: {config.secondary_dns}")

        if not dns_servers:
            dns_servers = ["1.1.1.1", "8.8.8.8"]
            notes.append("Using default DNS (no custom config)")

        dns_line = f"DNS = {', '.join(dns_servers)}"

        # Handle systemd-resolved integration
        if config.use_systemd_resolved:
            notes.append("Using systemd-resolved for DNS management")

            # Set up resolved for this interface
            dns_cmd = f"resolvectl dns %i {' '.join(dns_servers)}"
            postup.append(dns_cmd)

            # Add search domains
            if config.dns_search_domains:
                domains = ' '.join(f"~{d}" for d in config.dns_search_domains)
                postup.append(f"resolvectl domain %i {domains}")
                notes.append(f"Search domains: {', '.join(config.dns_search_domains)}")

            # Handle domain overrides with routing domains
            for domain, server in config.domain_overrides.items():
                notes.append(f"Route {domain} queries to {server}")
                # For domain overrides, we need split DNS routing
                postup.append(f"resolvectl dns %i {server}")
                postup.append(f"resolvectl domain %i ~{domain}")

            # Set as default route for DNS if preventing leaks
            if config.prevent_leaks:
                postup.append("resolvectl default-route %i true")
                notes.append("DNS leak prevention: enabled")

            # Cleanup on disconnect
            postdown.append("resolvectl revert %i")

        else:
            # Traditional DNS configuration (simpler)
            if config.domain_overrides:
                notes.append("Domain overrides require systemd-resolved")
                notes.append("Enable use_systemd_resolved for split DNS")

            if config.dns_search_domains:
                # Can't set search domains without resolved
                notes.append("Search domains require systemd-resolved")

        # DNS leak prevention with iptables (if not using resolved)
        if config.prevent_leaks and not config.use_systemd_resolved:
            # Block DNS to non-tunnel destinations
            postup.append(
                f"iptables -I OUTPUT -p udp --dport 53 "
                f"-m owner ! --gid-owner {interface_name} "
                f"-j REJECT 2>/dev/null || true"
            )
            postdown.append(
                f"iptables -D OUTPUT -p udp --dport 53 "
                f"-m owner ! --gid-owner {interface_name} "
                f"-j REJECT 2>/dev/null || true"
            )
            notes.append("DNS leak prevention: iptables rules")

        return DNSGeneratedConfig(
            dns_line=dns_line,
            postup_commands=postup,
            postdown_commands=postdown,
            notes=notes
        )

    def get_all_configs(self) -> List[DNSConfig]:
        """Get all DNS configurations."""
        conn = self._get_conn()
        try:
            rows = conn.execute("""
                SELECT * FROM dns_config ORDER BY entity_type, entity_id
            """).fetchall()

            return [
                DNSConfig(
                    entity_type=row['entity_type'],
                    entity_id=row['entity_id'],
                    primary_dns=row['primary_dns'],
                    secondary_dns=row['secondary_dns'],
                    domain_overrides=json.loads(row['domain_overrides'] or '{}'),
                    dns_search_domains=json.loads(row['dns_search_domains'] or '[]'),
                    prevent_leaks=bool(row['prevent_leaks']),
                    use_systemd_resolved=bool(row['use_systemd_resolved']),
                )
                for row in rows
            ]
        finally:
            conn.close()

    def delete_config(self, entity_type: str, entity_id: int) -> bool:
        """Delete DNS configuration for an entity."""
        conn = self._get_conn()
        try:
            result = conn.execute("""
                DELETE FROM dns_config
                WHERE entity_type = ? AND entity_id = ?
            """, (entity_type, entity_id))
            conn.commit()
            return result.rowcount > 0
        finally:
            conn.close()

    def get_dns_presets(self) -> Dict[str, Tuple[str, str]]:
        """Get common DNS presets (name -> (primary, secondary))."""
        return {
            "Cloudflare": ("1.1.1.1", "1.0.0.1"),
            "Cloudflare (Malware Blocking)": ("1.1.1.2", "1.0.0.2"),
            "Cloudflare (Family)": ("1.1.1.3", "1.0.0.3"),
            "Google": ("8.8.8.8", "8.8.4.4"),
            "Quad9": ("9.9.9.9", "149.112.112.112"),
            "Quad9 (No Filtering)": ("9.9.9.10", "149.112.112.10"),
            "OpenDNS": ("208.67.222.222", "208.67.220.220"),
            "OpenDNS Family": ("208.67.222.123", "208.67.220.123"),
            "AdGuard": ("94.140.14.14", "94.140.15.15"),
            "AdGuard Family": ("94.140.14.15", "94.140.15.16"),
            "NextDNS": ("45.90.28.0", "45.90.30.0"),
            "Mullvad": ("100.64.0.1", None),
        }

    def apply_preset(
        self,
        entity_type: str,
        entity_id: int,
        preset_name: str
    ) -> Optional[DNSConfig]:
        """Apply a DNS preset to an entity."""
        presets = self.get_dns_presets()
        if preset_name not in presets:
            return None

        primary, secondary = presets[preset_name]
        return self.set_dns_config(
            entity_type=entity_type,
            entity_id=entity_id,
            primary=primary,
            secondary=secondary
        )

    def get_statistics(self) -> Dict:
        """Get DNS configuration statistics."""
        conn = self._get_conn()
        try:
            stats = {
                "total_configs": 0,
                "by_entity_type": {},
                "with_overrides": 0,
                "with_search_domains": 0,
                "leak_prevention_enabled": 0,
                "using_resolved": 0,
            }

            rows = conn.execute("""
                SELECT
                    entity_type,
                    COUNT(*) as count,
                    SUM(CASE WHEN domain_overrides != '{}' THEN 1 ELSE 0 END) as with_overrides,
                    SUM(CASE WHEN dns_search_domains != '[]' THEN 1 ELSE 0 END) as with_search,
                    SUM(prevent_leaks) as leak_prevention,
                    SUM(use_systemd_resolved) as using_resolved
                FROM dns_config
                GROUP BY entity_type
            """).fetchall()

            for row in rows:
                stats["by_entity_type"][row['entity_type']] = row['count']
                stats["total_configs"] += row['count']
                stats["with_overrides"] += row['with_overrides']
                stats["with_search_domains"] += row['with_search']
                stats["leak_prevention_enabled"] += row['leak_prevention']
                stats["using_resolved"] += row['using_resolved']

            return stats
        finally:
            conn.close()


# CLI integration helpers
def format_dns_config_table(configs: List[DNSConfig]) -> str:
    """Format DNS configs for CLI display."""
    if not configs:
        return "No DNS configurations found."

    lines = [
        "Entity Type | Entity ID | Primary DNS    | Secondary DNS  | Overrides | Leak Prev",
        "-" * 85,
    ]

    for cfg in configs:
        override_count = len(cfg.domain_overrides)
        lines.append(
            f"{cfg.entity_type:11} | {cfg.entity_id:9} | "
            f"{cfg.primary_dns or '-':14} | {cfg.secondary_dns or '-':14} | "
            f"{override_count:9} | {'Yes' if cfg.prevent_leaks else 'No'}"
        )

    return '\n'.join(lines)


def format_generated_config(gen_config: DNSGeneratedConfig) -> str:
    """Format generated config for display."""
    lines = ["Generated DNS Configuration:", "=" * 40]
    lines.append("")
    lines.append(f"[Interface]")
    lines.append(gen_config.dns_line)

    if gen_config.postup_commands:
        lines.append("")
        lines.append("# DNS Setup Commands:")
        for cmd in gen_config.postup_commands:
            lines.append(f"PostUp = {cmd}")

    if gen_config.postdown_commands:
        lines.append("")
        lines.append("# DNS Cleanup Commands:")
        for cmd in gen_config.postdown_commands:
            lines.append(f"PostDown = {cmd}")

    if gen_config.notes:
        lines.append("")
        lines.append("Notes:")
        for note in gen_config.notes:
            lines.append(f"  - {note}")

    return '\n'.join(lines)
