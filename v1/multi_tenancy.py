"""
WireGuard Friend Multi-Tenancy Support

Provides tenant isolation for managing multiple WireGuard networks.

Use Cases:
- MSPs managing multiple client networks
- Enterprises with isolated network segments
- Personal/work network separation

Architecture:
    ~/.wireguard-friend/
    ├── tenants.json          # Tenant registry
    ├── current_tenant        # Active tenant ID
    └── tenants/
        ├── personal/
        │   └── wireguard.db
        ├── client-acme/
        │   └── wireguard.db
        └── client-globex/
            └── wireguard.db

Usage:
    from v1.multi_tenancy import TenantManager

    mgr = TenantManager()
    mgr.create_tenant('client-acme', 'Acme Corporation VPN')
    mgr.switch_tenant('client-acme')

    # Current tenant is now client-acme
    db_path = mgr.get_current_db_path()
"""

import json
import os
import shutil
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, List, Any
import re


@dataclass
class Tenant:
    """Represents a tenant/network environment."""
    id: str                         # Unique ID (alphanumeric + hyphens)
    name: str                       # Display name
    description: str = ""           # Optional description
    created_at: str = ""            # ISO timestamp
    last_accessed: str = ""         # ISO timestamp
    metadata: Dict[str, Any] = field(default_factory=dict)  # Custom data
    is_default: bool = False        # Default tenant flag

    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "created_at": self.created_at,
            "last_accessed": self.last_accessed,
            "metadata": self.metadata,
            "is_default": self.is_default,
        }

    @classmethod
    def from_dict(cls, data: Dict) -> 'Tenant':
        return cls(
            id=data["id"],
            name=data["name"],
            description=data.get("description", ""),
            created_at=data.get("created_at", ""),
            last_accessed=data.get("last_accessed", ""),
            metadata=data.get("metadata", {}),
            is_default=data.get("is_default", False),
        )


@dataclass
class TenantStats:
    """Statistics for a tenant."""
    id: str
    name: str
    peer_count: int
    cs_count: int
    router_count: int
    remote_count: int
    exit_count: int
    last_modified: Optional[str]
    db_size_bytes: int


class TenantManager:
    """Manages multiple tenant environments."""

    # Valid tenant ID pattern
    ID_PATTERN = re.compile(r'^[a-z0-9][a-z0-9-]*[a-z0-9]$|^[a-z0-9]$')

    def __init__(self, base_path: Optional[str] = None):
        """
        Initialize tenant manager.

        Args:
            base_path: Base directory for tenant data.
                       Defaults to ~/.wireguard-friend/
        """
        if base_path:
            self.base_path = Path(base_path)
        else:
            self.base_path = Path.home() / ".wireguard-friend"

        self.tenants_dir = self.base_path / "tenants"
        self.registry_file = self.base_path / "tenants.json"
        self.current_file = self.base_path / "current_tenant"

        self._ensure_directories()
        self._ensure_default_tenant()

    def _ensure_directories(self) -> None:
        """Ensure base directories exist."""
        self.base_path.mkdir(parents=True, exist_ok=True)
        self.tenants_dir.mkdir(parents=True, exist_ok=True)

    def _ensure_default_tenant(self) -> None:
        """Ensure default tenant exists."""
        if not self.registry_file.exists():
            # Create default tenant
            default = Tenant(
                id="default",
                name="Default Network",
                description="Default WireGuard network",
                created_at=datetime.utcnow().isoformat(),
                is_default=True,
            )
            self._save_registry([default])

            # Ensure default tenant directory
            (self.tenants_dir / "default").mkdir(exist_ok=True)

            # Set as current
            self._set_current("default")

    def _load_registry(self) -> List[Tenant]:
        """Load tenant registry."""
        if not self.registry_file.exists():
            return []

        try:
            with open(self.registry_file, 'r') as f:
                data = json.load(f)
                return [Tenant.from_dict(t) for t in data.get("tenants", [])]
        except Exception:
            return []

    def _save_registry(self, tenants: List[Tenant]) -> None:
        """Save tenant registry."""
        data = {
            "version": 1,
            "tenants": [t.to_dict() for t in tenants],
        }
        with open(self.registry_file, 'w') as f:
            json.dump(data, f, indent=2)

    def _get_current(self) -> Optional[str]:
        """Get current tenant ID."""
        if not self.current_file.exists():
            return "default"
        try:
            return self.current_file.read_text().strip()
        except Exception:
            return "default"

    def _set_current(self, tenant_id: str) -> None:
        """Set current tenant ID."""
        self.current_file.write_text(tenant_id)

    def _validate_id(self, tenant_id: str) -> bool:
        """Validate tenant ID format."""
        if not tenant_id or len(tenant_id) > 64:
            return False
        return bool(self.ID_PATTERN.match(tenant_id))

    def create_tenant(
        self,
        tenant_id: str,
        name: str,
        description: str = "",
        metadata: Optional[Dict] = None
    ) -> Tenant:
        """
        Create a new tenant.

        Args:
            tenant_id: Unique tenant ID (lowercase alphanumeric + hyphens)
            name: Display name
            description: Optional description
            metadata: Optional custom metadata

        Returns:
            Created Tenant object

        Raises:
            ValueError: If tenant_id is invalid or already exists
        """
        if not self._validate_id(tenant_id):
            raise ValueError(
                f"Invalid tenant ID '{tenant_id}'. "
                "Must be lowercase alphanumeric with hyphens, 1-64 chars."
            )

        tenants = self._load_registry()
        if any(t.id == tenant_id for t in tenants):
            raise ValueError(f"Tenant '{tenant_id}' already exists")

        # Create tenant
        tenant = Tenant(
            id=tenant_id,
            name=name,
            description=description,
            created_at=datetime.utcnow().isoformat(),
            metadata=metadata or {},
        )

        # Create tenant directory
        tenant_dir = self.tenants_dir / tenant_id
        tenant_dir.mkdir(parents=True, exist_ok=True)

        # Save to registry
        tenants.append(tenant)
        self._save_registry(tenants)

        return tenant

    def delete_tenant(self, tenant_id: str, force: bool = False) -> bool:
        """
        Delete a tenant.

        Args:
            tenant_id: Tenant ID to delete
            force: If True, delete even if tenant has data

        Returns:
            True if deleted, False otherwise

        Raises:
            ValueError: If trying to delete default tenant or current tenant
        """
        if tenant_id == "default":
            raise ValueError("Cannot delete default tenant")

        current = self._get_current()
        if tenant_id == current:
            raise ValueError("Cannot delete current tenant. Switch first.")

        tenants = self._load_registry()
        tenant = next((t for t in tenants if t.id == tenant_id), None)
        if not tenant:
            return False

        tenant_dir = self.tenants_dir / tenant_id
        db_path = tenant_dir / "wireguard.db"

        # Check if has data
        if db_path.exists() and not force:
            try:
                conn = sqlite3.connect(str(db_path))
                count = conn.execute(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='table'"
                ).fetchone()[0]
                conn.close()
                if count > 0:
                    raise ValueError(
                        f"Tenant '{tenant_id}' has data. Use force=True to delete."
                    )
            except sqlite3.Error:
                pass

        # Delete directory
        if tenant_dir.exists():
            shutil.rmtree(tenant_dir)

        # Remove from registry
        tenants = [t for t in tenants if t.id != tenant_id]
        self._save_registry(tenants)

        return True

    def switch_tenant(self, tenant_id: str) -> Tenant:
        """
        Switch to a different tenant.

        Args:
            tenant_id: Tenant ID to switch to

        Returns:
            Switched Tenant object

        Raises:
            ValueError: If tenant doesn't exist
        """
        tenant = self.get_tenant(tenant_id)
        if not tenant:
            raise ValueError(f"Tenant '{tenant_id}' not found")

        # Update last accessed
        tenant.last_accessed = datetime.utcnow().isoformat()
        self._update_tenant(tenant)

        # Set as current
        self._set_current(tenant_id)

        return tenant

    def get_tenant(self, tenant_id: str) -> Optional[Tenant]:
        """Get a tenant by ID."""
        tenants = self._load_registry()
        return next((t for t in tenants if t.id == tenant_id), None)

    def get_current_tenant(self) -> Optional[Tenant]:
        """Get the current active tenant."""
        current_id = self._get_current()
        return self.get_tenant(current_id)

    def list_tenants(self) -> List[Tenant]:
        """List all tenants."""
        return self._load_registry()

    def get_current_db_path(self) -> str:
        """Get the database path for current tenant."""
        current = self._get_current() or "default"
        return str(self.tenants_dir / current / "wireguard.db")

    def get_db_path(self, tenant_id: str) -> str:
        """Get the database path for a specific tenant."""
        return str(self.tenants_dir / tenant_id / "wireguard.db")

    def get_tenant_dir(self, tenant_id: Optional[str] = None) -> Path:
        """Get the directory for a tenant."""
        tid = tenant_id or self._get_current() or "default"
        return self.tenants_dir / tid

    def _update_tenant(self, tenant: Tenant) -> None:
        """Update a tenant in the registry."""
        tenants = self._load_registry()
        for i, t in enumerate(tenants):
            if t.id == tenant.id:
                tenants[i] = tenant
                break
        self._save_registry(tenants)

    def update_tenant(
        self,
        tenant_id: str,
        name: Optional[str] = None,
        description: Optional[str] = None,
        metadata: Optional[Dict] = None
    ) -> Optional[Tenant]:
        """
        Update tenant properties.

        Args:
            tenant_id: Tenant ID to update
            name: New name (optional)
            description: New description (optional)
            metadata: Metadata to merge (optional)

        Returns:
            Updated Tenant or None if not found
        """
        tenant = self.get_tenant(tenant_id)
        if not tenant:
            return None

        if name is not None:
            tenant.name = name
        if description is not None:
            tenant.description = description
        if metadata is not None:
            tenant.metadata.update(metadata)

        self._update_tenant(tenant)
        return tenant

    def get_tenant_stats(self, tenant_id: str) -> Optional[TenantStats]:
        """Get statistics for a tenant."""
        tenant = self.get_tenant(tenant_id)
        if not tenant:
            return None

        db_path = self.get_db_path(tenant_id)
        if not Path(db_path).exists():
            return TenantStats(
                id=tenant.id,
                name=tenant.name,
                peer_count=0,
                cs_count=0,
                router_count=0,
                remote_count=0,
                exit_count=0,
                last_modified=None,
                db_size_bytes=0,
            )

        try:
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row

            cs_count = conn.execute(
                "SELECT COUNT(*) FROM coordination_server"
            ).fetchone()[0]

            router_count = conn.execute(
                "SELECT COUNT(*) FROM subnet_router"
            ).fetchone()[0]

            remote_count = conn.execute(
                "SELECT COUNT(*) FROM remote"
            ).fetchone()[0]

            try:
                exit_count = conn.execute(
                    "SELECT COUNT(*) FROM exit_node"
                ).fetchone()[0]
            except sqlite3.OperationalError:
                exit_count = 0

            conn.close()

            db_size = Path(db_path).stat().st_size
            last_modified = datetime.fromtimestamp(
                Path(db_path).stat().st_mtime
            ).isoformat()

            return TenantStats(
                id=tenant.id,
                name=tenant.name,
                peer_count=router_count + remote_count + exit_count,
                cs_count=cs_count,
                router_count=router_count,
                remote_count=remote_count,
                exit_count=exit_count,
                last_modified=last_modified,
                db_size_bytes=db_size,
            )
        except Exception:
            return None

    def export_tenant(self, tenant_id: str, output_path: str) -> bool:
        """
        Export a tenant to a backup file.

        Args:
            tenant_id: Tenant to export
            output_path: Path for backup file

        Returns:
            True if exported successfully
        """
        tenant_dir = self.get_tenant_dir(tenant_id)
        if not tenant_dir.exists():
            return False

        # Create archive
        shutil.make_archive(
            output_path.rstrip('.zip'),
            'zip',
            tenant_dir
        )
        return True

    def import_tenant(
        self,
        archive_path: str,
        tenant_id: str,
        name: str,
        overwrite: bool = False
    ) -> Tenant:
        """
        Import a tenant from a backup file.

        Args:
            archive_path: Path to backup archive
            tenant_id: ID for the imported tenant
            name: Display name
            overwrite: Overwrite if exists

        Returns:
            Imported Tenant object
        """
        if not self._validate_id(tenant_id):
            raise ValueError(f"Invalid tenant ID '{tenant_id}'")

        existing = self.get_tenant(tenant_id)
        if existing and not overwrite:
            raise ValueError(f"Tenant '{tenant_id}' already exists")

        tenant_dir = self.tenants_dir / tenant_id
        tenant_dir.mkdir(parents=True, exist_ok=True)

        # Extract archive
        shutil.unpack_archive(archive_path, tenant_dir)

        # Create or update tenant
        if existing:
            return self.update_tenant(tenant_id, name=name)
        else:
            return self.create_tenant(tenant_id, name)

    def clone_tenant(
        self,
        source_id: str,
        target_id: str,
        target_name: str
    ) -> Tenant:
        """
        Clone a tenant to a new tenant.

        Args:
            source_id: Source tenant ID
            target_id: New tenant ID
            target_name: New tenant display name

        Returns:
            Cloned Tenant object
        """
        source = self.get_tenant(source_id)
        if not source:
            raise ValueError(f"Source tenant '{source_id}' not found")

        if not self._validate_id(target_id):
            raise ValueError(f"Invalid tenant ID '{target_id}'")

        if self.get_tenant(target_id):
            raise ValueError(f"Target tenant '{target_id}' already exists")

        # Create target tenant
        target = self.create_tenant(
            target_id,
            target_name,
            description=f"Cloned from {source.name}"
        )

        # Copy database
        source_db = self.get_db_path(source_id)
        target_db = self.get_db_path(target_id)
        if Path(source_db).exists():
            shutil.copy2(source_db, target_db)

        return target


# CLI formatting helpers
def format_tenant_list(tenants: List[Tenant], current_id: str) -> str:
    """Format tenant list for CLI display."""
    if not tenants:
        return "No tenants found."

    lines = [
        "  ID                  Name                    Last Accessed",
        "  " + "-" * 60,
    ]

    for t in tenants:
        marker = "*" if t.id == current_id else " "
        last_acc = t.last_accessed[:10] if t.last_accessed else "never"
        lines.append(
            f"{marker} {t.id:20} {t.name:23} {last_acc}"
        )

    lines.append("")
    lines.append("* = current tenant")

    return '\n'.join(lines)


def format_tenant_stats(stats: TenantStats) -> str:
    """Format tenant stats for CLI display."""
    size_kb = stats.db_size_bytes / 1024
    lines = [
        f"Tenant: {stats.name} ({stats.id})",
        "=" * 40,
        "",
        f"  Coordination Servers: {stats.cs_count}",
        f"  Subnet Routers:       {stats.router_count}",
        f"  Remote Clients:       {stats.remote_count}",
        f"  Exit Nodes:           {stats.exit_count}",
        "",
        f"  Total Peers:          {stats.peer_count}",
        f"  Database Size:        {size_kb:.1f} KB",
        f"  Last Modified:        {stats.last_modified or 'N/A'}",
    ]
    return '\n'.join(lines)


def format_tenant_detail(tenant: Tenant) -> str:
    """Format tenant details for CLI display."""
    lines = [
        f"Tenant: {tenant.name}",
        "=" * 40,
        "",
        f"  ID:          {tenant.id}",
        f"  Description: {tenant.description or '(none)'}",
        f"  Created:     {tenant.created_at}",
        f"  Last Access: {tenant.last_accessed or 'never'}",
        f"  Default:     {'Yes' if tenant.is_default else 'No'}",
    ]

    if tenant.metadata:
        lines.append("")
        lines.append("  Metadata:")
        for k, v in tenant.metadata.items():
            lines.append(f"    {k}: {v}")

    return '\n'.join(lines)
