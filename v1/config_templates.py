"""
WireGuard Friend Configuration Templates

Provides pre-built templates for common network patterns and quick setup wizards.

Templates:
- Personal VPN: CS + 3 remotes, basic access
- Home Access: CS + home router + remotes, full LAN access
- Multi-Site Office: CS + 2 site routers + remotes
- Privacy Exit: CS + exit nodes + remotes
- Family Network: CS + multiple routers + many remotes

Usage:
    from v1.config_templates import TemplateManager, Template

    mgr = TemplateManager(db_path)
    templates = mgr.list_templates()

    # Apply a template
    config = mgr.prepare_template('home_access')
    mgr.apply_template(config, user_inputs)
"""

import json
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Dict, List, Any, Callable
from enum import Enum


class TemplateCategory(Enum):
    """Template categories."""
    PERSONAL = "personal"
    HOME = "home"
    OFFICE = "office"
    PRIVACY = "privacy"
    CUSTOM = "custom"


@dataclass
class TemplatePrompt:
    """A prompt for user input during template application."""
    key: str                    # Variable name to store result
    label: str                  # Display label
    description: str            # Help text
    input_type: str = "text"    # text, number, ip, network, hostname, choice
    default: Any = None         # Default value
    required: bool = True
    choices: List[str] = field(default_factory=list)  # For choice type
    validation: Optional[str] = None  # Regex for validation


@dataclass
class TemplateEntity:
    """An entity to be created by the template."""
    entity_type: str            # cs, sr, remote, exit
    name_template: str          # Template for hostname (can use {variables})
    count: int = 1              # Number to create (or "prompt" for user input)
    config: Dict[str, Any] = field(default_factory=dict)  # Additional config


@dataclass
class Template:
    """A network configuration template."""
    id: str                     # Unique template ID
    name: str                   # Display name
    description: str            # Full description
    category: TemplateCategory
    version: int = 1
    prompts: List[TemplatePrompt] = field(default_factory=list)
    entities: List[TemplateEntity] = field(default_factory=list)
    post_setup_notes: List[str] = field(default_factory=list)
    icon: str = ""             # Emoji icon


# Built-in templates
BUILTIN_TEMPLATES = {
    "personal_vpn": Template(
        id="personal_vpn",
        name="Personal VPN",
        description="Basic cloud VPN for personal devices. Creates a coordination server and up to 5 remote clients with VPN-only access.",
        category=TemplateCategory.PERSONAL,
        icon="",
        prompts=[
            TemplatePrompt(
                key="cs_endpoint",
                label="Coordination Server",
                description="Public IP or hostname of your VPS",
                input_type="hostname",
            ),
            TemplatePrompt(
                key="vpn_network",
                label="VPN Network",
                description="WireGuard VPN subnet",
                input_type="network",
                default="10.66.0.0/24",
            ),
            TemplatePrompt(
                key="remote_count",
                label="Number of Devices",
                description="How many personal devices?",
                input_type="number",
                default=3,
            ),
            TemplatePrompt(
                key="remote_names",
                label="Device Names",
                description="Comma-separated list (e.g., laptop, phone, tablet)",
                input_type="text",
                default="laptop, phone, tablet",
            ),
        ],
        entities=[
            TemplateEntity(
                entity_type="cs",
                name_template="vpn",
                config={"listen_port": 51820},
            ),
            TemplateEntity(
                entity_type="remote",
                name_template="{remote_name}",
                count=-1,  # Dynamic from prompt
                config={"access_level": "vpn_only"},
            ),
        ],
        post_setup_notes=[
            "Deploy config to coordination server",
            "Use QR codes or manual config for devices",
            "Test connectivity from each device",
        ],
    ),

    "home_access": Template(
        id="home_access",
        name="Home Access",
        description="Access your home LAN from anywhere. Creates a CS, home router, and remote devices with full LAN access.",
        category=TemplateCategory.HOME,
        icon="",
        prompts=[
            TemplatePrompt(
                key="cs_endpoint",
                label="Coordination Server",
                description="Public IP or hostname of your VPS",
                input_type="hostname",
            ),
            TemplatePrompt(
                key="home_router_name",
                label="Home Router Name",
                description="Hostname for your home gateway",
                input_type="hostname",
                default="home-router",
            ),
            TemplatePrompt(
                key="home_lan",
                label="Home LAN Network",
                description="Your home network (e.g., 192.168.1.0/24)",
                input_type="network",
                default="192.168.1.0/24",
            ),
            TemplatePrompt(
                key="vpn_network",
                label="VPN Network",
                description="WireGuard VPN subnet",
                input_type="network",
                default="10.66.0.0/24",
            ),
            TemplatePrompt(
                key="remote_count",
                label="Number of Devices",
                description="How many remote devices?",
                input_type="number",
                default=3,
            ),
            TemplatePrompt(
                key="remote_names",
                label="Device Names",
                description="Comma-separated list",
                input_type="text",
                default="laptop, phone, tablet",
            ),
        ],
        entities=[
            TemplateEntity(
                entity_type="cs",
                name_template="vpn",
                config={"listen_port": 51820},
            ),
            TemplateEntity(
                entity_type="sr",
                name_template="{home_router_name}",
                config={"advertised_networks": ["{home_lan}"]},
            ),
            TemplateEntity(
                entity_type="remote",
                name_template="{remote_name}",
                count=-1,
                config={"access_level": "full_access", "sponsor_type": "sr"},
            ),
        ],
        post_setup_notes=[
            "Deploy config to coordination server",
            "Deploy config to home router (needs WireGuard installed)",
            "Enable IP forwarding on home router: sysctl -w net.ipv4.ip_forward=1",
            "Use QR codes for mobile devices",
            "Test access to home LAN resources",
        ],
    ),

    "multi_site_office": Template(
        id="multi_site_office",
        name="Multi-Site Office",
        description="Connect multiple office locations with site-to-site VPN. Full routing between sites.",
        category=TemplateCategory.OFFICE,
        icon="",
        prompts=[
            TemplatePrompt(
                key="cs_endpoint",
                label="Coordination Server",
                description="Public IP or hostname (cloud VPS recommended)",
                input_type="hostname",
            ),
            TemplatePrompt(
                key="site1_name",
                label="Site 1 Name",
                description="Primary site name",
                input_type="hostname",
                default="hq-router",
            ),
            TemplatePrompt(
                key="site1_lan",
                label="Site 1 LAN",
                description="Primary site network",
                input_type="network",
                default="10.0.1.0/24",
            ),
            TemplatePrompt(
                key="site2_name",
                label="Site 2 Name",
                description="Secondary site name",
                input_type="hostname",
                default="branch-router",
            ),
            TemplatePrompt(
                key="site2_lan",
                label="Site 2 LAN",
                description="Secondary site network",
                input_type="network",
                default="10.0.2.0/24",
            ),
            TemplatePrompt(
                key="vpn_network",
                label="VPN Network",
                description="WireGuard VPN subnet",
                input_type="network",
                default="10.66.0.0/24",
            ),
            TemplatePrompt(
                key="remote_count",
                label="Remote Workers",
                description="Number of remote worker devices",
                input_type="number",
                default=5,
            ),
        ],
        entities=[
            TemplateEntity(
                entity_type="cs",
                name_template="vpn-hub",
                config={"listen_port": 51820},
            ),
            TemplateEntity(
                entity_type="sr",
                name_template="{site1_name}",
                config={"advertised_networks": ["{site1_lan}"]},
            ),
            TemplateEntity(
                entity_type="sr",
                name_template="{site2_name}",
                config={"advertised_networks": ["{site2_lan}"]},
            ),
            TemplateEntity(
                entity_type="remote",
                name_template="remote-{n}",
                count=-1,
                config={"access_level": "full_access"},
            ),
        ],
        post_setup_notes=[
            "Deploy to coordination server (cloud VPS)",
            "Deploy to both site routers",
            "Enable IP forwarding on routers",
            "Configure firewall rules for inter-site traffic",
            "Test connectivity between sites",
            "Distribute remote configs to workers",
        ],
    ),

    "privacy_exit": Template(
        id="privacy_exit",
        name="Privacy Exit",
        description="Route internet traffic through exit nodes for privacy. Multiple geographic exit points.",
        category=TemplateCategory.PRIVACY,
        icon="",
        prompts=[
            TemplatePrompt(
                key="cs_endpoint",
                label="Coordination Server",
                description="Public IP or hostname of your VPS",
                input_type="hostname",
            ),
            TemplatePrompt(
                key="exit1_name",
                label="Exit Node 1 Name",
                description="First exit node hostname",
                input_type="hostname",
                default="exit-us",
            ),
            TemplatePrompt(
                key="exit1_endpoint",
                label="Exit Node 1 Endpoint",
                description="First exit node IP or hostname",
                input_type="hostname",
            ),
            TemplatePrompt(
                key="exit2_name",
                label="Exit Node 2 Name",
                description="Second exit node hostname",
                input_type="hostname",
                default="exit-eu",
            ),
            TemplatePrompt(
                key="exit2_endpoint",
                label="Exit Node 2 Endpoint",
                description="Second exit node IP or hostname",
                input_type="hostname",
            ),
            TemplatePrompt(
                key="vpn_network",
                label="VPN Network",
                description="WireGuard VPN subnet",
                input_type="network",
                default="10.66.0.0/24",
            ),
            TemplatePrompt(
                key="remote_count",
                label="Number of Devices",
                description="How many devices need exit routing?",
                input_type="number",
                default=3,
            ),
            TemplatePrompt(
                key="remote_names",
                label="Device Names",
                description="Comma-separated list",
                input_type="text",
                default="laptop, phone, tablet",
            ),
        ],
        entities=[
            TemplateEntity(
                entity_type="cs",
                name_template="vpn",
                config={"listen_port": 51820},
            ),
            TemplateEntity(
                entity_type="exit",
                name_template="{exit1_name}",
                config={"endpoint": "{exit1_endpoint}"},
            ),
            TemplateEntity(
                entity_type="exit",
                name_template="{exit2_name}",
                config={"endpoint": "{exit2_endpoint}"},
            ),
            TemplateEntity(
                entity_type="remote",
                name_template="{remote_name}",
                count=-1,
                config={"access_level": "vpn_only", "use_exit": True},
            ),
        ],
        post_setup_notes=[
            "Deploy to coordination server",
            "Deploy to both exit nodes",
            "Enable IP forwarding and NAT on exit nodes",
            "Configure iptables MASQUERADE on exit nodes",
            "Assign devices to preferred exit node",
            "Test IP changes via whatismyip.com",
        ],
    ),

    "family_network": Template(
        id="family_network",
        name="Family Network",
        description="Connect family members' homes with shared access. Multiple routers for different locations.",
        category=TemplateCategory.HOME,
        icon="",
        prompts=[
            TemplatePrompt(
                key="cs_endpoint",
                label="Coordination Server",
                description="Central VPS for family VPN hub",
                input_type="hostname",
            ),
            TemplatePrompt(
                key="location_count",
                label="Number of Homes",
                description="How many family locations?",
                input_type="number",
                default=3,
            ),
            TemplatePrompt(
                key="location_names",
                label="Location Names",
                description="Comma-separated (e.g., parents, sister, grandparents)",
                input_type="text",
                default="parents, sister, grandparents",
            ),
            TemplatePrompt(
                key="vpn_network",
                label="VPN Network",
                description="WireGuard VPN subnet",
                input_type="network",
                default="10.66.0.0/24",
            ),
            TemplatePrompt(
                key="device_per_location",
                label="Devices per Location",
                description="Average devices at each home",
                input_type="number",
                default=2,
            ),
        ],
        entities=[
            TemplateEntity(
                entity_type="cs",
                name_template="family-hub",
                config={"listen_port": 51820},
            ),
            TemplateEntity(
                entity_type="sr",
                name_template="{location_name}-router",
                count=-1,
                config={"advertised_networks": []},  # User sets per location
            ),
            TemplateEntity(
                entity_type="remote",
                name_template="{location_name}-device-{n}",
                count=-1,
                config={"access_level": "full_access"},
            ),
        ],
        post_setup_notes=[
            "Deploy to family VPN hub server",
            "Send router configs to each family member",
            "Help family members set up routers (Raspberry Pi works great)",
            "Create device configs as needed",
            "Consider setting up a family DNS server",
        ],
    ),
}


@dataclass
class TemplateApplication:
    """Result of preparing a template for application."""
    template: Template
    prompts: List[TemplatePrompt]
    collected_values: Dict[str, Any] = field(default_factory=dict)

    def set_value(self, key: str, value: Any) -> None:
        self.collected_values[key] = value

    def is_complete(self) -> bool:
        """Check if all required prompts have values."""
        for prompt in self.prompts:
            if prompt.required and prompt.key not in self.collected_values:
                return False
        return True

    def get_missing_prompts(self) -> List[TemplatePrompt]:
        """Get prompts that still need values."""
        return [
            p for p in self.prompts
            if p.required and p.key not in self.collected_values
        ]


class TemplateManager:
    """Manages configuration templates."""

    CUSTOM_TEMPLATES_TABLE = """
    CREATE TABLE IF NOT EXISTS custom_template (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        description TEXT,
        category TEXT DEFAULT 'custom',
        template_json TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
        """Ensure custom templates table exists."""
        conn = self._get_conn()
        try:
            conn.execute(self.CUSTOM_TEMPLATES_TABLE)
            conn.commit()
        finally:
            conn.close()

    def list_templates(self, category: Optional[TemplateCategory] = None) -> List[Template]:
        """List all available templates."""
        templates = list(BUILTIN_TEMPLATES.values())

        # Add custom templates
        conn = self._get_conn()
        try:
            rows = conn.execute("SELECT * FROM custom_template").fetchall()
            for row in rows:
                try:
                    template_data = json.loads(row['template_json'])
                    templates.append(self._dict_to_template(template_data))
                except Exception:
                    pass
        finally:
            conn.close()

        if category:
            templates = [t for t in templates if t.category == category]

        return templates

    def get_template(self, template_id: str) -> Optional[Template]:
        """Get a template by ID."""
        if template_id in BUILTIN_TEMPLATES:
            return BUILTIN_TEMPLATES[template_id]

        conn = self._get_conn()
        try:
            row = conn.execute(
                "SELECT template_json FROM custom_template WHERE id = ?",
                (template_id,)
            ).fetchone()

            if row:
                return self._dict_to_template(json.loads(row['template_json']))
            return None
        finally:
            conn.close()

    def prepare_template(self, template_id: str) -> Optional[TemplateApplication]:
        """
        Prepare a template for interactive application.

        Returns TemplateApplication with prompts to collect.
        """
        template = self.get_template(template_id)
        if not template:
            return None

        return TemplateApplication(
            template=template,
            prompts=template.prompts.copy(),
        )

    def apply_template(
        self,
        application: TemplateApplication,
        db_operations: Optional[Any] = None  # WireGuardDB instance
    ) -> Dict[str, Any]:
        """
        Apply a prepared template with collected values.

        Returns summary of created entities.
        """
        if not application.is_complete():
            raise ValueError("Template application is incomplete")

        values = application.collected_values
        template = application.template
        result = {
            "template_id": template.id,
            "template_name": template.name,
            "created_entities": [],
            "post_setup_notes": template.post_setup_notes,
        }

        # Process remote_names into list if provided
        if "remote_names" in values and isinstance(values["remote_names"], str):
            values["remote_name_list"] = [
                n.strip() for n in values["remote_names"].split(",")
            ]

        if "location_names" in values and isinstance(values["location_names"], str):
            values["location_name_list"] = [
                n.strip() for n in values["location_names"].split(",")
            ]

        # Generate entities
        for entity_def in template.entities:
            entity_type = entity_def.entity_type
            count = entity_def.count

            if count == -1:
                # Dynamic count from prompts
                if entity_type == "remote":
                    count = values.get("remote_count", 1)
                elif entity_type == "sr":
                    if "location_count" in values:
                        count = values["location_count"]
                    else:
                        count = 1

            for i in range(count):
                # Build entity name from template
                name_vars = dict(values)
                name_vars["n"] = i + 1

                if entity_type == "remote" and "remote_name_list" in values:
                    if i < len(values["remote_name_list"]):
                        name_vars["remote_name"] = values["remote_name_list"][i]
                    else:
                        name_vars["remote_name"] = f"device-{i+1}"

                if entity_type == "sr" and "location_name_list" in values:
                    if i < len(values["location_name_list"]):
                        name_vars["location_name"] = values["location_name_list"][i]
                    else:
                        name_vars["location_name"] = f"site-{i+1}"

                name = self._expand_template(entity_def.name_template, name_vars)

                # Build config
                config = {}
                for k, v in entity_def.config.items():
                    if isinstance(v, str):
                        config[k] = self._expand_template(v, name_vars)
                    elif isinstance(v, list):
                        config[k] = [
                            self._expand_template(item, name_vars) if isinstance(item, str) else item
                            for item in v
                        ]
                    else:
                        config[k] = v

                result["created_entities"].append({
                    "type": entity_type,
                    "name": name,
                    "config": config,
                })

        return result

    def _expand_template(self, template: str, values: Dict[str, Any]) -> str:
        """Expand {variable} placeholders in template string."""
        result = template
        for key, value in values.items():
            result = result.replace(f"{{{key}}}", str(value))
        return result

    def save_custom_template(self, template: Template) -> None:
        """Save a custom template to database."""
        conn = self._get_conn()
        try:
            template_json = self._template_to_dict(template)
            conn.execute("""
                INSERT OR REPLACE INTO custom_template
                (id, name, description, category, template_json, updated_at)
                VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """, (
                template.id,
                template.name,
                template.description,
                template.category.value,
                json.dumps(template_json),
            ))
            conn.commit()
        finally:
            conn.close()

    def delete_custom_template(self, template_id: str) -> bool:
        """Delete a custom template."""
        if template_id in BUILTIN_TEMPLATES:
            return False  # Can't delete built-in

        conn = self._get_conn()
        try:
            result = conn.execute(
                "DELETE FROM custom_template WHERE id = ?",
                (template_id,)
            )
            conn.commit()
            return result.rowcount > 0
        finally:
            conn.close()

    def _template_to_dict(self, template: Template) -> Dict:
        """Convert Template to dict for storage."""
        return {
            "id": template.id,
            "name": template.name,
            "description": template.description,
            "category": template.category.value,
            "version": template.version,
            "icon": template.icon,
            "prompts": [
                {
                    "key": p.key,
                    "label": p.label,
                    "description": p.description,
                    "input_type": p.input_type,
                    "default": p.default,
                    "required": p.required,
                    "choices": p.choices,
                    "validation": p.validation,
                }
                for p in template.prompts
            ],
            "entities": [
                {
                    "entity_type": e.entity_type,
                    "name_template": e.name_template,
                    "count": e.count,
                    "config": e.config,
                }
                for e in template.entities
            ],
            "post_setup_notes": template.post_setup_notes,
        }

    def _dict_to_template(self, data: Dict) -> Template:
        """Convert dict to Template."""
        return Template(
            id=data["id"],
            name=data["name"],
            description=data.get("description", ""),
            category=TemplateCategory(data.get("category", "custom")),
            version=data.get("version", 1),
            icon=data.get("icon", ""),
            prompts=[
                TemplatePrompt(
                    key=p["key"],
                    label=p["label"],
                    description=p.get("description", ""),
                    input_type=p.get("input_type", "text"),
                    default=p.get("default"),
                    required=p.get("required", True),
                    choices=p.get("choices", []),
                    validation=p.get("validation"),
                )
                for p in data.get("prompts", [])
            ],
            entities=[
                TemplateEntity(
                    entity_type=e["entity_type"],
                    name_template=e["name_template"],
                    count=e.get("count", 1),
                    config=e.get("config", {}),
                )
                for e in data.get("entities", [])
            ],
            post_setup_notes=data.get("post_setup_notes", []),
        )

    def get_template_summary(self, template_id: str) -> Optional[Dict]:
        """Get a summary of what a template will create."""
        template = self.get_template(template_id)
        if not template:
            return None

        # Count entity types
        entity_counts = {}
        for entity in template.entities:
            et = entity.entity_type
            if entity.count == -1:
                entity_counts[et] = entity_counts.get(et, 0)
                entity_counts[et] = f"{entity_counts.get(et, 0)}+" if et not in entity_counts else f"variable"
            else:
                entity_counts[et] = entity_counts.get(et, 0) + entity.count

        return {
            "id": template.id,
            "name": template.name,
            "description": template.description,
            "category": template.category.value,
            "icon": template.icon,
            "prompts_count": len(template.prompts),
            "entity_counts": entity_counts,
            "post_setup_notes": template.post_setup_notes,
        }


# CLI formatting helpers
def format_template_list(templates: List[Template]) -> str:
    """Format template list for CLI display."""
    if not templates:
        return "No templates available."

    lines = []
    by_category: Dict[str, List[Template]] = {}

    for t in templates:
        cat = t.category.value
        if cat not in by_category:
            by_category[cat] = []
        by_category[cat].append(t)

    for category, temps in sorted(by_category.items()):
        lines.append(f"\n{category.upper()}")
        lines.append("-" * 40)
        for t in temps:
            icon = t.icon if t.icon else " "
            lines.append(f"  {icon} {t.id:20} {t.name}")
            lines.append(f"     {t.description[:60]}...")

    return '\n'.join(lines)


def format_template_detail(template: Template) -> str:
    """Format template details for CLI display."""
    lines = [
        f"{template.icon} {template.name}",
        "=" * 50,
        "",
        template.description,
        "",
        "Required Information:",
        "-" * 30,
    ]

    for prompt in template.prompts:
        req = "*" if prompt.required else " "
        default = f" (default: {prompt.default})" if prompt.default else ""
        lines.append(f"  {req} {prompt.label}{default}")
        lines.append(f"      {prompt.description}")

    lines.append("")
    lines.append("Will Create:")
    lines.append("-" * 30)

    entity_summary = {}
    for entity in template.entities:
        et = entity.entity_type
        if entity.count == -1:
            entity_summary[et] = "variable"
        else:
            entity_summary[et] = entity_summary.get(et, 0) + entity.count

    for et, count in entity_summary.items():
        lines.append(f"  - {et}: {count}")

    if template.post_setup_notes:
        lines.append("")
        lines.append("Post-Setup Steps:")
        lines.append("-" * 30)
        for note in template.post_setup_notes:
            lines.append(f"  [ ] {note}")

    return '\n'.join(lines)


def format_application_result(result: Dict) -> str:
    """Format template application result for CLI display."""
    lines = [
        f"Template Applied: {result['template_name']}",
        "=" * 50,
        "",
        "Created Entities:",
        "-" * 30,
    ]

    for entity in result["created_entities"]:
        lines.append(f"  [{entity['type']:6}] {entity['name']}")
        for k, v in entity["config"].items():
            lines.append(f"           {k}: {v}")

    if result["post_setup_notes"]:
        lines.append("")
        lines.append("Next Steps:")
        lines.append("-" * 30)
        for i, note in enumerate(result["post_setup_notes"], 1):
            lines.append(f"  {i}. {note}")

    return '\n'.join(lines)
