# Extramural Configs - External VPN Management

**Version:** 1.0.0
**Status:** ✅ Fully Implemented

## Overview

The **Extramural Configs** feature allows you to manage external WireGuard configurations from commercial VPN providers (Mullvad, ProtonVPN, etc.) or employer networks alongside your own mesh network infrastructure.

### Key Concepts

- **Extramural** = External to your mesh network
- **Sponsor** = External VPN provider or service (e.g., "Mullvad VPN", "Company VPN")
- **Local Peer** = Your devices that connect to sponsors
- **Extramural Config** = Configuration linking a local peer to a sponsor
- **Extramural Peer** = Sponsor's server endpoints (multiple servers per config supported)

### Core Principles

1. **Complete Separation from Mesh**: Extramural configs exist independently from your mesh network topology
2. **Shared SSH Infrastructure**: SSH host configurations are reusable by both mesh and extramural systems
3. **Local-Only Control**: You control your endpoint (keys, interface), sponsor controls theirs (servers, routing)

## Quick Start

### 1. Add a Sponsor

```bash
wg-friend extramural add-sponsor "Mullvad VPN" \
  --website "https://mullvad.net" \
  --support "https://mullvad.net/help"
```

### 2. Add Your Device

```bash
wg-friend extramural add-peer "my-laptop" \
  --notes "Personal laptop"
```

### 3. Import Sponsor Config

When you sign up for a VPN service, they provide a `.conf` file. Import it:

```bash
wg-friend extramural import ~/Downloads/mullvad-us1.conf \
  --sponsor "Mullvad VPN" \
  --peer "my-laptop" \
  --interface "wg-mullvad"
```

### 4. View Configs

```bash
# List all configs
wg-friend extramural list

# Show detailed info
wg-friend extramural show my-laptop/Mullvad-VPN

# Generate .conf file
wg-friend extramural generate my-laptop/Mullvad-VPN --output /etc/wireguard/wg-mullvad.conf
```

## Common Workflows

### Import Multiple Sponsor Configs

You can have configs for multiple VPN providers on the same device:

```bash
# Import Mullvad config
wg-friend extramural import mullvad.conf \
  --sponsor "Mullvad VPN" \
  --peer "my-laptop"

# Import ProtonVPN config
wg-friend extramural import protonvpn.conf \
  --sponsor "ProtonVPN" \
  --peer "my-laptop"

# List all configs for this device
wg-friend extramural list --peer "my-laptop"
```

### Switch Between Server Endpoints

Most VPN providers offer multiple servers. When you import their config, one server becomes active. You can add more and switch between them:

```bash
# View current config
wg-friend extramural show my-laptop/Mullvad-VPN

# The sponsor has multiple servers (us-east-1, us-west-1, eu-central-1)
# Switch to a different one:
wg-friend extramural switch-peer my-laptop/Mullvad-VPN eu-central-1

# Regenerate config
wg-friend extramural generate my-laptop/Mullvad-VPN --output /etc/wireguard/wg-mullvad.conf
```

### Update Config from Sponsor

When your VPN provider sends you an updated config (new servers, changed keys, etc.):

```bash
# Simply re-import the new config
wg-friend extramural import new-mullvad.conf \
  --sponsor "Mullvad VPN" \
  --peer "my-laptop"

# This updates your existing config with the new details
# The pending_remote_update flag is automatically cleared
```

### SSH Deployment (Advanced)

If you want to deploy configs to remote devices via SSH:

```bash
# Add SSH host configuration
wg-friend extramural add-ssh-host "server1" \
  --host "server1.example.com" \
  --user "root" \
  --key-path "~/.ssh/id_rsa"

# Link local peer to SSH host
wg-friend extramural add-peer "server1" \
  --ssh-host "server1"

# Now you can deploy via SSH (future feature)
```

## Command Reference

### Entity Management

#### SSH Hosts
```bash
wg-friend extramural add-ssh-host <name> --host <hostname> [OPTIONS]
```

Options:
- `--port` - SSH port (default: 22)
- `--user` - SSH username
- `--key-path` - SSH private key path
- `--config-dir` - WireGuard config directory (default: /etc/wireguard)
- `--notes` - Additional notes

#### Sponsors
```bash
wg-friend extramural add-sponsor <name> [OPTIONS]
```

Options:
- `--website` - Sponsor website URL
- `--support` - Support/help URL
- `--notes` - Additional notes

#### Local Peers
```bash
wg-friend extramural add-peer <name> [OPTIONS]
```

Options:
- `--ssh-host` - SSH host name (if deploying via SSH)
- `--notes` - Additional notes

### Config Operations

#### List Configs
```bash
wg-friend extramural list [OPTIONS]
```

Options:
- `--sponsor <name>` - Filter by sponsor
- `--peer <name>` - Filter by local peer

#### Show Config Details
```bash
wg-friend extramural show <peer/sponsor>
# OR
wg-friend extramural show <config_id>
```

#### Import Config
```bash
wg-friend extramural import <config_file> --sponsor <name> --peer <name> [OPTIONS]
```

Options:
- `--interface` - Interface name (default: filename)
- `--website` - Sponsor website (if creating new sponsor)
- `--support` - Sponsor support URL (if creating new sponsor)

#### Generate Config
```bash
wg-friend extramural generate <peer/sponsor> [OPTIONS]
```

Options:
- `--output <path>` - Output file path (prints to stdout if omitted)

#### Switch Active Peer
```bash
wg-friend extramural switch-peer <peer/sponsor> <peer_name>
```

## Database Schema

### Tables

- **`ssh_host`** - Shared SSH connection details (reusable by mesh and extramural)
- **`sponsor`** - External VPN providers/services
- **`local_peer`** - Your devices receiving extramural configs
- **`extramural_config`** - Configurations linking devices to sponsors
- **`extramural_peer`** - Sponsor's server endpoints
- **`extramural_state_snapshot`** - State tracking snapshots
- **`extramural_state_change`** - Change history

### Key Features

- **Single active peer per config**: Enforced via database trigger
- **Pending remote update flag**: Tracks when you need to notify sponsor of key changes
- **Permanent GUID**: Uses public key as immutable identifier
- **SSH host sharing**: Same SSH configuration can be used by both mesh and extramural systems

## Python API

### Basic Operations

```python
from pathlib import Path
from v1.extramural_ops import ExtramuralOps
from v1.extramural_import import import_extramural_config
from v1.extramural_generator import ExtramuralConfigGenerator

db_path = Path("wireguard.db")
ops = ExtramuralOps(db_path)
gen = ExtramuralConfigGenerator(db_path)

# Add entities
sponsor_id = ops.add_sponsor("Mullvad VPN", website="https://mullvad.net")
peer_id = ops.add_local_peer("my-laptop")

# Import config
config_id, _, _ = import_extramural_config(
    db_path=db_path,
    config_path=Path("mullvad.conf"),
    sponsor_name="Mullvad VPN",
    local_peer_name="my-laptop"
)

# Generate config
content = gen.generate_config(config_id)
print(content)

# List configs
configs = ops.list_extramural_configs(sponsor_id=sponsor_id)
for config in configs:
    print(f"Config {config.id}: {config.interface_name}")

# Switch active peer
peers = ops.list_extramural_peers(config_id)
ops.set_active_peer(peers[1].id)  # Switch to second peer
```

### Advanced: Config Updates

```python
# Scenario 1: Sponsor sends updated config
ops.update_config_from_sponsor(
    config_id=config_id,
    assigned_ipv4="10.64.2.1/32",  # New IP
    dns_servers="10.64.0.1, 10.64.0.2"  # New DNS
)

# Scenario 2: You rotate your local key (unusual)
from v1.extramural_ops import generate_wireguard_keypair
new_private, new_public = generate_wireguard_keypair()

ops.rotate_local_key(config_id, new_private, new_public)
# This sets pending_remote_update=1
# You must notify sponsor of new public key

# After sponsor confirms update:
ops.clear_pending_update(config_id)
```

## Differences from Mesh Configs

| Aspect | Mesh Configs | Extramural Configs |
|--------|--------------|-------------------|
| Control | Both endpoints | Local endpoint only |
| Topology | Part of mesh | Independent |
| Key Rotation | Both sides | Local only (notify sponsor) |
| Deployment | Your infrastructure | Your device only |
| IP Allocation | You control | Sponsor assigns |
| Server Management | You manage | Sponsor manages |

## Limitations

You **cannot** with extramural configs:

- Rotate sponsor's keys (they control their infrastructure)
- Add/remove sponsor peers (they control their servers)
- Modify assigned addresses (sponsor assigns these)
- Change allowed IP ranges (sponsor determines access)
- Deploy to sponsor servers (no access to their infrastructure)
- Include in mesh topology visualization (completely separate system)

## Use Cases

1. **Commercial VPN Services**: Mullvad, ProtonVPN, NordVPN, etc.
2. **Employer VPNs**: Company-provided WireGuard configs
3. **Third-Party Services**: Any external WireGuard service you don't control
4. **Hybrid Setups**: Use your mesh for home/office, external VPN for public Wi-Fi

## Future Enhancements

- **API Integration**: Automatic config updates for providers with APIs
- **Deployment via SSH**: Auto-deploy configs to remote devices
- **TUI Integration**: Interactive terminal UI for management
- **Configuration Synchronization**: Share sponsor configs across multiple devices
- **Batch Export**: Backup all extramural configs
- **Provider Account Import**: Bulk download all configs from provider

## Testing

Run the end-to-end test:

```bash
python3 v1/test_extramural_e2e.py
```

This test demonstrates:
- Database initialization
- Entity creation (sponsors, peers, SSH hosts)
- Config import
- Multi-peer management
- Active peer switching
- Config generation
- Sponsor updates

## Architecture

See the [Extramural Configs Design Document](https://github.com/graemester/wireguard-friend/blob/main/plans/extramural-configs-design.md) for complete architectural details.

## Support

For issues or questions:
- GitHub Issues: https://github.com/graemester/wireguard-friend/issues
- Documentation: https://github.com/graemester/wireguard-friend

---

**Implemented:** 2025-11-30
**Author:** Claude Code with @graemester
