# WireGuard Friend - Documentation Guide

Documentation for building and managing WireGuard networks.

---

## Getting Started

### [README.md](../../README.md) - Project Overview

What WireGuard Friend does and whether it fits your needs.

- Network architecture overview
- Feature list
- Installation instructions
- Basic commands

---

### [WHERE_TO_RUN.md](WHERE_TO_RUN.md) - Installation Location Guide

Where to install WireGuard Friend: coordination server, subnet router, or client device.

- Recommended locations
- CS vs subnet router vs client comparison
- Workflow considerations
- Security considerations

---

### [quick-start.md](../quick-start.md) - Step-by-Step Tutorial

Walkthrough of features.

- Import existing WireGuard configs
- Maintenance mode
- Create peers with QR codes
- Access levels (full_access, vpn_only, lan_only, custom)
- Key rotation
- SSH deployment

---

### [COMMAND_REFERENCE.md](../COMMAND_REFERENCE.md) - Command Reference

Reference for all `wg-friend` commands.

- Setup commands (init, import)
- Config generation (generate, QR codes)
- Peer management (add, remove, rotate)
- Deployment (deploy, SSH)
- Status monitoring (status, live)
- Interactive mode (maintain)

---

## Architecture

### [ARCHITECTURE.md](ARCHITECTURE.md) - Design Documentation

Internal design and implementation.

- Database schema (permanent_guid system)
- Semantic configuration storage
- Key rotation with identity preservation
- Config generation
- Import/export flow

---

## Features

### [EXIT_NODES.md](EXIT_NODES.md) - Exit Node Guide

Configure internet egress servers for privacy and geo-location.

- Exit node concepts (split tunnel vs full tunnel)
- Adding and managing exit nodes
- Assigning exit nodes to remotes
- exit_only access level
- Config generation examples
- Security considerations

---

### [EXTRAMURAL_CONFIGS.md](EXTRAMURAL_CONFIGS.md) - Commercial VPN Integration

Manage configurations from commercial VPN providers.

- Extramural schema
- Import provider configs
- Switch endpoints
- Local peer management

---

## Guides

### Backup and Restore

Database backup:
```bash
cp wireguard.db wireguard.db.backup
```

The SQLite database contains all configuration data.

### Key Rotation

Rotate keys while preserving peer identity:
```bash
wg-friend rotate
# Select peer from list
# Provide rotation reason
# permanent_guid stays the same, current_public_key updates
```

### SSH Deployment

Setup passwordless SSH deployment:
```bash
wg-friend ssh-setup
# Follow wizard to configure SSH keys
# Test connection
# Deploy configs
```

---

## Support

Report issues: https://github.com/graemester/wireguard-friend/issues
