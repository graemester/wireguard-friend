# WireGuard Friend v1.0.1

**Release Date:** 2025-11-30
**Type:** Feature Release

## 🎉 Major New Feature: Extramural Configs

This release adds comprehensive support for managing **external WireGuard configurations** from commercial VPN providers (Mullvad, ProtonVPN, NordVPN, etc.) and employer networks alongside your mesh infrastructure.

### What is Extramural Configs?

Extramural configs allow you to:
- Import and manage VPN configs from external providers
- Switch between multiple VPN server endpoints
- Update configs when your provider sends changes
- Organize configs by sponsor (provider) and device
- Keep external VPNs completely separate from your mesh network

### Key Features

✅ **Import Sponsor Configs** - Parse and store .conf files from any VPN provider
```bash
wg-friend extramural import mullvad.conf --sponsor "Mullvad VPN" --peer "my-laptop"
```

✅ **Multi-Provider Support** - Manage configs from multiple VPN providers simultaneously
```bash
wg-friend extramural list
wg-friend extramural list --sponsor "Mullvad VPN"
wg-friend extramural list --peer "my-laptop"
```

✅ **Server Endpoint Switching** - Change between different server locations
```bash
wg-friend extramural switch-peer my-laptop/Mullvad-VPN eu-central-1
```

✅ **Config Generation** - Generate .conf files for deployment
```bash
wg-friend extramural generate my-laptop/Mullvad-VPN --output /etc/wireguard/wg-mullvad.conf
```

✅ **Config Updates** - Easy updates when sponsor sends new configs
```bash
wg-friend extramural import new-mullvad.conf --sponsor "Mullvad VPN" --peer "my-laptop"
```

✅ **Complete Separation** - Extramural configs are completely independent from your mesh network

### New CLI Commands

```bash
# Entity management
wg-friend extramural add-sponsor <name> [--website URL] [--support URL]
wg-friend extramural add-peer <name> [--ssh-host NAME]
wg-friend extramural add-ssh-host <name> --host HOST [OPTIONS]

# Config operations
wg-friend extramural list [--sponsor NAME] [--peer NAME]
wg-friend extramural show <peer/sponsor>
wg-friend extramural import <file> --sponsor NAME --peer NAME
wg-friend extramural generate <peer/sponsor> [--output FILE]
wg-friend extramural switch-peer <peer/sponsor> <peer_name>
```

### Database Schema

New tables added (automatically created on first run):
- `ssh_host` - Shared SSH configurations (reusable by mesh and extramural)
- `sponsor` - External VPN providers
- `local_peer` - Your devices receiving extramural configs
- `extramural_config` - Configurations linking devices to sponsors
- `extramural_peer` - Sponsor server endpoints (multiple per config)
- `extramural_state_snapshot` - State tracking
- `extramural_state_change` - Change history

### Use Cases

1. **Commercial VPNs** - Manage Mullvad, ProtonVPN, NordVPN configs
2. **Employer VPNs** - Store company WireGuard configs
3. **Hybrid Setup** - Use your mesh for home/office, external VPN for travel
4. **Multi-Device** - Same VPN provider across multiple devices
5. **Server Shopping** - Easily switch between VPN server locations

### Documentation

- 📖 **[Extramural Configs Guide](v1/docs/EXTRAMURAL_CONFIGS.md)** - Complete user guide with examples
- 📋 **[Implementation Summary](EXTRAMURAL_IMPLEMENTATION.md)** - Technical details
- 🎯 **[Design Document](https://github.com/graemester/wireguard-friend/blob/main/plans/extramural-configs-design.md)** - Architecture and design

### Example Workflow

```bash
# 1. Add your VPN provider
wg-friend extramural add-sponsor "Mullvad VPN" --website "https://mullvad.net"

# 2. Add your device
wg-friend extramural add-peer "my-laptop"

# 3. Import the config Mullvad sent you
wg-friend extramural import ~/Downloads/mullvad-us1.conf \
  --sponsor "Mullvad VPN" \
  --peer "my-laptop" \
  --interface "wg-mullvad"

# 4. View your configs
wg-friend extramural list

# 5. Generate .conf file for deployment
wg-friend extramural generate my-laptop/Mullvad-VPN \
  --output /etc/wireguard/wg-mullvad.conf

# 6. If Mullvad sends you an updated config, just re-import
wg-friend extramural import ~/Downloads/mullvad-updated.conf \
  --sponsor "Mullvad VPN" \
  --peer "my-laptop"
```

## Technical Details

### New Modules

- `v1/extramural_schema.py` - Database schema (140+ lines)
- `v1/extramural_ops.py` - Core operations (780+ lines)
- `v1/extramural_import.py` - Config parser and import (370+ lines)
- `v1/extramural_generator.py` - Config generation (260+ lines)
- `v1/cli/extramural.py` - CLI commands (450+ lines)

### Modified Files

- `v1/schema_semantic.py` - Integrated extramural schema initialization
- `v1/wg-friend` - Added extramural command routing
- `README.md` - Updated with v1.0.1 information

### Testing

✅ **End-to-End Test** - Complete workflow test covering:
- Database initialization
- Entity creation
- Config import
- Multi-peer management
- Active peer switching
- Config generation
- Sponsor updates
- **Status: ALL TESTS PASSING**

Run the test yourself:
```bash
python3 v1/test_extramural_e2e.py
```

## Compatibility

- ✅ **Backward Compatible** - No breaking changes to existing mesh functionality
- ✅ **Database Migration** - Existing databases automatically upgraded with new tables
- ✅ **Python 3.7+** - Same requirements as v1.0.0
- ✅ **Dependencies** - No new dependencies required

## What's NOT in This Release

The following features from the design document are planned for future releases:
- SSH deployment for extramural configs
- TUI integration (extramural menu in interactive mode)
- PostUp/PostDown command storage
- State snapshot operations
- API integration for provider-specific updates

## Upgrade Instructions

### From v1.0.0

```bash
# Pull latest changes
git pull origin main

# Database will auto-upgrade on first run
wg-friend

# That's it! Try the new extramural commands
wg-friend extramural --help
```

### Fresh Installation

```bash
git clone https://github.com/graemester/wireguard-friend.git
cd wireguard-friend
pip install -r requirements.txt

# Add to PATH (optional)
sudo ln -s $(pwd)/v1/wg-friend /usr/local/bin/wg-friend
```

## Documentation

- [README](README.md) - Overview and installation
- [Quick Start](v1/quick-start.md) - Mesh network walkthrough
- [Extramural Configs Guide](v1/docs/EXTRAMURAL_CONFIGS.md) - **NEW** - External VPN management
- [Command Reference](v1/COMMAND_REFERENCE.md) - All commands
- [Implementation Summary](EXTRAMURAL_IMPLEMENTATION.md) - **NEW** - Technical details

## Bug Fixes

- None (no bugs reported in v1.0.0)

## Known Issues

- None

## Contributors

- @graemester - Project creator and maintainer
- Claude Code - AI pair programmer (extramural feature implementation)

## Links

- **GitHub**: https://github.com/graemester/wireguard-friend
- **Issues**: https://github.com/graemester/wireguard-friend/issues
- **Design Doc**: https://github.com/graemester/wireguard-friend/blob/main/plans/extramural-configs-design.md

## Acknowledgments

Thanks to the WireGuard community for creating such an elegant VPN protocol, and to all VPN providers who offer WireGuard configs that make this feature useful!

---

**Full Changelog**: v1.0.0...v1.0.1
