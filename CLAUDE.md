# Claude Code Notes

Project-specific notes for Claude Code sessions.

## Build & Install

Build binary:
```bash
./build-binary.sh
```

Install to system (sudoers configured):
```bash
sudo /usr/bin/cp /home/ged/wireguard-friend/dist/wg-friend /usr/local/bin/
```

**Important**: The trailing slash on `/usr/local/bin/` is required - sudoers entries are literal and the entry ends with the directory, not the full destination path.

## Versioning

- Version and build name are in both `v1/wg-friend` and `v1/cli/tui.py` - keep in sync
- Build names are bird-themed: harrier, kestrel, ...

## Bash Aliases (user's shell)

```bash
alias edabout='nano /home/ged/wireguard-friend/v1/docs/help/about.txt'
alias pubabout='cd /home/ged/wireguard-friend && git add v1/docs/help/about.txt && git commit -m Update-about && git push && cd -'
```
