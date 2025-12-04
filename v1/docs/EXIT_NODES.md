# Exit Nodes - Internet Egress Servers

Exit nodes allow remotes to route internet traffic through a dedicated VPS/server for privacy or geo-location purposes. Unlike the coordination server which manages the VPN mesh, exit nodes only provide internet egress.

## Concepts

### Split Tunnel (Default)
By default, remotes use **split tunnel** - VPN traffic goes through the coordination server, but internet traffic uses the device's normal internet connection. This is efficient and doesn't route all traffic through the VPN.

### Exit Node Routing
When a remote is assigned an exit node, it gets **full tunnel** routing - all internet traffic (0.0.0.0/0, ::/0) is routed through the exit node. The exit node performs NAT and forwards traffic to the internet.

### Access Levels

| Level | VPN Traffic | LAN Traffic | Internet Traffic |
|-------|-------------|-------------|------------------|
| `full_access` | Through CS | Through CS | Split tunnel (or exit if assigned) |
| `vpn_only` | Through CS | No access | Split tunnel (or exit if assigned) |
| `lan_only` | Through CS | Through CS | Split tunnel (or exit if assigned) |
| `exit_only` | **No CS peer** | No access | Through exit node only |

The `exit_only` access level is special - the remote has **no coordination server peer** and only connects to the exit node. This is useful for devices that only need internet privacy without VPN network access.

## Usage

### Via TUI

Access exit node management from the main menu:

```
WIREGUARD FRIEND v1.0.7 (kestrel)
1. Manage Peers
2. Add Peer
3. Remove Peer
4. Rotate Keys
5. History
6. Exit Nodes     <-- New menu
7. Extramural
8. Generate Configs
9. Deploy Configs
```

The Exit Nodes menu provides:

1. **List Exit Nodes** - View all configured exit nodes and which remotes use them
2. **Add Exit Node** - Create a new exit node
3. **Assign Exit to Remote** - Route a remote's internet through an exit node
4. **Clear Exit from Remote** - Revert remote to split tunnel
5. **Remove Exit Node** - Delete an exit node (remotes revert to split tunnel)

### Via Manage Peers

Exit nodes also appear in **Manage Peers** under their own section:

```
[EXIT NODES]
  5. exit-us-west     10.66.0.100    us-west.example.com:51820   (2 clients)
  6. exit-eu-central  10.66.0.101    eu.example.com:51820        (1 client)
```

Selecting an exit node opens the detail view with actions:

1. **Edit Hostname** - Change the exit node name
2. **Rotate Keys** - Generate new WireGuard keys
3. **View Key History** - See previous public keys with GUIDs
4. **Edit Endpoint** - Update the public IP/domain
5. **Edit WAN Interface** - Change the NAT interface
6. **Generate Config** - Create the WireGuard config file
7. **Deploy Config** - SSH deploy to the exit node server
8. **Remove Exit Node** - Delete (remotes revert to split tunnel)

### Adding an Exit Node

When adding an exit node, provide:

- **Hostname**: Unique identifier (e.g., 'exit-us-west', 'exit-eu-central')
- **Endpoint**: Public IP or domain where clients connect
- **Listen Port**: WireGuard port (default 51820)
- **WAN Interface**: Interface for NAT masquerading (default 'eth0')
- **SSH Settings**: For deployment (optional)

The system automatically assigns a VPN IP in the 100-119 range.

### Assigning Exit Nodes

After creating an exit node, assign it to remotes:

```
1. Go to Exit Nodes menu
2. Select "Assign Exit to Remote"
3. Enter the remote ID
4. Enter the exit node ID
5. Generate new configs and deploy
```

## Generated Configs

### Remote Config (with exit node)

```ini
[Interface]
Address = 10.66.0.30/32, fd66::1e/128
PrivateKey = <remote-private-key>
DNS = 1.1.1.1, 8.8.8.8
MTU = 1280

[Peer]
# coordination-server
PublicKey = <cs-public-key>
Endpoint = cs.example.com:51820
AllowedIPs = 10.66.0.0/24, fd66::/64
PersistentKeepalive = 25

[Peer]
# exit-node: exit-us-west
PublicKey = <exit-public-key>
Endpoint = us-west.example.com:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
```

Note: The exit node peer gets the default route (0.0.0.0/0) while the CS peer gets VPN-only routes.

### Remote Config (exit_only)

```ini
[Interface]
Address = 10.66.0.30/32, fd66::1e/128
PrivateKey = <remote-private-key>
DNS = 1.1.1.1, 8.8.8.8
MTU = 1280

[Peer]
# exit-node: exit-us-west
PublicKey = <exit-public-key>
Endpoint = us-west.example.com:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
```

Note: No coordination server peer - this device only uses the exit node.

### Exit Node Config

```ini
[Interface]
Address = 10.66.0.100/32, fd66::64/128
PrivateKey = <exit-private-key>
ListenPort = 51820

# Enable IP forwarding and NAT for internet egress
PostUp = sysctl -w net.ipv4.ip_forward=1
PostUp = sysctl -w net.ipv6.conf.all.forwarding=1
PostUp = iptables -A FORWARD -i %i -j ACCEPT
PostUp = iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostUp = ip6tables -A FORWARD -i %i -j ACCEPT
PostUp = ip6tables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
PostDown = ip6tables -D FORWARD -i %i -j ACCEPT
PostDown = ip6tables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

[Peer]
# alice-laptop
PublicKey = <alice-public-key>
AllowedIPs = 10.66.0.30/32, fd66::1e/128

[Peer]
# bob-phone
PublicKey = <bob-public-key>
AllowedIPs = 10.66.0.31/32, fd66::1f/128
```

### CS Config (with exit nodes)

The coordination server config includes exit nodes as peers:

```ini
[Peer]
# exit-node: exit-us-west
PublicKey = <exit-public-key>
AllowedIPs = 10.66.0.100/32, fd66::64/128
Endpoint = us-west.example.com:51820
PersistentKeepalive = 25
```

## Key Rotation

Exit nodes support key rotation just like other peers. When you rotate keys:

1. A new WireGuard key pair is generated
2. The permanent GUID is preserved for identity tracking
3. The old public key is recorded in key history
4. A state snapshot is recorded for auditing

To rotate keys:

```
1. Go to Manage Peers
2. Select the exit node
3. Choose "Rotate Keys"
4. Confirm the rotation
5. Regenerate configs and deploy
```

Or use the Rotate Keys menu (option 4 from main menu):

```
ROTATE KEYS
...
[EXIT NODES]
  [1] exit-us-west (us-west.example.com:51820)
  [2] exit-eu-central (eu.example.com:51820)

Peer type [cs/router/remote/exit_node]: exit_node
Peer ID: 1
```

## Deployment

After adding or modifying exit nodes:

```bash
# Generate configs
wg-friend generate

# Deploy to all servers (includes exit nodes)
wg-friend deploy

# Or deploy to specific exit node
wg-friend deploy --entity exit-us-west
```

### Deploy from Manage Peers

You can also deploy directly from the exit node detail view:

1. Go to **Manage Peers**
2. Select the exit node
3. Choose **Deploy Config** (option 7)
4. Confirm deployment
5. Optionally restart WireGuard on the server

The system uses the SSH credentials stored with the exit node (ssh_host, ssh_user, ssh_port) for deployment.

### SSH Requirements

For deployment to work, ensure:

1. SSH key authentication is configured to the exit node
2. The SSH user has permission to write to `/etc/wireguard/`
3. The SSH user can run `wg-quick` commands (typically root or sudo)

## Security Considerations

1. **Exit Node Trust**: Traffic through exit nodes is decrypted at the exit node. Only use exit nodes you control or trust.

2. **Logging**: Exit nodes can see destination IPs of traffic. Consider privacy implications.

3. **DNS**: Remotes using exit nodes automatically get DNS settings (1.1.1.1, 8.8.8.8) to prevent DNS leaks.

4. **Kill Switch**: The generated config uses AllowedIPs = 0.0.0.0/0 which acts as a kill switch - if the VPN drops, no traffic can leak.

## IP Allocation

Exit nodes use VPN IPs in the 100-119 range, allowing up to 20 exit nodes:

| Entity Type | IP Range |
|------------|----------|
| Coordination Server | .1 |
| Subnet Routers | .20-.29 |
| Remote Clients | .30-.99 |
| **Exit Nodes** | **.100-.119** |
| Reserved | .120-.254 |

## Troubleshooting

### Exit node not routing traffic

1. Check IP forwarding is enabled:
   ```bash
   sysctl net.ipv4.ip_forward
   ```

2. Check NAT rules are in place:
   ```bash
   iptables -t nat -L POSTROUTING
   ```

3. Verify WireGuard is running:
   ```bash
   wg show
   ```

### Cannot clear exit from remote

If you get "Cannot clear exit node from exit_only remote", you need to change the access level first:

1. Go to Manage Peers
2. Select the remote
3. Change access level from `exit_only` to `full_access` or another level
4. Then clear the exit node assignment

### Remotes can't reach exit node

1. Check the exit node's endpoint is reachable
2. Verify firewall allows UDP on the listen port
3. Check the remote's config has the correct exit node public key
