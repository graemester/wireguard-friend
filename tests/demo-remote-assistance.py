#!/usr/bin/env python3
"""
Demo: Remote Assistance Peer Creation

This demonstrates creating a peer with the 'remote_assistance' access level,
which provides full network access and generates user-friendly setup instructions.
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.database import WireGuardDB
from src.keygen import generate_keypair
from rich.console import Console

console = Console()

def demo_remote_assistance():
    """Demonstrate remote assistance peer creation"""
    db_path = Path("wg-friend.db")

    if not db_path.exists():
        console.print("[red]Database not found. Run wg-friend-onboard-v2.py first.[/red]")
        return

    db = WireGuardDB(db_path)

    # Get coordination server
    cs = db.get_coordination_server()
    if not cs:
        console.print("[red]No coordination server found.[/red]")
        return

    console.print("[bold cyan]Remote Assistance Peer Creation Demo[/bold cyan]\n")

    # Generate keypair
    private_key, public_key = generate_keypair()

    # Create peer block for CS
    peer_name = "friend-remote-assist"
    ipv4 = "10.66.0.50"
    ipv6 = "fd66:6666::50"

    peer_block = f"[Peer]\n"
    peer_block += f"# {peer_name}\n"
    peer_block += f"PublicKey = {public_key}\n"
    peer_block += f"AllowedIPs = {ipv4}/32, {ipv6}/128\n"

    # Create client config with full access
    client_config = f"[Interface]\n"
    client_config += f"PrivateKey = {private_key}\n"
    client_config += f"Address = {ipv4}/24, {ipv6}/64\n"
    client_config += f"DNS = {cs['ipv4_address']}\n"
    if cs['mtu']:
        client_config += f"MTU = {cs['mtu']}\n"
    client_config += f"\n[Peer]\n"
    client_config += f"PublicKey = {cs['public_key']}\n"
    client_config += f"Endpoint = {cs['endpoint']}\n"

    # Get all networks for full access
    all_networks = [cs['network_ipv4'], cs['network_ipv6']]
    sns = db.get_subnet_routers(cs['id'])
    for sn in sns:
        lans = db.get_sn_lan_networks(sn['id'])
        all_networks.extend(lans)

    allowed_ips = ", ".join(all_networks)
    client_config += f"AllowedIPs = {allowed_ips}\n"
    client_config += f"PersistentKeepalive = 25\n"

    # Save peer with remote_assistance access level
    console.print("[cyan]Creating peer with 'remote_assistance' access level...[/cyan]")

    peer_id = db.save_peer(
        name=peer_name,
        cs_id=cs['id'],
        public_key=public_key,
        ipv4_address=ipv4,
        ipv6_address=ipv6,
        access_level='remote_assistance',  # Special access level
        raw_peer_block=peer_block,
        private_key=private_key,
        raw_interface_block=client_config,
        persistent_keepalive=25
    )

    console.print(f"[green]✓ Peer created: {peer_name} (ID: {peer_id})[/green]")
    console.print(f"[green]✓ Access level: remote_assistance[/green]")
    console.print(f"[green]✓ Networks: {allowed_ips}[/green]")

    # Export config with special filename
    output_dir = Path("output")
    output_dir.mkdir(exist_ok=True)

    output_file = output_dir / "RemoteAssist.conf"
    with open(output_file, 'w') as f:
        f.write(client_config)
    output_file.chmod(0o600)

    console.print(f"\n[green]✓ Config exported to: {output_file}[/green]")

    # Generate instructions file
    console.print("[cyan]\nGenerating user-friendly setup instructions...[/cyan]")

    instructions_file = output_dir / "remote-assist.txt"
    instructions = f"""
================================================================================
WIREGUARD REMOTE ASSISTANCE SETUP GUIDE
================================================================================

This guide will help you install WireGuard and connect to remote assistance.

Your configuration file: {output_file.name}

================================================================================
STEP 1: DOWNLOAD WIREGUARD
================================================================================

Visit: https://www.wireguard.com/install/

Download the installer for your operating system:
  • Windows: Download "WireGuard Installer"
  • macOS: Download from App Store or download "WireGuard for macOS"
  • Linux: Install via package manager (instructions on website)


================================================================================
MACOS SETUP INSTRUCTIONS
================================================================================

STEP 1: INSTALL WIREGUARD
--------------------------
1. Download WireGuard from the Mac App Store, or
2. Download from https://www.wireguard.com/install/ and install

STEP 2: IMPORT THE CONFIGURATION FILE
--------------------------------------
1. Click on the WireGuard icon in your macOS top menu bar
2. In the drop-down menu, select "Import tunnel(s) from file..."
3. Navigate to your Downloads folder and select: {output_file.name}
4. Click "Import"
5. Click "Allow" if you get a pop-up saying "WireGuard would like to Add VPN
   Configurations"

STEP 3: CONNECT
---------------
1. Click on the WireGuard icon in your desktop's top menu bar
2. In the drop-down menu, select the entry "RemoteAssist"
3. A checkmark will appear next to it - you're now connected!

You can view detailed connection information and manage your connection under
"Manage Tunnels" in the drop-down menu.

STEP 4: DISCONNECT
------------------
1. Click on the WireGuard icon in your desktop's top menu bar
2. In the drop-down menu, click on "RemoteAssist" (the one with a checkmark)
3. The checkmark will disappear - you're now disconnected


================================================================================
WINDOWS SETUP INSTRUCTIONS
================================================================================

STEP 1: INSTALL WIREGUARD
--------------------------
1. Download WireGuard from https://www.wireguard.com/install/
2. Run the installer (WireGuard-Installer.exe)
3. Follow the installation prompts

STEP 2: IMPORT THE CONFIGURATION
---------------------------------
1. Open the WireGuard app
2. Click "Add Tunnel"
3. Select the configuration file you received: {output_file.name}
4. Click "Open"

STEP 3: CONNECT
---------------
1. Open the WireGuard app
2. Select "RemoteAssist" from the list on the left
3. Press "Activate" to connect

The status will change to "Active" and show connection information.

STEP 4: DISCONNECT
------------------
1. Open the WireGuard app
2. Press "Deactivate" to disconnect


================================================================================
TROUBLESHOOTING
================================================================================

Connection won't activate:
  • Make sure you have an active internet connection
  • Try disabling any VPN or firewall software temporarily
  • Restart the WireGuard app

Can't find the configuration file:
  • Check your Downloads folder
  • The file is named: {output_file.name}
  • Make sure it wasn't blocked by your antivirus

Need help?
  • Contact your technical support person
  • They can remotely assist you once you're connected


================================================================================
IMPORTANT NOTES
================================================================================

• Only connect when you need remote assistance
• Disconnect when assistance is complete
• Your connection is encrypted and secure
• Your support person can access your computer via SSH, RDP, or VNC when
  you're connected


================================================================================
REMOTE ACCESS PROTOCOLS
================================================================================

When connected, your support person can reach your computer using:

  SSH (Secure Shell)
    - Port 22
    - Command-line access for troubleshooting
    - Available on: macOS, Linux, Windows (with OpenSSH)

  RDP (Remote Desktop Protocol)
    - Port 3389
    - Full graphical desktop access
    - Available on: Windows (built-in), macOS (Microsoft Remote Desktop app)

  VNC (Virtual Network Computing)
    - Port 5900
    - Cross-platform graphical desktop access
    - Available on: macOS (Screen Sharing), Linux, Windows (with VNC server)

Your support person will use the appropriate protocol based on your system.

================================================================================
"""

    with open(instructions_file, 'w') as f:
        f.write(instructions)
    instructions_file.chmod(0o644)

    console.print(f"[green]✓ Instructions saved to: {instructions_file}[/green]")

    console.print("\n[bold yellow]Next steps:[/bold yellow]")
    console.print(f"  1. Share {output_file.name} and {instructions_file.name} with the user")
    console.print(f"  2. Deploy updated coordination server config")
    console.print(f"  3. User follows instructions to connect")
    console.print(f"  4. Connect via SSH/RDP/VNC using their VPN IP: {ipv4}")

    console.print("\n[bold cyan]Example commands for remote access:[/bold cyan]")
    console.print(f"  SSH:  ssh user@{ipv4}")
    console.print(f"  RDP:  mstsc /v:{ipv4}  (Windows)")
    console.print(f"  VNC:  vnc://{ipv4}  (macOS Screen Sharing)")


if __name__ == "__main__":
    demo_remote_assistance()
