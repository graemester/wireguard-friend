"""
Key Validation Test

Demonstrates that we:
1. Derive public keys from private keys in [Interface]
2. Validate derived keys match the public keys in [Peer] sections
3. Detect mismatched/corrupted keypairs
"""

import sys
from pathlib import Path
from typing import Dict, List, Tuple

sys.path.insert(0, str(Path(__file__).parent))

from wg_keys import generate_keypair, derive_public_key


def parse_interface_private_key(config: str) -> str:
    """Extract PrivateKey from [Interface] section"""
    for line in config.split('\n'):
        stripped = line.strip()
        if stripped.startswith('PrivateKey'):
            # Split on = and get value, remove all whitespace
            value = stripped.split('=', 1)[1].strip()
            # Remove any comments
            if '#' in value:
                value = value.split('#')[0].strip()
            return value
    raise ValueError("No PrivateKey found in config")


def parse_peer_public_keys(config: str) -> List[str]:
    """Extract all PublicKey values from [Peer] sections"""
    public_keys = []
    for line in config.split('\n'):
        stripped = line.strip()
        if '[Peer]' in stripped:
            continue
        if stripped.startswith('PublicKey'):
            value = stripped.split('=', 1)[1].strip()
            # Remove any comments
            if '#' in value:
                value = value.split('#')[0].strip()
            public_keys.append(value)
    return public_keys


def test_key_validation():
    """Test key validation workflow"""
    print("=" * 70)
    print("KEY VALIDATION TEST")
    print("=" * 70)
    print()

    # Generate keypairs for 3 entities
    cs_private, cs_public = generate_keypair()
    snr_private, snr_public = generate_keypair()
    remote_private, remote_public = generate_keypair()

    print("Generated keypairs:")
    print(f"  CS:     {cs_public[:30]}...")
    print(f"  SNR:    {snr_public[:30]}...")
    print(f"  Remote: {remote_public[:30]}...")
    print()

    # Create configs (as they would actually appear)
    coordination_conf = f"""[Interface]
Address = 10.66.0.1/24
PrivateKey = {cs_private}
ListenPort = 51820

[Peer]
# subnet-router
PublicKey = {snr_public}
AllowedIPs = 10.66.0.20/32

[Peer]
# remote
PublicKey = {remote_public}
AllowedIPs = 10.66.0.30/32
"""

    wg0_conf = f"""[Interface]
Address = 10.66.0.20/32
PrivateKey = {snr_private}

[Peer]
# coordination-server
PublicKey = {cs_public}
AllowedIPs = 10.66.0.0/24
"""

    remote_conf = f"""[Interface]
Address = 10.66.0.30/32
PrivateKey = {remote_private}

[Peer]
# coordination-server
PublicKey = {cs_public}
AllowedIPs = 10.66.0.0/24
"""

    print("=" * 70)
    print("IMPORT SIMULATION")
    print("=" * 70)
    print()

    # Simulate import process
    configs = {
        'coordination.conf': coordination_conf,
        'wg0.conf': wg0_conf,
        'remote.conf': remote_conf,
    }

    # Store derived public keys
    derived_keys = {}
    # Store public keys seen in [Peer] sections
    peer_keys = {}

    # Phase 1: Extract private keys and derive public keys
    print("Phase 1: Derive public keys from private keys")
    print()

    for filename, config in configs.items():
        private_key = parse_interface_private_key(config)
        derived_public = derive_public_key(private_key)
        derived_keys[filename] = derived_public

        print(f"  {filename}:")
        print(f"    PrivateKey: {private_key[:30]}...")
        print(f"    Derived PublicKey: {derived_public[:30]}...")
        print()

    # Phase 2: Extract public keys from [Peer] sections
    print("Phase 2: Extract public keys from [Peer] sections")
    print()

    for filename, config in configs.items():
        public_keys = parse_peer_public_keys(config)
        peer_keys[filename] = public_keys

        print(f"  {filename} references:")
        for pk in public_keys:
            print(f"    PublicKey: {pk[:30]}...")
        print()

    # Phase 3: Validate
    print("=" * 70)
    print("VALIDATION")
    print("=" * 70)
    print()

    validation_map = {
        # (derived_from, appears_in_peers_of)
        ('wg0.conf', 'coordination.conf'): 'SNR',
        ('remote.conf', 'coordination.conf'): 'Remote',
        ('coordination.conf', 'wg0.conf'): 'CS (in SNR config)',
        ('coordination.conf', 'remote.conf'): 'CS (in Remote config)',
    }

    all_valid = True

    for (derived_from, appears_in), entity_name in validation_map.items():
        derived = derived_keys[derived_from]
        peers = peer_keys[appears_in]

        print(f"Validating {entity_name}:")
        print(f"  Derived from {derived_from}: {derived[:30]}...")

        if derived in peers:
            print(f"  Found in {appears_in} [Peer] sections: ✓ VALID")
        else:
            print(f"  NOT found in {appears_in} [Peer] sections: ✗ INVALID")
            all_valid = False

        print()

    # Show what would happen with corrupted key
    print("=" * 70)
    print("CORRUPTION DETECTION TEST")
    print("=" * 70)
    print()

    print("Scenario: SNR's public key is corrupted in coordination.conf")
    print()

    # Corrupt SNR's key
    corrupted_snr_public = snr_public[:-5] + "WRONG"

    corrupted_coord_conf = f"""[Interface]
PrivateKey = {cs_private}

[Peer]
# subnet-router (CORRUPTED KEY!)
PublicKey = {corrupted_snr_public}
AllowedIPs = 10.66.0.20/32
"""

    # Try to validate
    derived_snr = derived_keys['wg0.conf']
    corrupted_peers = parse_peer_public_keys(corrupted_coord_conf)

    print(f"  SNR's derived public key: {derived_snr[:30]}...")
    print(f"  Key in coordination.conf:  {corrupted_snr_public[:30]}...")
    print()

    if derived_snr in corrupted_peers:
        print("  ✓ Keys match")
    else:
        print("  ✗ Keys DO NOT match - CORRUPTION DETECTED!")
        print()
        print("  This would indicate:")
        print("    - Wrong keypair deployed to SNR")
        print("    - Corrupted config file")
        print("    - Manual editing error")
        print("    - Need to regenerate or redeploy configs")

    print()

    # Summary
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print()

    if all_valid:
        print("✓ All public keys validated successfully")
        print()
        print("Key validation workflow:")
        print("  1. Import config → read PrivateKey from [Interface]")
        print("  2. Derive public key: public = derive(private)")
        print("  3. Set permanent_guid = public")
        print("  4. Validate: Check derived public appears in other configs' [Peer]")
        print("  5. If mismatch → ERROR (corrupted keys!)")
        print()
        print("This ensures:")
        print("  - Keypairs are consistent across all configs")
        print("  - No corrupted keys")
        print("  - No mismatched deployments")
    else:
        print("✗ Validation failures detected")

    print()

    return all_valid


if __name__ == "__main__":
    success = test_key_validation()
    sys.exit(0 if success else 1)
