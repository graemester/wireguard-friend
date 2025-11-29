"""
WireGuard Key Operations

Public keys are DERIVED from private keys (not stored separately).
This is fundamental to WireGuard's design.
"""

import base64
import subprocess
from typing import Tuple


def derive_public_key(private_key_base64: str) -> str:
    """
    Derive WireGuard public key from private key.

    Uses PyNaCl for derivation (same curve25519 as WireGuard).

    Args:
        private_key_base64: Base64-encoded private key

    Returns:
        Base64-encoded public key
    """
    from nacl.public import PrivateKey

    # Clean input
    private_key_base64 = private_key_base64.strip()

    private_bytes = base64.b64decode(private_key_base64)
    private = PrivateKey(private_bytes)
    public_bytes = bytes(private.public_key)
    return base64.b64encode(public_bytes).decode('ascii')


def generate_keypair() -> Tuple[str, str]:
    """
    Generate a WireGuard keypair.

    Returns:
        (private_key_base64, public_key_base64)
    """
    try:
        # Generate private key
        result = subprocess.run(
            ['wg', 'genkey'],
            capture_output=True,
            check=True
        )
        private_key = result.stdout.decode().strip()

        # Derive public key
        public_key = derive_public_key(private_key)

        return private_key, public_key

    except (subprocess.CalledProcessError, FileNotFoundError):
        # Fallback to PyNaCl
        from nacl.public import PrivateKey as NaClPrivateKey

        private = NaClPrivateKey.generate()
        private_bytes = bytes(private)
        public_bytes = bytes(private.public_key)

        private_key = base64.b64encode(private_bytes).decode('ascii')
        public_key = base64.b64encode(public_bytes).decode('ascii')

        return private_key, public_key


def generate_preshared_key() -> str:
    """
    Generate a WireGuard preshared key.

    Preshared keys provide additional security (post-quantum resistance).

    Returns:
        Base64-encoded preshared key
    """
    try:
        # Use wg genpsk command
        result = subprocess.run(
            ['wg', 'genpsk'],
            capture_output=True,
            check=True
        )
        preshared_key = result.stdout.decode().strip()
        return preshared_key

    except (subprocess.CalledProcessError, FileNotFoundError):
        # Fallback to generating random 32 bytes
        import os
        preshared_bytes = os.urandom(32)
        preshared_key = base64.b64encode(preshared_bytes).decode('ascii')
        return preshared_key


def test_key_derivation():
    """Test that public key derivation works"""
    print("Testing WireGuard key operations...")
    print()

    # Generate a keypair
    private_key, public_key = generate_keypair()

    print(f"Generated keypair:")
    print(f"  Private: {private_key}")
    print(f"  Public:  {public_key}")
    print()

    # Verify derivation is deterministic
    derived = derive_public_key(private_key)

    print(f"Derived public from private:")
    print(f"  Derived: {derived}")
    print()

    assert public_key == derived, "Public key derivation mismatch!"

    print("✓ Public key derivation works correctly")
    print()

    # Show that this is how we get permanent_guid
    print("For permanent_guid assignment:")
    print(f"  1. Read PrivateKey from [Interface]: {private_key}")
    print(f"  2. Derive public key: {derived}")
    print(f"  3. Set permanent_guid = {derived}")
    print()


if __name__ == "__main__":
    test_key_derivation()
