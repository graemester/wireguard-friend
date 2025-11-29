"""WireGuard keypair generation utilities"""

import subprocess
import logging
from typing import Tuple


logger = logging.getLogger(__name__)


def generate_keypair() -> Tuple[str, str]:
    """
    Generate a WireGuard keypair

    Returns:
        (private_key, public_key) tuple
    """
    try:
        # Generate private key
        result = subprocess.run(
            ['wg', 'genkey'],
            capture_output=True,
            text=True,
            check=True
        )
        private_key = result.stdout.strip()

        # Derive public key from private key
        public_key = derive_public_key(private_key)

        logger.info("Generated WireGuard keypair")
        return private_key, public_key

    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to generate keypair: {e}")
        raise RuntimeError("WireGuard key generation failed. Is 'wg' command available?")
    except FileNotFoundError:
        logger.error("WireGuard tools not found (wg command)")
        raise RuntimeError("WireGuard tools not installed. Install with: sudo apt install wireguard-tools")


def derive_public_key(private_key: str) -> str:
    """
    Derive public key from private key

    Args:
        private_key: WireGuard private key

    Returns:
        Corresponding public key
    """
    try:
        result = subprocess.run(
            ['wg', 'pubkey'],
            input=private_key,
            capture_output=True,
            text=True,
            check=True
        )
        public_key = result.stdout.strip()

        logger.debug("Derived public key from private key")
        return public_key

    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to derive public key: {e}")
        raise RuntimeError("Failed to derive public key from private key")
    except FileNotFoundError:
        raise RuntimeError("WireGuard tools not installed")


def generate_preshared_key() -> str:
    """
    Generate a WireGuard preshared key

    Returns:
        Preshared key string
    """
    try:
        result = subprocess.run(
            ['wg', 'genpsk'],
            capture_output=True,
            text=True,
            check=True
        )
        preshared_key = result.stdout.strip()

        logger.info("Generated preshared key")
        return preshared_key

    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to generate preshared key: {e}")
        raise RuntimeError("Preshared key generation failed. Is 'wg' command available?")
    except FileNotFoundError:
        logger.error("WireGuard tools not found (wg command)")
        raise RuntimeError("WireGuard tools not installed. Install with: sudo apt install wireguard-tools")


def validate_key(key: str) -> bool:
    """
    Validate a WireGuard key format

    Args:
        key: Key to validate

    Returns:
        True if valid, False otherwise
    """
    # WireGuard keys are base64-encoded 32-byte values (44 characters including padding)
    import re
    pattern = r'^[A-Za-z0-9+/]{42}[A-Za-z0-9+/=]{2}$'
    return bool(re.match(pattern, key))
