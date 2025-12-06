"""
Database Encryption Module - Column-Level AES-256-GCM

Provides transparent encryption for sensitive columns (private keys, preshared keys).
Uses Scrypt for key derivation (memory-hard, ASIC-resistant) and AES-256-GCM
for authenticated encryption.

Architecture Decision: Column-level encryption over SQLCipher because:
- Surgical control over what's encrypted
- Standard library (cryptography), no external dependencies
- Incremental adoption (can encrypt existing databases)
- Query limitations acceptable (keys not queried, just retrieved)

Usage:
    from encryption import EncryptionManager

    # Initialize (prompts for passphrase if encrypted DB)
    manager = EncryptionManager(db_path)

    # Enable encryption on existing database
    manager.enable_encryption("my-secure-passphrase")

    # Encrypt/decrypt values
    encrypted = manager.encrypt("sensitive-data")
    decrypted = manager.decrypt(encrypted)

    # Check if database is encrypted
    if manager.is_encrypted:
        manager.unlock("my-secure-passphrase")
"""

import os
import base64
import hashlib
import json
import logging
from pathlib import Path
from typing import Optional
from dataclasses import dataclass
from datetime import datetime

logger = logging.getLogger(__name__)

# Encryption marker prefix for encrypted values
ENCRYPTED_PREFIX = "enc:v1:"


@dataclass
class EncryptionMetadata:
    """Metadata stored in database for encryption verification"""
    salt: bytes
    key_check: str  # Encrypted canary value for passphrase verification
    algorithm: str
    kdf: str
    created_at: str


class SecureColumn:
    """
    Encrypt sensitive columns with AES-256-GCM authenticated encryption.

    Uses Scrypt for key derivation:
    - n=2^20 (1MB memory)
    - r=8 (block size)
    - p=1 (parallelization)

    Each encrypted value includes:
    - 12-byte nonce (unique per encryption)
    - Ciphertext
    - 16-byte authentication tag
    """

    def __init__(self, key: bytes):
        """Initialize with derived key (32 bytes for AES-256)"""
        if len(key) != 32:
            raise ValueError("Key must be 32 bytes for AES-256")
        self._key = key

    def encrypt(self, plaintext: str) -> str:
        """
        Encrypt plaintext and return base64-encoded result.

        Format: enc:v1:<base64(nonce + ciphertext + tag)>

        Returns prefixed string to identify encrypted values.
        """
        if not plaintext:
            return plaintext

        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        except ImportError:
            raise ImportError(
                "cryptography package required for encryption. "
                "Install with: pip install cryptography"
            )

        # Generate unique 96-bit nonce for each encryption
        nonce = os.urandom(12)

        # Encrypt with AES-256-GCM (includes authentication tag)
        cipher = AESGCM(self._key)
        ciphertext = cipher.encrypt(nonce, plaintext.encode('utf-8'), None)

        # Combine nonce + ciphertext (tag is appended by AESGCM)
        encrypted_data = nonce + ciphertext

        # Return with prefix for identification
        return f"{ENCRYPTED_PREFIX}{base64.b64encode(encrypted_data).decode('ascii')}"

    def decrypt(self, encrypted: str) -> str:
        """
        Decrypt encrypted value.

        Handles both encrypted (prefixed) and plaintext values for
        backward compatibility during migration.
        """
        if not encrypted:
            return encrypted

        # Check if value is encrypted (has our prefix)
        if not encrypted.startswith(ENCRYPTED_PREFIX):
            # Not encrypted - return as-is (backward compatibility)
            return encrypted

        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        except ImportError:
            raise ImportError(
                "cryptography package required for decryption. "
                "Install with: pip install cryptography"
            )

        # Remove prefix and decode
        encoded_data = encrypted[len(ENCRYPTED_PREFIX):]
        encrypted_data = base64.b64decode(encoded_data)

        # Extract nonce (first 12 bytes) and ciphertext+tag
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]

        # Decrypt and verify authentication tag
        cipher = AESGCM(self._key)
        try:
            plaintext = cipher.decrypt(nonce, ciphertext, None)
            return plaintext.decode('utf-8')
        except Exception as e:
            raise ValueError(f"Decryption failed (wrong passphrase?): {e}")


class EncryptionManager:
    """
    Manages database encryption lifecycle.

    Responsibilities:
    - Key derivation from passphrase
    - Encryption metadata storage
    - Passphrase verification
    - Migration of existing keys to encrypted form
    """

    # Canary value for passphrase verification
    CANARY_VALUE = "wireguard-friend-encryption-check"

    def __init__(self, db_path: Path | str):
        self.db_path = Path(db_path) if isinstance(db_path, str) else db_path
        self._secure_column: Optional[SecureColumn] = None
        self._metadata: Optional[EncryptionMetadata] = None
        self._is_unlocked = False

    @property
    def is_encrypted(self) -> bool:
        """Check if database has encryption enabled"""
        return self._load_metadata() is not None

    @property
    def is_unlocked(self) -> bool:
        """Check if encryption key is available for operations"""
        return self._is_unlocked and self._secure_column is not None

    def _load_metadata(self) -> Optional[EncryptionMetadata]:
        """Load encryption metadata from database if exists"""
        if self._metadata is not None:
            return self._metadata

        import sqlite3
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            # Check if table exists
            cursor.execute("""
                SELECT name FROM sqlite_master
                WHERE type='table' AND name='encryption_metadata'
            """)
            if not cursor.fetchone():
                conn.close()
                return None

            # Load metadata
            cursor.execute("SELECT * FROM encryption_metadata WHERE id = 1")
            row = cursor.fetchone()
            conn.close()

            if row:
                self._metadata = EncryptionMetadata(
                    salt=row['salt'],
                    key_check=row['key_check'],
                    algorithm=row['algorithm'],
                    kdf=row['kdf'],
                    created_at=row['created_at']
                )
                return self._metadata

        except sqlite3.Error as e:
            logger.warning(f"Could not load encryption metadata: {e}")

        return None

    def _derive_key(self, passphrase: str, salt: bytes) -> bytes:
        """
        Derive 256-bit key from passphrase using Scrypt.

        Scrypt parameters:
        - n=2^20 (1,048,576) - Memory cost (1MB)
        - r=8 - Block size
        - p=1 - Parallelization

        These parameters provide strong protection against:
        - Brute force attacks
        - ASIC/GPU attacks (memory-hard)
        """
        try:
            from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
            from cryptography.hazmat.backends import default_backend
        except ImportError:
            raise ImportError(
                "cryptography package required for key derivation. "
                "Install with: pip install cryptography"
            )

        kdf = Scrypt(
            salt=salt,
            length=32,  # 256 bits for AES-256
            n=2**20,    # Memory cost
            r=8,        # Block size
            p=1,        # Parallelization
            backend=default_backend()
        )
        return kdf.derive(passphrase.encode('utf-8'))

    def enable_encryption(self, passphrase: str) -> dict:
        """
        Enable encryption on the database.

        Steps:
        1. Generate random salt
        2. Derive key from passphrase
        3. Create encryption metadata table
        4. Store encrypted canary for verification
        5. Encrypt all existing private keys

        Returns dict with migration statistics.
        """
        if self.is_encrypted:
            raise ValueError("Database is already encrypted")

        if len(passphrase) < 8:
            raise ValueError("Passphrase must be at least 8 characters")

        import sqlite3

        # Generate salt
        salt = os.urandom(32)

        # Derive key
        key = self._derive_key(passphrase, salt)
        secure_column = SecureColumn(key)

        # Encrypt canary for verification
        encrypted_canary = secure_column.encrypt(self.CANARY_VALUE)

        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        try:
            # Create encryption metadata table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS encryption_metadata (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    salt BLOB NOT NULL,
                    key_check TEXT NOT NULL,
                    algorithm TEXT DEFAULT 'AES-256-GCM',
                    kdf TEXT DEFAULT 'Scrypt-1048576-8-1',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Insert metadata
            cursor.execute("""
                INSERT INTO encryption_metadata (id, salt, key_check)
                VALUES (1, ?, ?)
            """, (salt, encrypted_canary))

            # Migrate existing keys
            stats = self._migrate_to_encrypted(cursor, secure_column)

            conn.commit()

            # Update internal state
            self._secure_column = secure_column
            self._is_unlocked = True
            self._metadata = EncryptionMetadata(
                salt=salt,
                key_check=encrypted_canary,
                algorithm='AES-256-GCM',
                kdf='Scrypt-1048576-8-1',
                created_at=datetime.now().isoformat()
            )

            logger.info(f"Encryption enabled: {stats}")
            return stats

        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()

    def _migrate_to_encrypted(self, cursor, secure_column: SecureColumn) -> dict:
        """Encrypt all existing private keys and preshared keys"""
        stats = {
            'coordination_server': 0,
            'subnet_router': 0,
            'exit_node': 0,
            'remote': 0,
            'preshared_keys': 0,
            'extramural': 0
        }

        # Coordination server
        cursor.execute("SELECT id, private_key FROM coordination_server")
        for row in cursor.fetchall():
            if row['private_key'] and not row['private_key'].startswith(ENCRYPTED_PREFIX):
                encrypted = secure_column.encrypt(row['private_key'])
                cursor.execute(
                    "UPDATE coordination_server SET private_key = ? WHERE id = ?",
                    (encrypted, row['id'])
                )
                stats['coordination_server'] += 1

        # Subnet routers
        cursor.execute("SELECT id, private_key, preshared_key FROM subnet_router")
        for row in cursor.fetchall():
            updates = []
            params = []
            if row['private_key'] and not row['private_key'].startswith(ENCRYPTED_PREFIX):
                updates.append("private_key = ?")
                params.append(secure_column.encrypt(row['private_key']))
                stats['subnet_router'] += 1
            if row['preshared_key'] and not row['preshared_key'].startswith(ENCRYPTED_PREFIX):
                updates.append("preshared_key = ?")
                params.append(secure_column.encrypt(row['preshared_key']))
                stats['preshared_keys'] += 1
            if updates:
                params.append(row['id'])
                cursor.execute(
                    f"UPDATE subnet_router SET {', '.join(updates)} WHERE id = ?",
                    params
                )

        # Exit nodes
        cursor.execute("SELECT id, private_key FROM exit_node")
        for row in cursor.fetchall():
            if row['private_key'] and not row['private_key'].startswith(ENCRYPTED_PREFIX):
                encrypted = secure_column.encrypt(row['private_key'])
                cursor.execute(
                    "UPDATE exit_node SET private_key = ? WHERE id = ?",
                    (encrypted, row['id'])
                )
                stats['exit_node'] += 1

        # Remotes
        cursor.execute("SELECT id, private_key, preshared_key FROM remote")
        for row in cursor.fetchall():
            updates = []
            params = []
            if row['private_key'] and not row['private_key'].startswith(ENCRYPTED_PREFIX):
                updates.append("private_key = ?")
                params.append(secure_column.encrypt(row['private_key']))
                stats['remote'] += 1
            if row['preshared_key'] and not row['preshared_key'].startswith(ENCRYPTED_PREFIX):
                updates.append("preshared_key = ?")
                params.append(secure_column.encrypt(row['preshared_key']))
                stats['preshared_keys'] += 1
            if updates:
                params.append(row['id'])
                cursor.execute(
                    f"UPDATE remote SET {', '.join(updates)} WHERE id = ?",
                    params
                )

        # Key rotation history
        cursor.execute("SELECT id, new_private_key FROM key_rotation_history")
        for row in cursor.fetchall():
            if row['new_private_key'] and not row['new_private_key'].startswith(ENCRYPTED_PREFIX):
                encrypted = secure_column.encrypt(row['new_private_key'])
                cursor.execute(
                    "UPDATE key_rotation_history SET new_private_key = ? WHERE id = ?",
                    (encrypted, row['id'])
                )

        # Extramural configs
        try:
            cursor.execute("SELECT id, local_private_key FROM extramural_config")
            for row in cursor.fetchall():
                if row['local_private_key'] and not row['local_private_key'].startswith(ENCRYPTED_PREFIX):
                    encrypted = secure_column.encrypt(row['local_private_key'])
                    cursor.execute(
                        "UPDATE extramural_config SET local_private_key = ? WHERE id = ?",
                        (encrypted, row['id'])
                    )
                    stats['extramural'] += 1

            # Extramural peers (preshared keys)
            cursor.execute("SELECT id, preshared_key FROM extramural_peer")
            for row in cursor.fetchall():
                if row['preshared_key'] and not row['preshared_key'].startswith(ENCRYPTED_PREFIX):
                    encrypted = secure_column.encrypt(row['preshared_key'])
                    cursor.execute(
                        "UPDATE extramural_peer SET preshared_key = ? WHERE id = ?",
                        (encrypted, row['id'])
                    )
                    stats['preshared_keys'] += 1
        except Exception:
            pass  # Extramural tables might not exist

        return stats

    def unlock(self, passphrase: str) -> bool:
        """
        Unlock encrypted database with passphrase.

        Verifies passphrase by decrypting canary value.
        Returns True if successful, False otherwise.
        """
        metadata = self._load_metadata()
        if not metadata:
            raise ValueError("Database is not encrypted")

        # Derive key from passphrase
        key = self._derive_key(passphrase, metadata.salt)
        secure_column = SecureColumn(key)

        # Verify by decrypting canary
        try:
            decrypted_canary = secure_column.decrypt(metadata.key_check)
            if decrypted_canary != self.CANARY_VALUE:
                return False

            self._secure_column = secure_column
            self._is_unlocked = True
            logger.info("Database unlocked successfully")
            return True

        except Exception as e:
            logger.warning(f"Failed to unlock database: {e}")
            return False

    def encrypt(self, value: str) -> str:
        """Encrypt a value (requires unlocked database)"""
        if not self.is_unlocked:
            if not self.is_encrypted:
                return value  # Not encrypted, return as-is
            raise ValueError("Database is locked - call unlock() first")
        return self._secure_column.encrypt(value)

    def decrypt(self, value: str) -> str:
        """Decrypt a value (requires unlocked database)"""
        if not value:
            return value

        # Check if value is actually encrypted
        if not value.startswith(ENCRYPTED_PREFIX):
            return value  # Not encrypted, return as-is

        if not self.is_unlocked:
            raise ValueError("Database is locked - call unlock() first")

        return self._secure_column.decrypt(value)

    def change_passphrase(self, old_passphrase: str, new_passphrase: str) -> bool:
        """
        Change encryption passphrase.

        Steps:
        1. Verify old passphrase
        2. Decrypt all keys with old passphrase
        3. Generate new salt and derive new key
        4. Re-encrypt all keys with new passphrase
        5. Update metadata
        """
        if not self.is_encrypted:
            raise ValueError("Database is not encrypted")

        if len(new_passphrase) < 8:
            raise ValueError("New passphrase must be at least 8 characters")

        # Verify old passphrase
        if not self.unlock(old_passphrase):
            return False

        old_secure_column = self._secure_column

        # Generate new salt and key
        new_salt = os.urandom(32)
        new_key = self._derive_key(new_passphrase, new_salt)
        new_secure_column = SecureColumn(new_key)

        # Re-encrypt canary
        new_encrypted_canary = new_secure_column.encrypt(self.CANARY_VALUE)

        import sqlite3
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        try:
            # Re-encrypt all keys
            self._reencrypt_all(cursor, old_secure_column, new_secure_column)

            # Update metadata
            cursor.execute("""
                UPDATE encryption_metadata
                SET salt = ?, key_check = ?, created_at = CURRENT_TIMESTAMP
                WHERE id = 1
            """, (new_salt, new_encrypted_canary))

            conn.commit()

            # Update internal state
            self._secure_column = new_secure_column
            self._metadata = EncryptionMetadata(
                salt=new_salt,
                key_check=new_encrypted_canary,
                algorithm='AES-256-GCM',
                kdf='Scrypt-1048576-8-1',
                created_at=datetime.now().isoformat()
            )

            logger.info("Passphrase changed successfully")
            return True

        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()

    def _reencrypt_all(self, cursor, old_secure: SecureColumn, new_secure: SecureColumn):
        """Re-encrypt all values with new key"""
        def reencrypt(value: str) -> str:
            if not value or not value.startswith(ENCRYPTED_PREFIX):
                return value
            decrypted = old_secure.decrypt(value)
            return new_secure.encrypt(decrypted)

        # Coordination server
        cursor.execute("SELECT id, private_key FROM coordination_server")
        for row in cursor.fetchall():
            if row['private_key']:
                cursor.execute(
                    "UPDATE coordination_server SET private_key = ? WHERE id = ?",
                    (reencrypt(row['private_key']), row['id'])
                )

        # Subnet routers
        cursor.execute("SELECT id, private_key, preshared_key FROM subnet_router")
        for row in cursor.fetchall():
            cursor.execute(
                "UPDATE subnet_router SET private_key = ?, preshared_key = ? WHERE id = ?",
                (reencrypt(row['private_key']), reencrypt(row['preshared_key']), row['id'])
            )

        # Exit nodes
        cursor.execute("SELECT id, private_key FROM exit_node")
        for row in cursor.fetchall():
            if row['private_key']:
                cursor.execute(
                    "UPDATE exit_node SET private_key = ? WHERE id = ?",
                    (reencrypt(row['private_key']), row['id'])
                )

        # Remotes
        cursor.execute("SELECT id, private_key, preshared_key FROM remote")
        for row in cursor.fetchall():
            cursor.execute(
                "UPDATE remote SET private_key = ?, preshared_key = ? WHERE id = ?",
                (reencrypt(row['private_key']), reencrypt(row['preshared_key']), row['id'])
            )

        # Key rotation history
        cursor.execute("SELECT id, new_private_key FROM key_rotation_history")
        for row in cursor.fetchall():
            if row['new_private_key']:
                cursor.execute(
                    "UPDATE key_rotation_history SET new_private_key = ? WHERE id = ?",
                    (reencrypt(row['new_private_key']), row['id'])
                )

        # Extramural configs
        try:
            cursor.execute("SELECT id, local_private_key FROM extramural_config")
            for row in cursor.fetchall():
                if row['local_private_key']:
                    cursor.execute(
                        "UPDATE extramural_config SET local_private_key = ? WHERE id = ?",
                        (reencrypt(row['local_private_key']), row['id'])
                    )

            cursor.execute("SELECT id, preshared_key FROM extramural_peer")
            for row in cursor.fetchall():
                if row['preshared_key']:
                    cursor.execute(
                        "UPDATE extramural_peer SET preshared_key = ? WHERE id = ?",
                        (reencrypt(row['preshared_key']), row['id'])
                    )
        except Exception:
            pass  # Extramural tables might not exist

    def disable_encryption(self, passphrase: str) -> dict:
        """
        Disable encryption and decrypt all keys.

        WARNING: This stores private keys in plaintext!
        """
        if not self.is_encrypted:
            raise ValueError("Database is not encrypted")

        # Verify passphrase
        if not self.unlock(passphrase):
            raise ValueError("Invalid passphrase")

        import sqlite3
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        try:
            stats = self._decrypt_all(cursor)

            # Remove encryption metadata
            cursor.execute("DROP TABLE IF EXISTS encryption_metadata")

            conn.commit()

            # Update internal state
            self._secure_column = None
            self._is_unlocked = False
            self._metadata = None

            logger.info(f"Encryption disabled: {stats}")
            return stats

        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()

    def _decrypt_all(self, cursor) -> dict:
        """Decrypt all values (for disable_encryption)"""
        stats = {'decrypted': 0}

        def decrypt_if_encrypted(value: str) -> str:
            if not value or not value.startswith(ENCRYPTED_PREFIX):
                return value
            stats['decrypted'] += 1
            return self._secure_column.decrypt(value)

        # Coordination server
        cursor.execute("SELECT id, private_key FROM coordination_server")
        for row in cursor.fetchall():
            if row['private_key']:
                cursor.execute(
                    "UPDATE coordination_server SET private_key = ? WHERE id = ?",
                    (decrypt_if_encrypted(row['private_key']), row['id'])
                )

        # Subnet routers
        cursor.execute("SELECT id, private_key, preshared_key FROM subnet_router")
        for row in cursor.fetchall():
            cursor.execute(
                "UPDATE subnet_router SET private_key = ?, preshared_key = ? WHERE id = ?",
                (decrypt_if_encrypted(row['private_key']),
                 decrypt_if_encrypted(row['preshared_key']),
                 row['id'])
            )

        # Exit nodes
        cursor.execute("SELECT id, private_key FROM exit_node")
        for row in cursor.fetchall():
            if row['private_key']:
                cursor.execute(
                    "UPDATE exit_node SET private_key = ? WHERE id = ?",
                    (decrypt_if_encrypted(row['private_key']), row['id'])
                )

        # Remotes
        cursor.execute("SELECT id, private_key, preshared_key FROM remote")
        for row in cursor.fetchall():
            cursor.execute(
                "UPDATE remote SET private_key = ?, preshared_key = ? WHERE id = ?",
                (decrypt_if_encrypted(row['private_key']),
                 decrypt_if_encrypted(row['preshared_key']),
                 row['id'])
            )

        # Key rotation history
        cursor.execute("SELECT id, new_private_key FROM key_rotation_history")
        for row in cursor.fetchall():
            if row['new_private_key']:
                cursor.execute(
                    "UPDATE key_rotation_history SET new_private_key = ? WHERE id = ?",
                    (decrypt_if_encrypted(row['new_private_key']), row['id'])
                )

        # Extramural
        try:
            cursor.execute("SELECT id, local_private_key FROM extramural_config")
            for row in cursor.fetchall():
                if row['local_private_key']:
                    cursor.execute(
                        "UPDATE extramural_config SET local_private_key = ? WHERE id = ?",
                        (decrypt_if_encrypted(row['local_private_key']), row['id'])
                    )

            cursor.execute("SELECT id, preshared_key FROM extramural_peer")
            for row in cursor.fetchall():
                if row['preshared_key']:
                    cursor.execute(
                        "UPDATE extramural_peer SET preshared_key = ? WHERE id = ?",
                        (decrypt_if_encrypted(row['preshared_key']), row['id'])
                    )
        except Exception:
            pass

        return stats


def get_encryption_manager(db_path: Path | str) -> EncryptionManager:
    """Factory function to get encryption manager for a database"""
    return EncryptionManager(db_path)


# Singleton for the active database
_active_manager: Optional[EncryptionManager] = None


def set_active_encryption_manager(manager: EncryptionManager):
    """Set the active encryption manager for the session"""
    global _active_manager
    _active_manager = manager


def get_active_encryption_manager() -> Optional[EncryptionManager]:
    """Get the active encryption manager"""
    return _active_manager


def encrypt_value(value: str) -> str:
    """Encrypt a value using the active manager"""
    if _active_manager and _active_manager.is_unlocked:
        return _active_manager.encrypt(value)
    return value


def decrypt_value(value: str) -> str:
    """Decrypt a value using the active manager"""
    if _active_manager and _active_manager.is_unlocked:
        return _active_manager.decrypt(value)
    # If not unlocked but value is encrypted, return as-is (will fail later)
    return value


if __name__ == "__main__":
    # Demo/test
    import tempfile

    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
        db_path = Path(f.name)

    try:
        # Create test database with schema
        import sqlite3
        conn = sqlite3.connect(db_path)
        conn.execute("""
            CREATE TABLE coordination_server (
                id INTEGER PRIMARY KEY,
                private_key TEXT NOT NULL
            )
        """)
        conn.execute(
            "INSERT INTO coordination_server (id, private_key) VALUES (1, ?)",
            ("test-private-key-abc123",)
        )
        conn.commit()
        conn.close()

        print("=== Database Encryption Demo ===\n")

        # Create manager
        manager = EncryptionManager(db_path)
        print(f"Database encrypted: {manager.is_encrypted}")

        # Enable encryption
        print("\nEnabling encryption...")
        stats = manager.enable_encryption("my-secure-passphrase")
        print(f"Migration stats: {stats}")
        print(f"Database encrypted: {manager.is_encrypted}")

        # Verify encryption in database
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT private_key FROM coordination_server WHERE id = 1")
        encrypted_key = cursor.fetchone()[0]
        print(f"\nStored value: {encrypted_key[:50]}...")
        print(f"Is encrypted: {encrypted_key.startswith(ENCRYPTED_PREFIX)}")
        conn.close()

        # Test unlock and decrypt
        manager2 = EncryptionManager(db_path)
        print(f"\nNew manager - encrypted: {manager2.is_encrypted}")
        print(f"New manager - unlocked: {manager2.is_unlocked}")

        print("\nUnlocking with correct passphrase...")
        if manager2.unlock("my-secure-passphrase"):
            print("Unlocked successfully!")
            decrypted = manager2.decrypt(encrypted_key)
            print(f"Decrypted value: {decrypted}")
        else:
            print("Failed to unlock!")

        print("\nTrying wrong passphrase...")
        manager3 = EncryptionManager(db_path)
        if manager3.unlock("wrong-passphrase"):
            print("Unlocked (unexpected!)")
        else:
            print("Failed to unlock (expected)")

    finally:
        db_path.unlink()
        print("\nDemo complete!")
