"""
SPAZE Server - Ephemeral Key Management

Generates, distributes, and revokes file encryption keys.
Keys are short-lived (TTL) and cached in Redis.
"""

import os
import time
import hashlib
import hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# Default key TTL in seconds
DEFAULT_KEY_TTL = 60


def generate_file_encryption_key() -> bytes:
    """Generate a random 256-bit File Encryption Key (FEK)."""
    return AESGCM.generate_key(bit_length=256)


def encrypt_fek_with_master(fek: bytes, master_key: bytes) -> bytes:
    """
    Encrypt a FEK using the master key (key wrapping).
    This is how FEKs are stored in the database.
    """
    aesgcm = AESGCM(master_key)
    nonce = os.urandom(12)
    encrypted = aesgcm.encrypt(nonce, fek, associated_data=None)
    return nonce + encrypted


def decrypt_fek_with_master(encrypted_fek: bytes, master_key: bytes) -> bytes:
    """Unwrap a FEK using the master key."""
    aesgcm = AESGCM(master_key)
    nonce = encrypted_fek[:12]
    ciphertext = encrypted_fek[12:]
    return aesgcm.decrypt(nonce, ciphertext, associated_data=None)


def create_key_request_hmac(badge_id: str, device_id: str, file_id: str,
                             timestamp: int, secret: bytes) -> str:
    """
    Create an HMAC for a key request to prevent tampering.
    The agent uses this to prove the request is authentic.
    """
    message = f"{badge_id}:{device_id}:{file_id}:{timestamp}".encode()
    return hmac.new(secret, message, hashlib.sha256).hexdigest()


def verify_key_request_hmac(badge_id: str, device_id: str, file_id: str,
                             timestamp: int, secret: bytes,
                             provided_hmac: str) -> bool:
    """Verify that a key request HMAC is valid and not expired."""
    # Check timestamp freshness (within 30 seconds)
    if abs(time.time() - timestamp) > 30:
        return False

    expected = create_key_request_hmac(badge_id, device_id, file_id,
                                        timestamp, secret)
    return hmac.compare_digest(expected, provided_hmac)
