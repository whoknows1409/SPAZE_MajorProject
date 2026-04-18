"""
SPAZE - AES-256-GCM File Encryption/Decryption Module

Handles transparent file encryption at rest and ephemeral decryption into memory.
Uses AES-256-GCM for authenticated encryption (confidentiality + integrity).
"""

import os
import struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# File format: [12-byte nonce][16-byte auth tag][ciphertext]
NONCE_SIZE = 12
TAG_SIZE = 16


def generate_key() -> bytes:
    """Generate a random 256-bit AES key."""
    return AESGCM.generate_key(bit_length=256)


def encrypt_file(filepath: str, key: bytes) -> str:
    """
    Encrypt a file in-place using AES-256-GCM.
    
    The encrypted file format:
    [12-byte nonce][ciphertext + 16-byte auth tag]
    
    Returns the path to the encrypted file (.enc extension).
    """
    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_SIZE)

    with open(filepath, "rb") as f:
        plaintext = f.read()

    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)

    encrypted_path = filepath + ".enc"
    with open(encrypted_path, "wb") as f:
        f.write(nonce)
        f.write(ciphertext)  # Includes auth tag appended by AESGCM

    # Securely delete the original plaintext file
    _secure_delete(filepath)

    return encrypted_path


def decrypt_file_to_memory(filepath: str, key: bytes) -> bytes:
    """
    Decrypt a file entirely in memory. Never writes plaintext to disk.
    
    Returns the decrypted content as bytes.
    Raises InvalidTag if the file has been tampered with.
    """
    aesgcm = AESGCM(key)

    with open(filepath, "rb") as f:
        nonce = f.read(NONCE_SIZE)
        ciphertext = f.read()

    plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
    return plaintext


def secure_wipe_bytes(data: bytearray) -> None:
    """Overwrite a bytearray with zeros to wipe sensitive data from memory."""
    for i in range(len(data)):
        data[i] = 0


def _secure_delete(filepath: str) -> None:
    """Overwrite a file with random data before deletion."""
    file_size = os.path.getsize(filepath)
    with open(filepath, "wb") as f:
        f.write(os.urandom(file_size))  # Overwrite with random bytes
    os.remove(filepath)
