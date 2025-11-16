"""
AES-128 ECB mode with PKCS#7 padding
Uses cryptography library for AES operations
"""

import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    """
    Apply PKCS#7 padding to data
    
    Args:
        data: Raw bytes to pad
        block_size: Block size (16 for AES)
    
    Returns:
        Padded data
    """
    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length] * padding_length)
    return data + padding


def pkcs7_unpad(data: bytes) -> bytes:
    """
    Remove PKCS#7 padding from data
    
    Args:
        data: Padded data
    
    Returns:
        Unpadded data
    
    Raises:
        ValueError: If padding is invalid
    """
    if not data:
        raise ValueError("Cannot unpad empty data")
    
    padding_length = data[-1]
    
    if padding_length > len(data) or padding_length > 16:
        raise ValueError("Invalid padding length")
    
    # Verify all padding bytes are correct
    if data[-padding_length:] != bytes([padding_length] * padding_length):
        raise ValueError("Invalid padding bytes")
    
    return data[:-padding_length]


def aes_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """
    Encrypt plaintext using AES-128 ECB mode with PKCS#7 padding
    
    Args:
        plaintext: Data to encrypt
        key: 16-byte AES key
    
    Returns:
        Ciphertext (padded and encrypted)
    
    Raises:
        ValueError: If key is not 16 bytes
    """
    if len(key) != 16:
        raise ValueError("AES-128 requires 16-byte key")
    
    # Pad plaintext
    padded = pkcs7_pad(plaintext)
    
    # Encrypt with ECB mode (no IV needed)
    cipher = Cipher(
        algorithms.AES(key),
        modes.ECB(),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    
    return ciphertext


def aes_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """
    Decrypt ciphertext using AES-128 ECB mode and remove PKCS#7 padding
    
    Args:
        ciphertext: Data to decrypt
        key: 16-byte AES key
    
    Returns:
        Plaintext (decrypted and unpadded)
    
    Raises:
        ValueError: If key is not 16 bytes or padding is invalid
    """
    if len(key) != 16:
        raise ValueError("AES-128 requires 16-byte key")
    
    # Decrypt with ECB mode
    cipher = Cipher(
        algorithms.AES(key),
        modes.ECB(),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Remove padding
    plaintext = pkcs7_unpad(padded_plaintext)
    
    return plaintext


# Convenience functions for string inputs
def encrypt_str(plaintext: str, key: bytes) -> bytes:
    """Encrypt UTF-8 string"""
    return aes_encrypt(plaintext.encode('utf-8'), key)


def decrypt_str(ciphertext: bytes, key: bytes) -> str:
    """Decrypt to UTF-8 string"""
    return aes_decrypt(ciphertext, key).decode('utf-8')