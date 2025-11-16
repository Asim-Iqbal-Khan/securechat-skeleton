"""
Common utility functions
Base64 encoding/decoding, timestamps, hashing
"""

import base64
import hashlib
import time
from typing import Union


def b64encode(data: bytes) -> str:
    """
    Encode bytes to base64 string
    
    Args:
        data: Bytes to encode
    
    Returns:
        Base64-encoded string
    """
    return base64.b64encode(data).decode('utf-8')


def b64decode(data: str) -> bytes:
    """
    Decode base64 string to bytes
    
    Args:
        data: Base64-encoded string
    
    Returns:
        Decoded bytes
    """
    return base64.b64decode(data)


def now_ms() -> int:
    """
    Get current timestamp in milliseconds (Unix epoch)
    
    Returns:
        Current time in milliseconds
    """
    return int(time.time() * 1000)


def sha256_hex(*args) -> str:
    """
    Compute SHA-256 hash of concatenated arguments and return as hex string
    
    Args:
        *args: Variable number of arguments (bytes, str, or int)
    
    Returns:
        SHA-256 hash as hex string
    """
    hasher = hashlib.sha256()
    
    for arg in args:
        if isinstance(arg, bytes):
            hasher.update(arg)
        elif isinstance(arg, str):
            hasher.update(arg.encode('utf-8'))
        elif isinstance(arg, int):
            # Convert int to big-endian bytes
            byte_length = (arg.bit_length() + 7) // 8
            if byte_length == 0:
                byte_length = 1
            hasher.update(arg.to_bytes(byte_length, 'big'))
        else:
            raise TypeError(f"Unsupported type for hashing: {type(arg)}")
    
    return hasher.hexdigest()


def sha256_bytes(*args) -> bytes:
    """
    Compute SHA-256 hash of concatenated arguments and return as bytes
    
    Args:
        *args: Variable number of arguments (bytes, str, or int)
    
    Returns:
        SHA-256 hash as bytes
    """
    return bytes.fromhex(sha256_hex(*args))


def constant_time_compare(a: str, b: str) -> bool:
    """
    Constant-time string comparison to prevent timing attacks
    
    Args:
        a: First string
        b: Second string
    
    Returns:
        True if strings match, False otherwise
    """
    if len(a) != len(b):
        return False
    
    result = 0
    for x, y in zip(a, b):
        result |= ord(x) ^ ord(y)
    
    return result == 0