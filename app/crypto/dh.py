"""
Classic Diffie-Hellman key exchange helpers
Uses 2048-bit safe prime from RFC 3526
"""

import os
import hashlib
from typing import Tuple


# RFC 3526 Group 14 - 2048-bit MODP Group
DH_PRIME = int("""
FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74
020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437
4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED
EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05
98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB
9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B
E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718
3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
""".replace("\n", "").strip(), 16)

DH_GENERATOR = 2


def generate_private_key(p: int = DH_PRIME) -> int:
    """
    Generate a random DH private key
    
    Args:
        p: Prime modulus (default: RFC 3526 Group 14)
    
    Returns:
        Random integer in range [2, p-2]
    """
    # Generate 256 random bytes for private key
    random_bytes = os.urandom(256)
    private_key = int.from_bytes(random_bytes, 'big') % (p - 2) + 2
    return private_key


def compute_public_key(g: int, private_key: int, p: int) -> int:
    """
    Compute DH public key: g^private_key mod p
    
    Args:
        g: Generator
        private_key: Private exponent
        p: Prime modulus
    
    Returns:
        Public key
    """
    return pow(g, private_key, p)


def compute_shared_secret(peer_public_key: int, private_key: int, p: int) -> int:
    """
    Compute shared secret: peer_public_key^private_key mod p
    
    Args:
        peer_public_key: Other party's public key
        private_key: Own private key
        p: Prime modulus
    
    Returns:
        Shared secret (integer)
    """
    return pow(peer_public_key, private_key, p)


def derive_aes_key(shared_secret: int) -> bytes:
    """
    Derive AES-128 key from DH shared secret
    K = Trunc_16(SHA256(big_endian(shared_secret)))
    
    Args:
        shared_secret: DH shared secret (integer)
    
    Returns:
        16-byte AES key
    """
    # Convert shared secret to big-endian bytes
    secret_bytes = shared_secret.to_bytes(
        (shared_secret.bit_length() + 7) // 8,
        byteorder='big'
    )
    
    # Hash with SHA-256
    digest = hashlib.sha256(secret_bytes).digest()
    
    # Truncate to 16 bytes for AES-128
    return digest[:16]


def get_default_params() -> Tuple[int, int]:
    """
    Get default DH parameters (RFC 3526 Group 14)
    
    Returns:
        Tuple of (generator, prime)
    """
    return (DH_GENERATOR, DH_PRIME)