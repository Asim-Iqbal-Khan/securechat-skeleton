"""
RSA signature operations using SHA-256 with PKCS#1 v1.5 padding
"""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization


def sign(private_key: rsa.RSAPrivateKey, data: bytes) -> bytes:
    """
    Sign data with RSA private key using SHA-256 and PKCS#1 v1.5
    
    Args:
        private_key: RSA private key object
        data: Data to sign
    
    Returns:
        Signature bytes
    """
    signature = private_key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return signature


def verify(public_key: rsa.RSAPublicKey, signature: bytes, data: bytes) -> bool:
    """
    Verify RSA signature using SHA-256 and PKCS#1 v1.5
    
    Args:
        public_key: RSA public key object
        signature: Signature to verify
        data: Original data
    
    Returns:
        True if signature is valid, False otherwise
    """
    try:
        public_key.verify(
            signature,
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


def load_private_key(path: str) -> rsa.RSAPrivateKey:
    """
    Load RSA private key from PEM file
    
    Args:
        path: Path to private key file
    
    Returns:
        RSA private key object
    """
    with open(path, 'rb') as f:
        key = serialization.load_pem_private_key(
            f.read(),
            password=None
        )
    return key


def load_public_key_from_cert(cert_path: str) -> rsa.RSAPublicKey:
    """
    Load RSA public key from certificate file
    
    Args:
        cert_path: Path to certificate file
    
    Returns:
        RSA public key object
    """
    from cryptography import x509
    
    with open(cert_path, 'rb') as f:
        cert = x509.load_pem_x509_certificate(f.read())
    
    return cert.public_key()