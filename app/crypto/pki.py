"""
X.509 certificate validation
Validates certificate signature, validity period, and common name
"""

from datetime import datetime
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from typing import Tuple, Optional


def load_cert(path: str) -> x509.Certificate:
    """
    Load X.509 certificate from PEM file
    
    Args:
        path: Path to certificate file
    
    Returns:
        Certificate object
    """
    with open(path, 'rb') as f:
        cert = x509.load_pem_x509_certificate(f.read())
    return cert


def validate_cert(cert: x509.Certificate, ca_cert: x509.Certificate, 
                  expected_cn: Optional[str] = None) -> Tuple[bool, str]:
    """
    Validate certificate against CA and check validity period
    
    Args:
        cert: Certificate to validate
        ca_cert: CA certificate
        expected_cn: Expected Common Name (optional)
    
    Returns:
        Tuple of (is_valid, error_message)
        If valid, error_message is empty string
        If invalid, error_message describes the problem
    """
    try:
        # Check validity period
        now = datetime.utcnow()
        
        if now < cert.not_valid_before:
            return False, "BAD_CERT: Certificate not yet valid"
        
        if now > cert.not_valid_after:
            return False, "BAD_CERT: Certificate expired"
        
        # Verify issuer matches CA subject
        if cert.issuer != ca_cert.subject:
            return False, "BAD_CERT: Certificate not issued by trusted CA"
        
        # Verify signature chain
        ca_public_key = ca_cert.public_key()
        
        try:
            ca_public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm
            )
        except Exception as e:
            return False, f"BAD_CERT: Invalid signature - {str(e)}"
        
        # Verify Common Name if provided
        if expected_cn:
            actual_cn = get_common_name(cert)
            if actual_cn != expected_cn:
                return False, f"BAD_CERT: CN mismatch (expected {expected_cn}, got {actual_cn})"
        
        return True, ""
        
    except Exception as e:
        return False, f"BAD_CERT: Validation error - {str(e)}"


def get_common_name(cert: x509.Certificate) -> str:
    """
    Extract Common Name from certificate subject
    
    Args:
        cert: Certificate object
    
    Returns:
        Common Name string
    """
    try:
        cn_attrs = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        if cn_attrs:
            return cn_attrs[0].value
    except (IndexError, AttributeError):
        pass
    return "Unknown"


def get_fingerprint(cert: x509.Certificate) -> str:
    """
    Get SHA-256 fingerprint of certificate
    
    Args:
        cert: Certificate object
    
    Returns:
        Hex string of fingerprint
    """
    return cert.fingerprint(hashes.SHA256()).hex()


def cert_to_pem(cert: x509.Certificate) -> str:
    """
    Convert certificate to PEM string
    
    Args:
        cert: Certificate object
    
    Returns:
        PEM-encoded certificate string
    """
    from cryptography.hazmat.primitives import serialization
    return cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')


def pem_to_cert(pem_str: str) -> x509.Certificate:
    """
    Convert PEM string to certificate object
    
    Args:
        pem_str: PEM-encoded certificate
    
    Returns:
        Certificate object
    """
    return x509.load_pem_x509_certificate(pem_str.encode('utf-8'))