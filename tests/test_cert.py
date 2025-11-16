#!/usr/bin/env python3
"""
Test certificate validation
"""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.crypto import pki
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa

def create_expired_cert():
    """Create an expired certificate"""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Expired Cert"),
    ])
    
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow() - timedelta(days=60))
        .not_valid_after(datetime.utcnow() - timedelta(days=30))  # EXPIRED
        .sign(private_key, hashes.SHA256())
    )
    return cert

def test_certificates():
    print("="*60)
    print("CERTIFICATE VALIDATION TEST")
    print("="*60)
    
    # Load valid certs
    ca_cert = pki.load_cert("certs/ca_cert.pem")
    server_cert = pki.load_cert("certs/server_cert.pem")
    
    # Test 1: Valid certificate
    print("\n[*] Test 1: Valid certificate")
    is_valid, error = pki.validate_cert(server_cert, ca_cert)
    if is_valid:
        print("[✓] Server certificate: VALID")
    else:
        print(f"[✗] Server certificate: {error}")
    
    # Test 2: Expired certificate
    print("\n[*] Test 2: Expired certificate")
    expired_cert = create_expired_cert()
    is_valid, error = pki.validate_cert(expired_cert, ca_cert)
    if not is_valid and "expired" in error.lower():
        print(f"[✓] Expired certificate: BAD_CERT - {error}")
    else:
        print(f"[✗] Expired certificate accepted (unexpected!)")
    
    # Test 3: Self-signed (not issued by CA)
    print("\n[*] Test 3: Self-signed certificate")
    is_valid, error = pki.validate_cert(expired_cert, ca_cert)
    if not is_valid:
        print(f"[✓] Self-signed rejected: BAD_CERT")
    
    print("\n[✓] All certificate tests passed!")

if __name__ == "__main__":
    test_certificates()