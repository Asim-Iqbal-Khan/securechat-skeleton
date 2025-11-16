#!/usr/bin/env python3
"""
Generate self-signed Root Certificate Authority (CA)
"""

import os
import sys
import argparse
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def generate_ca(name: str = "SecureChat Root CA"):
    """Generate root CA private key and self-signed certificate"""
    
    # Create certs directory
    os.makedirs("certs", exist_ok=True)
    
    print(f"[*] Generating Root CA: {name}")
    
    # Generate RSA private key (2048 bits)
    print("[*] Generating RSA private key (2048 bits)...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    # Create subject and issuer (same for self-signed)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Punjab"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Islamabad"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FAST NUCES"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "SecureChat"),
        x509.NameAttribute(NameOID.COMMON_NAME, name),
    ])
    
    # Build certificate
    print("[*] Building self-signed certificate...")
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(private_key, hashes.SHA256())
    )
    
    # Save private key
    private_key_path = "certs/ca_private_key.pem"
    print(f"[*] Saving CA private key to {private_key_path}")
    with open(private_key_path, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    
    # Save certificate
    cert_path = "certs/ca_cert.pem"
    print(f"[*] Saving CA certificate to {cert_path}")
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    print("\n[✓] Root CA generated successfully!")
    print(f"[✓] Private Key: {private_key_path}")
    print(f"[✓] Certificate: {cert_path}")
    print(f"\n[*] Certificate Details:")
    print(f"    Subject: {cert.subject.rfc4514_string()}")
    print(f"    Serial: {cert.serial_number}")
    print(f"    Valid From: {cert.not_valid_before}")
    print(f"    Valid Until: {cert.not_valid_after}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate Root CA")
    parser.add_argument(
        "--name",
        default="SecureChat Root CA",
        help="Common Name for the CA (default: SecureChat Root CA)"
    )
    args = parser.parse_args()
    
    try:
        generate_ca(args.name)
    except Exception as e:
        print(f"\n[✗] Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)