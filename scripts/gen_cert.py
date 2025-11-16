#!/usr/bin/env python3
"""
Generate X.509 certificates signed by Root CA
Issues certificates for server and client
"""

import os
import sys
import argparse
import ipaddress
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def load_ca():
    """Load CA private key and certificate"""
    ca_key_path = "certs/ca_private_key.pem"
    ca_cert_path = "certs/ca_cert.pem"
    
    if not os.path.exists(ca_key_path) or not os.path.exists(ca_cert_path):
        print("[✗] CA not found! Run gen_ca.py first.", file=sys.stderr)
        sys.exit(1)
    
    # Load CA private key
    with open(ca_key_path, "rb") as f:
        ca_private_key = serialization.load_pem_private_key(
            f.read(),
            password=None
        )
    
    # Load CA certificate
    with open(ca_cert_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    
    return ca_private_key, ca_cert


def generate_cert(cn: str, out_prefix: str, is_server: bool = False):
    """Generate certificate signed by CA"""
    
    print(f"\n[*] Generating certificate for: {cn}")
    
    # Load CA
    ca_private_key, ca_cert = load_ca()
    
    # Generate entity private key
    print("[*] Generating RSA private key (2048 bits)...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    # Create subject
    entity_type = "Server" if is_server else "Client"
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Punjab"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Islamabad"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FAST NUCES"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, f"SecureChat {entity_type}"),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])
    
    # Build certificate
    print("[*] Building certificate signed by CA...")
    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_private_key.public_key()),
            critical=False,
        )
    )
    
    # Add Subject Alternative Name for server
    if is_server:
        cert_builder = cert_builder.add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(cn),
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        )
    
    cert = cert_builder.sign(ca_private_key, hashes.SHA256())
    
    # Save private key
    private_key_path = f"{out_prefix}_private_key.pem"
    print(f"[*] Saving private key to {private_key_path}")
    with open(private_key_path, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    
    # Save certificate
    cert_path = f"{out_prefix}_cert.pem"
    print(f"[*] Saving certificate to {cert_path}")
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    print(f"\n[✓] Certificate generated successfully!")
    print(f"[✓] Private Key: {private_key_path}")
    print(f"[✓] Certificate: {cert_path}")
    print(f"    Subject: {cert.subject.rfc4514_string()}")
    print(f"    Serial: {cert.serial_number}")
    print(f"    Valid: {cert.not_valid_before} to {cert.not_valid_after}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate certificates signed by CA")
    parser.add_argument("--cn", required=True, help="Common Name for the certificate")
    parser.add_argument("--out", required=True, help="Output prefix (e.g., certs/server)")
    parser.add_argument("--server", action="store_true", help="Generate server certificate with SAN")
    args = parser.parse_args()
    
    try:
        print("[*] Loading Root CA...")
        generate_cert(args.cn, args.out, args.server)
        print("\n[✓] Done!")
    except Exception as e:
        print(f"\n[✗] Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)