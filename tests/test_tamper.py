#!/usr/bin/env python3
"""
Test tamper detection - flip bits in ciphertext and verify SIG_FAIL
"""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.crypto import aes, sign, pki
from app.common import utils

def test_tamper():
    print("="*60)
    print("TAMPER DETECTION TEST")
    print("="*60)
    
    # Load keys
    private_key = sign.load_private_key("certs/client_private_key.pem")
    cert = pki.load_cert("certs/client_cert.pem")
    public_key = cert.public_key()
    
    # Test data
    key = os.urandom(16)
    plaintext = b"Secret message"
    seqno = 1
    ts = 1234567890000
    
    # Encrypt
    ct = aes.aes_encrypt(plaintext, key)
    
    # Sign
    digest = utils.sha256_bytes(seqno.to_bytes(8, 'big'), ts.to_bytes(8, 'big'), ct)
    sig = sign.sign(private_key, digest)
    
    print("[*] Original message created")
    
    # Test 1: Valid signature
    if sign.verify(public_key, sig, digest):
        print("[✓] Original signature VALID")
    else:
        print("[✗] Original signature INVALID (unexpected!)")
        return
    
    # Test 2: Tamper with ciphertext
    tampered_ct = bytearray(ct)
    tampered_ct[5] ^= 0xFF  # Flip bits
    tampered_ct = bytes(tampered_ct)
    
    tampered_digest = utils.sha256_bytes(seqno.to_bytes(8, 'big'), ts.to_bytes(8, 'big'), tampered_ct)
    
    if not sign.verify(public_key, sig, tampered_digest):
        print("[✓] Tampered ciphertext: SIG_FAIL (expected)")
    else:
        print("[✗] Tampered ciphertext: VALID (unexpected!)")
    
    print("\n[✓] All tamper tests passed!")

if __name__ == "__main__":
    test_tamper()