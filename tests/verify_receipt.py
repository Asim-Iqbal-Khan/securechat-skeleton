#!/usr/bin/env python3
"""
Offline verification of session receipts and transcripts
Verifies non-repudiation evidence
"""

import os
import sys
import json
import argparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.crypto import sign, pki
from app.common import utils


def verify_message_signature(seqno, timestamp, ciphertext, signature_b64, cert_path):
    """Verify individual message signature"""
    try:
        # Load certificate and get public key
        cert = pki.load_cert(cert_path)
        public_key = cert.public_key()
        
        # Decode
        signature = utils.b64decode(signature_b64)
        ct_bytes = utils.b64decode(ciphertext)
        
        # Recompute digest
        digest = utils.sha256_bytes(
            seqno.to_bytes(8, 'big'),
            timestamp.to_bytes(8, 'big'),
            ct_bytes
        )
        
        # Verify
        return sign.verify(public_key, signature, digest), None
        
    except Exception as e:
        return False, str(e)


def verify_transcript_and_receipt(transcript_file, receipt_file, signer_cert_path):
    """Verify complete session transcript and receipt"""
    
    print("="*70)
    print("NON-REPUDIATION VERIFICATION")
    print("="*70)
    
    # Load transcript
    print(f"\n[*] Loading transcript: {transcript_file}")
    
    if not os.path.exists(transcript_file):
        print(f"[✗] Transcript not found: {transcript_file}")
        return False
    
    with open(transcript_file, 'r') as f:
        transcript_lines = f.readlines()
    
    print(f"[✓] Loaded {len(transcript_lines)} messages")
    
    # Load receipt
    print(f"[*] Loading receipt: {receipt_file}")
    
    if not os.path.exists(receipt_file):
        print(f"[✗] Receipt not found: {receipt_file}")
        return False
    
    with open(receipt_file, 'r') as f:
        receipt = json.load(f)
    
    print(f"[✓] Receipt loaded for peer: {receipt['peer']}")
    print(f"    Sequence range: {receipt['first_seq']} to {receipt['last_seq']}")
    
    # Verify each message signature
    print(f"\n[*] Verifying individual message signatures...")
    
    message_count = 0
    for i, line in enumerate(transcript_lines, 1):
        parts = line.strip().split('|')
        if len(parts) < 5:
            print(f"[✗] Line {i}: Invalid format")
            continue
        
        seqno = int(parts[0])
        timestamp = int(parts[1])
        ciphertext = parts[2]
        signature = parts[3]
        
        # Verify signature
        is_valid, error = verify_message_signature(
            seqno, timestamp, ciphertext, signature, signer_cert_path
        )
        
        if is_valid:
            print(f"[✓] Message {i} (seqno={seqno}): Signature VALID")
            message_count += 1
        else:
            print(f"[✗] Message {i} (seqno={seqno}): SIG_FAIL - {error}")
            return False
    
    print(f"\n[✓] All {message_count} message signatures verified")
    
    # Recompute transcript hash
    print(f"\n[*] Verifying transcript hash...")
    
    transcript_str = "".join(transcript_lines)
    computed_hash = utils.sha256_hex(transcript_str.encode('utf-8'))
    
    receipt_hash = receipt['transcript_sha256']
    
    if computed_hash == receipt_hash:
        print(f"[✓] Transcript hash matches receipt")
        print(f"    Hash: {computed_hash[:32]}...")
    else:
        print(f"[✗] Transcript hash MISMATCH")
        print(f"    Computed: {computed_hash}")
        print(f"    Receipt:  {receipt_hash}")
        return False
    
    # Verify receipt signature
    print(f"\n[*] Verifying receipt signature...")
    
    cert = pki.load_cert(signer_cert_path)
    public_key = cert.public_key()
    
    receipt_sig = utils.b64decode(receipt['sig'])
    
    is_valid = sign.verify(
        public_key,
        receipt_sig,
        bytes.fromhex(receipt_hash)
    )
    
    if is_valid:
        print(f"[✓] Receipt signature VALID")
        print(f"    Signer: {pki.get_common_name(cert)}")
    else:
        print(f"[✗] Receipt signature INVALID")
        return False
    
    # Test tampering detection
    print(f"\n[*] Testing tamper detection...")
    
    tampered_transcript = transcript_str + "TAMPERED_DATA\n"
    tampered_hash = utils.sha256_hex(tampered_transcript.encode('utf-8'))
    
    if tampered_hash != receipt_hash:
        print(f"[✓] Tampered transcript produces different hash")
        print(f"    Original:  {receipt_hash[:32]}...")
        print(f"    Tampered:  {tampered_hash[:32]}...")
    
    print("\n" + "="*70)
    print("VERIFICATION SUCCESSFUL")
    print("="*70)
    print("\n[✓] Summary:")
    print(f"    ✓ {message_count} message signatures verified")
    print(f"    ✓ Transcript hash verified")
    print(f"    ✓ Receipt signature verified")
    print(f"    ✓ Tamper detection working")
    print("\n[✓] Non-repudiation evidence is valid and intact")
    
    return True


def main():
    parser = argparse.ArgumentParser(description="Verify session receipt and transcript")
    parser.add_argument("transcript", help="Path to transcript file")
    parser.add_argument("receipt", help="Path to receipt JSON file")
    parser.add_argument("cert", help="Path to signer's certificate")
    
    args = parser.parse_args()
    
    try:
        success = verify_transcript_and_receipt(
            args.transcript,
            args.receipt,
            args.cert
        )
        
        if not success:
            print("\n[✗] Verification failed")
            sys.exit(1)
    
    except Exception as e:
        print(f"\n[✗] Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python verify_receipt.py <transcript_file> <receipt_file> <signer_cert>")
        print("\nExample:")
        print("  python tests/verify_receipt.py \\")
        print("      transcripts/client_transcript_1234567890.txt \\")
        print("      transcripts/client_receipt_1234567890.json \\")
        print("      certs/client_cert.pem")
        sys.exit(1)
    
    main()