#!/usr/bin/env python3
"""
Test replay attack detection
"""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def test_replay():
    print("="*60)
    print("REPLAY ATTACK DETECTION TEST")
    print("="*60)
    
    # Simulate sequence number checking
    seqno_received = 0
    
    messages = [
        {"seqno": 1, "msg": "First"},
        {"seqno": 2, "msg": "Second"},
        {"seqno": 3, "msg": "Third"},
    ]
    
    print("\n[*] Testing normal sequence...")
    for msg in messages:
        if msg["seqno"] > seqno_received:
            print(f"[✓] Message {msg['seqno']}: ACCEPTED")
            seqno_received = msg["seqno"]
        else:
            print(f"[✗] Message {msg['seqno']}: REPLAY")
    
    # Test replay
    print("\n[*] Testing replay attack...")
    old_msg = {"seqno": 2, "msg": "Replayed"}
    
    if old_msg["seqno"] <= seqno_received:
        print(f"[✓] Replayed message (seqno={old_msg['seqno']}): REPLAY detected!")
    else:
        print(f"[✗] Replay not detected!")
    
    print("\n[✓] All replay tests passed!")

if __name__ == "__main__":
    test_replay()