"""
Append-only transcript for session messages
Maintains message log and computes transcript hash for non-repudiation
"""

import os
from typing import List, Optional
from app.common.utils import sha256_hex


class TranscriptEntry:
    """Single message entry in transcript"""
    
    def __init__(self, seqno: int, timestamp: int, ciphertext: str, 
                 signature: str, peer_fingerprint: str, direction: str):
        self.seqno = seqno
        self.timestamp = timestamp
        self.ciphertext = ciphertext
        self.signature = signature
        self.peer_fingerprint = peer_fingerprint
        self.direction = direction  # 'sent' or 'received'
    
    def to_line(self) -> str:
        """Convert entry to transcript line format"""
        return f"{self.seqno}|{self.timestamp}|{self.ciphertext}|{self.signature}|{self.peer_fingerprint}"


class Transcript:
    """Manages session transcript and hash computation"""
    
    def __init__(self):
        self.entries: List[TranscriptEntry] = []
    
    def add_entry(self, seqno: int, timestamp: int, ciphertext: str,
                  signature: str, peer_fingerprint: str, direction: str):
        """
        Add message to transcript
        
        Args:
            seqno: Sequence number
            timestamp: Timestamp in milliseconds
            ciphertext: Base64-encoded ciphertext
            signature: Base64-encoded signature
            peer_fingerprint: SHA-256 fingerprint of peer certificate
            direction: 'sent' or 'received'
        """
        entry = TranscriptEntry(seqno, timestamp, ciphertext, signature, 
                               peer_fingerprint, direction)
        self.entries.append(entry)
    
    def compute_hash(self) -> str:
        """
        Compute SHA-256 hash of entire transcript
        
        Returns:
            Hex string of transcript hash
        """
        lines = [entry.to_line() for entry in self.entries]
        transcript_str = "\n".join(lines)
        return sha256_hex(transcript_str.encode('utf-8'))
    
    def save(self, filepath: str):
        """
        Save transcript to file
        
        Args:
            filepath: Path to save transcript
        """
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        
        with open(filepath, 'w') as f:
            for entry in self.entries:
                f.write(entry.to_line() + "\n")
    
    def get_first_seqno(self) -> Optional[int]:
        """Get first sequence number in transcript"""
        return self.entries[0].seqno if self.entries else None
    
    def get_last_seqno(self) -> Optional[int]:
        """Get last sequence number in transcript"""
        return self.entries[-1].seqno if self.entries else None
    
    def is_empty(self) -> bool:
        """Check if transcript is empty"""
        return len(self.entries) == 0
    
    def __len__(self) -> int:
        """Get number of entries"""
        return len(self.entries)