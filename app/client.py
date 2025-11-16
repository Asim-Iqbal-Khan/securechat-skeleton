"""
Secure Chat Client
Connects to server, authenticates, and enables encrypted messaging
"""

import socket
import json
import os
import sys
import threading
from dotenv import load_dotenv

from app.crypto import aes, dh, pki, sign
from app.common import protocol, utils
from app.storage.transcript import Transcript

load_dotenv()


class SecureChatClient:
    """Client implementation for secure chat"""
    
    def __init__(self):
        self.host = os.getenv("SERVER_HOST", "localhost")
        self.port = int(os.getenv("SERVER_PORT", "5555"))
        
        # Load client credentials
        self.private_key = sign.load_private_key("certs/client_private_key.pem")
        self.certificate = pki.load_cert("certs/client_cert.pem")
        self.ca_cert = pki.load_cert("certs/ca_cert.pem")
        
        # Session state
        self.socket = None
        self.server_cert = None
        self.peer_public_key = None
        self.temp_aes_key = None
        self.session_key = None
        self.authenticated_user = None
        self.seqno_sent = 0
        self.seqno_received = 0
        self.transcript = Transcript()
        self.running = False
        
        print(f"[*] Client initialized")
        print(f"[*] Certificate CN: {pki.get_common_name(self.certificate)}")
        print(f"[*] Fingerprint: {pki.get_fingerprint(self.certificate)[:32]}...")
    
    def connect(self):
        """Connect to server"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            print(f"\n[✓] Connected to server at {self.host}:{self.port}")
            return True
        except Exception as e:
            print(f"[✗] Connection failed: {e}")
            return False
    
    def run(self):
        """Main client flow"""
        if not self.connect():
            return
        
        try:
            # Phase 1: Control Plane
            if not self.control_plane():
                return
            
            # Phase 2: Key Agreement
            if not self.key_agreement():
                return
            
            # Phase 3: Data Plane
            self.data_plane()
            
            # Phase 4: Teardown
            self.teardown()
            
        except Exception as e:
            print(f"\n[✗] Client error: {e}")
            import traceback
            traceback.print_exc()
        
        finally:
            if self.socket:
                self.socket.close()
            print("\n[*] Disconnected from server")
    
    def control_plane(self):
        """Phase 1: Certificate exchange and authentication"""
        print("\n" + "="*60)
        print("PHASE 1: CONTROL PLANE (Authentication)")
        print("="*60)
        
        try:
            # Send client hello
            client_nonce = os.urandom(16)
            hello = protocol.HelloMessage(
                client_cert=pki.cert_to_pem(self.certificate),
                nonce=utils.b64encode(client_nonce)
            )
            self.socket.send(hello.model_dump_json().encode('utf-8'))
            print("[*] Sent client hello")
            
            # Receive server hello
            data = self.socket.recv(16384).decode('utf-8')
            server_hello_data = json.loads(data)
            
            if server_hello_data["type"] == "error":
                error_msg = protocol.ErrorMessage(**server_hello_data)
                print(f"[✗] Server error: {error_msg.message}")
                return False
            
            server_hello = protocol.ServerHelloMessage(**server_hello_data)
            print("[*] Received server hello")
            
            # Verify server certificate
            server_cert = pki.pem_to_cert(server_hello.server_cert)
            is_valid, error = pki.validate_cert(server_cert, self.ca_cert)
            
            if not is_valid:
                print(f"[✗] {error}")
                return False
            
            self.server_cert = server_cert
            self.peer_public_key = server_cert.public_key()
            
            print(f"[✓] Server certificate verified")
            print(f"    CN: {pki.get_common_name(server_cert)}")
            
            # Temporary DH for credential encryption
            print("\n[*] Performing temporary DH exchange...")
            g, p = dh.get_default_params()
            a = dh.generate_private_key(p)
            A = dh.compute_public_key(g, a, p)
            
            dh_temp = protocol.DHClientMessage(g=g, p=p, A=A)
            self.socket.send(dh_temp.model_dump_json().encode('utf-8'))
            
            # Receive server's B
            dh_response_data = json.loads(self.socket.recv(8192).decode('utf-8'))
            dh_response = protocol.DHServerMessage(**dh_response_data)
            
            # Derive temporary AES key
            shared_secret = dh.compute_shared_secret(dh_response.B, a, p)
            self.temp_aes_key = dh.derive_aes_key(shared_secret)
            print("[✓] Temporary session key established")
            
            # Choose register or login
            print("\n" + "-"*60)
            choice = input("Choose action:\n1. Register\n2. Login\nEnter choice (1 or 2): ").strip()
            
            if choice == "1":
                return self.register()
            elif choice == "2":
                return self.login()
            else:
                print("[✗] Invalid choice")
                return False
                
        except Exception as e:
            print(f"[✗] Control plane error: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def register(self):
        """Register new user"""
        print("\n[*] Registration")
        print("-"*60)
        
        try:
            email = input("Email: ").strip()
            username = input("Username: ").strip()
            password = input("Password: ").strip()
            
            # Generate salt
            salt = os.urandom(16)
            
            # Compute salted password hash
            pwd_hash = utils.sha256_bytes(salt, password.encode('utf-8'))
            
            # Create registration payload
            reg_payload = protocol.RegisterPayload(
                email=email,
                username=username,
                pwd=utils.b64encode(pwd_hash),
                salt=utils.b64encode(salt)
            )
            
            # Encrypt payload
            payload_json = reg_payload.model_dump_json()
            encrypted = aes.aes_encrypt(payload_json.encode('utf-8'), self.temp_aes_key)
            
            # Send encrypted registration
            reg_msg = protocol.EncryptedRegisterMessage(
                payload=utils.b64encode(encrypted)
            )
            self.socket.send(reg_msg.model_dump_json().encode('utf-8'))
            
            # Receive response
            response_data = json.loads(self.socket.recv(8192).decode('utf-8'))
            
            if response_data["type"] == "register_success":
                success_msg = protocol.SuccessMessage(**response_data)
                print(f"[✓] {success_msg.message}")
                self.authenticated_user = success_msg.username
                return True
            else:
                error_msg = protocol.ErrorMessage(**response_data)
                print(f"[✗] Registration failed: {error_msg.message}")
                return False
                
        except Exception as e:
            print(f"[✗] Registration error: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def login(self):
        """Login existing user"""
        print("\n[*] Login")
        print("-"*60)
        
        try:
            email = input("Email: ").strip()
            password = input("Password: ").strip()
            
            # Create login payload
            nonce = os.urandom(16)
            login_payload = protocol.LoginPayload(
                email=email,
                password=password,
                nonce=utils.b64encode(nonce)
            )
            
            # Encrypt payload
            payload_json = login_payload.model_dump_json()
            encrypted = aes.aes_encrypt(payload_json.encode('utf-8'), self.temp_aes_key)
            
            # Send encrypted login
            login_msg = protocol.EncryptedLoginMessage(
                payload=utils.b64encode(encrypted)
            )
            self.socket.send(login_msg.model_dump_json().encode('utf-8'))
            
            # Receive response
            response_data = json.loads(self.socket.recv(8192).decode('utf-8'))
            
            if response_data["type"] == "login_success":
                success_msg = protocol.SuccessMessage(**response_data)
                print(f"[✓] {success_msg.message}")
                self.authenticated_user = success_msg.username
                return True
            else:
                error_msg = protocol.ErrorMessage(**response_data)
                print(f"[✗] Login failed: {error_msg.message}")
                return False
                
        except Exception as e:
            print(f"[✗] Login error: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def key_agreement(self):
        """Phase 2: Session key establishment via DH"""
        print("\n" + "="*60)
        print("PHASE 2: KEY AGREEMENT (Session DH)")
        print("="*60)
        
        try:
            # Generate DH parameters
            g, p = dh.get_default_params()
            a = dh.generate_private_key(p)
            A = dh.compute_public_key(g, a, p)
            
            # Send DH client message
            dh_client = protocol.DHSessionClientMessage(g=g, p=p, A=A)
            self.socket.send(dh_client.model_dump_json().encode('utf-8'))
            print(f"[*] Sent DH parameters (p: {p.bit_length()} bits)")
            
            # Receive server DH response
            dh_response_data = json.loads(self.socket.recv(8192).decode('utf-8'))
            dh_response = protocol.DHSessionServerMessage(**dh_response_data)
            print("[*] Received server DH public key")
            
            # Compute shared secret and derive session key
            shared_secret = dh.compute_shared_secret(dh_response.B, a, p)
            self.session_key = dh.derive_aes_key(shared_secret)
            
            print(f"[✓] Session key established")
            print(f"    Key (hex): {self.session_key.hex()}")
            
            return True
            
        except Exception as e:
            print(f"[✗] Key agreement error: {e}")
            return False
    
    def data_plane(self):
        """Phase 3: Encrypted message exchange"""
        print("\n" + "="*60)
        print("PHASE 3: DATA PLANE (Encrypted Chat)")
        print("="*60)
        print(f"[*] Chat session started")
        print("[*] Type messages and press Enter")
        print("[*] Type '/quit' to end session\n")
        
        self.running = True
        
        # Start receiver thread
        receiver_thread = threading.Thread(target=self.receive_messages)
        receiver_thread.daemon = True
        receiver_thread.start()
        
        try:
            while self.running:
                user_input = input()
                
                if user_input.strip() == "/quit":
                    quit_msg = protocol.QuitMessage()
                    self.socket.send(quit_msg.model_dump_json().encode('utf-8'))
                    print("[*] Ending session...")
                    self.running = False
                    break
                
                if user_input.strip():
                    # Create and send encrypted message
                    msg = self.create_chat_message(user_input)
                    self.socket.send(msg.model_dump_json().encode('utf-8'))
        
        except KeyboardInterrupt:
            print("\n[*] Session interrupted")
            self.running = False
    
    def receive_messages(self):
        """Receive messages in background thread"""
        while self.running:
            try:
                self.socket.settimeout(0.5)
                data = self.socket.recv(8192).decode('utf-8')
                
                if not data:
                    print("\n[*] Server disconnected")
                    self.running = False
                    break
                
                message = json.loads(data)
                
                if message["type"] == "msg":
                    chat_msg = protocol.ChatMessage(**message)
                    success, plaintext = self.verify_and_decrypt_message(chat_msg)
                    
                    if success:
                        print(f"\nServer: {plaintext}")
                        print(f"{self.authenticated_user}> ", end='', flush=True)
                    else:
                        print(f"\n[✗] Message verification failed: {plaintext}")
                
                elif message["type"] == "quit":
                    print(f"\n[*] Server ended the session")
                    self.running = False
                    break
                
                elif message["type"] == "receipt":
                    # Received session receipt from server
                    self.handle_receipt(message)
                    
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    print(f"\n[✗] Receive error: {e}")
                break
    
    def handle_receipt(self, receipt_data):
        """Handle received session receipt from server"""
        try:
            receipt = protocol.ReceiptMessage(**receipt_data)
            print("\n[*] Received session receipt from server")
            
            # Save receipt
            os.makedirs("transcripts", exist_ok=True)
            timestamp = int(utils.now_ms() / 1000)
            receipt_file = f"transcripts/server_receipt_received_{timestamp}.json"
            
            with open(receipt_file, 'w') as f:
                f.write(receipt.model_dump_json(indent=2))
            
            print(f"[✓] Server receipt saved: {receipt_file}")
        except Exception as e:
            print(f"[✗] Error handling receipt: {e}")
    
    def create_chat_message(self, plaintext: str) -> protocol.ChatMessage:
        """Create encrypted and signed chat message"""
        self.seqno_sent += 1
        seqno = self.seqno_sent
        timestamp = utils.now_ms()
        
        # Encrypt
        ciphertext = aes.aes_encrypt(plaintext.encode('utf-8'), self.session_key)
        ct_b64 = utils.b64encode(ciphertext)
        
        # Compute digest: SHA256(seqno || ts || ct)
        digest = utils.sha256_bytes(
            seqno.to_bytes(8, 'big'),
            timestamp.to_bytes(8, 'big'),
            ciphertext
        )
        
        # Sign
        signature = sign.sign(self.private_key, digest)
        sig_b64 = utils.b64encode(signature)
        
        # Add to transcript
        peer_fp = pki.get_fingerprint(self.server_cert)
        self.transcript.add_entry(seqno, timestamp, ct_b64, sig_b64, peer_fp, "sent")
        
        return protocol.ChatMessage(
            seqno=seqno,
            ts=timestamp,
            ct=ct_b64,
            sig=sig_b64
        )
    
    def verify_and_decrypt_message(self, message: protocol.ChatMessage):
        """Verify signature and decrypt message"""
        try:
            seqno = message.seqno
            timestamp = message.ts
            ct_b64 = message.ct
            sig_b64 = message.sig
            
            # Replay protection
            if seqno <= self.seqno_received:
                return False, "REPLAY: Invalid sequence number"
            
            # Decode
            ciphertext = utils.b64decode(ct_b64)
            signature = utils.b64decode(sig_b64)
            
            # Recompute digest
            digest = utils.sha256_bytes(
                seqno.to_bytes(8, 'big'),
                timestamp.to_bytes(8, 'big'),
                ciphertext
            )
            
            # Verify signature
            if not sign.verify(self.peer_public_key, signature, digest):
                return False, "SIG_FAIL: Invalid signature"
            
            # Decrypt
            plaintext = aes.aes_decrypt(ciphertext, self.session_key)
            
            # Update state
            self.seqno_received = seqno
            
            # Add to transcript
            peer_fp = pki.get_fingerprint(self.server_cert)
            self.transcript.add_entry(seqno, timestamp, ct_b64, sig_b64, peer_fp, "received")
            
            return True, plaintext.decode('utf-8')
            
        except Exception as e:
            return False, f"Error: {str(e)}"
    
    def teardown(self):
        """Phase 4: Non-repudiation (session receipt)"""
        print("\n" + "="*60)
        print("PHASE 4: TEARDOWN (Non-Repudiation)")
        print("="*60)
        
        if self.transcript.is_empty():
            print("[*] No messages exchanged")
            return
        
        try:
            # Compute transcript hash
            transcript_hash = self.transcript.compute_hash()
            
            # Sign transcript hash
            receipt_sig = sign.sign(self.private_key, bytes.fromhex(transcript_hash))
            
            # Create receipt
            receipt = protocol.ReceiptMessage(
                peer="client",
                first_seq=self.transcript.get_first_seqno(),
                last_seq=self.transcript.get_last_seqno(),
                transcript_sha256=transcript_hash,
                sig=utils.b64encode(receipt_sig)
            )
            
            # Save transcript and receipt
            os.makedirs("transcripts", exist_ok=True)
            timestamp = int(utils.now_ms() / 1000)
            
            transcript_file = f"transcripts/client_transcript_{timestamp}.txt"
            receipt_file = f"transcripts/client_receipt_{timestamp}.json"
            
            self.transcript.save(transcript_file)
            with open(receipt_file, 'w') as f:
                f.write(receipt.model_dump_json(indent=2))
            
            print(f"[✓] Transcript saved: {transcript_file}")
            print(f"[✓] Receipt saved: {receipt_file}")
            print(f"[*] Transcript hash: {transcript_hash[:32]}...")
            
        except Exception as e:
            print(f"[✗] Teardown error: {e}")


if __name__ == "__main__":
    try:
        client = SecureChatClient()
        client.run()
    except KeyboardInterrupt:
        print("\n[*] Client stopped")
    except Exception as e:
        print(f"[✗] Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)