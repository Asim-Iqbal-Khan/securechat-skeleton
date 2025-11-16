"""
Secure Chat Server
Handles client connections, authentication, and encrypted messaging
"""

import socket
import json
import os
import sys
import threading
from dotenv import load_dotenv

from app.crypto import aes, dh, pki, sign
from app.common import protocol, utils
from app.storage.db import Database
from app.storage.transcript import Transcript

load_dotenv()


class SecureChatServer:
    """Server implementation for secure chat"""
    
    def __init__(self):
        self.host = os.getenv("SERVER_HOST", "localhost")
        self.port = int(os.getenv("SERVER_PORT", "5555"))
        
        # Load server credentials
        self.private_key = sign.load_private_key("certs/server_private_key.pem")
        self.certificate = pki.load_cert("certs/server_cert.pem")
        self.ca_cert = pki.load_cert("certs/ca_cert.pem")
        
        # Database
        self.db = Database()
        
        # Session state
        self.client_cert = None
        self.peer_public_key = None
        self.temp_aes_key = None
        self.session_key = None
        self.authenticated_user = None
        self.seqno_sent = 0
        self.seqno_received = 0
        self.transcript = Transcript()
        
        print(f"[*] Server initialized")
        print(f"[*] Certificate CN: {pki.get_common_name(self.certificate)}")
        print(f"[*] Fingerprint: {pki.get_fingerprint(self.certificate)[:32]}...")
    
    def start(self):
        """Start server and listen for connections"""
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((self.host, self.port))
        server_socket.listen(1)
        
        print(f"\n[✓] Server listening on {self.host}:{self.port}")
        print(f"[*] Waiting for client connection...\n")
        
        while True:
            client_socket, address = server_socket.accept()
            print(f"[*] Client connected from {address}")
            
            try:
                self.handle_client(client_socket)
            except Exception as e:
                print(f"[✗] Error handling client: {e}")
                import traceback
                traceback.print_exc()
            finally:
                client_socket.close()
                print(f"[*] Client disconnected\n")
                # Reset state
                self.reset_session()
    
    def reset_session(self):
        """Reset session state for next connection"""
        self.client_cert = None
        self.peer_public_key = None
        self.temp_aes_key = None
        self.session_key = None
        self.authenticated_user = None
        self.seqno_sent = 0
        self.seqno_received = 0
        self.transcript = Transcript()
    
    def handle_client(self, client_socket):
        """Handle single client connection through all phases"""
        
        # Phase 1: Control Plane
        if not self.control_plane(client_socket):
            return
        
        # Phase 2: Key Agreement
        if not self.key_agreement(client_socket):
            return
        
        # Phase 3: Data Plane
        self.data_plane(client_socket)
        
        # Phase 4: Teardown
        self.teardown(client_socket)
    
    def control_plane(self, client_socket):
        """Phase 1: Certificate exchange and authentication"""
        print("\n" + "="*60)
        print("PHASE 1: CONTROL PLANE (Authentication)")
        print("="*60)
        
        try:
            # Receive client hello
            data = client_socket.recv(16384).decode('utf-8')
            hello_data = json.loads(data)
            hello_msg = protocol.HelloMessage(**hello_data)
            
            print("[*] Received client hello")
            
            # Verify client certificate
            client_cert = pki.pem_to_cert(hello_msg.client_cert)
            is_valid, error = pki.validate_cert(client_cert, self.ca_cert)
            
            if not is_valid:
                print(f"[✗] {error}")
                error_msg = protocol.ErrorMessage(message=error)
                client_socket.send(error_msg.model_dump_json().encode('utf-8'))
                return False
            
            self.client_cert = client_cert
            self.peer_public_key = client_cert.public_key()
            
            print(f"[✓] Client certificate verified")
            print(f"    CN: {pki.get_common_name(client_cert)}")
            
            # Send server hello
            server_nonce = os.urandom(16)
            server_hello = protocol.ServerHelloMessage(
                server_cert=pki.cert_to_pem(self.certificate),
                nonce=utils.b64encode(server_nonce)
            )
            client_socket.send(server_hello.model_dump_json().encode('utf-8'))
            print("[*] Sent server hello")
            
            # Temporary DH for credential encryption
            print("\n[*] Performing temporary DH exchange...")
            dh_data = client_socket.recv(8192).decode('utf-8')
            dh_msg = protocol.DHClientMessage(**json.loads(dh_data))
            
            # Generate server DH keypair
            b = dh.generate_private_key(dh_msg.p)
            B = dh.compute_public_key(dh_msg.g, b, dh_msg.p)
            
            # Send B to client
            dh_response = protocol.DHServerMessage(B=B)
            client_socket.send(dh_response.model_dump_json().encode('utf-8'))
            
            # Derive temporary AES key
            shared_secret = dh.compute_shared_secret(dh_msg.A, b, dh_msg.p)
            self.temp_aes_key = dh.derive_aes_key(shared_secret)
            print("[✓] Temporary session key established")
            
            # Receive encrypted credentials
            cred_data = client_socket.recv(8192).decode('utf-8')
            cred_msg = json.loads(cred_data)
            
            if cred_msg["type"] == "encrypted_register":
                return self.handle_registration(client_socket, cred_msg)
            elif cred_msg["type"] == "encrypted_login":
                return self.handle_login(client_socket, cred_msg)
            else:
                print(f"[✗] Unknown message type: {cred_msg['type']}")
                return False
                
        except Exception as e:
            print(f"[✗] Control plane error: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def handle_registration(self, client_socket, cred_msg):
        """Handle user registration"""
        print("\n[*] Processing registration...")
        
        try:
            # Decrypt payload
            encrypted = utils.b64decode(cred_msg["payload"])
            decrypted_json = aes.decrypt_str(encrypted, self.temp_aes_key)
            reg_payload = protocol.RegisterPayload(**json.loads(decrypted_json))
            
            email = reg_payload.email
            username = reg_payload.username
            salt = utils.b64decode(reg_payload.salt)
            pwd_hash = utils.b64decode(reg_payload.pwd)
            
            # Register in database
            success, message = self.db.register_user(email, username, salt, pwd_hash.hex())
            
            if success:
                print(f"[✓] User registered: {username} ({email})")
                self.authenticated_user = username
                response = protocol.SuccessMessage(
                    type="register_success",
                    message=message,
                    username=username
                )
            else:
                print(f"[✗] Registration failed: {message}")
                response = protocol.ErrorMessage(message=message)
                client_socket.send(response.model_dump_json().encode('utf-8'))
                return False
            
            client_socket.send(response.model_dump_json().encode('utf-8'))
            return True
            
        except Exception as e:
            print(f"[✗] Registration error: {e}")
            import traceback
            traceback.print_exc()
            error_msg = protocol.ErrorMessage(message=str(e))
            client_socket.send(error_msg.model_dump_json().encode('utf-8'))
            return False
    
    def handle_login(self, client_socket, cred_msg):
        """Handle user login"""
        print("\n[*] Processing login...")
        
        try:
            # Decrypt payload
            encrypted = utils.b64decode(cred_msg["payload"])
            decrypted_json = aes.decrypt_str(encrypted, self.temp_aes_key)
            login_payload = protocol.LoginPayload(**json.loads(decrypted_json))
            
            email = login_payload.email
            password = login_payload.password
            
            # Verify credentials
            success, result = self.db.verify_login(email, password)
            
            if success:
                username = result
                print(f"[✓] User authenticated: {username} ({email})")
                self.authenticated_user = username
                response = protocol.SuccessMessage(
                    type="login_success",
                    message="Login successful",
                    username=username
                )
            else:
                print(f"[✗] Login failed: {result}")
                response = protocol.ErrorMessage(message=result)
                client_socket.send(response.model_dump_json().encode('utf-8'))
                return False
            
            client_socket.send(response.model_dump_json().encode('utf-8'))
            return True
            
        except Exception as e:
            print(f"[✗] Login error: {e}")
            import traceback
            traceback.print_exc()
            error_msg = protocol.ErrorMessage(message=str(e))
            client_socket.send(error_msg.model_dump_json().encode('utf-8'))
            return False
    
    def key_agreement(self, client_socket):
        """Phase 2: Session key establishment via DH"""
        print("\n" + "="*60)
        print("PHASE 2: KEY AGREEMENT (Session DH)")
        print("="*60)
        
        try:
            # Receive client DH parameters
            dh_data = client_socket.recv(8192).decode('utf-8')
            dh_msg = protocol.DHSessionClientMessage(**json.loads(dh_data))
            
            print(f"[*] Received DH parameters (p: {dh_msg.p.bit_length()} bits)")
            
            # Generate server DH keypair
            b = dh.generate_private_key(dh_msg.p)
            B = dh.compute_public_key(dh_msg.g, b, dh_msg.p)
            
            # Send B to client
            dh_response = protocol.DHSessionServerMessage(B=B)
            client_socket.send(dh_response.model_dump_json().encode('utf-8'))
            print("[*] Sent server DH public key")
            
            # Compute shared secret and derive session key
            shared_secret = dh.compute_shared_secret(dh_msg.A, b, dh_msg.p)
            self.session_key = dh.derive_aes_key(shared_secret)
            
            print(f"[✓] Session key established")
            print(f"    Key (hex): {self.session_key.hex()}")
            
            return True
            
        except Exception as e:
            print(f"[✗] Key agreement error: {e}")
            return False
    
    def data_plane(self, client_socket):
        """Phase 3: Encrypted message exchange"""
        print("\n" + "="*60)
        print("PHASE 3: DATA PLANE (Encrypted Chat)")
        print("="*60)
        print(f"[*] Chat session started with {self.authenticated_user}")
        print("[*] Type messages and press Enter")
        print("[*] Type '/quit' to end session\n")
        
        # Start receiver thread
        stop_event = threading.Event()
        receiver_thread = threading.Thread(
            target=self.receive_messages,
            args=(client_socket, stop_event)
        )
        receiver_thread.daemon = True
        receiver_thread.start()
        
        try:
            while not stop_event.is_set():
                server_input = input()
                
                if server_input.strip() == "/quit":
                    quit_msg = protocol.QuitMessage()
                    client_socket.send(quit_msg.model_dump_json().encode('utf-8'))
                    print("[*] Ending session...")
                    stop_event.set()
                    break
                
                if server_input.strip():
                    # Create and send encrypted message
                    msg = self.create_chat_message(server_input)
                    client_socket.send(msg.model_dump_json().encode('utf-8'))
        
        except KeyboardInterrupt:
            print("\n[*] Session interrupted")
            stop_event.set()
    
    def receive_messages(self, client_socket, stop_event):
        """Receive messages in background thread"""
        while not stop_event.is_set():
            try:
                client_socket.settimeout(0.5)
                data = client_socket.recv(8192).decode('utf-8')
                
                if not data:
                    print("\n[*] Client disconnected")
                    stop_event.set()
                    break
                
                message = json.loads(data)
                
                if message["type"] == "msg":
                    chat_msg = protocol.ChatMessage(**message)
                    success, plaintext = self.verify_and_decrypt_message(chat_msg)
                    
                    if success:
                        print(f"\n{self.authenticated_user}: {plaintext}")
                        print("Server> ", end='', flush=True)
                    else:
                        print(f"\n[✗] Message verification failed: {plaintext}")
                
                elif message["type"] == "quit":
                    print(f"\n[*] {self.authenticated_user} ended the session")
                    stop_event.set()
                    break
                    
            except socket.timeout:
                continue
            except Exception as e:
                if not stop_event.is_set():
                    print(f"\n[✗] Receive error: {e}")
                break
    
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
        peer_fp = pki.get_fingerprint(self.client_cert)
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
            peer_fp = pki.get_fingerprint(self.client_cert)
            self.transcript.add_entry(seqno, timestamp, ct_b64, sig_b64, peer_fp, "received")
            
            return True, plaintext.decode('utf-8')
            
        except Exception as e:
            return False, f"Error: {str(e)}"
    
    def teardown(self, client_socket):
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
                peer="server",
                first_seq=self.transcript.get_first_seqno(),
                last_seq=self.transcript.get_last_seqno(),
                transcript_sha256=transcript_hash,
                sig=utils.b64encode(receipt_sig)
            )
            
            # Save transcript and receipt
            os.makedirs("transcripts", exist_ok=True)
            timestamp = int(utils.now_ms() / 1000)
            
            transcript_file = f"transcripts/server_transcript_{timestamp}.txt"
            receipt_file = f"transcripts/server_receipt_{timestamp}.json"
            
            self.transcript.save(transcript_file)
            with open(receipt_file, 'w') as f:
                f.write(receipt.model_dump_json(indent=2))
            
            print(f"[✓] Transcript saved: {transcript_file}")
            print(f"[✓] Receipt saved: {receipt_file}")
            print(f"[*] Transcript hash: {transcript_hash[:32]}...")
            
            # Send receipt to client
            client_socket.send(receipt.model_dump_json().encode('utf-8'))
            print(f"[✓] Receipt sent to client")
            
        except Exception as e:
            print(f"[✗] Teardown error: {e}")


if __name__ == "__main__":
    try:
        server = SecureChatServer()
        server.start()
    except KeyboardInterrupt:
        print("\n[*] Server stopped")
    except Exception as e:
        print(f"[✗] Server error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)