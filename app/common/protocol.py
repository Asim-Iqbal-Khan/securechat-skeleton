"""
Pydantic message models for secure chat protocol
Defines structure for all protocol messages
"""

from pydantic import BaseModel, Field
from typing import Optional


class HelloMessage(BaseModel):
    """Client hello with certificate and nonce"""
    type: str = "hello"
    client_cert: str = Field(..., description="PEM-encoded client certificate")
    nonce: str = Field(..., description="Base64-encoded random nonce")


class ServerHelloMessage(BaseModel):
    """Server hello response with certificate"""
    type: str = "server_hello"
    server_cert: str = Field(..., description="PEM-encoded server certificate")
    nonce: str = Field(..., description="Base64-encoded random nonce")


class DHClientMessage(BaseModel):
    """Client DH parameters for temporary credential encryption"""
    type: str = "dh_temp"
    g: int = Field(..., description="DH generator")
    p: int = Field(..., description="DH prime modulus")
    A: int = Field(..., description="Client DH public key (g^a mod p)")


class DHServerMessage(BaseModel):
    """Server DH response"""
    type: str = "dh_temp_response"
    B: int = Field(..., description="Server DH public key (g^b mod p)")


class DHSessionClientMessage(BaseModel):
    """Client DH parameters for session key"""
    type: str = "dh_client"
    g: int = Field(..., description="DH generator")
    p: int = Field(..., description="DH prime modulus")
    A: int = Field(..., description="Client DH public key (g^a mod p)")


class DHSessionServerMessage(BaseModel):
    """Server DH response for session key"""
    type: str = "dh_server"
    B: int = Field(..., description="Server DH public key (g^b mod p)")


class EncryptedRegisterMessage(BaseModel):
    """Encrypted registration payload"""
    type: str = "encrypted_register"
    payload: str = Field(..., description="Base64-encoded encrypted registration data")


class EncryptedLoginMessage(BaseModel):
    """Encrypted login payload"""
    type: str = "encrypted_login"
    payload: str = Field(..., description="Base64-encoded encrypted login data")


class RegisterPayload(BaseModel):
    """Decrypted registration data"""
    email: str
    username: str
    pwd: str = Field(..., description="Base64-encoded SHA256(salt||password)")
    salt: str = Field(..., description="Base64-encoded 16-byte salt")


class LoginPayload(BaseModel):
    """Decrypted login data"""
    email: str
    password: str
    nonce: str = Field(..., description="Base64-encoded nonce for freshness")


class SuccessMessage(BaseModel):
    """Generic success response"""
    type: str
    message: str
    username: Optional[str] = None


class ErrorMessage(BaseModel):
    """Error response"""
    type: str = "error"
    message: str


class ChatMessage(BaseModel):
    """Encrypted and signed chat message"""
    type: str = "msg"
    seqno: int = Field(..., description="Sequence number for replay protection")
    ts: int = Field(..., description="Timestamp in milliseconds")
    ct: str = Field(..., description="Base64-encoded ciphertext (AES-128-ECB)")
    sig: str = Field(..., description="Base64-encoded RSA signature of SHA256(seqno||ts||ct)")


class QuitMessage(BaseModel):
    """Session termination message"""
    type: str = "quit"


class ReceiptMessage(BaseModel):
    """Non-repudiation session receipt"""
    type: str = "receipt"
    peer: str = Field(..., description="'client' or 'server'")
    first_seq: int = Field(..., description="First sequence number in session")
    last_seq: int = Field(..., description="Last sequence number in session")
    transcript_sha256: str = Field(..., description="Hex SHA-256 of transcript")
    sig: str = Field(..., description="Base64 RSA signature of transcript hash")