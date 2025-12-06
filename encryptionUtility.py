# encryptionUtility.py
import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import serialization

# ----- Symmetric message encryption using ChaCha20-Poly1305 -----
def generate_chacha_key() -> bytes:
    return ChaCha20Poly1305.generate_key()  # 256-bit

def encrypt_message_with_key(plaintext: bytes, key: bytes, aad: bytes | None = None):
    nonce = os.urandom(12)
    chacha = ChaCha20Poly1305(key)
    ciphertext = chacha.encrypt(nonce, plaintext, aad)
    return ciphertext, nonce

def decrypt_message_with_key(ciphertext: bytes, nonce: bytes, key: bytes, aad: bytes | None = None):
    chacha = ChaCha20Poly1305(key)
    plaintext = chacha.decrypt(nonce, ciphertext, aad)
    return plaintext

# ----- RSA key generation and serialization -----
def generate_rsa_keypair(key_size=2048):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_public_key_to_pem(pubkey) -> bytes:
    return pubkey.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def serialize_private_key_to_pem(privkey, password: bytes | None = None) -> bytes:
    encryption_algo = serialization.NoEncryption()
    if password:
        encryption_algo = serialization.BestAvailableEncryption(password)
    return privkey.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_algo
    )

def load_public_key_from_pem(pem_bytes: bytes):
    return serialization.load_pem_public_key(pem_bytes)

def load_private_key_from_pem(pem_bytes: bytes, password: bytes | None = None):
    return serialization.load_pem_private_key(pem_bytes, password=password)

# ----- RSA-OAEP encrypt/decrypt of symmetric (session) key -----
def rsa_encrypt_session_key(pubkey, session_key: bytes) -> bytes:
    ciphertext = pubkey.encrypt(
        session_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def rsa_decrypt_session_key(privkey, enc_session_key: bytes) -> bytes:
    session_key = privkey.decrypt(
        enc_session_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return session_key

# ----- Signing (RSA-PSS SHA256) and verification -----
def sign_bytes_rsa(privkey, data: bytes) -> bytes:
    signature = privkey.sign(
        data,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def verify_signature_rsa(pubkey, signature: bytes, data: bytes) -> bool:
    try:
        pubkey.verify(
            signature,
            data,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

# ----- Helpers to base64 encode/decode JSON-friendly bundles -----
def b64(x: bytes) -> str:
    return base64.b64encode(x).decode('ascii')

def ub64(s: str) -> bytes:
    return base64.b64decode(s.encode('ascii'))

def make_transport_bundle(ciphertext: bytes, nonce: bytes, enc_session_key: bytes, signature: bytes, sender_pub_pem: bytes, timestamp: str = None, msg_id: str = None):
    bundle = {
        "ciphertext": b64(ciphertext),
        "nonce": b64(nonce),
        "enc_session_key": b64(enc_session_key),
        "signature": b64(signature),
        "sender_pub_pem": sender_pub_pem.decode('utf-8')
    }
    if timestamp:
        bundle["timestamp"] = timestamp
    if msg_id:
        bundle["message_id"] = msg_id
    return bundle

def parse_transport_bundle(bundle_json):
    # expects dict-like (already parsed)
    return {
        "ciphertext": ub64(bundle_json["ciphertext"]),
        "nonce": ub64(bundle_json["nonce"]),
        "enc_session_key": ub64(bundle_json["enc_session_key"]),
        "signature": ub64(bundle_json["signature"]),
        "sender_pub_pem": bundle_json["sender_pub_pem"].encode('utf-8'),
        "timestamp": bundle_json.get("timestamp"),
        "message_id": bundle_json.get("message_id")
    }
