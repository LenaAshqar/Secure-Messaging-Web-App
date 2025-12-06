"""Cryptographic helpers for the secure messaging demo.

This module centralises symmetric encryption (AES-256-GCM),
key exchange (ECDH + AES-GCM wrapping) and digital signatures (RSA-PSS).
All helpers are intentionally small wrappers around ``cryptography`` primitives
to keep the Flask views readable.
"""

import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding as asym_padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# ----- Symmetric message encryption using AES-256-GCM -----
def generate_aes_key() -> bytes:
    """Return a fresh 256-bit AES key for content encryption."""
    return AESGCM.generate_key(bit_length=256)


def encrypt_message_with_key(plaintext: bytes, key: bytes, aad: bytes | None = None):
    """Encrypt ``plaintext`` with AES-256-GCM and return (ciphertext, nonce)."""
    nonce = os.urandom(12)
    aes = AESGCM(key)
    ciphertext = aes.encrypt(nonce, plaintext, aad)
    return ciphertext, nonce


def decrypt_message_with_key(ciphertext: bytes, nonce: bytes, key: bytes, aad: bytes | None = None):
    """Decrypt AES-256-GCM ciphertext and return the original plaintext."""
    aes = AESGCM(key)
    plaintext = aes.decrypt(nonce, ciphertext, aad)
    return plaintext


# ----- RSA key generation and serialization (signing) -----
def generate_rsa_keypair(key_size: int = 2048):
    """Generate an RSA key pair used for digital signatures."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    public_key = private_key.public_key()
    return private_key, public_key


def serialize_public_key_to_pem(pubkey) -> bytes:
    return pubkey.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def serialize_private_key_to_pem(privkey, password: bytes | None = None) -> bytes:
    encryption_algo = serialization.NoEncryption()
    if password:
        encryption_algo = serialization.BestAvailableEncryption(password)
    return privkey.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_algo,
    )


def load_public_key_from_pem(pem_bytes: bytes):
    return serialization.load_pem_public_key(pem_bytes)


def load_private_key_from_pem(pem_bytes: bytes, password: bytes | None = None):
    return serialization.load_pem_private_key(pem_bytes, password=password)


# ----- ECDH for secure key exchange -----
def generate_ecdh_keypair():
    """Generate a P-256 ECDH key pair for key agreement."""
    priv = ec.generate_private_key(ec.SECP256R1())
    return priv, priv.public_key()


def derive_ecdh_shared_key(privkey, peer_pubkey) -> bytes:
    """Derive a shared secret using ECDH and HKDF-SHA256."""
    shared = privkey.exchange(ec.ECDH(), peer_pubkey)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"ecdh-session-wrap",
    ).derive(shared)


def encrypt_session_key_ecdh(sender_priv, receiver_pub, session_key: bytes):
    """Wrap the symmetric ``session_key`` using ECDH + AES-GCM.

    The sender uses their ECDH private key with the receiver's ECDH public key
    to derive a shared key. The derived key is then used to AES-GCM encrypt the
    session key. The caller must send the sender's public ECDH key and the wrap
    nonce alongside the ciphertext so the receiver can unwrap it.
    """

    wrap_key = derive_ecdh_shared_key(sender_priv, receiver_pub)
    wrap_nonce = os.urandom(12)
    wrapper = AESGCM(wrap_key)
    enc_session_key = wrapper.encrypt(wrap_nonce, session_key, None)
    sender_pub_pem = serialize_public_key_to_pem(sender_priv.public_key())
    return enc_session_key, wrap_nonce, sender_pub_pem


def decrypt_session_key_ecdh(receiver_priv, sender_pub, enc_session_key: bytes, wrap_nonce: bytes) -> bytes:
    """Unwrap the encrypted session key using the receiver's ECDH private key."""

    wrap_key = derive_ecdh_shared_key(receiver_priv, sender_pub)
    wrapper = AESGCM(wrap_key)
    return wrapper.decrypt(wrap_nonce, enc_session_key, None)


# ----- Signing (RSA-PSS SHA256) and verification -----
def sign_bytes_rsa(privkey, data: bytes) -> bytes:
    signature = privkey.sign(
        data,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    return signature


def verify_signature_rsa(pubkey, signature: bytes, data: bytes) -> bool:
    try:
        pubkey.verify(
            signature,
            data,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False


# ----- Helpers to base64 encode/decode JSON-friendly bundles -----
def b64(x: bytes) -> str:
    return base64.b64encode(x).decode("ascii")


def ub64(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def make_transport_bundle(
    ciphertext: bytes,
    nonce: bytes,
    enc_session_key: bytes,
    wrap_nonce: bytes,
    signature: bytes,
    sender_pub_pem: bytes,
    sender_ecdh_pub_pem: bytes,
    timestamp: str | None = None,
    msg_id: str | None = None,
):
    bundle = {
        "ciphertext": b64(ciphertext),
        "nonce": b64(nonce),
        "enc_session_key": b64(enc_session_key),
        "wrap_nonce": b64(wrap_nonce),
        "signature": b64(signature),
        "sender_pub_pem": sender_pub_pem.decode("utf-8"),
        "sender_ecdh_pub_pem": sender_ecdh_pub_pem.decode("utf-8"),
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
        "wrap_nonce": ub64(bundle_json["wrap_nonce"]),
        "signature": ub64(bundle_json["signature"]),
        "sender_pub_pem": bundle_json["sender_pub_pem"].encode("utf-8"),
        "sender_ecdh_pub_pem": bundle_json["sender_ecdh_pub_pem"].encode("utf-8"),
        "timestamp": bundle_json.get("timestamp"),
        "message_id": bundle_json.get("message_id"),
    }
