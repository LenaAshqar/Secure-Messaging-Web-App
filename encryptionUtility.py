import os
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidSignature


# --------- ChaCha20-Poly1305 (with provided key) ---------

def encrypt_with_key(key: bytes, plaintext: bytes, aad: bytes | None = None):
    """
    Encrypt using ChaCha20-Poly1305 with a given 256-bit key.
    Returns (ciphertext, nonce).
    """
    nonce = os.urandom(12)  # 96-bit nonce
    chacha = ChaCha20Poly1305(key)
    ciphertext = chacha.encrypt(nonce, plaintext, aad)
    return ciphertext, nonce


def decrypt_with_key(key: bytes, ciphertext: bytes, nonce: bytes, aad: bytes | None = None):
    """
    Decrypt using ChaCha20-Poly1305 with a given 256-bit key.
    """
    chacha = ChaCha20Poly1305(key)
    return chacha.decrypt(nonce, ciphertext, aad)


# --------- ECDH key exchange ---------

def generate_ecdh_keypair():
    """
    Generate an EC keypair for ECDH (SECP256R1).
    """
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key


def derive_shared_key(private_key, peer_public_key) -> bytes:
    """
    Perform ECDH and derive a 256-bit symmetric key with HKDF(SHA-256).
    """
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # 256-bit
        salt=None,
        info=b"secure-messaging-ecdh"
    ).derive(shared_secret)
    return derived_key


def serialize_public_key(public_key) -> bytes:
    """
    Export public key in PEM format to share with peers.
    """
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def load_public_key(pem_bytes: bytes):
    """
    Load a public key from PEM bytes.
    """
    return serialization.load_pem_public_key(pem_bytes)


# --------- Digital signatures (ECDSA) ---------

def generate_signing_keypair():
    """
    Generate an EC keypair for signing (ECDSA with SECP256R1).
    """
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key


def sign_data(private_key, data: bytes) -> bytes:
    """
    Sign arbitrary bytes using ECDSA (SHA-256).
    """
    return private_key.sign(data, ec.ECDSA(hashes.SHA256()))


def verify_signature(public_key, data: bytes, signature: bytes) -> bool:
    """
    Verify ECDSA signature; returns True if valid, False otherwise.
    """
    try:
        public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False
