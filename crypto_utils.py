"""
crypto_utils.py
---------------
Core cryptography functions for the Cryptography Lib Lab project.
Implements AES-256-CBC, DES-CBC, and RSA-2048 using the 'cryptography' library.
"""

import os
import time
import base64
import hashlib
import json

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
try:
    from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES as _TripleDES
except ImportError:
    _TripleDES = algorithms.TripleDES  # fallback for older versions
from cryptography.hazmat.primitives import padding, hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.backends import default_backend

BACKEND = default_backend()


# ─────────────────────────────────────────────
#  KEY GENERATION
# ─────────────────────────────────────────────

def generate_aes_key(key_size: int = 256) -> bytes:
    """Generate a random AES key (128, 192, or 256 bits)."""
    return os.urandom(key_size // 8)


def generate_des_key() -> bytes:
    """Generate a random 8-byte DES key."""
    return os.urandom(8)


def generate_rsa_keypair(key_size: int = 2048):
    """Generate an RSA private/public key pair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=BACKEND
    )
    public_key = private_key.public_key()
    return private_key, public_key


# ─────────────────────────────────────────────
#  AES ENCRYPTION / DECRYPTION (CBC mode)
# ─────────────────────────────────────────────

def aes_encrypt(plaintext: bytes, key: bytes) -> dict:
    """
    Encrypt plaintext using AES-256-CBC.
    Returns dict with ciphertext (bytes) and iv (bytes).
    """
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=BACKEND)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    return {"ciphertext": ciphertext, "iv": iv}


def aes_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """Decrypt AES-256-CBC ciphertext back to plaintext bytes."""
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=BACKEND)
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded) + unpadder.finalize()
    return plaintext


# ─────────────────────────────────────────────
#  DES ENCRYPTION / DECRYPTION (CBC mode)
# ─────────────────────────────────────────────

def des_encrypt(plaintext: bytes, key: bytes) -> dict:
    """
    Encrypt plaintext using DES-CBC.
    NOTE: DES is included for educational comparison only.
          It is NOT secure for modern use.
    """
    iv = os.urandom(8)
    padder = padding.PKCS7(64).padder()
    padded = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(_TripleDES(key * 3), modes.CBC(iv), backend=BACKEND)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    return {"ciphertext": ciphertext, "iv": iv}


def des_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """Decrypt DES-CBC ciphertext back to plaintext bytes."""
    cipher = Cipher(_TripleDES(key * 3), modes.CBC(iv), backend=BACKEND)
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(64).unpadder()
    plaintext = unpadder.update(padded) + unpadder.finalize()
    return plaintext


# ─────────────────────────────────────────────
#  RSA ENCRYPTION / DECRYPTION (for AES key)
# ─────────────────────────────────────────────

def rsa_encrypt_key(aes_key: bytes, public_key) -> bytes:
    """Encrypt an AES key using RSA public key (OAEP padding)."""
    return public_key.encrypt(
        aes_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def rsa_decrypt_key(encrypted_key: bytes, private_key) -> bytes:
    """Decrypt an RSA-encrypted AES key using the private key."""
    return private_key.decrypt(
        encrypted_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


# ─────────────────────────────────────────────
#  FILE I/O
# ─────────────────────────────────────────────

def load_file(path: str) -> bytes:
    """Load raw bytes from a file."""
    with open(path, "rb") as f:
        return f.read()


def save_file(path: str, data: bytes):
    """Save raw bytes to a file."""
    with open(path, "wb") as f:
        f.write(data)


def save_metadata(path: str, meta: dict):
    """Save metadata (IV, algorithm, etc.) as JSON."""
    # Convert bytes values to base64 strings for JSON serialisation
    serialisable = {}
    for k, v in meta.items():
        if isinstance(v, bytes):
            serialisable[k] = base64.b64encode(v).decode()
        else:
            serialisable[k] = v
    with open(path, "w") as f:
        json.dump(serialisable, f, indent=2)


def load_metadata(path: str) -> dict:
    """Load metadata JSON and decode base64 byte fields."""
    with open(path, "r") as f:
        raw = json.load(f)
    decoded = {}
    for k, v in raw.items():
        if isinstance(v, str):
            try:
                decoded[k] = base64.b64decode(v)
            except Exception:
                decoded[k] = v
        else:
            decoded[k] = v
    return decoded


# ─────────────────────────────────────────────
#  VERIFICATION
# ─────────────────────────────────────────────

def sha256_hash(data: bytes) -> str:
    """Return hex SHA-256 digest of data."""
    return hashlib.sha256(data).hexdigest()


def verify_files(original: bytes, decrypted: bytes) -> bool:
    """Return True if SHA-256 hashes match."""
    return sha256_hash(original) == sha256_hash(decrypted)


# ─────────────────────────────────────────────
#  TIMED WRAPPERS (for comparison)
# ─────────────────────────────────────────────

def timed_aes_encrypt(plaintext: bytes, key: bytes):
    start = time.perf_counter()
    result = aes_encrypt(plaintext, key)
    elapsed = time.perf_counter() - start
    return result, elapsed


def timed_aes_decrypt(ciphertext: bytes, key: bytes, iv: bytes):
    start = time.perf_counter()
    result = aes_decrypt(ciphertext, key, iv)
    elapsed = time.perf_counter() - start
    return result, elapsed


def timed_des_encrypt(plaintext: bytes, key: bytes):
    start = time.perf_counter()
    result = des_encrypt(plaintext, key)
    elapsed = time.perf_counter() - start
    return result, elapsed


def timed_des_decrypt(ciphertext: bytes, key: bytes, iv: bytes):
    start = time.perf_counter()
    result = des_decrypt(ciphertext, key, iv)
    elapsed = time.perf_counter() - start
    return result, elapsed
