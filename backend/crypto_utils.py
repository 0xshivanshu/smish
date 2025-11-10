from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib

def hash_data(data: str) -> str:
    """
    Hashes a string using SHA-256 and returns the hex digest.
    """
    h = hashlib.sha256()
    h.update(data.encode('utf-8'))
    return h.hexdigest()

def encrypt_data(key: bytes, data: str) -> tuple[str, str]:
    """
    Encrypts a string using AES (EAX mode) and returns the nonce and ciphertext as hex strings.
    """
    data_bytes = data.encode('utf-8')
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data_bytes)
    return cipher.nonce.hex(), ciphertext.hex()