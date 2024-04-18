import base64
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

from core.symmetric.interface import SymmetricEncryption
from core.symmetric.models import Options


class ChaCha20(SymmetricEncryption):
    def encrypt(self, payload: str, key: str, options: Options) -> str:
        key_bytes = base64.urlsafe_b64decode(key)
        nonce = os.urandom(options.key_size)
        cipher = Cipher(
            algorithms.ChaCha20(key_bytes, nonce),
            mode=None,
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(
            payload.encode('utf-8')) + encryptor.finalize()
        encrypted_nonce = nonce + encrypted
        return base64.urlsafe_b64encode(encrypted_nonce).decode('utf-8')

    def decrypt(self, encrypted: str, key: str, options: Options) -> str:
        key_bytes = base64.urlsafe_b64decode(key)
        encrypted_nonce = base64.urlsafe_b64decode(encrypted)
        nonce = encrypted_nonce[:options.key_size]
        encrypted_data = encrypted_nonce[options.key_size:]
        cipher = Cipher(
            algorithms.ChaCha20(key_bytes, nonce),
            mode=None,
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(encrypted_data) + decryptor.finalize()
        return decrypted.decode('utf-8')
