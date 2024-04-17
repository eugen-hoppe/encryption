import base64
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from symmetric.interface import SymmetricEncryption


class AES256(SymmetricEncryption):
    def encrypt(self, payload: str, key: str, size: int) -> str:
        """Encrypts a given payload using AES-256 encryption in CBC mode.

        https://github.com/eugen-hoppe/encryption/blob/main/docs/v4.md#d17a
        """
        key_bytes = base64.urlsafe_b64decode(key)
        iv = os.urandom(size)
        cipher = Cipher(
            algorithms.AES(key_bytes),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        payload_bytes = payload.encode('utf-8')
        padding_length = size - len(payload_bytes) % size
        padded_payload = payload_bytes + bytes(
            [padding_length] * padding_length
        )
        encrypted = encryptor.update(padded_payload) + encryptor.finalize()
        encrypted_iv = iv + encrypted
        return base64.urlsafe_b64encode(encrypted_iv).decode('utf-8')

    def decrypt(self, encrypted: str, key: str, size: int) -> str:
        """Decrypts encrypted message using AES-256 encryption in CBC mode.

        https://github.com/eugen-hoppe/encryption/blob/main/docs/v4.md#d17b
        """
        key_bytes = base64.urlsafe_b64decode(key)
        encrypted_iv = base64.urlsafe_b64decode(encrypted)
        iv = encrypted_iv[:size]
        encrypted_data = encrypted_iv[size:]
        cipher = Cipher(
            algorithms.AES(key_bytes),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(encrypted_data) + decryptor.finalize()
        padding_length = decrypted[-1]
        unpadded_decrypted = decrypted[:-padding_length]
        return unpadded_decrypted.decode('utf-8')
