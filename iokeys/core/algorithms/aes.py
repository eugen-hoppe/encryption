import base64
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from iokeys.core.symmetric.interface import SymmetricEncryption
from iokeys.core.symmetric.models import Options


class AES256(SymmetricEncryption):
    def encrypt(self, payload: str, key: str, options: Options) -> str:
        """
        https://github.com/eugen-hoppe/encryption/blob/main/docs/core.md#40419c
        """
        key_bytes = base64.urlsafe_b64decode(key)
        iv = os.urandom(options.key_size)
        cipher = Cipher(
            algorithms.AES(key_bytes), modes.CBC(iv), backend=default_backend()
        )
        encryptor = cipher.encryptor()
        payload_bytes = payload.encode("utf-8")
        padding_length = options.key_size - len(payload_bytes) % options.key_size
        padded_payload = payload_bytes + bytes([padding_length] * padding_length)
        encrypted = encryptor.update(padded_payload) + encryptor.finalize()
        encrypted_iv = iv + encrypted
        return base64.urlsafe_b64encode(encrypted_iv).decode("utf-8")

    def decrypt(self, encrypted: str, key: str, options: Options) -> str:
        key_bytes = base64.urlsafe_b64decode(key)
        encrypted_iv = base64.urlsafe_b64decode(encrypted)
        iv = encrypted_iv[: options.key_size]
        encrypted_data = encrypted_iv[options.key_size :]
        cipher = Cipher(
            algorithms.AES(key_bytes), modes.CBC(iv), backend=default_backend()
        )
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(encrypted_data) + decryptor.finalize()
        padding_length = decrypted[-1]
        unpadded_decrypted = decrypted[:-padding_length]
        return unpadded_decrypted.decode("utf-8")
