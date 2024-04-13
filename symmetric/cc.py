import base64
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

from symmetric.interface import SymmetricEncryption


class ChaCha20(SymmetricEncryption):
    def encrypt(self, payload: str, key: str, size: int) -> str:
        """Encrypts a given payload using ChaCha20 encryption.

        Parameters:
            payload (str):
                The plaintext string to encrypt.
            key (str):
                The base64-url encoded string representing the secret key.
                The key must be 256 bits long (32 bytes) when decoded.
            size (int):
                The nonce size in bytes.
        Returns (str):
            A base64-url encoded string of the encrypted data, which includes
            the nonce prepended to the ciphertext.
        """
        key_bytes = base64.urlsafe_b64decode(key)
        nonce = os.urandom(size)
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

    def decrypt(self, encrypted: str, key: str, size: int) -> str:
        """Decrypts a encrypted message using ChaCha20 encryption.

        Parameters:
            encrypted (str):
                The base64-url encoded string of the encrypted data,
                which includes the nonce followed by the ciphertext.
            key (str):
                The base64-url encoded string representing the secret key.
                The key must be 256 bits long (32 bytes) when decoded.
            size (int):
                The nonce size in bytes used during encryption.
        Returns (str):
            The decrypted plaintext string.
        """
        key_bytes = base64.urlsafe_b64decode(key)
        encrypted_nonce = base64.urlsafe_b64decode(encrypted)
        nonce = encrypted_nonce[:size]
        encrypted_data = encrypted_nonce[size:]
        cipher = Cipher(
            algorithms.ChaCha20(key_bytes, nonce),
            mode=None,
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(encrypted_data) + decryptor.finalize()
        return decrypted.decode('utf-8')
