import base64
import os

from abc import ABC, abstractmethod

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class EncryptionAlgorithm(ABC):
    @abstractmethod
    def generate(self, pw: str, salt: str) -> bytes:
        pass

    @abstractmethod
    def encrypt(self, payload: str, key: bytes) -> str:
        pass

    @abstractmethod
    def decrypt(self, encrypted: str, key: bytes) -> str:
        pass


class AES256(EncryptionAlgorithm):
    def generate(self, pw: str, salt: str) -> bytes:
        salt = salt.encode('utf-8')
        backend = default_backend()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=backend
        )
        key = kdf.derive(pw.encode('utf-8'))
        return key

    def encrypt(self, payload: str, key: bytes) -> str:
        iv = os.urandom(16)  # Generiert einen zufälligen 16-Byte IV
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        payload = payload.encode('utf-8')
        padding_length = 16 - len(payload) % 16
        padded_payload = payload + bytes([padding_length] * padding_length)
        encrypted = encryptor.update(padded_payload) + encryptor.finalize()
        encrypted_iv = iv + encrypted  # IV wird dem verschlüsselten Text vorangestellt
        return base64.urlsafe_b64encode(encrypted_iv).decode('utf-8')

    def decrypt(self, encrypted: str, key: bytes) -> str:
        encrypted_iv = base64.urlsafe_b64decode(encrypted)
        iv = encrypted_iv[:16]  # Extrahiert den IV
        encrypted_data = encrypted_iv[16:]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(encrypted_data) + decryptor.finalize()
        padding_length = decrypted[-1]
        unpadded_decrypted = decrypted[:-padding_length]
        return unpadded_decrypted.decode('utf-8')


class ChaCha20(EncryptionAlgorithm):
    def generate(self, pw: str, salt: str) -> bytes:
        salt = salt.encode('utf-8')
        backend = default_backend()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=backend
        )
        return kdf.derive(pw.encode('utf-8'))

    def encrypt(self, payload: str, key: bytes) -> str:
        nonce = os.urandom(16)
        cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(payload.encode('utf-8')) + encryptor.finalize()
        encrypted_nonce = nonce + encrypted
        return base64.urlsafe_b64encode(encrypted_nonce).decode('utf-8')

    def decrypt(self, encrypted: str, key: bytes) -> str:
        encrypted_nonce = base64.urlsafe_b64decode(encrypted)
        nonce = encrypted_nonce[:16]
        encrypted_data = encrypted_nonce[16:]
        cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(encrypted_data) + decryptor.finalize()
        return decrypted.decode('utf-8')



class Key:
    def __init__(self, algorithm):
        self.key: EncryptionAlgorithm = algorithm()

    def generate(self, pw, salt):
        return self.key.generate(pw, salt)

    def encrypt(self, payload, key):
        return self.key.encrypt(payload, key)

    def decrypt(self, encrypted, key):
        return self.key.decrypt(encrypted, key)


encryption = Key(AES256)
key = encryption.generate("password", "salt")
encrypted = encryption.encrypt("Secret Message", key)
decrypted = encryption.decrypt(encrypted, key)

print("Encrypted:", encrypted)
print("Decrypted:", decrypted)
