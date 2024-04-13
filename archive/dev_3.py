import base64
import os

from abc import ABC, abstractmethod

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class SymetricEncryption(ABC):
    @abstractmethod
    def encrypt(self, payload: str, key: bytes) -> str:
        pass

    @abstractmethod
    def decrypt(self, encrypted: str, key: bytes) -> str:
        pass

    @staticmethod
    def generate_key(pw: str, salt: str) -> bytes:
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


class AES256(SymetricEncryption):
    def encrypt(self, payload: str, key: bytes) -> str:
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        payload = payload.encode('utf-8')
        padding_length = 16 - len(payload) % 16
        padded_payload = payload + bytes([padding_length] * padding_length)
        encrypted = encryptor.update(padded_payload) + encryptor.finalize()
        encrypted_iv = iv + encrypted
        return base64.urlsafe_b64encode(encrypted_iv).decode('utf-8')

    def decrypt(self, encrypted: str, key: bytes) -> str:
        encrypted_iv = base64.urlsafe_b64decode(encrypted)
        iv = encrypted_iv[:16]
        encrypted_data = encrypted_iv[16:]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(encrypted_data) + decryptor.finalize()
        padding_length = decrypted[-1]
        unpadded_decrypted = decrypted[:-padding_length]
        return unpadded_decrypted.decode('utf-8')


class ChaCha20(SymetricEncryption):
    def encrypt(self, payload: str, key: bytes) -> str:
        nonce = os.urandom(16)
        cipher = Cipher(
            algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend()
        )
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(payload.encode('utf-8')) + encryptor.finalize()
        encrypted_nonce = nonce + encrypted
        return base64.urlsafe_b64encode(encrypted_nonce).decode('utf-8')

    def decrypt(self, encrypted: str, key: bytes) -> str:
        encrypted_nonce = base64.urlsafe_b64decode(encrypted)
        nonce = encrypted_nonce[:16]
        encrypted_data = encrypted_nonce[16:]
        cipher = Cipher(
            algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend()
        )
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(encrypted_data) + decryptor.finalize()
        return decrypted.decode('utf-8')



class Key:
    def __init__(self, algorithm):
        self.alorithm: str = algorithm.__name__
        self.core: SymetricEncryption = algorithm()

    def generate(self, pw: str, salt: str = ""):
        salt = self.alorithm if salt == "" else salt
        return SymetricEncryption.generate_key(pw, salt)

    def encrypt(self, payload: str, key: str):
        return self.core.encrypt(payload, key)

    def decrypt(self, encrypted: str, key: str):
        return self.core.decrypt(encrypted, key)


encryption = Key(AES256)
key = encryption.generate("password")
encrypted = encryption.encrypt("Secret Message", key)
decrypted = encryption.decrypt(encrypted, key)

print("Encrypted:", encrypted)
print("Decrypted:", decrypted)
