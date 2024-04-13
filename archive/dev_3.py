import base64
import os

from abc import ABC, abstractmethod

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class SymmetricEncryption(ABC):
    @abstractmethod
    def encrypt(self, payload: str, key: str) -> str:
        pass

    @abstractmethod
    def decrypt(self, encrypted: str, key: str) -> str:
        pass

    @staticmethod
    def generate_key(pw: str, salt: str) -> str:
        salt_bytes = salt.encode('utf-8')
        backend = default_backend()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt_bytes,
            iterations=100000,
            backend=backend
        )
        key_bytes = kdf.derive(pw.encode('utf-8'))
        return base64.urlsafe_b64encode(key_bytes).decode('utf-8')


class AES256(SymmetricEncryption):
    def encrypt(self, payload: str, key: str, size: int = 16) -> str:
        key_bytes = base64.urlsafe_b64decode(key)
        iv = os.urandom(size)
        cipher = Cipher(
            algorithms.AES(key_bytes), modes.CBC(iv), backend=default_backend()
        )
        encryptor = cipher.encryptor()
        payload_bytes = payload.encode('utf-8')
        padding_length = 16 - len(payload_bytes) % size
        padded_payload = payload_bytes + bytes([padding_length] * padding_length)
        encrypted = encryptor.update(padded_payload) + encryptor.finalize()
        encrypted_iv = iv + encrypted
        return base64.urlsafe_b64encode(encrypted_iv).decode('utf-8')

    def decrypt(self, encrypted: str, key: str, size: int = 16) -> str:
        key_bytes = base64.urlsafe_b64decode(key)
        encrypted_iv = base64.urlsafe_b64decode(encrypted)
        iv = encrypted_iv[:size]
        encrypted_data = encrypted_iv[size:]
        cipher = Cipher(
            algorithms.AES(key_bytes), modes.CBC(iv), backend=default_backend()
        )
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(encrypted_data) + decryptor.finalize()
        padding_length = decrypted[-1]
        unpadded_decrypted = decrypted[:-padding_length]
        return unpadded_decrypted.decode('utf-8')


class ChaCha20(SymmetricEncryption):
    def encrypt(self, payload: str, key: str, size: int = 16) -> str:
        key_bytes = base64.urlsafe_b64decode(key)
        nonce = os.urandom(size)
        cipher = Cipher(
            algorithms.ChaCha20(key_bytes, nonce),
            mode=None,
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(payload.encode('utf-8')) + encryptor.finalize()
        encrypted_nonce = nonce + encrypted
        return base64.urlsafe_b64encode(encrypted_nonce).decode('utf-8')

    def decrypt(self, encrypted: str, key: str, size: int = 16) -> str:
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


class Key:
    def __init__(self, algorithm):
        self.algorithm: str = algorithm.__name__
        self.core: SymmetricEncryption = algorithm()

    def generate(self, pw: str, salt: str = ""):
        if salt == "":
            salt = os.urandom(16).hex()
        return self.core.generate_key(pw, salt)

    def encrypt(self, payload: str, key: str):
        return self.core.encrypt(payload, key)

    def decrypt(self, encrypted: str, key: str):
        return self.core.decrypt(encrypted, key)


# Beispiel für die Verwendung der überarbeiteten Klassen
encryption = Key(AES256)
key = encryption.generate("password")
encrypted = encryption.encrypt("Secret Message", key)
decrypted = encryption.decrypt(encrypted, key)

print("Encrypted:", encrypted)
print("Decrypted:", decrypted)

encryption = Key(ChaCha20)
key = encryption.generate("password")
encrypted = encryption.encrypt("Secret Message", key)
decrypted = encryption.decrypt(encrypted, key)

print("Encrypted:", encrypted)
print("Decrypted:", decrypted)
