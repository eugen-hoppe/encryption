import base64

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
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
        encryptor = cipher.encryptor()
        payload = payload.encode('utf-8')
        padding_length = 16 - len(payload) % 16
        padded_payload = payload + bytes([padding_length] * padding_length)
        encrypted = encryptor.update(padded_payload) + encryptor.finalize()
        return base64.urlsafe_b64encode(encrypted).decode('utf-8')

    def decrypt(self, encrypted: str, key: bytes) -> str:
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted = (
            decryptor.update(base64.urlsafe_b64decode(encrypted)) + decryptor.finalize()
        )
        padding_length = decrypted[-1]
        unpadded_decrypted = decrypted[:-padding_length]
        return unpadded_decrypted.decode('utf-8')


class ChaCha20(EncryptionAlgorithm):
    def generate(self, pw: str, salt: str) -> bytes:
        pass

    def encrypt(self, payload: str, key: bytes) -> str:
        pass

    def decrypt(self, encrypted: str, key: bytes) -> str:
        pass


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
encrypted = encryption.encrypt("Hello World", key)
decrypted = encryption.decrypt(encrypted, key)

print("Encrypted:", encrypted)
print("Decrypted:", decrypted)
