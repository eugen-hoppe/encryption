import base64
import os

from abc import ABC, abstractmethod
from enum import Enum
from typing import Type

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.exceptions import InvalidKey, AlreadyFinalized, UnsupportedAlgorithm


class Mode(str, Enum):
    PRODUCTION: str = "production"
    DEVELOPMENT: str = "development"


MODE = Mode.PRODUCTION
DEFAULT_NONCE_OR_PADDING = 16

class SymmetricEncryption(ABC):
    @abstractmethod
    def encrypt(self, payload: str, key: str, size: int) -> str:
        pass

    @abstractmethod
    def decrypt(self, encrypted: str, key: str, size: int) -> str:
        pass

    @staticmethod
    def generate_key(
        pw: str,
        salt: str,
        iterations: int,
        get_salt: bool,
        get_pw: bool
    ) -> tuple[str, str | None, str | None]:
        salt_bytes = salt.encode('utf-8')
        backend = default_backend()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt_bytes,
            iterations=iterations,
            backend=backend
        )
        key_bytes = kdf.derive(pw.encode('utf-8'))
        key_str = base64.urlsafe_b64encode(key_bytes).decode('utf-8')
        salt = salt if get_salt is True else None
        password = pw if get_pw is True else None
        return key_str, salt, password
    
    @staticmethod
    def raise_value_error(
        log: str,
        error: Exception,
        level: Mode = Mode.PRODUCTION
    ) -> None:
        error_message = f"{level.value}: {log}"
        if level.value == Mode.DEVELOPMENT:
            raise ValueError(f"{error_message}: {str(error)}") from error
        else:
            raise ValueError(error_message) from None


class AES256(SymmetricEncryption):
    def encrypt(self, payload: str, key: str, size: int) -> str:
        key_bytes = base64.urlsafe_b64decode(key)
        iv = os.urandom(size)
        cipher = Cipher(
            algorithms.AES(key_bytes), modes.CBC(iv), backend=default_backend()
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
    def encrypt(self, payload: str, key: str, size: int) -> str:
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
    def __init__(self, algorithm: Type[SymmetricEncryption]):
        self.algorithm: str = algorithm.__name__
        self.core: SymmetricEncryption = algorithm()

    def generate(
        self,
        pw: str,
        salt: str = "", 
        iterations: int = 100_000,
        get_salt: bool = False,
        get_pw: bool = False
    ) -> tuple[str, str | None, str | None]:
        try:
            self.validate_strings(pw, salt)
            if salt == "":
                salt = os.urandom(16).hex()
            return self.core.generate_key(pw, salt, iterations, get_salt, get_pw)
        except (ValueError, TypeError) as e:
            self.core.raise_value_error("Failed to generate key", e, MODE)

    def encrypt(
            self,
            payload: str,
            key: str,
            size: int = DEFAULT_NONCE_OR_PADDING
        ) -> str:
        try:
            self.validate_strings(payload, key)
            return self.core.encrypt(payload, key, size)
        except (InvalidKey, UnsupportedAlgorithm) as e:
            self.core.raise_value_error("Encryption failed", e, MODE)

    def decrypt(
            self,
            encrypted: str,
            key: str,
            size: int = DEFAULT_NONCE_OR_PADDING
        ) -> str:
        try:
            self.validate_strings(encrypted, key)
            return self.core.decrypt(encrypted, key, size)
        except (InvalidKey, AlreadyFinalized, UnsupportedAlgorithm, ValueError) as e:
            self.core.raise_value_error("Decryption failed", e, MODE)
    
    @staticmethod
    def validate_strings(*args) -> None:
        for arg_id, string in enumerate(args):
            if not isinstance(string, str):
                raise TypeError(
                    f"ERROR: arg_{arg_id + 1} is not a string. Type:{type(string)}"
                )


def test_encryption(
        index: int,
        enc: SymmetricEncryption,
        print_at: int = 5
    ) -> None:
    encryption = Key(enc)
    key, salt, pw = encryption.generate(
        os.urandom(index).hex(), get_salt=True, get_pw=True
    )
    message = f"Message with {encryption.algorithm } {os.urandom(index).hex()}"
    if index == print_at:
        message, salt, pw = "", "", ""
    encrypted = encryption.encrypt(message, key)
    decrypted = encryption.decrypt(encrypted, key)
    if index % print_at == 0:
        print("TEST_ID:", index, "SALT:", salt, "PW:", pw)
        print("PAYLOAD:", decrypted, "\nENCRYPTED:", encrypted, "\n")
    assert encryption.decrypt(encrypted, key) == message


for index in range(10, 50):
    test_encryption(index, AES256, 9)
    test_encryption(index, ChaCha20, 11)

