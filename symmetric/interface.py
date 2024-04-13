import base64

from abc import ABC, abstractmethod
from enum import Enum

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class Mode(str, Enum):
    PRODUCTION: str = "production"
    DEVELOPMENT: str = "development"


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
        get_salt: bool,
        get_pw: bool,
        iterations: int,
        key_lenght: int
    ) -> tuple[str, str | None, str | None]:
        salt_bytes = salt.encode('utf-8')
        backend = default_backend()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=key_lenght,
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
