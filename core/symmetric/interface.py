import base64

from abc import ABC, abstractmethod
from enum import Enum

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class Mode(str, Enum):  # TODO: Configuration
    PRODUCTION: str = "production"
    DEVELOPMENT: str = "development"


class AbstractKey(ABC):
    @abstractmethod
    def __init__(self, algorithm: type["SymmetricEncryption"]):
        """Initializes the Key object with a specific encryption class

        Parameters:
            algorithm (Type[SymmetricEncryption]):
                The class of the encryption algorithm to be used for
                cryptographic operations.
        Attributes:
            algorithm (str):
                The name of the encryption algorithm class.
            core (SymmetricEncryption):
                An instance of the specified encryption algorithm.
        """
        pass


class SymmetricEncryption(ABC):
    @abstractmethod
    def encrypt(self, payload: str, key: str, size: int) -> str:
        """Encrypts the given payload with the specified key and block size

        AES: Encrypts a given payload using AES-256 encryption in CBC mode.
        https://github.com/eugen-hoppe/encryption/blob/main/docs/v4.md#d17a

        ChaCha20: Encrypts a given payload using ChaCha20 encryption.
        https://github.com/eugen-hoppe/encryption/blob/main/docs/v4.md#d18a
        
        Parameters:
            payload (str): The plaintext data to encrypt.
            key (str): The cryptogsraphic key used for encryption.
            size (int): The block size in bytes for the encryption algorithm.
        Returns (str):
            The encrypted data as a string.
        """
        pass

    @abstractmethod
    def decrypt(self, encrypted: str, key: str, size: int) -> str:
        """Decrypts encrypted data with the specified key and block size

        AES: Decrypts encrypted message using AES-256 encryption in CBC mode.
        https://github.com/eugen-hoppe/encryption/blob/main/docs/v4.md#d17b
    
        ChaCha20: Encrypts a given payload using ChaCha20 encryption.
        https://github.com/eugen-hoppe/encryption/blob/main/docs/v4.md#d18b

        Parameters:
            encrypted (str): The encrypted data to decrypt.
            key (str): The cryptographic key used for decryption.
            size (int): The block size in bytes used in the encryption process.
        Returns (str):
            The decrypted data as a string.
        """
        pass

    @staticmethod
    def generate(
        pw: str,
        salt: str,
        get_salt: bool,
        get_pw: bool,
        iterations: int,
        key_lenght: int
    ) -> tuple[str, str | None, str | None]:
        """Generates a cryptographic key (password-based) via PBKDF2 function

        Parameters:
            pw (str): The password from which to derive the key.
            salt (str): The salt to use in the derivation process.
            get_salt (bool): If True, returns the salt used.
            get_pw (bool): If True, returns the original password.
            iterations (int): Iterations to use in the derivation.
            key_length (int): The desired length of the derived key in bytes.
        Returns (tuple[str, str | None, str | None]):
            A tuple containing the derived key as a base64-encoded string,
            optionally the salt, and optionally the password.
        """
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
