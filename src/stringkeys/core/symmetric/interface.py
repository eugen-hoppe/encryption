from abc import ABC, abstractmethod

from stringkeys.core.symmetric.models import Options, Access


class AbstractKey(ABC):
    @abstractmethod
    def __init__(self, algorithm: type["SymmetricEncryption"]):
        """
        Initializes the Key object with a specific encryption class
        """
        pass

    @abstractmethod
    def generate(pw: str, salt: str = "", options: Options = Options()) -> Access:
        """
        Generates a cryptographic key (password-based) via PBKDF2 function
        """
        pass


class SymmetricEncryption(ABC):
    @abstractmethod
    def encrypt(self, payload: str, key: str | Access, options: Options) -> str:
        """
        Encrypts the given payload with the specified key and block size
        """
        pass

    @abstractmethod
    def decrypt(self, encrypted: str | Access, key: str, options: Options) -> str:
        """
        Decrypts encrypted data with the specified key and block size
        """
        pass
