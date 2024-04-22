from abc import ABC, abstractmethod

from stringkeys.core.asymmetric.models import Options


class AbstractKeys(ABC):
    @abstractmethod
    def __init__(self, algorithm: type["AsymmetricEncryption"]):
        """
        Initializes the Keys object with a specific encryption class
        """
        pass


class AsymmetricEncryption(ABC):
    @abstractmethod
    def generate(self, options: Options) -> tuple[str, str]:
        """Generates a Key-Pair(Public/Private)"""
        pass

    @abstractmethod
    def encrypt(self, public_key: str, payload: str) -> str:
        """
        Encrypts plaintext using the public key.
        """
        pass

    @abstractmethod
    def decrypt(self, private_key: str, cipher: str, pw: str) -> str:
        """
        Decrypts ciphertext using the private key.
        """
        pass

    @abstractmethod
    def sign(self, private_key: str, message: str) -> str:
        """
        Signs a message using the private key.
        """
        pass

    @abstractmethod
    def validate(self, public_key: str, message: str, signature: str) -> bool:
        """
        Validates a signature using the public key.
        """
        pass
