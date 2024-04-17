from abc import ABC, abstractmethod


class AsymmetricEncryption(ABC):
    @abstractmethod
    def generate_keys(self, pw):
        """Generates a Key-Pair(Public/Private)
        """
        pass

    @abstractmethod
    def encrypt(self, public_key, plaintext):
        """
        Encrypts plaintext using the public key.
        """
        pass

    @abstractmethod
    def decrypt(self, private_key, ciphertext):
        """
        Decrypts ciphertext using the private key.
        """
        pass

    @abstractmethod
    def sign(self, private_key, message):
        """Signs a message using the private key."""
        pass

    @abstractmethod
    def validate(self, public_key, message, signature):
        """Validates a signature using the public key."""
        pass
