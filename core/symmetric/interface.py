from abc import ABC, abstractmethod

from core.symmetric.models import Options, Access


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

    @abstractmethod
    def generate(pw: str, salt: str = "", options: Options = Options()) -> Access:
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
        pass



class SymmetricEncryption(ABC):
    @abstractmethod
    def encrypt(self, payload: str, key: str | Access, options: Options) -> str:
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
    def decrypt(self, encrypted: str | Access, key: str, options: Options) -> str:
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
