import os

from typing import Type

from cryptography.exceptions import (
    InvalidKey,
    AlreadyFinalized,
    UnsupportedAlgorithm
)

from symmetric.interface import SymmetricEncryption, Mode


MODE = Mode.PRODUCTION

DEFAULT_NONCE_OR_PADDING = 16
DEFAULT_KEY_GENERATION_LENGTH = 32
DEFAULT_KEY_GENERATION_ITERATIONS = 100_000

ERR_GENENRATE_KEY = "Key generation failed"
ERR_ENCRYPTION = "Encryption failed"
ERR_DECRYPTION = "Decryption failed"
ERR_INVALID_STR = "ERROR: arg_{0} is not a string. Type:{1}"


class Key:
    def __init__(self, algorithm: Type[SymmetricEncryption]):
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
        self.algorithm: str = algorithm.__name__
        self.core: SymmetricEncryption = algorithm()

    def generate(
        self,
        pw: str,
        salt: str = "", 
        get_salt: bool = False,
        get_pw: bool = False,
        iterations: int = DEFAULT_KEY_GENERATION_ITERATIONS,
        key_length: bool = DEFAULT_KEY_GENERATION_LENGTH
    ) -> tuple[str, str | None, str | None]:
        """Generates a cryptographic key using the specified password and salt

        Parameters:
            pw (str):
                The password from which to derive the key.
            salt (str):
                The salt to use in the key derivation process.
                If empty, a random salt is generated.
            get_salt (bool):
                If True, returns the salt used in the key derivation.
            get_pw (bool):
                If True, returns the original password used.
            iterations (int):
                The number of iterations to use in the PBKDF2 algorithm.
            key_length (int):
                The desired length of the derived key in bytes.
        Returns (tuple[str, str | None, str | None]):
            A tuple containing the base64-encoded key,
            optionally the salt, and optionally the password.
        Raises:
            ValueError: If the key generation process fails.
        """
        try:
            self.validate_strings(pw, salt)
            if salt == "":
                salt = os.urandom(16).hex()
            return self.core.generate_key(
                pw, salt, get_salt, get_pw, iterations, key_length
            )
        except (ValueError, TypeError) as e:
            self.core.raise_value_error(ERR_GENENRATE_KEY, e, MODE)

    def encrypt(
            self,
            payload: str,
            key: str,
            size: int = DEFAULT_NONCE_OR_PADDING
        ) -> str:
        """Encrypts the given payload using the specified cryptographic key

        Parameters:
            payload (str): The plaintext data to encrypt.
            key (str): The cryptographic key used for encryption.
            size (int): The nonce or padding size in bytes.
        Returns:
            str: The encrypted data as a string.
        Raises:
            ValueError: If the encryption process fails due to an invalid key,
            unsupported algorithm, etc.
        """
        try:
            self.validate_strings(payload, key)
            return self.core.encrypt(payload, key, size)
        except (InvalidKey, UnsupportedAlgorithm) as err:
            self.core.raise_value_error(ERR_ENCRYPTION, err, MODE)

    def decrypt(
            self,
            encrypted: str,
            key: str,
            size: int = DEFAULT_NONCE_OR_PADDING
        ) -> str:
        """Decrypts encrypted data using the specified cryptographic key

        Parameters:
            encrypted (str): The encrypted data to decrypt.
            key (str): The cryptographic key used for decryption.
            size (int): The nonce or padding size in bytes used.
        Returns:
            str: The decrypted data as a string.
        Raises (ValueError):
            If the decryption process fails due to an invalid key,
            algorithm unsupported, etc.
        """
        try:
            self.validate_strings(encrypted, key)
            return self.core.decrypt(encrypted, key, size)
        except (InvalidKey,
                AlreadyFinalized,
                UnsupportedAlgorithm,
                ValueError) as err:
            self.core.raise_value_error(ERR_DECRYPTION, err, MODE)
    
    @staticmethod
    def validate_strings(*args) -> None:
        """Validates that each argument provided is a string.

        Parameters:
            *args: Variable length argument list intended to be strings.
        Raises (TypeError):
            If any argument is not a string, indicating the argument number
            and its incorrect type.
        """
        for arg_id, string in enumerate(args):
            if not isinstance(string, str):
                raise TypeError(
                    ERR_INVALID_STR.format(arg_id + 1, str(type(string)))
                )
