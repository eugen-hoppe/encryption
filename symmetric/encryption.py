import os

from typing import Type

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
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
        try:
            self.validate_strings(pw, salt)
            if salt == "":
                salt = os.urandom(16).hex()
            return self.core.generate_key(
                pw, salt, iterations, get_salt, get_pw, key_length
            )
        except (ValueError, TypeError) as e:
            self.core.raise_value_error(ERR_GENENRATE_KEY, e, MODE)

    def encrypt(
            self,
            payload: str,
            key: str,
            size: int = DEFAULT_NONCE_OR_PADDING
        ) -> str:
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
        for arg_id, string in enumerate(args):
            if not isinstance(string, str):
                raise TypeError(
                    ERR_INVALID_STR.format(arg_id + 1, str(type(string)))
                )
