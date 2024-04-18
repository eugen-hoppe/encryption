import os

from typing import Type

from cryptography.exceptions import (
    InvalidKey,
    AlreadyFinalized,
    UnsupportedAlgorithm
)

from symmetric.interface import SymmetricEncryption, GenericKey, Mode
from utils.exceptions import ErrTxt


MODE = Mode.PRODUCTION

DEFAULT_NONCE_OR_PADDING = 16
DEFAULT_KEY_GENERATION_LENGTH = 32
DEFAULT_KEY_GENERATION_ITERATIONS = 100_000

ERR_GENENRATE_KEY = "Key generation failed"
ERR_ENCRYPTION = "Encryption failed"
ERR_DECRYPTION = "Decryption failed"
ERR_INVALID_STR = "ERROR: arg_{0} is not a string. Type:{1}"


class Key(SymmetricEncryption, GenericKey):
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
            ErrTxt.validate_strings(pw, salt)
            if salt == "":
                salt = os.urandom(16).hex()
            return self.core.generate(
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
        try:
            ErrTxt.validate_strings(payload, key)
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
            ErrTxt.validate_strings(encrypted, key)
            return self.core.decrypt(encrypted, key, size)
        except (InvalidKey,
                AlreadyFinalized,
                UnsupportedAlgorithm,
                ValueError) as err:
            self.core.raise_value_error(ERR_DECRYPTION, err, MODE)
