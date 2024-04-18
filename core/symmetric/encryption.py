import os

from typing import Type

from core.symmetric.interface import SymmetricEncryption, AbstractKey, Mode
from utils.exceptions import ErrTxt, TryExceptKeys
from utils.error_handling import try_except


MODE = Mode.PRODUCTION

DEFAULT_NONCE_OR_PADDING = 16
DEFAULT_KEY_GENERATION_LENGTH = 32
DEFAULT_KEY_GENERATION_ITERATIONS = 100_000


class Key(SymmetricEncryption, AbstractKey):
    def __init__(self, algorithm: Type[SymmetricEncryption]):
        self.algorithm: str = algorithm.__name__
        self.core: SymmetricEncryption = algorithm()

    @try_except(**TryExceptKeys.GENERATE_ERROR.kw())
    def generate(
        self,
        pw: str,
        salt: str = "", 
        get_salt: bool = False,
        get_pw: bool = False,
        iterations: int = DEFAULT_KEY_GENERATION_ITERATIONS,
        key_length: bool = DEFAULT_KEY_GENERATION_LENGTH
    ) -> tuple[str, str | None, str | None]:
        ErrTxt.validate_strings(pw, salt)
        if salt == "":
            salt = os.urandom(16).hex()
        return self.core.generate(
            pw, salt, get_salt, get_pw, iterations, key_length
        )

    @try_except(**TryExceptKeys.ENCRYPT_ERROR.kw())
    def encrypt(
            self,
            payload: str,
            key: str,
            size: int = DEFAULT_NONCE_OR_PADDING
        ) -> str:
        ErrTxt.validate_strings(payload, key)
        return self.core.encrypt(payload, key, size)


    @try_except(**TryExceptKeys.DECRYPT_ERROR.kw())
    def decrypt(
            self,
            encrypted: str,
            key: str,
            size: int = DEFAULT_NONCE_OR_PADDING
        ) -> str:
        ErrTxt.validate_strings(encrypted, key)
        return self.core.decrypt(encrypted, key, size)
