from typing import Type, Optional

from asymmetric.interface import AsymmetricEncryption
from utils.exceptions import TryExceptKeys, ErrTxt
from utils.error_handling import try_except


class Keys:
    def __init__(self, algorithm: Type[AsymmetricEncryption]):
        self.algorithm: str = algorithm.__name__
        self.core: AsymmetricEncryption = algorithm()

    @try_except(**TryExceptKeys.GENERATE_ERROR.kw())
    def generate(
        self,
        pw: Optional[str] = None,
        get_pw: bool = False
    ) -> tuple[str, str, Optional[str]]:
        if pw is not None:
            self.validate_strings(pw)
        return self.core.generate_keys(pw, get_pw)

    @try_except(**TryExceptKeys.ENCRYPT_ERROR.kw())
    def encrypt(self, payload: str, key: str) -> str:
        self.validate_strings(payload, key)
        return self.core.encrypt(key, payload)

    @try_except(**TryExceptKeys.DECRYPT_ERROR.kw())
    def decrypt(
        self,
        encrypted: str,
        key: str,
        pw: Optional[str] = None
    ) -> str:
        self.validate_strings(encrypted, key)
        if pw:
            self.validate_strings(pw)
        return self.core.decrypt(key, encrypted, pw)

    def sign(self, private_key_pem: str, message: str, pw: str):
        return self.core.sign(private_key_pem, message, pw)
    
    def validate(self, public_key_pem: str, message: str, signature: str):
        return self.core.validate(public_key_pem, message, signature)

    @staticmethod
    def validate_strings(*args) -> None:
        for arg_id, string in enumerate(args):
            if not isinstance(string, str):
                raise TypeError(
                    ErrTxt.ERR_INVALID_STR.fmt(arg_id + 1, str(type(string)))
                )
