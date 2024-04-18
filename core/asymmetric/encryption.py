from typing import Type, Optional

from core.asymmetric.interface import AsymmetricEncryption, AbstractKeys
from settings.constants.exceptions import TryExceptKeys, ErrTxt
from utils.error_handling import try_except
from utils.validation import validate_strings


class Keys(AsymmetricEncryption, AbstractKeys):
    def __init__(self, algorithm: Type[AsymmetricEncryption]):
        self.algorithm: str = algorithm.__name__
        self.core: AsymmetricEncryption = algorithm()

    @try_except(**TryExceptKeys.GENERATE_ERROR.kw())
    def generate(
        self, pw: Optional[str] = None, get_pw: bool = False
    ) -> tuple[str, str, Optional[str]]:
        if pw is not None:
            validate_strings(pw)
        return self.core.generate(pw, get_pw)

    @try_except(**TryExceptKeys.ENCRYPT_ERROR.kw())
    def encrypt(self, payload: str, key: str) -> str:
        validate_strings(payload, key)
        return self.core.encrypt(key, payload)

    @try_except(**TryExceptKeys.DECRYPT_ERROR.kw())
    def decrypt(self, encrypted: str, key: str, pw: Optional[str] = None) -> str:
        validate_strings(encrypted, key)
        if pw:
            validate_strings(pw)
        return self.core.decrypt(key, encrypted, pw)

    def sign(self, private_key_pem: str, message: str, pw: str):
        return self.core.sign(private_key_pem, message, pw)

    def validate(self, public_key_pem: str, message: str, signature: str):
        return self.core.validate(public_key_pem, message, signature)
