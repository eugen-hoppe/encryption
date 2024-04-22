from typing import Type, Optional

from stringkeys.core.asymmetric.interface import AsymmetricEncryption, AbstractKeys
from stringkeys.settings.constants.exceptions import TryExceptKeys
from stringkeys.utils.error_handling import try_except
from stringkeys.utils.validation import validate_strings
from stringkeys.core.asymmetric.models import Options


class Keys(AsymmetricEncryption, AbstractKeys):
    def __init__(self, algorithm: Type[AsymmetricEncryption]):
        self.algorithm: str = algorithm.__name__
        self.core: AsymmetricEncryption = algorithm()

    @try_except(**TryExceptKeys.GENERATE_ERROR.kw())
    def generate(self, options: Options = Options()) -> tuple[str, str]:
        if options.key_gen_private_key_pw is not None:
            validate_strings(options.key_gen_private_key_pw)
        return self.core.generate(options)

    @try_except(**TryExceptKeys.ENCRYPT_ERROR.kw())
    def encrypt(self, public_key: str, payload: str) -> str:
        validate_strings(public_key, payload)
        return self.core.encrypt(public_key, payload)

    @try_except(**TryExceptKeys.DECRYPT_ERROR.kw())
    def decrypt(self, private_key: str, cipher: str, pw: str | None = None) -> str:
        validate_strings(private_key, cipher)
        if pw is not None:
            validate_strings(pw)
        return self.core.decrypt(private_key, cipher, pw)

    @try_except(**TryExceptKeys.SIGN_ERROR.kw())
    def sign(self, private_key: str, message: str, pw: str) -> str:
        return self.core.sign(private_key, message, pw)

    @try_except(**TryExceptKeys.VALIDATE_ERROR.kw())
    @try_except(**TryExceptKeys.INVALID_SIGNATURE_ERROR.kw())
    def validate(self, public_key: str, message: str, signature: str) -> bool:
        return self.core.validate(public_key, message, signature)
