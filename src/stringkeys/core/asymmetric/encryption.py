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
    def generate(
        self, options: Options = Options()
    ) -> tuple[str, str, Optional[str]]:
        if options.key_gen_private_key_pw is not None:
            validate_strings(options.key_gen_private_key_pw)
        return self.core.generate(options)

    @try_except(**TryExceptKeys.ENCRYPT_ERROR.kw())
    def encrypt(self, key: str, payload: str) -> str:
        validate_strings(key, payload)
        return self.core.encrypt(key, payload)

    @try_except(**TryExceptKeys.DECRYPT_ERROR.kw())
    def decrypt(self, key: str, cipher: str, pw: str | None = None) -> str:
        validate_strings(key, cipher)
        if pw is not None:
            validate_strings(pw)
        return self.core.decrypt(key, cipher, pw)

    @try_except(**TryExceptKeys.SIGN_ERROR.kw())
    def sign(self, private_key_pem: str, message: str, pw: str) -> str:
        return self.core.sign(private_key_pem, message, pw)

    @try_except(**TryExceptKeys.VALIDATE_ERROR.kw())
    @try_except(**TryExceptKeys.INVALID_SIGNATURE_ERROR.kw())
    def validate(self, public_key_pem: str, message: str, signature: str) -> bool:
        return self.core.validate(public_key_pem, message, signature)
