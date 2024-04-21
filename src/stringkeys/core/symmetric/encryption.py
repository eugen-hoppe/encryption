import base64
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from stringkeys.core.symmetric.interface import SymmetricEncryption, AbstractKey
from stringkeys.core.symmetric.models import Options, Access
from stringkeys.settings.constants.exceptions import TryExceptKeys
from stringkeys.utils.error_handling import try_except
from stringkeys.utils.validation import validate_strings


class Key(SymmetricEncryption, AbstractKey):
    def __init__(self, algorithm: type[SymmetricEncryption]):
        self.algorithm: str = algorithm.__name__
        self.core: SymmetricEncryption = algorithm()

    @try_except(**TryExceptKeys.ENCRYPT_ERROR.kw())
    def encrypt(
        self, payload: str, key: str | Access, options: Options = Options()
    ) -> str:
        validate_strings(payload, str(key))
        return self.core.encrypt(payload, str(key), options=options)

    @try_except(**TryExceptKeys.DECRYPT_ERROR.kw())
    def decrypt(
        self, payload: str, key: str | Access, options: Options = Options()
    ) -> str:
        validate_strings(payload, str(key))
        return self.core.decrypt(payload, str(key), options)

    @try_except(**TryExceptKeys.GENERATE_ERROR.kw())
    def generate(self, pw: str, salt: str = "", options: Options = Options()) -> Access:
        if salt == "":
            salt = os.urandom(16).hex()
        salt_bytes = salt.encode("utf-8")
        backend = default_backend()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=options.key_gen_length,
            salt=salt_bytes,
            iterations=options.key_gen_iterations,
            backend=backend,
        )
        key_bytes = kdf.derive(pw.encode("utf-8"))
        access = Access(
            key=base64.urlsafe_b64encode(key_bytes).decode("utf-8"),
            salt=salt if options.key_gen_get_salt is True else None,
            password=pw if options.key_gen_get_pw is True else None,
        )
        return access
