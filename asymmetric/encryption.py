from typing import Type
from asymmetric.interface import AsymmetricEncryption


ERR_INVALID_STR = "ERROR: arg_{0} is not a string. Type:{1}"


class Keys:
    def __init__(self, algorithm: Type[AsymmetricEncryption]):
        self.algorithm: str = algorithm.__name__
        self.core: AsymmetricEncryption = algorithm()

    def generate(self, pw: str, get_pw: bool = False) -> tuple[str, str, str | None]:
        self.validate_strings(pw)
        return self.core.generate_keys(pw, get_pw)

    def encrypt(self, payload: str, key: str) -> str:
        self.validate_strings(payload, key)
        return self.core.encrypt(key, payload)

    def decrypt(self, encrypted: str, key: str, pw: str) -> str:
        self.validate_strings(encrypted, key, pw)
        return self.core.decrypt(key, encrypted, pw)

    @staticmethod
    def validate_strings(*args) -> None:
        for arg_id, string in enumerate(args):
            if not isinstance(string, str):
                raise TypeError(ERR_INVALID_STR.format(arg_id + 1, str(type(string))))
