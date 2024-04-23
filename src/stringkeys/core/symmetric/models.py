from dataclasses import dataclass

from stringkeys.utils.validation import validate_strings

@dataclass
class Options:
    key_size: int = 16
    key_gen_length: int = 32
    key_gen_iterations: int = 100_000
    key_gen_get_pw: bool = False
    key_gen_get_salt: bool = False


@dataclass
class Access:
    """TODO validate keysize"""
    key: str
    salt: str | None = None
    password: str | None = None

    def __str__(self) -> str:
        return self.key

    @staticmethod
    def to_string(symmetric_key: "str | Access") -> str:
        if not isinstance(symmetric_key, str):
            return symmetric_key.key
        return symmetric_key
