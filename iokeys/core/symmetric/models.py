from dataclasses import dataclass


@dataclass
class Options:
    key_size: int = 16
    key_gen_length: int = 32
    key_gen_iterations: int = 100_000
    key_gen_get_pw: bool = False
    key_gen_get_salt: bool = False


@dataclass
class Access:
    key: str
    salt: str | None = None
    password: str | None = None

    def __str__(self) -> str:
        return self.key
