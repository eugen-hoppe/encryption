from dataclasses import dataclass


@dataclass
class Options:
    key_size: int = 2048
    key_public_exponent: int = 65537
    key_gen_private_key_pw: str | None = None
    key_gen_get_pw: bool = False
