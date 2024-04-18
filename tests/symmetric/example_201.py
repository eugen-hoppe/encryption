import os

from core.algorithms import aes, cc
from core.symmetric import encryption
from core.symmetric.models import Options


def test_encryption(index, enc, print_at = 5) -> None:
    encryption_ = encryption.Key(enc)
    access = encryption_.generate(
        pw=os.urandom(index).hex(),
        options=Options(key_gen_get_pw=True, key_gen_get_salt=True)
    )
    salt, pw = access.salt, access.password
    message = f"Message with {encryption_.algorithm } {os.urandom(index).hex()}"
    if index == print_at:
        message, salt, pw = "", "", ""
    encrypted = encryption_.encrypt(message, access)
    decrypted = encryption_.decrypt(encrypted, access)
    if index % print_at == 0:
        print("TEST_ID:", index, "SALT:", salt, "PW:", pw)
        print("PAYLOAD:", decrypted, "\nENCRYPTED:", encrypted, "\n")
    assert encryption_.decrypt(encrypted, access) == message


def run_test():
    for index in range(10, 100):
        test_encryption(index, aes.AES256, 9)
        test_encryption(index, cc.ChaCha20, 11)
