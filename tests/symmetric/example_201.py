import os

from core.algorithms import aes, cc
from core.symmetric import encryption


def test_encryption(index, enc, print_at = 5) -> None:
    encryption_ = encryption.Key(enc)
    key, salt, pw = encryption_.generate(
        os.urandom(index).hex(), get_salt=True, get_pw=True
    )
    message = f"Message with {encryption_.algorithm } {os.urandom(index).hex()}"
    if index == print_at:
        message, salt, pw = "", "", ""
    encrypted = encryption_.encrypt(message, key)
    decrypted = encryption_.decrypt(encrypted, key)
    if index % print_at == 0:
        print("TEST_ID:", index, "SALT:", salt, "PW:", pw)
        print("PAYLOAD:", decrypted, "\nENCRYPTED:", encrypted, "\n")
    assert encryption_.decrypt(encrypted, key) == message


def run_test():
    for index in range(10, 100):
        test_encryption(index, aes.AES256, 9)
        test_encryption(index, cc.ChaCha20, 11)
