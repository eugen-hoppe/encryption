from core.asymmetric.encryption import Keys
from core.symmetric.encryption import Key
from core.algorithms.aes import AES256
from core.algorithms.rsa import RSA


PRIVATE_KEY_PW = "Alice"
PASSWORD = "Bob"


def run_test():
    # Alice
    key_alice = Key(AES256)
    keys = Keys(RSA)
    private, public, _ = keys.generate(PRIVATE_KEY_PW)
    # Bob
    key_bob = Key(AES256)
    keys_bob = Keys(RSA)
    bob_exchange = key_bob.generate(pw=PASSWORD, salt=public)
    symmetric_key = keys_bob.encrypt(bob_exchange.key, public)
    # Alice
    alice_exchange_key = keys.decrypt(
        encrypted=symmetric_key, key=private, pw=PRIVATE_KEY_PW
    )
    encrypted = key_alice.encrypt("Hello Bob", alice_exchange_key)
    # Bob
    message = key_bob.decrypt(encrypted, bob_exchange.key)
    print(message)
