import time
from dataclasses import dataclass

from core.asymmetric.encryption import Keys
from core.symmetric.encryption import Key
from core.algorithms.aes import AES256
from core.algorithms.rsa import RSA


MSG_1_HELLO_BOB = "Hello Bob"


@dataclass
class Person:
    keys_asymmetric: Keys | None = None
    key_symmetric: Key | None = None
    key_exchange: str | None = None


@dataclass
class Alice(Person):
    password: str = "Alice1995"
    public_key: str | None = None
    private_key: str | None = None
    signature: str | None = None


@dataclass
class Bob(Person):
    password: str = "Bob$123"


def run_test():
    # 1. Alice
    # ========
    print("Initializing Alice...")
    alice = Alice()
    alice.keys_asymmetric, alice.key_symmetric = Keys(RSA), Key(AES256)
    alice.private_key, alice.public_key, _ = alice.keys_asymmetric.generate(pw=alice.password)
    print(f"Alice's keys generated. Public Key: {alice.public_key[:30]}... Private Key: {alice.private_key[:30]}...")
    time.sleep(2)

    # 2. Bob
    # ======
    print("\nInitializing Bob...")
    bob = Bob()
    bob.keys_asymmetric, bob.key_symmetric = Keys(RSA), Key(AES256)
    print("Bob's asymmetric and symmetric keys are being set up.")
    exchange = bob.key_symmetric.generate(pw=bob.password, salt=alice.public_key)
    bob.key_exchange = exchange.key
    print(f"Bob generated a symmetric key: {bob.key_exchange[:30]}...")
    symmetric_key = bob.keys_asymmetric.encrypt(payload=bob.key_exchange, key=alice.public_key)
    print("Bob encrypted the symmetric key using Alice's public key.")
    time.sleep(2)

    # 3. Alice
    # ========
    print("\nAlice receives the encrypted symmetric key and decrypts it.")
    alice.key_exchange = alice.keys_asymmetric.decrypt(
        encrypted=symmetric_key, key=alice.private_key, pw=alice.password
    )
    print(f"Alice decrypted the symmetric key: {alice.key_exchange[:30]}...")
    encrypted_message = alice.key_symmetric.encrypt(payload=MSG_1_HELLO_BOB, key=alice.key_exchange)
    print("Alice encrypts the message: 'Hello Bob' and prepares to send it.")
    alice.signature = alice.keys_asymmetric.sign(private_key_pem=alice.private_key, message=MSG_1_HELLO_BOB, pw=alice.password)
    print("Alice signed the message.")
    time.sleep(2)

    # 4. Bob
    # ======
    print("\nBob receives the encrypted message and signature.")
    decrypted_message = bob.key_symmetric.decrypt(payload=encrypted_message, key=bob.key_exchange)
    is_from_alice = bob.keys_asymmetric.validate(
        public_key_pem=alice.public_key, message=decrypted_message, signature=alice.signature,
    )
    print(f"Bob decrypted the message: {decrypted_message}")

    if decrypted_message == MSG_1_HELLO_BOB:
        if is_from_alice:
            print("Message verified as from Alice: " + decrypted_message)
        else:
            print("Security error: The message is not authenticated.")
    else:
        print("Error: The message could not be decrypted correctly.")

    time.sleep(2)


if __name__ == "__main__":
    run_test()
