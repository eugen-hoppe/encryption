from dataclasses import dataclass

from stringkeys.core.asymmetric.encryption import Keys
from stringkeys.core.symmetric.encryption import Key
from stringkeys.core.algorithms.aes import AES256
from stringkeys.core.algorithms.rsa import RSA
from stringkeys.core.asymmetric.models import Options


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


def run_example():

    # 1. Alice
    # ========
    alice = Alice()
    alice.keys_asymmetric, alice.key_symmetric = Keys(RSA), Key(AES256)

    alice.private_key, alice.public_key = alice.keys_asymmetric.generate(
        Options(key_gen_private_key_pw=alice.password)
    )

    # 2. Bob
    # ======
    bob = Bob()
    bob.keys_asymmetric, bob.key_symmetric = Keys(RSA), Key(AES256)

    exchange = bob.key_symmetric.generate(
        pw=bob.password,
        salt=alice.public_key,
    )
    bob.key_exchange = exchange.key
    symmetric_key = bob.keys_asymmetric.encrypt(
        public_key=alice.public_key,
        payload=bob.key_exchange,
    )

    # 3. Alice
    # ========
    alice.key_exchange = alice.keys_asymmetric.decrypt(
        private_key=alice.private_key,
        cipher=symmetric_key,
        pw=alice.password,
    )
    encrypted_message = alice.key_symmetric.encrypt(
        payload=MSG_1_HELLO_BOB, key=alice.key_exchange
    )
    alice.signature = alice.keys_asymmetric.sign(
        private_key=alice.private_key,
        message=MSG_1_HELLO_BOB,
        pw=alice.password,
    )

    # 4. Bob
    # ======
    decrypted_message = bob.key_symmetric.decrypt(
        payload=encrypted_message, key=bob.key_exchange
    )
    is_from_alice = bob.keys_asymmetric.validate(
        public_key=alice.public_key,
        message=decrypted_message,
        signature=alice.signature,
    )

    if decrypted_message == MSG_1_HELLO_BOB:
        if is_from_alice is True:
            print(decrypted_message)
        else:
            assert False
