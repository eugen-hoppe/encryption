import time
from dataclasses import dataclass

from stringkeys.core.asymmetric.encryption import Keys
from stringkeys.core.symmetric.encryption import Key
from stringkeys.core.algorithms.aes import AES256
from stringkeys.core.algorithms.rsa import RSA


BR = "\n"
MSG_1_HELLO_BOB = "Hello Bob"
DELAY_SHORT = 1 # * 0.05


DELAY_LONG = 2 * DELAY_SHORT


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


def print_delayed(text, delay=DELAY_SHORT, br = False):
    print(text)
    if br:
        print()
    time.sleep(delay)


def run_test():
    print(BR * 20)
    print(" ILLUSTRATION OF HYBRID ENCRYPTION", BR, "* " * 50)
    print(BR * 20)
    # 1. Alice: Key Generation
    print_delayed(BR + "=" * 80 + " [ STEP 1 ]", delay=DELAY_LONG)
    print_delayed(BR + "Initializing Alice...")
    alice = Alice()
    alice.keys_asymmetric = Keys(RSA)
    alice.key_symmetric = Key(AES256)
    alice.private_key, alice.public_key, _ = alice.keys_asymmetric.generate(
        alice.password
    )
    print_delayed(f"  Alice's generates ASYMMTRIC KEY_PAIR:")
    print_delayed(f"    - PUBLIC_KEY: {alice.public_key[:50]}...".replace(BR, ""))
    print_delayed(f"    - PRIVATE_KEY: {alice.private_key[:50]}...".replace(BR, ""))

    # 2. Bob: Key Generation and Encryption
    print_delayed(BR + "=" * 80 + " [ STEP 2 ]", delay=DELAY_LONG)
    print_delayed(BR + "Initializing Bob...")
    bob = Bob()
    bob.keys_asymmetric = Keys(RSA)
    bob.key_symmetric = Key(AES256)
    print_delayed(
        "  Bob's asymmetric and symmetric keys are being set up..."
    )
    bob.key_exchange = bob.key_symmetric.generate(bob.password, alice.public_key)
    print_delayed(
        f"  Bob generated a SYMMETRIC_KEY: {bob.key_exchange.key[:30]}..."
    )
    symmetric_key = bob.keys_asymmetric.encrypt(
        str(bob.key_exchange), alice.public_key
    )
    print_delayed(
        "  Bob encrypts the SYMMETRIC_KEY using Alice's PUBLIC_KEY."
    )

    print(BR + BR + "Bob sends ->" + BR)
    print_delayed("  ENCRYPTED with PUBLIC_KEY(Alice) his SYMMETRIC_KEY")
    print("       |" + BR + "         -> to Alice" + BR)

    # 3. Alice: Decrypting Key and Encrypting Message
    print_delayed(BR + "=" * 80 + " [ STEP 3 ]", delay=DELAY_LONG)
    print_delayed(
        BR + "Alice receives the ASYMMETRICALY ENCRYPTED SYMMETRIC_KEY"
        + " - ( HANDSHAKE )"
    )
    alice.key_exchange = alice.keys_asymmetric.decrypt(
        symmetric_key, alice.private_key, alice.password
    )
    print_delayed(
        f"  Alice decrypts with PRIVATE_KEY the SYMMETRIC_KEY:" + BR
        + f"       {alice.key_exchange[:30]}..."
    )
    encrypted_message = alice.key_symmetric.encrypt('Hello Bob', alice.key_exchange)
    print_delayed(
        "  Alice encrypts the MESSAGE 'Hello Bob' and prepares to send it..."
    )
    alice.signature = alice.keys_asymmetric.sign(
        alice.private_key, 'Hello Bob', alice.password)
    print_delayed("  Alice SIGN the MESSAGE.")

    print(BR + BR + "Alice sends ->" + BR)
    print_delayed("  ENCRYPTED MESSAGE (+SIGNUTURE) with SYMMETRIC_KEY(Bob)")
    print("       |" + BR + "         -> to Bob" + BR)


    # 4. Bob: Decrypting Message and Verifying Signature
    print_delayed(BR + "=" * 80 + " [ STEP 4 ]", delay=DELAY_LONG)
    print_delayed(
        BR + "Bob receives the ENCRYPTED MESSAGE and SIGNATURE..." + BR
    )
    decrypted_message = bob.key_symmetric.decrypt(
        encrypted_message, bob.key_exchange
    )
    print_delayed(
        f"  Bob READ the DECRYPTED MESSAGE: "
        + BR + f"     {decrypted_message}"
    )
    is_from_alice = bob.keys_asymmetric.validate(
        alice.public_key, decrypted_message, alice.signature
    )
    print()
    print_delayed(
        f"  Bob checks SIGNATURE of the MESSAGE with PUBLIC_KEY(Alice):" + BR
        + f"       = signature(" + alice.signature[:10] + ") -> OK"
    )

    if is_from_alice:
        print_delayed(
            BR + "  MESSAGE IS_VALID as from Alice: " + decrypted_message + BR
        )
    else:
        print_delayed("  Security ERROR: The message is not authenticated.")


if __name__ == "__main__":
    run_test()
