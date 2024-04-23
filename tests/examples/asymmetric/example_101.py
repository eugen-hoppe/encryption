from src.stringkeys.core.asymmetric.encryption import Keys
from src.stringkeys.core.algorithms.rsa import RSA
from src.stringkeys.core.asymmetric.models import Options


PASSWORD = "123Passw"


def run_example(password: str | None = None):
    rsa_keys = Keys(RSA)
    private_key_pem, public_key = rsa_keys.generate(
        Options(key_gen_private_key_pw=password)
    )
    print(public_key)

    original_message = "Secret Message: RSA-Encryption" * 4 + " len 128"
    print(len(original_message))
    encrypted = rsa_keys.encrypt(public_key=public_key, payload=original_message)
    decrypted = rsa_keys.decrypt(
        private_key=private_key_pem, cipher=encrypted, pw=password
    )

    print("Original:", original_message)
    print("Encrypted:", encrypted)
    print("Decrypted:", decrypted)

    signature = rsa_keys.sign(private_key_pem, original_message, password)
    is_valid = rsa_keys.validate(public_key, original_message, signature)

    print("Signature:", signature)
    print("Signature valid:", is_valid)
