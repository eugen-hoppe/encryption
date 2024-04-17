from asymmetric.encryption import Keys
from asymmetric.rsa import RSA


PASSWORD = "123Passw"


def main(password: str | None = None):
    rsa_keys = Keys(RSA)
    
    private_key_pem, public_key_pem, pw = rsa_keys.generate(
        password, get_pw=True
    )
    print(pw)

    original_message = "Secret Message: RSA-Encryption"
    encrypted = rsa_keys.encrypt(original_message, public_key_pem)
    decrypted = rsa_keys.decrypt(encrypted, private_key_pem, pw)

    print("Original:", original_message)
    print("Encrypted:", encrypted)
    print("Decrypted:", decrypted)


if __name__ == "__main__":
    PASSWORD = "123Passw"

    main(PASSWORD)
