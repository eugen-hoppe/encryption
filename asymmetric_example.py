from asymmetric.encryption import Keys
from asymmetric.rsa import RSA


def main():
    rsa_keys = Keys(RSA)
    
    private_key_pem, public_key_pem, pw = rsa_keys.generate(
        pw="securepassword", get_pw=True
    )

    original_message = "Hello, World!"
    
    encrypted_message = rsa_keys.encrypt(original_message, public_key_pem)
    
    decrypted_message = rsa_keys.decrypt(encrypted_message, private_key_pem, pw)

    print("Original:", original_message)
    print("Encrypted:", encrypted_message)
    print("Decrypted:", decrypted_message)


if __name__ == "__main__":
    main()
