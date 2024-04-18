from core.symmetric.encryption import Key
from core.algorithms.aes import AES256


PASSWORT = "Pa$sW0rT"
SALT = "i38McOSAm94gSR18FMrQh8"
PAYLOAD = "Secret Message"

BR = "\n"


def run_test():

    # Init Key
    # ========
    encryption_ = Key(AES256)


    # Generate Key
    # ============
    key, salt, pw = encryption_.generate(
        PASSWORT,
        SALT,
        get_salt=True,
        get_pw=True
    )
    print(BR + "KEY:", key, BR + "SALT:", salt, BR + "PW:", pw, BR)


    # Encrypt and Decrypt with Passwort
    # =================================
    message_1 = "Encrypt secret message with paswort and salt ..."

    encrypted_with_pw = encryption_.encrypt(message_1, key)  # Encrypt
    decrypted_with_pw = encryption_.decrypt(encrypted_with_pw, key)  # Decrypt

    print(encrypted_with_pw, BR, "|", BR, " -> ", decrypted_with_pw, BR)


    # Encrypt and Decrypt with Key
    # ============================
    message_2 = "... or use key directly as string"
    persistant_key = "m8569Q2yfE1L9NTD1PwYP3m4TkPR31q5ZtSL0cUkV5A="

    encrypted_with_key = encryption_.encrypt(  # Encrypt
        message_2, persistant_key
    )
    decrypted_with_key = encryption_.decrypt(    # Decrypt
        encrypted_with_key, persistant_key
    )
    print(encrypted_with_key, BR, "|", BR, " -> ", decrypted_with_key, BR)
