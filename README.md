# encryption
Encryption Utils v1.0


## Symmetric Encryption Module Usage

Below are detailed example on how to generate a cryptographic key,
and how to encrypt and decrypt messages.

### Dependencies

Ensure you have the necessary custom modules and dependencies installed,
including the cryptography package and any specific modules
(`symmetric`, `encryption`, `aes`) your project uses.

### Initialization

Start by creating an instance of the `Key` class with `AES256` as the
encryption algorithm:

```python
from symmetric import encryption, aes

encryption_ = encryption.Key(aes.AES256)
```

### Key Generation

Generate a cryptographic key using a password and a salt. 
You can optionally retrieve the salt and password used:

```python
PASSWORT = "Pa$sW0rT"
SALT = "i38McOSAm94gSR18FMrQh8"

key, salt, pw = encryption_.generate(
    PASSWORT,
    SALT,
    get_salt=True,
    get_pw=True
)
print("\nKEY:", key, "\nSALT:", salt, "\nPW:", pw, "\n")
```

### Encrypt and Decrypt Messages

#### Using Password and Salt

Encrypt and decrypt a message using the generated key:

```python
message_1 = "Encrypt secret message with paswort and salt ..."
encrypted_with_pw = encryption_.encrypt(message_1, key)
decrypted_with_pw = encryption_.decrypt(encrypted_with_pw, key)

print(encrypted_with_pw, "\n", "|", "\n", " -> ", decrypted_with_pw, "\n")
```

#### Using a Persistent Key

Directly use a pre-existing key to encrypt and decrypt a message:

```python
message_2 = "... or use key directly as string"
persistent_key = "m8569Q2yfE1L9NTD1PwYP3m4TkPR31q5ZtSL0cUkV5A="

encrypted_with_key = encryption_.encrypt(message_2, persistent_key)
decrypted_with_key = encryption_.decrypt(encrypted_with_key, persistent_key)
print(encrypted_with_key, "\n", "|", "\n", " -> ", decrypted_with_key, "\n")
```

### Handling Exceptions

Ensure to handle potential exceptions such as `ValueError` and `TypeError` that
may occur during key generation, encryption, or decryption processes.
