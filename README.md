# encryption v1.0

## Description

This project offers a flexible implementation for symmetric encryption, enabling the use of various algorithms such as AES256 and ChaCha20 for encryption operations. The framework is designed to be easily extendable to support additional algorithms.

### Dependencies

Ensure that the necessary packages are installed:

- `cryptography`
- Custom `symmetric` module that includes `encryption` and `aes` (or other algorithms).

### Setup

Import the required modules and initialize the encryption key with the desired algorithm:

```python
from symmetric.encryption import Key
from symmetric.aes import AES256
# Optional: from symmetric.chacha import ChaCha20

encryption_ = Key(AES256)
# Optional: encryption_ = Key(ChaCha20) to use ChaCha20
```

### Key Generation

Generate a key based on a password and optionally a salt:

```python
PASSWORD = "Pa$sW0rT"
SALT = "i38McOSAm94gSR18FMrQh8"

key, salt, pw = encryption_.generate(
    PASSWORD,
    SALT,
    get_salt=True,
    get_pw=True
)
print("\nKEY:", key, "\nSALT:", salt, "\nPW:", pw, "\n")
```

### Encryption and Decryption

#### With Password and Salt

Encrypt and decrypt a message using the previously generated key:

```python
message_1 = "Encrypt secret message with password and salt ..."
encrypted_with_pw = encryption_.encrypt(message_1, key)
decrypted_with_pw = encryption_.decrypt(encrypted_with_pw, key)

print(encrypted_with_pw, "\n", "|", "\n", " -> ", decrypted_with_pw, "\n")
```

#### With a Persistent Key

Directly use a persistent key for encryption and decryption:

```python
message_2 = "... or use key directly as string"
persistent_key = "m8569Q2yfE1L9NTD1PwYP3m4TkPR31q5ZtSL0cUkV5A="

encrypted_with_key = encryption_.encrypt(message_2, persistent_key)
decrypted_with_key = encryption_.decrypt(encrypted_with_key, persistent_key)

print(encrypted_with_key, "\n", "|", "\n", " -> ", decrypted_with_key, "\n")
```

### Exception and Error Handling

Ensure that potential exceptions such as `ValueError` and `TypeError` are properly handled. These may occur during key generation or the encryption/decryption processes.

### Extensibility for Other Algorithms

The modular design of the project allows for easy injection of other encryption algorithms like ChaCha20 by simply changing the imports and the initialization of the `Key` class. This enables flexible adaptation to various security requirements and scenarios.