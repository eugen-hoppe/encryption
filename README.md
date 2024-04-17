# encryption v1.0

## Symmetric Encryption (AES, ChaCha20)

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

---

## Assymetric Encryption (RSA)

This project provides a Python module for asymmetric encryption, including RSA encryption, that can be used to securely encrypt, decrypt, sign, and verify messages using public and private keys.

## Features
- **Key Pair Generation:** Generate public and private keys with optional password protection.
- **Encryption and Decryption:** Encrypt messages with a public key and decrypt them with the corresponding private key.
- **Signing and Verification:** Sign messages with a private key and verify signatures with the corresponding public key.
- **Error Handling:** Robust error handling using decorators to manage and log exceptions effectively.

## Project Structure
The project is organized into two main directories:
- `asymmetric/`: Contains the core logic for asymmetric encryption including an abstract base class and specific algorithm implementations.
- `utils/`: Contains utility functions and classes for error handling and exception management.

### Module Files
- `asymmetric/encryption.py`: Implements the main functionality for key management and cryptographic operations.
- `asymmetric/interface.py`: Defines an abstract base class for implementing various asymmetric encryption algorithms.
- `asymmetric/rsa.py`: Provides a concrete implementation of RSA encryption.
- `utils/error_handling.py`: Decorators and configurations for error handling.
- `utils/exceptions.py`: Custom exceptions and error messages used across the module.

## Usage

### Generating Keys
```python
from asymmetric.encryption import Keys
from asymmetric.rsa import RSA

key_manager = Keys(RSA)
private_key, public_key = key_manager.generate()
```

### Encrypting a Message
```python
encrypted_message = key_manager.encrypt(public_key, 'Hello, world!')
```

### Decrypting a Message
```python
decrypted_message = key_manager.decrypt(private_key, encrypted_message)
```

### Signing a Message
```python
signature = key_manager.sign(private_key, 'Message to sign')
```

### Verifying a Signature
```python
is_valid = key_manager.validate(public_key, 'Message to sign', signature)
print(is_valid)  # True or False
```

## Contributing
Contributions are welcome! Please feel free to submit pull requests, report bugs, and suggest features.
