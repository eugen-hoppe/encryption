# symmetric

## symmetric.aes

### symmetric.aes.AES256

#### symmetric.aes.AES256.encrypt

```python
"""Encrypts a given payload using AES-256 encryption in CBC mode.

Parameters:
    payload (str):
        The plaintext string to encrypt.
    key (str):
        The base64-url encoded string representing the secret key.
        It must be a 256-bit key encoded in base64.
    size (int):
        The block size in bytes. Typically, this should be 16 bytes.
Returns (str):
    The base64-url encoded string of the encrypted data, which includes
    the initialization vector (IV) prepended to the ciphertext.
"""

```

#### symmetric.aes.AES256.decrypt

```python
"""Decrypts encrypted message using AES-256 encryption in CBC mode.

Parameters:
    encrypted (str):
        The base64-url encoded string of the encrypted data,
        which includes the initialization vector (IV) followed
        by the ciphertext.
    key (str):
        The base64-url encoded string representing the secret key.
        It must be a 256-bit key encoded in base64.
    size (int):
        The block size in bytes used during encryption.
        Typically, this should be 16 bytes for AES.
Returns:
    str: The decrypted plaintext string.
"""

```