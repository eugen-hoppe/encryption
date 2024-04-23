# Docstrings

### Module: `aes.py`

```python
class AES256(SymmetricEncryption):
    def encrypt(self, payload: str, key: str, options: Options) -> str:
        """
        Encrypts the provided plaintext payload using AES-256 encryption algorithm.
        The payload is padded according to PKCS#7 before encryption to ensure it matches
        the block size. IV is randomly generated and prepended to the encrypted data.

        Args:
            payload (str): Plaintext message to be encrypted.
            key (str): The encryption key (base64 encoded).
            options (Options): Configuration options including key size.

        Returns:
            str: The base64 encoded IV and encrypted data as a single string.
        """
    
    def decrypt(self, encrypted: str, key: str, options: Options) -> str:
        """
        Decrypts a previously encrypted message using AES-256. The IV is extracted
        from the beginning of the encrypted message and used along with the key
        for decryption. Padding is removed after decryption.

        Args:
            encrypted (str): Base64 encoded string containing the IV and the encrypted data.
            key (str): The decryption key (base64 encoded).
            options (Options): Configuration options including key size.

        Returns:
            str: The decrypted plaintext message.
        """
```

### Module: `cc.py`

```python
class ChaCha20(SymmetricEncryption):
    def encrypt(self, payload: str, key: str, options: Options) -> str:
        """
        Encrypts the provided plaintext using the ChaCha20 encryption algorithm.
        A nonce is generated randomly for each encryption operation and is prepended
        to the result.

        Args:
            payload (str): Plaintext message to be encrypted.
            key (str): Encryption key (base64 encoded).
            options (Options): Configuration options including key size (used for nonce).

        Returns:
            str: Base64 encoded string containing the nonce and the encrypted data.
        """

    def decrypt(self, encrypted: str, key: str, options: Options) -> str:
        """
        Decrypts a previously encrypted message using ChaCha20. The nonce is extracted
        from the beginning of the encrypted message and used along with the key
        for decryption.

        Args:
            encrypted (str): Base64 encoded string containing the nonce and the encrypted data.
            key (str): The decryption key (base64 encoded).
            options (Options): Configuration options including key size (used for nonce).

        Returns:
            str: The decrypted plaintext message.
        """
```

### Module: `rsa.py`

```python
class RSA(AsymmetricEncryption):
    def generate(self, options: Options = Options()) -> tuple[str, str]:
        """
        Generates a public/private key pair using RSA encryption algorithm.
        The key size and public exponent are configurable through the options.

        Args:
            options (Options): Configuration for key generation including size and public exponent.

        Returns:
            tuple[str, str]: A tuple containing the PEM encoded private key and public key.
        """

    def encrypt(self, public_key: str, payload: str) -> str:
        """
        Encrypts the given payload using the public key. Uses OAEP padding with SHA-256.

        Args:
            public_key (str): PEM encoded RSA public key.
            payload (str): Plaintext message to be encrypted.

        Returns:
            str: Base64 encoded encrypted data.
        """

    def decrypt(self, private_key: str, cipher: str, pw: str | None = None) -> str:
        """
        Decrypts the given encrypted data using the private key and optional password.
        Uses OAEP padding with SHA-256 for decryption.

        Args:
            private_key (str): PEM encoded RSA private key.
            cipher (str): Base64 encoded encrypted data to be decrypted.
            pw (str | None): Optional password for encrypted private key.

        Returns:
            str: Decrypted plaintext message.
        """

    def sign(self, private_key: str, message: str, pw: str | None = None) -> str:
        """
        Signs a message using the private RSA key and returns the signature.
        Uses PSS padding with SHA-256.

        Args:
            private_key (str): PEM encoded RSA private key.
            message (str): Message to be signed.
            pw (str | None): Optional password for encrypted private key.

        Returns:
            str: Base64 encoded digital signature.
        """

    def validate(self, public_key: str, message: str, signature: str) -> bool:
        """
        Validates a digital signature using the public key.

        Args:
            public_key (str): PEM encoded RSA public key.
            message (str): The original message that was signed.
            signature (str): Base64 encoded digital

 signature to be validated.

        Returns:
            bool: True if the signature is valid; False otherwise.
        """
```
