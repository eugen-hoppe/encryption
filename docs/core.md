# core

## algorithms

### algorithms.aes.AES256

#### algorithms.aes.AES256.encrypt

###### 40419c

```python
def encrypt(self, payload: str, key: str, options: Options) -> str:
    # Decode the key from base64 URL-safe encoding to bytes
    key_bytes = base64.urlsafe_b64decode(key)
    # Generate a random Initialization Vector (IV) of size options.key_size
    iv = os.urandom(options.key_size)
    # Create the Cipher object with AES algorithm and CBC mode
    cipher = Cipher(
        algorithms.AES(key_bytes), modes.CBC(iv), backend=default_backend()
    )
    # Create an Encryptor object from the Cipher
    encryptor = cipher.encryptor()
    # Convert the plaintext to bytes
    payload_bytes = payload.encode("utf-8")
    # Calculate the required padding length
    padding_length = options.key_size - len(payload_bytes) % options.key_size
    # Add padding to the plaintext; each padding byte is the padding length itself
    padded_payload = payload_bytes + bytes([padding_length] * padding_length)
    # Encrypt the data
    encrypted = encryptor.update(padded_payload) + encryptor.finalize()
    # Append the IV to the encrypted data
    encrypted_iv = iv + encrypted
    # Return the encrypted data, encoded in base64 URL-safe string
    return base64.urlsafe_b64encode(encrypted_iv).decode("utf-8")

```
- **Key Decoding**: The key is converted from base64 URL-safe encoding to bytes, making it usable for the encryption process.
- **IV Generation**: A random IV is critical for the security of the CBC mode, as it ensures that identical plaintext blocks lead to different encrypted blocks.
- **Cipher Creation**: Here, the AES algorithm is initialized with the previously generated IV in CBC mode.
- **Encryptor Object**: This object performs the actual encryption.
- **Payload Preparation and Padding**: AES requires that the data length be a multiple of the block size. The padding ensures that this condition is met.
- **Performing Encryption**: The data is encrypted and the encryption is completed.
- **Compiling Encrypted Data**: The IV is prefixed to the encrypted data to make it available for later decryption.
- **Return**: The data is returned in a format that is easy to transport and store.

#### algorithms.aes.AES256.decrypt

...

### algorithms.cc.ChaCha20

#### algorithms.cc.ChaCha20.encrypt

###### 40419d

```python
def encrypt(self, payload: str, key: str, options: Options) -> str:
    # Decode the key from base64 URL-safe encoding to bytes
    key_bytes = base64.urlsafe_b64decode(key)
    # Generate a random nonce (number used once) of size options.key_size
    nonce = os.urandom(options.key_size)
    # Create the Cipher object with the ChaCha20 algorithm, without an explicit mode
    cipher = Cipher(
        algorithms.ChaCha20(key_bytes, nonce), mode=None, backend=default_backend()
    )
    # Create an Encryptor object from the Cipher
    encryptor = cipher.encryptor()
    # Convert the plaintext to bytes
    encrypted = encryptor.update(payload.encode("utf-8")) + encryptor.finalize()
    # Append the nonce to the encrypted data
    encrypted_nonce = nonce + encrypted
    # Return the encrypted data, encoded in a base64 URL-safe string
    return base64.urlsafe_b64encode(encrypted_nonce).decode("utf-8")

```

### Explanation of Comments and Functionality:

1. **Key Decoding**: The secret key used for encryption is converted from URL-safe base64 encoding to bytes to make it usable for the cryptographic algorithm.

2. **Nonce Generation**: The ChaCha20 algorithm requires a nonce (number used once). This should be unique for each encryption to ensure security. Here, the nonce is randomly generated and matches the length specified in the `options.key_size`.

3. **Cipher Creation**: A `Cipher` object is initialized using the ChaCha20 algorithm. Unlike block ciphers like AES, ChaCha20 does not require an operating mode such as CBC or GCM, as it is a stream cipher.

4. **Perform Encryption**: The plaintext is converted to bytes and encrypted using the `Encryptor`. The `update` method of the `Encryptor` object processes the bytes, and `finalize` completes the encryption.

5. **Compile Encrypted Data**: The nonce, which is needed for decryption, is prefixed to the encrypted data.

6. **Return**: The combination of nonce and encrypted data is returned as a base64-encoded URL-safe string, facilitating the transport and storage of these data.


#### algorithms.cc.ChaCha20.decrypt

...

