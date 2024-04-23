# StringKeys Encryption Framework (Experimental)

## Overview

StringKeys is an experimental encryption framework designed to illustrate the combination of symmetric and asymmetric encryption techniques.
The project is developed in Python and leverages the `cryptography.hazmat` library to implement various cryptographic algorithms.

## Disclaimer

This project is **experimental** and intended primarily for educational purposes.
It serves as a reference or a "cheat sheet" for developers looking to understand or implement encryption functionalities in their projects.
**It is not recommended to use this framework in security-critical infrastructures** due to its experimental nature.
Instead, use this as a guide to better understand the practical applications and integration of cryptographic techniques in software projects.

## Features

- **Symmetric Encryption**: Includes implementations of AES-256 and ChaCha20 algorithms.
- **Asymmetric Encryption**: Utilizes the RSA algorithm for public-key cryptographic operations including encryption, decryption, and digital signatures.
- **Modular Design**: The framework is structured to separate concerns clearly, making it easy to navigate and extend.
- **Error Handling**: Incorporates a comprehensive error handling module that demonstrates how to manage and report encryption-related errors gracefully.

## Installation

The project is configured with `pip`, making it straightforward to install the necessary dependencies.
However, due to the experimental nature of this project, ensure you are using a virtual environment to avoid conflicts with existing Python packages.

```bash
pip install git+https://github.com/eugen-hoppe/encryption.git
```

## Usage

The project is structured to allow easy access to cryptographic functions.
Below are snippets on how to use the symmetric and asymmetric encryption modules:

### Symmetric Encryption

```python
from stringkeys.core.symmetric.encryption import AES256
from stringkeys.core.symmetric.models import Options

aes = AES256()
options = Options(key_size=16)  # Block size for AES
key = "your_base64_encoded_key_here"
payload = "Secret Message"

encrypted = aes.encrypt(payload, key, options)
print("Encrypted:", encrypted)

decrypted = aes.decrypt(encrypted, key, options)
print("Decrypted:", decrypted)
```

### Asymmetric Encryption

```python
from stringkeys.core.asymmetric.encryption import Keys
from stringkeys.core.asymmetric.models import Options
from stringkeys.core.algorithms.rsa import RSA

keys = Keys(algorithm=RSA)
options = Options(key_size=2048)  # RSA key size
private_key, public_key = keys.generate(options)

encrypted = keys.encrypt(public_key, "Secret Message")
print("Encrypted:", encrypted)

decrypted = keys.decrypt(private_key, encrypted)
print("Decrypted:", decrypted)
```

## Contributing

Contributions are welcome! If you have improvements or bug fixes, please fork the repository and submit a pull request.

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details.
