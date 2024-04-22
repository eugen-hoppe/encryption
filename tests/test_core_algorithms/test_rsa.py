import unittest
import base64

from cryptography.hazmat.primitives import serialization
from stringkeys.core.algorithms.rsa import RSA


class TestRSA(unittest.TestCase):
    def setUp(self):
        self.rsa = RSA()
        self.private_key, self.public_key, _ = self.rsa.generate()
        self.private_key_obj = serialization.load_pem_private_key(
            self.private_key.encode(), password=None, backend=None
        )
        self.public_key_obj = serialization.load_pem_public_key(
            self.public_key.encode(), backend=None
        )

    def test_encrypt_decrypt(self):
        plaintext = "Hello RSA Encryption!"
        encrypted = self.rsa.encrypt(self.public_key, plaintext)
        decrypted = self.rsa.decrypt(self.private_key, encrypted)
        self.assertEqual(
            decrypted,
            plaintext,
            "Decrypted text does not match the original",
        )

    def test_sign_verify(self):
        message = "Sign this message"
        signature = self.rsa.sign(self.private_key, message)
        is_valid = self.rsa.validate(self.public_key, message, signature)
        self.assertTrue(
            is_valid,
            "The RSA signature validation failed",
        )

    def test_encrypt_with_invalid_key(self):
        invalid_public_key = self.private_key
        with self.assertRaises(Exception):
            self.rsa.encrypt(
                invalid_public_key,
                "This should fail",
            )

    def test_decrypt_with_invalid_key(self):
        plaintext = "Data to encrypt"
        encrypted = self.rsa.encrypt(self.public_key, plaintext)
        invalid_private_key = self.public_key
        with self.assertRaises(Exception):
            self.rsa.decrypt(invalid_private_key, encrypted)

    def test_invalid_signature(self):
        message = "Original message"
        invalid_signature = base64.b64encode(b"invalid_signature").decode("utf-8")
        is_valid = self.rsa.validate(self.public_key, message, invalid_signature)
        self.assertFalse(
            is_valid,
            "The signature validation should fail with an invalid signature",
        )


if __name__ == "__main__":
    unittest.main()
