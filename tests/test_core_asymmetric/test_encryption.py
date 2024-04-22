import unittest

from stringkeys.core.asymmetric.encryption import Keys
from stringkeys.core.algorithms.rsa import RSA
from stringkeys.core.asymmetric.models import Options


class TestKeys(unittest.TestCase):
    def setUp(self):
        self.rsa_algorithm = RSA()
        self.keys = Keys(algorithm=RSA)
        self.options = Options(key_size=2048, key_public_exponent=65537)

    def test_generate_keys(self):
        private_key, public_key = self.keys.generate(self.options)
        self.assertTrue(isinstance(private_key, str))
        self.assertTrue(isinstance(public_key, str))
        self.assertNotEqual(private_key, public_key)

    def test_encrypt_decrypt(self):
        private_key, public_key = self.keys.generate(self.options)
        payload = "Hello Asymmetric Encryption!"
        encrypted = self.keys.encrypt(public_key, payload)
        decrypted = self.keys.decrypt(private_key, encrypted)
        self.assertEqual(decrypted, payload)

    def test_sign_verify(self):
        private_key, public_key = self.keys.generate(self.options)
        message = "Sign this message"
        signature = self.keys.sign(private_key, message)
        is_valid = self.keys.validate(public_key, message, signature)
        self.assertTrue(is_valid)

    def test_encrypt_with_invalid_public_key(self):
        payload = "This should fail"
        with self.assertRaises(Exception):
            self.keys.encrypt("invalid_public_key", payload)

    def test_decrypt_with_invalid_private_key(self):
        private_key, public_key = self.keys.generate(self.options)
        payload = "Data to encrypt"
        encrypted = self.keys.encrypt(public_key, payload)
        with self.assertRaises(Exception):
            self.keys.decrypt("invalid_private_key", encrypted)

    def test_invalid_signature(self):
        private_key, public_key = self.keys.generate(self.options)
        message = "Original message"
        invalid_signature = "invalid_signature"
        is_valid = self.keys.validate(public_key, message, invalid_signature)
        self.assertFalse(is_valid)


if __name__ == "__main__":
    unittest.main()
