import base64
import os

import unittest

from stringkeys.core.symmetric.models import Options
from stringkeys.core.algorithms.aes import AES256


class TestAES256(unittest.TestCase):
    def setUp(self):
        self.key = base64.urlsafe_b64encode(os.urandom(32)).decode("utf-8")
        self.aes256 = AES256()
        self.options = Options(key_size=16)

    def test_encrypt_valid_inputs(self):
        payload = "Hello, world!"
        encrypted = self.aes256.encrypt(payload, self.key, self.options)
        self.assertIsInstance(encrypted, str)
        self.assertNotEqual(encrypted, payload)

    def test_encrypt_with_invalid_key(self):
        invalid_key = base64.urlsafe_b64encode(b"short_key").decode("utf-8")
        with self.assertRaises(ValueError):
            self.aes256.encrypt("Hello, world!", invalid_key, self.options)

    def test_encrypt_with_empty_payload(self):
        payload = ""
        encrypted = self.aes256.encrypt(payload, self.key, self.options)
        self.assertIsInstance(encrypted, str)
        decrypted = self.aes256.decrypt(encrypted, self.key, self.options)
        self.assertEqual(decrypted, payload)

    def test_encrypt_result_length(self):
        payload = "Data that is exactly 32 bytes!!"
        encrypted = self.aes256.encrypt(payload, self.key, self.options)
        self.assertTrue(len(base64.urlsafe_b64decode(encrypted)) > len(payload))


if __name__ == "__main__":
    unittest.main()
