import base64
import os

import unittest

from stringkeys.core.algorithms.cc import ChaCha20
from stringkeys.core.symmetric.models import Options


class TestChaCha20(unittest.TestCase):
    def setUp(self):
        self.key = base64.urlsafe_b64encode(os.urandom(32)).decode("utf-8")
        self.chacha20 = ChaCha20()
        self.options = Options(key_size=16)

    def test_encrypt_valid_inputs(self):
        payload = "Hello, world!"
        encrypted = self.chacha20.encrypt(payload, self.key, self.options)
        self.assertIsInstance(encrypted, str)
        self.assertNotEqual(encrypted, payload)

    def test_encrypt_with_invalid_key(self):
        invalid_key = base64.urlsafe_b64encode(b"short_key").decode("utf-8")
        with self.assertRaises(ValueError):
            self.chacha20.encrypt("Hello, world!", invalid_key, self.options)

    def test_encrypt_with_empty_payload(self):
        payload = ""
        encrypted = self.chacha20.encrypt(payload, self.key, self.options)
        self.assertIsInstance(encrypted, str)
        decrypted = self.chacha20.decrypt(encrypted, self.key, self.options)
        self.assertEqual(decrypted, payload)

    def test_encrypt_result_length(self):
        payload = "Data that is exactly 32 bytes!!"
        encrypted = self.chacha20.encrypt(payload, self.key, self.options)
        self.assertTrue(len(base64.urlsafe_b64decode(encrypted)) > len(payload))

    def test_decrypt_with_invalid_nonce(self):
        payload = "Valid payload"
        encrypted = self.chacha20.encrypt(payload, self.key, self.options)
        invalid_nonce = base64.urlsafe_b64encode(b"invalid_nonce").decode("utf-8")
        with self.assertRaises(ValueError):
            self.chacha20.decrypt(
                encrypted[:16] + invalid_nonce + encrypted[16:], self.key, self.options
            )

    def test_encrypt_non_ascii_characters(self):
        payload = "안녕하세요"  # Korean for "Hello"
        encrypted = self.chacha20.encrypt(payload, self.key, self.options)
        decrypted = self.chacha20.decrypt(encrypted, self.key, self.options)
        self.assertEqual(decrypted, payload)


if __name__ == "__main__":
    unittest.main()
