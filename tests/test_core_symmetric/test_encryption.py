import base64
import unittest
import os

from iokeys.core.algorithms.aes import AES256
from iokeys.core.algorithms.cc import ChaCha20
from iokeys.core.symmetric.models import Options


class EncryptionTestBase(unittest.TestCase):
    def setUp(self):
        self.key = base64.urlsafe_b64encode(os.urandom(32)).decode("utf-8")
        self.options = Options(key_size=16)
        self.payload = "Test data for encryption"
        self.encryption_class: type[AES256] | type[ChaCha20] | None = None

    def __skip_test(self):
        if not self.encryption_class:
            self.skipTest("Encryption class not set")

    def test_encrypt_decrypt(self):
        self.__skip_test()
        if not self.encryption_class:
            self.fail("Encryption class not set")

        encryptor = self.encryption_class()
        encrypted = encryptor.encrypt(self.payload, self.key, self.options)
        decrypted = encryptor.decrypt(encrypted, self.key, self.options)
        self.assertEqual(decrypted, self.payload)

    def test_invalid_key(self):
        self.__skip_test()
        if not self.encryption_class:
            self.fail("Encryption class not set")

        invalid_key = base64.urlsafe_b64encode(b"short_key").decode("utf-8")
        encryptor = self.encryption_class()
        with self.assertRaises(ValueError):
            encryptor.encrypt(self.payload, invalid_key, self.options)

    def test_empty_payload(self):
        self.__skip_test()
        if not self.encryption_class:
            self.fail("Encryption class not set")

        encryptor = self.encryption_class()
        encrypted = encryptor.encrypt("", self.key, self.options)
        decrypted = encryptor.decrypt(encrypted, self.key, self.options)
        self.assertEqual(decrypted, "")


class TestAES256(EncryptionTestBase):
    def setUp(self):
        super().setUp()
        self.encryption_class = AES256


class TestChaCha20(EncryptionTestBase):
    def setUp(self):
        super().setUp()
        self.encryption_class = ChaCha20


if __name__ == "__main__":
    unittest.main()
