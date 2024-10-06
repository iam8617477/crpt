import unittest
from sync_encryptor import SyncEncryptor


class TestSyncEncryptor(unittest.TestCase):
    def setUp(self):
        self.passphrase = "my_strong_passphrase"
        self.encryptor = SyncEncryptor(self.passphrase)

    def test_encrypt_decrypt_without_salt(self):
        plain_text = "This is a secret message"
        encrypted_text, salt = self.encryptor.encrypt(plain_text, use_salt=False)
        self.assertIsNone(salt)
        decrypted_text = self.encryptor.decrypt(encrypted_text)
        self.assertEqual(plain_text, decrypted_text)

    def test_encrypt_decrypt_with_salt(self):
        plain_text = "This is another secret message"
        encrypted_text, salt = self.encryptor.encrypt(plain_text, use_salt=True)
        self.assertIsNotNone(salt)
        decrypted_text = self.encryptor.decrypt(encrypted_text, salt=salt)
        self.assertEqual(plain_text, decrypted_text)

    def test_encryption_produces_different_results_with_salt(self):
        plain_text = "Consistent message"
        encrypted_text_1, salt_1 = self.encryptor.encrypt(plain_text, use_salt=True)
        encrypted_text_2, salt_2 = self.encryptor.encrypt(plain_text, use_salt=True)
        self.assertNotEqual(encrypted_text_1, encrypted_text_2)
        self.assertNotEqual(salt_1, salt_2)


if __name__ == '__main__':
    unittest.main()
