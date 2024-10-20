import unittest
from rsa_encryptor import RSAEncryptor


class TestRSAEncryptor(unittest.TestCase):

    def setUp(self):
        self.encryptor = RSAEncryptor()
        self.password = 'test_password'
        self.message = 'This is a secret message.'
        self.private_key, self.public_key = self.encryptor.generate_keys(password=self.password)

    def test_generate_keys(self):
        self.assertIsNotNone(self.private_key)
        self.assertIsNotNone(self.public_key)

    def test_encrypt_decrypt_with_public_key(self):
        encrypted_message = self.encryptor.encrypt_with_public_key(self.public_key, self.message)
        decrypted_message = self.encryptor.decrypt_with_private_key(
            self.private_key, encrypted_message, password=self.password
        )

        self.assertEqual(self.message, decrypted_message)

    def test_encrypt_decrypt_with_private_key(self):
        signed_message = self.encryptor.encrypt_with_private_key(self.private_key, self.message, password=self.password)
        is_verified = self.encryptor.verify_with_public_key(self.public_key, signed_message, self.message)

        self.assertTrue(is_verified)

    def test_encryption_without_password(self):
        private_key_no_password, public_key_no_password = self.encryptor.generate_keys(password=None)
        encrypted_message = self.encryptor.encrypt_with_public_key(public_key_no_password, self.message)
        decrypted_message = self.encryptor.decrypt_with_private_key(private_key_no_password, encrypted_message)

        self.assertEqual(self.message, decrypted_message)

    def test_sign_and_verify(self):
        signed_message = self.encryptor.encrypt_with_private_key(self.private_key, self.message, password=self.password)
        is_verified = self.encryptor.verify_with_public_key(self.public_key, signed_message, self.message)

        self.assertTrue(is_verified)


import unittest
from rsa_encryptor import RSAEncryptor


class TestRSAEncryptorWithoutPassword(unittest.TestCase):

    def setUp(self):
        self.encryptor = RSAEncryptor()
        self.message = 'This is a secret message.'
        self.private_key, self.public_key = self.encryptor.generate_keys(password=None)

    def test_generate_keys(self):
        self.assertIsNotNone(self.private_key)
        self.assertIsNotNone(self.public_key)

    def test_encrypt_decrypt_with_public_key(self):
        encrypted_message = self.encryptor.encrypt_with_public_key(self.public_key, self.message)
        decrypted_message = self.encryptor.decrypt_with_private_key(self.private_key, encrypted_message)

        self.assertEqual(self.message, decrypted_message)

    def test_encrypt_decrypt_with_private_key(self):
        signed_message = self.encryptor.encrypt_with_private_key(self.private_key, self.message)
        is_verified = self.encryptor.verify_with_public_key(self.public_key, signed_message, self.message)

        self.assertTrue(is_verified)

    def test_encryption_without_password(self):
        private_key_no_password, public_key_no_password = self.encryptor.generate_keys(password=None)
        encrypted_message = self.encryptor.encrypt_with_public_key(public_key_no_password, self.message)
        decrypted_message = self.encryptor.decrypt_with_private_key(private_key_no_password, encrypted_message)

        self.assertEqual(self.message, decrypted_message)

    def test_sign_and_verify(self):
        signed_message = self.encryptor.encrypt_with_private_key(self.private_key, self.message)
        is_verified = self.encryptor.verify_with_public_key(self.public_key, signed_message, self.message)

        self.assertTrue(is_verified)


if __name__ == '__main__':
    unittest.main()
