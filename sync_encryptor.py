import os
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet


class SyncEncryptor:

    def __init__(self, passphrase: str):

        self.passphrase = passphrase.encode()

    def _generate_salt(self) -> bytes:
        return os.urandom(16)

    def _generate_key(self, salt: bytes = b'') -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        return base64.urlsafe_b64encode(kdf.derive(self.passphrase))

    def encrypt(self, plain_text: str, use_salt: bool = False) -> (str, str):
        if use_salt:
            salt = self._generate_salt()
            key = self._generate_key(salt)
            cipher = Fernet(key)
            encrypted_text = cipher.encrypt(plain_text.encode())
            return encrypted_text.decode(), base64.urlsafe_b64encode(salt).decode()
        else:
            key = self._generate_key()
            cipher = Fernet(key)
            encrypted_text = cipher.encrypt(plain_text.encode())
            return encrypted_text.decode(), None

    def decrypt(self, encrypted_text: str, salt: str = None) -> str:
        if salt:
            salt = base64.urlsafe_b64decode(salt)
            key = self._generate_key(salt)
        else:
            key = self._generate_key()
        cipher = Fernet(key)
        decrypted_text = cipher.decrypt(encrypted_text.encode()).decode()
        return decrypted_text
