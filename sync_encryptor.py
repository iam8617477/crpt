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

    def encrypt(self, data, use_salt: bool = False, is_bytes: bool = False) -> (str, str):
        salt = None
        if use_salt:
            salt = self._generate_salt()
            key = self._generate_key(salt)
        else:
            key = self._generate_key()

        cipher = Fernet(key)

        if not is_bytes:
            data = data.encode()

        encrypted_data = cipher.encrypt(data)

        return (encrypted_data.decode() if not is_bytes else encrypted_data,
                base64.urlsafe_b64encode(salt).decode() if use_salt else None)

    def decrypt(self, encrypted_data, salt: str = None, is_bytes: bool = False) -> (str, bytes):
        if salt:
            salt = base64.urlsafe_b64decode(salt)
            key = self._generate_key(salt)
        else:
            key = self._generate_key()

        cipher = Fernet(key)

        if not is_bytes:
            encrypted_data = encrypted_data.encode()

        decrypted_data = cipher.decrypt(encrypted_data)

        return decrypted_data if is_bytes else decrypted_data.decode()
