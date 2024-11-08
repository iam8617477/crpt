from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes


class RSAEncryptor:

    @staticmethod
    def generate_keys(password: str = None) -> (str, str):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()

        if password:
            encryption_algorithm = serialization.BestAvailableEncryption(password.encode())
        else:
            encryption_algorithm = serialization.NoEncryption()

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=encryption_algorithm
        ).decode('utf-8')

        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        return private_pem, public_pem

    @staticmethod
    def encrypt_with_public_key(public_key_pem: str, message: str) -> bytes:
        public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))
        encrypted = public_key.encrypt(
            message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted

    @staticmethod
    def encrypt_with_private_key(private_key_pem: str, message: str, password: str = None) -> bytes:
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode('utf-8'),
            password=password.encode() if password else None
        )
        encrypted = private_key.sign(
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return encrypted

    @staticmethod
    def decrypt_with_private_key(private_key_pem: str, encrypted_message: bytes, password: str = None) -> str:
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode('utf-8'),
            password=password.encode() if password else None
        )
        decrypted = private_key.decrypt(
            encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted.decode('utf-8')

    @staticmethod
    def verify_with_public_key(public_key_pem: str, signed_message: bytes, original_message: str) -> bool:
        public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))
        try:
            public_key.verify(
                signed_message,
                original_message.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False
