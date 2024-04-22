import base64

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    NoEncryption,
    BestAvailableEncryption,
    PublicFormat,
    load_pem_public_key,
    load_pem_private_key,
)
from cryptography.hazmat.primitives import hashes

from stringkeys.core.asymmetric.interface import AsymmetricEncryption
from stringkeys.core.asymmetric.models import Options


class RSA(AsymmetricEncryption):
    def generate(self, options: Options = Options()) -> tuple[str, str]:
        private_key = rsa.generate_private_key(
            public_exponent=options.key_public_exponent,
            key_size=options.key_size,
        )
        if options.key_gen_private_key_pw:
            encryption_algorithm = BestAvailableEncryption(
                options.key_gen_private_key_pw.encode()
            )
        else:
            encryption_algorithm = NoEncryption()
        private_key_bytes = private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm,
        )
        public_key_bytes = private_key.public_key().public_bytes(
            encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo
        )
        return private_key_bytes.decode(), public_key_bytes.decode()

    def encrypt(self, public_key: str, payload: str) -> str:
        cipher = load_pem_public_key(public_key.encode()).encrypt(
            payload.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return base64.b64encode(cipher).decode("utf-8")

    def decrypt(self, private_key: str, cipher: str, pw: str = None) -> str:
        payload = RSA.pem_private_key(private_key, pw).decrypt(
            base64.b64decode(cipher),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return payload.decode()

    def sign(self, private_key: str, message: str, pw: str | None = None) -> str:
        signature = RSA.pem_private_key(private_key, pw).sign(
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )
        return base64.b64encode(signature).decode("utf-8")

    def validate(self, public_key: str, message: str, signature: str) -> bool:
        try:
            load_pem_public_key(public_key.encode()).verify(
                base64.b64decode(signature),
                message.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            return True
        except InvalidSignature:
            return False

    @staticmethod
    def pem_private_key(private_key: str, pw: str | None) -> PrivateKeyTypes:
        loaded_private_key = load_pem_private_key( 
            private_key.encode(),
            password=(pw.encode() if isinstance(pw, str) else None),
            backend=None,
        )
        return loaded_private_key
