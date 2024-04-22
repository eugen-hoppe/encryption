import base64

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import rsa, padding
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
    def generate(self, options: Options = Options()) -> tuple[str, str, None | str]:
        private_key = rsa.generate_private_key(
            public_exponent=options.key_public_exponent,
            key_size=options.key_size,
        )
        public_key = private_key.public_key()
        if options.key_gen_private_key_pw:
            encryption_algorithm = BestAvailableEncryption(
                options.key_gen_private_key_pw.encode()
            )
        else:
            encryption_algorithm = NoEncryption()
        private_key_pem = private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm,
        )
        public_key_pem = public_key.public_bytes(
            encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo
        )
        return_pw = options.key_gen_private_key_pw
        if not options.key_gen_get_pw is True:  # TODO Remove get_pw
            return_pw = None
        return private_key_pem.decode(), public_key_pem.decode(), return_pw

    def encrypt(self, public_key_pem: str, payload: str):
        public_key = load_pem_public_key(public_key_pem.encode())
        cipher = public_key.encrypt(
            payload.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return base64.b64encode(cipher).decode("utf-8")

    def decrypt(self, private_key_pem: str, cipher: str, pw: str = None):
        private_key = load_pem_private_key(
            private_key_pem.encode(),
            password=(pw.encode() if pw else None),
            backend=None,
        )
        plaintext = private_key.decrypt(
            base64.b64decode(cipher),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return plaintext.decode()

    def sign(
        self, private_key_pem: str, message: str, password: str | None = None
    ) -> str:
        private_key = load_pem_private_key(
            private_key_pem.encode(),
            password=(password.encode() if password else None),
            backend=None,
        )
        signature = private_key.sign(
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )
        return base64.b64encode(signature).decode("utf-8")

    def validate(self, public_key_pem: str, message: str, signature: str) -> bool:
        public_key = load_pem_public_key(public_key_pem.encode())
        try:
            public_key.verify(
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
