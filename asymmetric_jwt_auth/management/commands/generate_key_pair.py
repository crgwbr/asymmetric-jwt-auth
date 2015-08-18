from django.core.management.base import NoArgsCommand
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    PublicFormat,
    NoEncryption
)


class Command(NoArgsCommand):
    help = "Generate a public / private RSA key pair"

    def handle_noargs(self, **options):
        private = rsa.generate_private_key(
            public_exponent=65537,
            key_size=options.get('bits', 2048),
            backend=default_backend()
        )
        public = private.public_key()

        print private.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        print public.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
