from django.core.management.base import BaseCommand
from asymmetric_jwt_auth.utils import (
    generate_ed25519_key_pair,
    generate_rsa_key_pair,
)

TYPE_RSA = 'RSA'
TYPE_ED25519 = 'Ed25519'
TYPE_CHOICES = [
    TYPE_RSA,
    TYPE_ED25519,
]


class Command(BaseCommand):
    help = "Generate a public / private RSA key pair"

    def add_arguments(self, parser):
        parser.add_argument('-t', '--keytype',
            choices=TYPE_CHOICES,
            default=TYPE_RSA)

    def handle(self, *args, keytype=TYPE_RSA, **options):
        if keytype == TYPE_ED25519:
            pem_private, pem_public = generate_ed25519_key_pair()
        else:
            pem_private, pem_public = generate_rsa_key_pair()
        self.stdout.write(pem_private)
        self.stdout.write(pem_public)
