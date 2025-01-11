from argparse import ArgumentParser
from typing import Any

from django.core.management.base import BaseCommand

from asymmetric_jwt_auth.keys import Ed25519PrivateKey, FacadePrivateKey, RSAPrivateKey

TYPE_RSA = "RSA"
TYPE_ED25519 = "Ed25519"
TYPE_CHOICES = [
    TYPE_RSA,
    TYPE_ED25519,
]


class Command(BaseCommand):
    help = "Generate a public / private RSA key pair"

    def add_arguments(self, parser: ArgumentParser) -> None:
        parser.add_argument("-t", "--keytype", choices=TYPE_CHOICES, default=TYPE_RSA)

    def handle(self, *args: Any, keytype: str = TYPE_RSA, **options: Any) -> None:
        privkey: FacadePrivateKey
        if keytype == TYPE_ED25519:
            privkey = Ed25519PrivateKey.generate()
        else:
            privkey = RSAPrivateKey.generate()
        self.stdout.write(privkey.as_pem.decode())
        self.stdout.write(privkey.public_key.as_pem.decode())
