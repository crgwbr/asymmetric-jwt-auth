from django.core.management.base import NoArgsCommand
from asymmetric_jwt_auth import generate_key_pair


class Command(NoArgsCommand):
    help = "Generate a public / private RSA key pair"

    def handle_noargs(self, **options):
        pem_private, pem_public = generate_key_pair()
        print(pem_private)
        print(pem_public)
