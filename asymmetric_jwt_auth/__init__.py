from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    PublicFormat,
    NoEncryption
)
import os.path
import asymmetric_jwt_auth.token as token


default_app_config = 'asymmetric_jwt_auth.apps.JWTAuthConfig'


AUTH_METHOD = 'JWT'
ENCODING = 'utf-8'


def generate_key_pair(size=2048, public_exponent=65537, as_string=True):
    private = rsa.generate_private_key(
        public_exponent=public_exponent,
        key_size=size,
        backend=default_backend()
    )
    public = private.public_key()

    if not as_string:
        return private, public

    pem_private = private.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode(ENCODING)
    pem_public = public.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode(ENCODING)
    return pem_private, pem_public


def load_private_key(key_file, key_password=None):
    key_file = os.path.expanduser(key_file)
    key_file = os.path.abspath(key_file)

    if not key_password:
        with open(key_file, 'r') as key:
            return key.read()

    with open(key_file, 'rb') as key:
        key_bytes = key.read()
    return decrypt_key(key_bytes, key_password).decode(ENCODING)


def decrypt_key(key, password):
    private = serialization.load_pem_private_key(key, password=password, backend=default_backend())
    return private.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())


def create_auth_header(username, key=None, key_file="~/.ssh/id_rsa", key_password=None):
    """Create an HTTP Authorization header using a private key file

    username - The username to authenticate as on the remote system
    key - Optional. A private key as either a string or an instance of
          cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey
    key_file - Path to a file containing the user's private key. Defaults
               to ~/.ssh/id_rsa. Should be in PEM format.
    key_password - Password to decrypt key_file. Should be a bytes object
    """
    if not key:
        key = load_private_key(key_file, key_password)
    claim = token.sign(username, key)
    return "%s %s" % (AUTH_METHOD, claim.decode(ENCODING))
