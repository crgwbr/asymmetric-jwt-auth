from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    NoEncryption
)
import os.path
import asymmetric_jwt_auth.token as token


def load_private_key(key_file, key_password=None):
    key_file = os.path.expanduser(key_file)
    key_file = os.path.abspath(key_file)
    with open(key_file, 'rU') as key:
        private = serialization.load_pem_private_key(
            key.read(),
            password=key_password,
            backend=default_backend()
        )
        private = private.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    return private


def create_auth_header(username, key_file="~/.ssh/id_rsa", key_password=None):
    """Create an HTTP Authorization header using a private key file

    username - The username to authenticate as on the remote system
    key_file - Path to a file containing the user's private key. Defaults
               to ~/.ssh/id_rsa. Should be in PEM format.
    """
    key = load_private_key(key_file, key_password)
    claim = token.sign(username, key)
    return "JWT %s" % claim
