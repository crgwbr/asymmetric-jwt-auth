from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    PublicFormat,
    NoEncryption
)
from django.conf import settings
from . import token, default_settings
import os.path
import struct
import base64


def generate_ed25519_key_pair(as_string=True, encoding=Encoding.PEM):
    private = Ed25519PrivateKey.generate()
    public = private.public_key()
    if not as_string:
        return private, public
    pem_private = private.private_bytes(encoding, PrivateFormat.PKCS8, NoEncryption()).decode()
    pem_public = public.public_bytes(encoding, PublicFormat.SubjectPublicKeyInfo).decode()
    return pem_private, pem_public


def generate_rsa_key_pair(size=2048, public_exponent=65537, as_string=True, encoding=Encoding.PEM):
    """
    Generate an RSA public/private key pair.

    :param size: Optional. Describes how many bits long the key should be, larger keys provide more security,
        currently 1024 and below are considered breakable, and 2048 or 4096 are reasonable default
        key sizes for new keys. Defaults to 2048.
    :param public_exponent: Optional. Indicates what one mathematical property of the key generation will be.
        65537 is the default and should almost always be used.
    :param as_string: Optional. If True, return tuple of strings. If false, return tuple of RSA key objects.
        Defaults to True.
    :return: (PrivateKey<string>, PublicKey<string>)
    :return: (
        `RSAPrivateKey <https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey>`_,
        `RSAPublicKey <https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey>`_)
    """
    private = rsa.generate_private_key(
        public_exponent=public_exponent,
        key_size=size,
        backend=default_backend()
    )
    public = private.public_key()
    if not as_string:
        return private, public
    pem_private = private.private_bytes(encoding, PrivateFormat.PKCS8, NoEncryption()).decode()
    pem_public = public.public_bytes(encoding, PublicFormat.SubjectPublicKeyInfo).decode()
    return pem_private, pem_public


def load_private_key(key_file, key_password=None):
    """
    Load a private key from disk.

    :param key_file: File path to key file.
    :param key_password: Optional. If the key file is encrypted, provide the password to decrypt it. Defaults to None.
    :return: PrivateKey<string>
    """
    key_file = os.path.expanduser(key_file)
    key_file = os.path.abspath(key_file)

    if not key_password:
        with open(key_file, 'r') as key:
            return key.read()

    with open(key_file, 'rb') as key:
        key_bytes = key.read()
    return decrypt_key(key_bytes, key_password).decode()


def decrypt_key(key, password):
    """
    Decrypt an encrypted private key.

    :param key: Encrypted private key as a string.
    :param password: Key pass-phrase.
    :return: Decrypted private key as a string.
    """
    private = serialization.load_pem_private_key(key, password=password, backend=default_backend())
    return private.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())


def create_auth_header(username, key=None, key_file="~/.ssh/id_rsa", key_password=None, algorithm=None):
    """
    Create an HTTP Authorization header using a private key file.

    Either a key or a key_file must be provided.

    :param username: The username to authenticate as on the remote system.
    :param key: Optional. A private key as either a string or an instance of cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey.
    :param key_file: Optional. Path to a file containing the user's private key. Defaults to ~/.ssh/id_rsa. Should be in PEM format.
    :param key_password: Optional. Password to decrypt key_file. If set, should be a bytes object.
    :return: Authentication header value as a string.
    """
    if not key:
        key = load_private_key(key_file, key_password)
    if not algorithm:
        algorithm = getattr(settings, 'ASYMMETRIC_JWT_AUTH', default_settings)['DEFAULT_ALGORITHM']
    auth_method = getattr(settings, 'ASYMMETRIC_JWT_AUTH', default_settings)['AUTH_METHOD']
    claim = token.sign(username, key,
        algorithm=algorithm)
    return "%s %s" % (auth_method, claim)


def long2intarr(long_int):
    _bytes = []
    while long_int:
        long_int, r = divmod(long_int, 256)
        _bytes.insert(0, r)
    return _bytes


def long_to_base64(n, mlen=0):
    bys = long2intarr(n)
    if mlen:
        _len = mlen - len(bys)
        if _len:
            bys = [0] * _len + bys
    data = struct.pack('%sB' % len(bys), *bys)
    if not len(data):
        data = '\x00'
    s = base64.urlsafe_b64encode(data).rstrip(b'=')
    return s.decode("ascii")
