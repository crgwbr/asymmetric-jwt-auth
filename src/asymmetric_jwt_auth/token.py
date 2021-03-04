from django.conf import settings
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_ssh_public_key
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_pem_private_key,
)
from . import default_settings
import jwt
import time
import logging
import secrets
import hashlib

logger = logging.getLogger(__name__)


def load_serialized_public_key(keystr):
    exc = None
    for load in (load_pem_public_key, load_ssh_public_key):
        try:
            return None, load(keystr.encode())
        except Exception as e:
            exc = e
    return exc, None


def get_public_key_fingerprint(public_key):
    pem_bytes = public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(pem_bytes).hexdigest()


def sign(username, private_key, generate_nonce=None, iat=None, algorithm=None):
    """
    Create a signed JWT using the given username and RSA private key.

    :param username: Username (string) to authenticate as on the remote system.
    :param private_key: Private key to use to sign the JWT claim.
    :param generate_nonce: Optional. Callable to use to generate a new nonce. Defaults to
        `random.random <https://docs.python.org/3/library/random.html#random.random>`_.
    :param iat: Optional. Timestamp to include in the JWT claim. Defaults to
        `time.time <https://docs.python.org/3/library/time.html#time.time>`_.
    :param algorithm: Optional. Algorithm to use to sign the JWT claim. Default to ``RS512``.
        See `pyjwt.readthedocs.io <https://pyjwt.readthedocs.io/en/latest/algorithms.html>`_ for other possible algorithms.
    :return: JWT claim as a string.
    """
    iat = iat if iat else time.time()
    if not generate_nonce:
        generate_nonce = lambda username, iat: secrets.token_urlsafe(nbytes=8)  # NOQA

    if not algorithm:
        algorithm = getattr(settings, 'ASYMMETRIC_JWT_AUTH', default_settings)['DEFAULT_ALGORITHM']

    # Load private key
    if isinstance(private_key, str):
        private_key = private_key.encode()
    if isinstance(private_key, bytes):
        private_key = load_pem_private_key(private_key, password=None)
    # Use public key fingerprint as KID
    public_key = private_key.public_key()
    kid = get_public_key_fingerprint(public_key)
    # Build and sign claim data
    token_data = {
        'username': username,
        'time': iat,
        'nonce': generate_nonce(username, iat),
    }
    headers = {
        'kid': kid,
    }
    token = jwt.encode(token_data, private_key,
        algorithm=algorithm,
        headers=headers)
    return token


def get_claimed_username(token):
    """
    Given a JWT, get the username that it is claiming to be `without verifying that the signature is valid`.

    :param token: JWT claim
    :return: Username
    """
    unverified_data = jwt.decode(token, options={
        'verify_signature': False
    })
    return unverified_data.get('username')


def verify(token, public_key, validate_nonce, algorithms):
    """
    Verify the validity of the given JWT using the given public key.

    :param token: JWM claim
    :param public_key: Public key to use when verifying the claim's signature.
    :param validate_nonce: Callable to use to validate the claim's nonce.
    :param algorithms: Allowable signing algorithms. Defaults to ['RS512'].
    :return: False if the token is determined to be invalid or a dictionary of the token data if it is valid.
    """
    try:
        token_data = jwt.decode(token, public_key, algorithms=algorithms)
    except jwt.InvalidTokenError:
        logger.debug('JWT failed verification')
        return False

    claimed_username = token_data.get('username')
    claimed_time = token_data.get('time', 0)
    claimed_nonce = token_data.get('nonce')

    # Ensure time is within acceptable bounds
    current_time = time.time()
    timestamp_tolerance = getattr(settings, 'ASYMMETRIC_JWT_AUTH', default_settings)['TIMESTAMP_TOLERANCE']
    min_time, max_time = (current_time - timestamp_tolerance, current_time + timestamp_tolerance)
    if claimed_time < min_time or claimed_time > max_time:
        logger.debug('Claimed time is outside of allowable tolerances')
        return False

    # Ensure nonce is unique
    if not validate_nonce(claimed_username, claimed_time, claimed_nonce):
        logger.debug('Claimed nonce failed to validate')
        return False

    # If we've gotten this far, the token is valid
    return token_data
