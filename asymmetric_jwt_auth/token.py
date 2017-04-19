import jwt
import time
import random
import logging

logger = logging.getLogger(__name__)


#: Default JWT signing algorithm
DEFAULT_ALGORITHM = 'RS512'

# Number of seconds of clock-drift to tolerate when verifying the authenticity of a JWT.
TIMESTAMP_TOLERANCE = 20  # Seconds


def sign(username, private_key, generate_nonce=None, iat=None, algorithm=DEFAULT_ALGORITHM):
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
        generate_nonce = lambda username, iat: random.random()  # NOQA

    token_data = {
        'username': username,
        'time': iat,
        'nonce': generate_nonce(username, iat),
    }

    token = jwt.encode(token_data, private_key, algorithm=algorithm)
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

    if 'username' not in unverified_data:
        return None
    return unverified_data['username']


def verify(token, public_key, validate_nonce=None, algorithms=[DEFAULT_ALGORITHM]):
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
    min_time, max_time = (current_time - TIMESTAMP_TOLERANCE, current_time + TIMESTAMP_TOLERANCE)
    if claimed_time < min_time or claimed_time > max_time:
        logger.debug('Claimed time is outside of allowable tolerances')
        return False

    # Ensure nonce is unique
    if validate_nonce:
        if not validate_nonce(claimed_username, claimed_time, claimed_nonce):
            logger.debug('Claimed nonce failed to validate')
            return False
    else:
        logger.warning('validate_nonce function was not supplied!')

    # If we've gotten this far, the token is valid
    return token_data
