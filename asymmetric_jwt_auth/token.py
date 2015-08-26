import jwt
import time
import random
import logging

DEFAULT_ALGORITHM = 'RS512'
TIMESTAMP_TOLERANCE = 20 # Seconds

logger = logging.getLogger(__name__)


def sign(username, private_key, generate_nonce=None, iat=None, algorithm=DEFAULT_ALGORITHM):
    """Create a signed JWT using the given username and RSA private key"""

    iat = iat if iat else time.time()
    if not generate_nonce:
        generate_nonce = lambda username, iat: random.random()

    token_data = {
        'username': username,
        'time': iat,
        'nonce': generate_nonce(username, iat),
    }

    token = jwt.encode(token_data, private_key, algorithm=algorithm)
    return token


def get_claimed_username(token):
    unverified_data = jwt.decode(token, options={
        'verify_signature': False
    })

    if 'username' not in unverified_data:
        return None
    return unverified_data['username']


def verify(token, public_key, validate_nonce=None, algorithms=[DEFAULT_ALGORITHM]):
    """Verify the validity of the given JWT using a public key"""
    try:
        token_data = jwt.decode(token, public_key, algorithms=algorithms)
    except jwt.InvalidTokenError as e:
        logger.info('JWT failed verification', exc_info=e)
        return False

    claimed_username = token_data.get('username')
    claimed_time = token_data.get('time', 0)
    claimed_nonce = token_data.get('nonce')

    # Ensure time is within acceptable bounds
    current_time = time.time()
    min_time, max_time = (current_time - TIMESTAMP_TOLERANCE, current_time + TIMESTAMP_TOLERANCE)
    if claimed_time < min_time or claimed_time > max_time:
        logger.info('Claimed time is outside of allowable tolerances')
        return False

    # Ensure nonce is unique
    if validate_nonce:
        if not validate_nonce(claimed_username, claimed_time, claimed_nonce):
            logger.info('Claimed nonce failed to validate')
            return False
    else:
        logger.warning('validate_nonce function was not supplied!')

    # If we've gotten this far, the token is valid
    return token_data
