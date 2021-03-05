from typing import Optional, Union
from .nonce import get_nonce_backend
from . import keys, get_setting
import jwt
import time
import logging

logger = logging.getLogger(__name__)



class Token:
    """
    Represents a JWT that's either been constructed by our code or has been
    verified to be valid.
    """
    username: str
    timestamp: int

    def __init__(self, username: str, timestamp: Optional[int] = None):
        self.username = username
        self.timestamp = int(time.time()) if timestamp is None else timestamp


    def create_auth_header(self, private_key: keys.PrivateKey) -> str:
        """
        Create an HTTP Authorization header
        """

        auth_method = get_setting('AUTH_METHOD')
        token = self.sign(private_key)
        return f"{auth_method} {token}"


    def sign(self, private_key: keys.PrivateKey) -> str:
        """
        Create and return signed authentication JWT
        """
        public_key = private_key.public_key
        algorithm = public_key.allowed_algorithms[0]
        nonce = get_nonce_backend().generate_nonce()
        kid = public_key.fingerprint
        # Build and sign claim data
        token_data = {
            'username': self.username,
            'time': self.timestamp,
            'nonce': nonce,
        }
        headers = {
            'kid': kid,
        }
        token = jwt.encode(
            payload=token_data,
            key=private_key.as_pem,
            algorithm=algorithm,
            headers=headers)
        return token



class UntrustedToken:
    """
    Represents a JWT received from user input (and not yet trusted)
    """
    token: str

    def __init__(self, token: str):
        self.token = token


    def get_claimed_username(self) -> Union[None, str]:
        """
        Given a JWT, get the username that it is claiming to be `without verifying that the signature is valid`.

        :param token: JWT claim
        :return: Username
        """
        unverified_data = jwt.decode(self.token, options={
            'verify_signature': False
        })
        return unverified_data.get('username')


    def verify(self, public_key: keys.PublicKey) -> Union[None, Token]:
        """
        Verify the validity of the given JWT using the given public key.
        """
        try:
            token_data = jwt.decode(
                jwt=self.token,
                key=public_key.as_pem.decode(),
                algorithms=public_key.allowed_algorithms)
        except jwt.InvalidTokenError:
            logger.debug('JWT failed verification')
            return None

        claimed_username = token_data.get('username')
        claimed_time = token_data.get('time', 0)
        claimed_nonce = token_data.get('nonce')

        # Ensure fields aren't blank
        if not claimed_username or not claimed_time or not claimed_nonce:
            return None

        # Ensure time is within acceptable bounds
        current_time = time.time()
        timestamp_tolerance = get_setting('TIMESTAMP_TOLERANCE')
        min_time, max_time = (current_time - timestamp_tolerance, current_time + timestamp_tolerance)
        if claimed_time < min_time or claimed_time > max_time:
            logger.debug('Claimed time is outside of allowable tolerances')
            return None

        # Ensure nonce is unique
        nonce_backend = get_nonce_backend()
        if not nonce_backend.validate_nonce(claimed_username, claimed_time, claimed_nonce):
            logger.debug('Claimed nonce failed to validate')
            return None

        # If we've gotten this far, the token is valid
        nonce_backend.log_used_nonce(claimed_username, claimed_time, claimed_nonce)
        return Token(claimed_username, claimed_time)
