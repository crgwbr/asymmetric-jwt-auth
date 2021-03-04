from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.cache import cache
from jwt.exceptions import PyJWKClientError
from . import token, default_settings
from .models import JWKSEndpointTrust
import logging

logger = logging.getLogger(__name__)


class JWTAuthMiddleware(object):
    """Django middleware class for authenticating users using JWT Authentication headers"""

    def __init__(self, get_response):
        self.get_response = get_response


    def __call__(self, request):
        # Attempt to authorize the request
        self.authorize_request(request)
        # Continue with the request
        return self.get_response(request)


    def authorize_request(self, request):
        """
        Process a Django request and authenticate users.

        If a JWT authentication header is detected and it is determined to be valid, the user is set as
        ``request.user`` and CSRF protection is disabled (``request._dont_enforce_csrf_checks = True``) on
        the request.

        :param request: Django Request instance
        """
        # Check for presence of auth header
        if 'HTTP_AUTHORIZATION' not in request.META:
            return request

        # Ensure this auth header was meant for us (it has the JWT auth method).
        try:
            method, claim = request.META['HTTP_AUTHORIZATION'].split(' ', 1)
        except ValueError:
            return request

        auth_method_setting = getattr(settings, 'ASYMMETRIC_JWT_AUTH', default_settings)['AUTH_METHOD']
        if method.upper() != auth_method_setting:
            return request

        # Get the (unvalidated!) username that the request is claiming to be
        username = token.get_claimed_username(claim)
        if not username:
            return request

        # Get the Django user model
        User = get_user_model()
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            return request

        claim_data = None

        # Try to validate the claim using the user's JWKS endpoint
        jwks_endpoint = JWKSEndpointTrust.objects.filter(user=user).first()
        if jwks_endpoint:
            try:
                public = jwks_endpoint.get_signing_key(claim)
                # TODO: Why doesn't the JWK RFC support EdDSA keys?
                # https://tools.ietf.org/html/rfc7517
                algorithms = ['RS384', 'RS256', 'RS512']
                claim_data = token.verify(
                    token=claim,
                    public_key=public.key,
                    validate_nonce=self.validate_nonce,
                    algorithms=algorithms)
            except PyJWKClientError:
                claim_data = None

        # Try to find a public key assigned to the user which validates the claimed username
        if claim_data is None:
            for public in user.public_keys.all():
                claim_data = token.verify(
                    token=claim,
                    public_key=public.key,
                    validate_nonce=self.validate_nonce,
                    algorithms=public.get_allowed_algorithms())
                if claim_data:
                    public.update_last_used_datetime()
                    break

        # No keys successfully validated the claim? Abort.
        if not claim_data:
            return request

        # Log the nonce so it can't be used again
        self.log_used_nonce(user.username, claim_data['time'], claim_data['nonce'])

        # Assign the user to the request
        logger.debug('Successfully authenticated %s using JWT', user.username)
        request._dont_enforce_csrf_checks = True
        request.user = user
        return request


    def create_nonce_key(self, username, timestamp):
        """
        Create and return the cache key for storing nonces

        :param username: Username as a string.
        :param timestamp: Unix timestamp float or integer of when the nonce was used.
        :return: Cache key string.
        """
        return '%s-nonces-%s-%s' % (
            self.__class__.__name__,
            username,
            timestamp,
        )


    def log_used_nonce(self, username, timestamp, nonce):
        """
        Log a nonce as being used, and therefore henceforth invalid.

        :param username: Username as a string.
        :param iat: Unix timestamp float or integer of when the nonce was used.
        :param nonce: Nonce value.
        """
        # TODO: Figure out some way to do this in a thread-safe manner. It'd be better to use
        # a Redis Set or something, but we don't necessarily want to be tightly coupled to
        # Redis either since not everyone uses it.
        key = self.create_nonce_key(username, timestamp)
        used = cache.get(key, [])
        used.append(nonce)
        timestamp_tolerance = getattr(settings, 'ASYMMETRIC_JWT_AUTH', default_settings)['TIMESTAMP_TOLERANCE']
        cache.set(key, set(used), timestamp_tolerance * 2)


    def validate_nonce(self, username, timestamp, nonce):
        """
        Confirm that the given nonce hasn't already been used.

        :param username: Username as a string.
        :param timestamp: Unix timestamp float or integer of when the nonce was used.
        :param nonce: Nonce value.
        :return: True if nonce is valid, False if it is invalid.
        """
        key = self.create_nonce_key(username, timestamp)
        used = cache.get(key, [])
        return nonce not in used
