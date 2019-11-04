from django.contrib.auth import get_user_model
from django.core.cache import cache
from asymmetric_jwt_auth import AUTH_METHOD
import asymmetric_jwt_auth.token as token
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
        if 'HTTP_AUTHORIZATION' not in request.META:
            return request

        try:
            method, claim = request.META['HTTP_AUTHORIZATION'].split(' ', 1)
        except ValueError:
            return request

        if method.upper() != AUTH_METHOD:
            return request

        username = token.get_claimed_username(claim)
        if not username:
            return request

        User = get_user_model()
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            return request

        claim_data = None
        for public in user.public_keys.all():
            claim_data = token.verify(claim, public.key, validate_nonce=self.validate_nonce)
            if claim_data:
                public.update_last_used_datetime()
                break
        if not claim_data:
            return request

        logger.debug('Successfully authenticated %s using JWT', user.username)
        request._dont_enforce_csrf_checks = True
        request.user = user
        return request


    def create_nonce_key(self, username, iat):
        """
        Create and return the cache key for storing nonces

        :param username: Username as a string.
        :param iat: Unix timestamp float or integer of when the nonce was used.
        :return: Cache key string.
        """
        return '%s-nonces-%s-%s' % (
            self.__class__.__name__,
            username,
            iat,
        )


    def log_used_nonce(self, username, iat, nonce):
        """
        Log a nonce as being used, and therefore henceforth invalid.

        :param username: Username as a string.
        :param iat: Unix timestamp float or integer of when the nonce was used.
        :param nonce: Nonce value.
        """
        # TODO: Figure out some way to do this in a thread-safe manner. It'd be better to use
        # a Redis Set or something, but we don't necessarily want to be tightly coupled to
        # Redis either since not everyone uses it.
        key = self.create_nonce_key(username, iat)
        used = cache.get(key, [])
        used.append(nonce)
        cache.set(key, set(used), token.TIMESTAMP_TOLERANCE * 2)


    def validate_nonce(self, username, iat, nonce):
        """
        Confirm that the given nonce hasn't already been used.

        :param username: Username as a string.
        :param iat: Unix timestamp float or integer of when the nonce was used.
        :param nonce: Nonce value.
        :return: True if nonce is valid, False if it is invalid.
        """
        key = self.create_nonce_key(username, iat)
        used = cache.get(key, [])
        return nonce not in used
