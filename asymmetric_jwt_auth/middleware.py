from django.contrib.auth import get_user_model
from django.core.cache import cache
from asymmetric_jwt_auth import AUTH_METHOD
import asymmetric_jwt_auth.token as token
import logging

logger = logging.getLogger(__name__)


class JWTAuthMiddleware(object):
    def create_nonce_key(self, username, iat):
        """Create the cache key for storing nonces"""
        return '%s-nonces-%s-%s' % (
            self.__class__.__name__,
            username,
            iat,
        )


    def log_used_nonce(self, username, iat, nonce):
        key = self.create_nonce_key(username, iat)
        used = cache.get(key, [])
        used.append(nonce)
        cache.set(key, set(used), token.TIMESTAMP_TOLERANCE * 2)


    def validate_nonce(self, username, iat, nonce):
        key = self.create_nonce_key(username, iat)
        used = cache.get(key, [])
        return nonce not in used


    def process_request(self, request):
        if 'HTTP_AUTHORIZATION' not in request.META:
            return

        method, claim = request.META['HTTP_AUTHORIZATION'].split(' ', 1)
        if method.upper() != AUTH_METHOD:
            return

        username = token.get_claimed_username(claim)
        if not username:
            return

        User = get_user_model()
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            return

        claim_data = None
        for public in user.public_keys.all():
            claim_data = token.verify(claim, public.key, validate_nonce=self.validate_nonce)
            if claim_data:
                break
        if not claim_data:
            return

        logging.info('Successfully authenticated %s using JWT', user.username)
        request._dont_enforce_csrf_checks = True
        request.user = user
