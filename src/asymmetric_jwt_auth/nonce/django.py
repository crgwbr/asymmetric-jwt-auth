from django.core.cache import cache
from django.conf import settings
from .. import default_settings
from . import BaseNonceBackend


class DjangoCacheNonceBackend(BaseNonceBackend):
    """
    Nonce backend which uses DJango's cache system.

    Simple, but not great. Prone to race conditions.
    """

    def validate_nonce(self, username: str, timestamp: int, nonce: str) -> bool:
        """
        Confirm that the given nonce hasn't already been used.
        """
        key = self._create_nonce_key(username, timestamp)
        used = cache.get(key, set([]))
        return nonce not in used


    def log_used_nonce(self, username: str, timestamp: int, nonce: str) -> None:
        """
        Log a nonce as being used, and therefore henceforth invalid.
        """
        key = self._create_nonce_key(username, timestamp)
        used = cache.get(key, set([]))
        used.add(nonce)
        timestamp_tolerance = getattr(settings, 'ASYMMETRIC_JWT_AUTH', default_settings)['TIMESTAMP_TOLERANCE']
        cache.set(key, used, timestamp_tolerance * 2)


    def _create_nonce_key(self, username: str, timestamp: int) -> str:
        """
        Create and return the cache key for storing nonces
        """
        return '%s-nonces-%s-%s' % (
            self.__class__.__name__,
            username,
            timestamp,
        )
