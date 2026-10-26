from typing import Any
import copy

from django.conf import settings

#: Default settings. Override using a dictionary named ASYMMETRIC_JWT_AUTH in Django's settings.py.
default_settings = {
    #: Auth method searched for in the prefix of the Authentication header. Similar to ``Bearer`` or ``Basic``.
    "AUTH_METHOD": "JWT",
    #: Number of seconds of clock-drift to tolerate when verifying the authenticity of a JWT.
    "TIMESTAMP_TOLERANCE": 20,  # Seconds
    #: Class used to store and validate nonces
    "NONCE_BACKEND": "asymmetric_jwt_auth.nonce.django.DjangoCacheNonceBackend",
    #: Repository class used to fetch users by their username
    "USER_REPOSITORY": "asymmetric_jwt_auth.repos.django.DjangoUserRepository",
    #: List of repository classes used to fetch public keys for a user
    "PUBLIC_KEY_REPOSITORIES": [
        "asymmetric_jwt_auth.repos.django.DjangoJWKSRepository",
        "asymmetric_jwt_auth.repos.django.DjangoPublicKeyListRepository",
    ],
    #: List of public keys that should be advertised on our JWKS endpoint.
    "SIGNING_PUBLIC_KEYS": [],
    #: Cache TTL for the JWKS key view
    "JWKS_VIEW_TTL": (60 * 5),
    #: Age in seconds at which a key set fetched from a trusted JWKS endpoint is refreshed in the background.
    "JWKS_CACHE_TTL": (60 * 5),
    #: Seconds after its last successful fetch that a key set stops being trusted. This bounds how long a key
    #: removed from a JWKS endpoint keeps working if refreshes stop.
    "JWKS_CACHE_MAX_AGE": (60 * 60),
    #: Minimum seconds between refreshes of one JWKS endpoint, e.g. after a token names an unknown key ID.
    "JWKS_REFRESH_COOLDOWN": 30,
    #: Seconds a whole JWKS download may take. Keep it well below ``JWKS_REFRESH_COOLDOWN``, since one slow endpoint
    #: holds up every other refresh queued in the same process.
    "JWKS_FETCH_TIMEOUT": 5,
    #: Largest JWKS response, in bytes and headers included, that is accepted.
    "JWKS_MAX_RESPONSE_BYTES": 1024 * 1024,
}


def get_setting(name: str) -> Any:
    _settings = copy.deepcopy(default_settings)
    _settings.update(getattr(settings, "ASYMMETRIC_JWT_AUTH", {}))
    return _settings[name]
