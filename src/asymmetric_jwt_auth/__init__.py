from django.conf import settings
import copy

default_app_config = 'asymmetric_jwt_auth.apps.JWTAuthConfig'

#: Default settings. Override using a dictionary named ASYMMETRIC_JWT_AUTH in Django's settings.py.
default_settings = {
    #: Auth method searched for in the prefix of the Authentication header. Similar to ``Bearer`` or ``Basic``.
    'AUTH_METHOD': 'JWT',

    #: Number of seconds of clock-drift to tolerate when verifying the authenticity of a JWT.
    'TIMESTAMP_TOLERANCE': 20,  # Seconds

    #: Class used to store and validate nonces
    'NONCE_BACKEND': 'asymmetric_jwt_auth.nonce.django.DjangoCacheNonceBackend',

    #: Repository class used to fetch users by their username
    'USER_REPOSITORY': 'asymmetric_jwt_auth.repos.django.DjangoUserRepository',

    #: List of repository classes used to fetch public keys for a user
    'PUBLIC_KEY_REPOSITORIES': [
        'asymmetric_jwt_auth.repos.django.DjangoPublicKeyListRepository',
        'asymmetric_jwt_auth.repos.django.DjangoJWKSRepository',
    ],

    #: List of public keys that should be advertised on our JWKS endpoint.
    'SIGNING_PUBLIC_KEYS': [],

    #: Cache TTL for the JWKS key view
    'JWKS_VIEW_TTL': (60 * 5),
}


def get_setting(name: str):
    _settings = copy.deepcopy(default_settings)
    _settings.update(getattr(settings, 'ASYMMETRIC_JWT_AUTH', {}))
    return _settings[name]
