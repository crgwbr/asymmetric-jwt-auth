default_app_config = 'asymmetric_jwt_auth.apps.JWTAuthConfig'

#: Default settings. Override using a dictionary named ASYMMETRIC_JWT_AUTH in Django's settings.py.
default_settings = {
    #: Default JWT signing algorithm
    'DEFAULT_ALGORITHM': 'RS512',

    #: Auth method searched for in the prefix of the Authentication header. Similar to ``Bearer`` or ``Basic``.
    'AUTH_METHOD': 'JWT',

    # Number of seconds of clock-drift to tolerate when verifying the authenticity of a JWT.
    'TIMESTAMP_TOLERANCE': 20,  # Seconds
}

from .utils import (  # NOQA
    generate_rsa_key_pair,
    load_private_key,
    decrypt_key,
    create_auth_header,
)
