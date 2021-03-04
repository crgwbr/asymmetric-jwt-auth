default_app_config = 'asymmetric_jwt_auth.apps.JWTAuthConfig'

#: Auth method searched for in the prefix of the Authentication header. Similar to ``Bearer`` or ``Basic``.
AUTH_METHOD = 'JWT'

#: Default JWT signing algorithm
DEFAULT_ALGORITHM = 'RS512'

ALLOWED_ALGORITHMS = [
    'RS512',
]

# Number of seconds of clock-drift to tolerate when verifying the authenticity of a JWT.
TIMESTAMP_TOLERANCE = 20  # Seconds


from .utils import (  # NOQA
    generate_rsa_key_pair,
    load_private_key,
    decrypt_key,
    create_auth_header,
)
