from django.conf import settings
from django.db import models
from django.utils import timezone
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jwt import PyJWKClient
from .token import load_serialized_public_key


def validate_public_key(keystr):
    """
    Check that the given value is a valid RSA Public key in either PEM or OpenSSH format. If it is invalid,
    raises ``django.core.exceptions.ValidationError``.
    """
    exc, key = load_serialized_public_key(keystr)
    is_valid = (exc is None) and (key is not None)
    if not is_valid:
        raise ValidationError('Public key is invalid: %s' % exc)


class PublicKey(models.Model):
    """
    Store a public key and associate it to a particular user.

    Implements the same concept as the OpenSSH ``~/.ssh/authorized_keys`` file on a Unix system.
    """

    #: Foreign key to the Django User model. Related name: ``public_keys``.
    user = models.ForeignKey(settings.AUTH_USER_MODEL,
        verbose_name=_("User"),
        related_name='public_keys',
        on_delete=models.CASCADE)

    #: Key text in either PEM or OpenSSH format.
    key = models.TextField(_("Public Key"),
        help_text=_("The user's RSA public key"),
        validators=[validate_public_key])

    #: Comment describing the key. Use this to note what system is authenticating with the key, when it was last rotated, etc.
    comment = models.CharField(_("Comment"),
        max_length=100,
        help_text=_("Comment describing this key"),
        blank=True)

    #: Date and time that key was last used for authenticating a request.
    last_used_on = models.DateTimeField(_("Last Used On"),
        null=True,
        blank=True)

    class Meta:
        verbose_name = _("Public Key")
        verbose_name_plural = _("Public Keys")

    def get_allowed_algorithms(self):
        pubkey = self.get_loaded_key()
        if isinstance(pubkey, Ed25519PublicKey):
            return [
                'EdDSA',
            ]
        return [
            'RS384',
            'RS256',
            'RS512',
        ]

    def get_loaded_key(self):
        exc, key = load_serialized_public_key(self.key)
        if exc is not None and key is None:
            raise exc
        return key

    def update_last_used_datetime(self):
        self.last_used_on = timezone.now()
        self.save(update_fields=["last_used_on"])

    def save(self, *args, **kwargs):
        key_parts = self.key.split(' ')
        if len(key_parts) == 3 and not self.comment:
            self.comment = key_parts.pop()
        super(PublicKey, self).save(*args, **kwargs)


class JWKSEndpointTrust(models.Model):
    """
    Associate a JSON Web Key Set (JWKS) URL with a Django User.

    This accomplishes the same purpose of the PublicKey model, in a more automated
    fashion. Instead of manually assigning a public key to a user, the system will
    load a list of public keys from this URL.
    """

    #: Foreign key to the Django User model. Related name: ``public_keys``.
    user = models.OneToOneField(settings.AUTH_USER_MODEL,
        verbose_name=_("User"),
        related_name='jwks_endpoint',
        on_delete=models.CASCADE)

    #: URL of the JSON Web Key Set (JWKS)
    jwks_url = models.URLField(_("JSON Web Key Set (JWKS) URL"),
        help_text=_("e.g. https://dev-87evx9ru.auth0.com/.well-known/jwks.json"))

    class Meta:
        verbose_name = _("JSON Web Key Set")
        verbose_name_plural = _("JSON Web Key Sets")


    @property
    def jwks_client(self):
        return PyJWKClient(self.jwks_url)


    def get_signing_key(self, claim):
        return self.jwks_client.get_signing_key_from_jwt(claim)
