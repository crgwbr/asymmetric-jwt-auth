from django.conf import settings
from django.db import models
from django.utils import timezone
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
from django.utils.encoding import force_str, force_bytes
from jwt import PyJWKClient
from . import keys, tokens



def validate_public_key(keystr: str) -> None:
    """
    Check that the given value is a valid public key in either PEM or OpenSSH format. If it is invalid,
    raises ``django.core.exceptions.ValidationError``.
    """
    key_bytes = keystr.encode()
    exc, key = keys.PublicKey.load_serialized_public_key(key_bytes)
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
        help_text=_("The user's RSA/Ed25519 public key"),
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


    def get_key(self) -> keys.FacadePublicKey:
        key_bytes = force_bytes(self.key)
        exc, key = keys.PublicKey.load_serialized_public_key(key_bytes)
        if key is None:
            if exc is None:  # pragma: no cover
                raise ValueError("Failed to load key")
            raise exc
        return key


    def update_last_used_datetime(self) -> None:
        self.last_used_on = timezone.now()
        self.save(update_fields=["last_used_on"])


    def save(self, *args, **kwargs) -> None:
        key_parts = force_str(self.key).split(' ')
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
    def jwks_client(self) -> PyJWKClient:
        return PyJWKClient(self.jwks_url)


    def get_signing_key(self, untrusted_token: tokens.UntrustedToken) -> keys.PublicKey:
        jwk = self.jwks_client.get_signing_key_from_jwt(untrusted_token.token)
        return keys.PublicKey.from_cryptography_pubkey(jwk.key)
