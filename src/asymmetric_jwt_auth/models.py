from django.conf import settings
from django.db import models
from django.utils import timezone
from django.core.exceptions import ValidationError
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_ssh_public_key
from cryptography.hazmat.backends import default_backend


def validate_public_key(value):
    """
    Check that the given value is a valid RSA Public key in either PEM or OpenSSH format. If it is invalid,
    raises ``django.core.exceptions.ValidationError``.
    """
    is_valid = False
    exc = None

    for load in (load_pem_public_key, load_ssh_public_key):
        if not is_valid:
            try:
                load(value.encode('utf-8'), default_backend())
                is_valid = True
            except Exception as e:
                exc = e

    if not is_valid:
        raise ValidationError('Public key is invalid: %s' % exc)


class PublicKey(models.Model):
    """
    Store a public key and associate it to a particular user.

    Implements the same concept as the OpenSSH ``~/.ssh/authorized_keys`` file on a Unix system.
    """

    #: Foreign key to the Django User model. Related name: ``public_keys``.
    user = models.ForeignKey(settings.AUTH_USER_MODEL, related_name='public_keys', on_delete=models.CASCADE)

    #: Key text in either PEM or OpenSSH format.
    key = models.TextField(help_text="The user's RSA public key", validators=[validate_public_key])

    #: Comment describing the key. Use this to note what system is authenticating with the key, when it was last rotated, etc.
    comment = models.CharField(max_length=100, help_text="Comment describing this key", blank=True)

    #: Date and time that key was last used for authenticating a request.
    last_used_on = models.DateTimeField("Last Used On", null=True, blank=True)


    def update_last_used_datetime(self):
        self.last_used_on = timezone.now()
        self.save(update_fields=["last_used_on"])


    def save(self, *args, **kwargs):
        key_parts = self.key.split(' ')
        if len(key_parts) == 3 and not self.comment:
            self.comment = key_parts.pop()
        super(PublicKey, self).save(*args, **kwargs)
