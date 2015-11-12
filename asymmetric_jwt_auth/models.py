from django.conf import settings
from django.db import models
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_ssh_public_key
from cryptography.hazmat.backends import default_backend


def validate_public_key(value):
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
    user = models.ForeignKey(settings.AUTH_USER_MODEL, related_name='public_keys')
    key = models.TextField(help_text="The user's RSA public key", validators=[validate_public_key])
    comment = models.CharField(max_length=100, help_text="Comment describing this key", blank=True)

    def save(self, *args, **kwargs):
        key_parts = self.key.split(' ')
        if len(key_parts) == 3 and not self.comment:
            self.comment = key_parts.pop()

        super(PublicKey, self).save(*args, **kwargs)
