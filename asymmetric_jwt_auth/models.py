from django.conf import settings
from django.db import models
from django.contrib.auth.models import User


class PublicKey(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, related_name='public_keys')
    key = models.TextField(help_text="The user's RSA public key")
    comment = models.CharField(max_length=100, help_text="Comment describing this key", blank=True)

    def save(self, *args, **kwargs):
        key_parts = self.key.split(' ')
        if len(key_parts) == 3 and not self.comment:
            self.comment = key_parts.pop()

        super(PublicKey, self).save(*args, **kwargs)
