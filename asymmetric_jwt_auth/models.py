from django.db import models
from django.contrib.auth.models import User


class PublicKey(models.Model):
    user = models.ForeignKey(User, related_name='public_keys')
    key = models.TextField(help_text="The user's RSA public key")
