from typing import Union
from django.contrib.auth import get_user_model
from django.contrib.auth.models import User
from jwt.exceptions import PyJWKClientError
from .base import BaseUserRepository, BasePublicKeyRepository
from ..tokens import UntrustedToken, Token
from .. import models



class DjangoUserRepository(BaseUserRepository):
    def __init__(self):
        self.User = get_user_model()

    def get_user(self, username: str) -> Union[None, User]:
        """
        Get a Django user by username
        """
        try:
            return self.User.objects.get(username=username)
        except self.User.DoesNotExist:
            pass
        return None



class DjangoPublicKeyListRepository(BasePublicKeyRepository):
    def attempt_to_verify_token(self, user: User, untrusted_token: UntrustedToken) -> Union[Token, None]:
        """
        Attempt to verify a JWT for the given user using public keys from the PublicKey model.
        """
        for user_key in models.PublicKey.objects.filter(user=user).all():
            public_key = user_key.get_key()
            token = untrusted_token.verify(
                public_key=public_key)
            if token:
                user_key.update_last_used_datetime()
                return token
        return None



class DjangoJWKSRepository(BasePublicKeyRepository):
    def attempt_to_verify_token(self, user: User, untrusted_token: UntrustedToken) -> Union[Token, None]:
        """
        Attempt to verify a JWT for the given user using public keys the user's JWKS endpoint.
        """
        jwks_endpoint = models.JWKSEndpointTrust.objects.filter(user=user).first()
        if not jwks_endpoint:
            return None
        try:
            public_key = jwks_endpoint.get_signing_key(untrusted_token)
        except PyJWKClientError:
            return None
        token = untrusted_token.verify(
            public_key=public_key)
        if token:
            return token
        return None
