from typing import Union
from django.contrib.auth.models import User
from ..tokens import UntrustedToken, Token


class BaseUserRepository:
    def get_user(self, username: str) -> Union[None, User]:  # pragma: no cover
        raise NotImplementedError()


class BasePublicKeyRepository:
    def attempt_to_verify_token(self, user: User, untrusted_token: UntrustedToken) -> Union[Token, None]:  # pragma: no cover
        raise NotImplementedError()
