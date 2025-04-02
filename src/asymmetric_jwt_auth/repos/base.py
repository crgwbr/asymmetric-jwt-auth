from django.contrib.auth.models import User

from ..tokens import Token, UntrustedToken


class BaseUserRepository:
    def get_user(self, username: str) -> None | User:  # pragma: no cover
        raise NotImplementedError()


class BasePublicKeyRepository:
    def attempt_to_verify_token(
        self, user: User, untrusted_token: UntrustedToken
    ) -> Token | None:  # pragma: no cover
        raise NotImplementedError()
