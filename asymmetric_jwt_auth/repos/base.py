from django.contrib.auth.models import User

from ..tokens import Token, UntrustedToken


class BaseUserRepository:
    def get_user(self, username: str) -> None | User:  # pragma: no cover
        raise NotImplementedError()


class BasePublicKeyRepository:
    #: JWT signing algorithms this repository can verify, or ``None`` if it may verify any. When every configured
    #: repository declares a set, tokens using an algorithm none of them support are rejected before their
    #: claimed user is looked up.
    supported_algorithms: frozenset[str] | None = None

    def attempt_to_verify_token(self, user: User, untrusted_token: UntrustedToken) -> Token | None:  # pragma: no cover
        raise NotImplementedError()

    def simulate_attempt_to_verify_token(self, username: str, untrusted_token: UntrustedToken) -> None:
        """
        Called in place of :meth:`attempt_to_verify_token` when the token's claimed username matches no user.

        Override this to do the same work :meth:`attempt_to_verify_token` does for a user with no keys, without
        reading any real user's keys, so that response times don't reveal which usernames exist. The default does
        nothing.
        """
