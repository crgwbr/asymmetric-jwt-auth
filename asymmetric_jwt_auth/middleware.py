from collections.abc import Callable
import logging

from django.http import HttpRequest, HttpResponse

from . import get_setting
from .nonce import get_nonce_backend
from .repos import get_public_key_repositories, get_user_repository
from .tokens import UntrustedToken

logger = logging.getLogger(__name__)


class JWTAuthMiddleware:
    """Django middleware class for authenticating users using JWT Authentication headers"""

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]):
        self.get_response = get_response
        self.nonce_backend = get_nonce_backend()
        self.user_repo = get_user_repository()
        self.key_repos = get_public_key_repositories()
        self.supported_algorithms = self._get_supported_algorithms()

    def _get_supported_algorithms(self) -> frozenset[str] | None:
        """
        The algorithms some configured key repository can verify, or ``None`` if any repository may verify any.
        """
        algorithm_sets: list[frozenset[str] | None] = [getattr(repo, "supported_algorithms", None) for repo in self.key_repos]
        if any(algorithms is None for algorithms in algorithm_sets):
            return None
        return frozenset[str]().union(*(algorithms for algorithms in algorithm_sets if algorithms is not None))

    def __call__(self, request: HttpRequest) -> HttpResponse:
        # Attempt to authorize the request
        self.authorize_request(request)
        # Continue with the request
        return self.get_response(request)

    def authorize_request(self, request: HttpRequest) -> HttpRequest:
        """
        Process a Django request and authenticate users.

        If a JWT authentication header is detected and it is determined to be valid, the user is set as
        ``request.user`` and CSRF protection is disabled (``request._dont_enforce_csrf_checks = True``) on
        the request.

        :param request: Django Request instance
        """
        # Check for presence of auth header
        if "authorization" not in request.headers:
            logger.debug(
                "Exiting JWTAuthMiddleware because request does not contain authorization header",
            )
            return request

        # Ensure this auth header was meant for us (it has the JWT auth method).
        try:
            method, header_data = request.headers["authorization"].split(" ", 1)
        except ValueError as e:
            logger.debug(
                "Exiting JWTAuthMiddleware because authorization header is malformed. %s",
                str(e),
            )
            return request

        auth_method_setting = get_setting("AUTH_METHOD")
        if method.upper() != auth_method_setting:
            logger.debug(
                "Exiting JWTAuthMiddleware because header method [%s] does not match expected [%s]",
                method.upper(),
                auth_method_setting,
            )
            return request

        untrusted_token = UntrustedToken(header_data)
        # Not needed for equal timing (the decoy checks cover that), but it skips the DB for junk tokens
        if self.supported_algorithms is not None and not untrusted_token.has_supported_algorithm(self.supported_algorithms):
            logger.debug(
                "Exiting JWTAuthMiddleware because JWT is malformed or does not use a supported signing algorithm. jwt:[%s]",
                header_data,
            )
            return request

        # Get the (unvalidated!) username that the request is claiming to be
        username = untrusted_token.get_claimed_username()
        if not username:
            logger.debug(
                "Exiting JWTAuthMiddleware because JWT did not contain a username claim. jwt:[%s]",
                header_data,
            )
            return request

        # Get the user model
        user = self.user_repo.get_user(username=username)
        if not user:
            # Do the key lookups a real user would get, so the response time doesn't reveal whether the user exists
            for repo in self.key_repos:
                simulate = getattr(repo, "simulate_attempt_to_verify_token", None)
                if simulate is not None:
                    simulate(username, untrusted_token)
            logger.debug(
                "Exiting JWTAuthMiddleware because claimed username [%s] did not match any known users.",
                username,
            )
            return request

        # Try and validate the token using a key from the key repo
        verified_token = None
        for repo in self.key_repos:
            verified_token = repo.attempt_to_verify_token(user, untrusted_token)
            if verified_token:
                break

        # No keys successfully validated the claim? Abort.
        if not verified_token:
            logger.debug(
                "Exiting JWTAuthMiddleware because JWT verification failed for claimed user [%s]. jwt:[%s]",
                username,
                header_data,
            )
            return request

        # Assign the user to the request
        logger.debug("Successfully authenticated %s using JWT", user.username)
        request._dont_enforce_csrf_checks = True  # type:ignore[attr-defined]
        request.user = user
        return request
