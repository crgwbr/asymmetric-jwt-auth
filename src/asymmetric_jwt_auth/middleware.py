from typing import Callable
from django.http import HttpRequest, HttpResponse
from .nonce import get_nonce_backend
from .tokens import UntrustedToken
from .repos import get_user_repository, get_public_key_repositories
from . import get_setting
import logging

logger = logging.getLogger(__name__)


class JWTAuthMiddleware:
    """Django middleware class for authenticating users using JWT Authentication headers"""

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]):
        self.get_response = get_response
        self.nonce_backend = get_nonce_backend()
        self.user_repo = get_user_repository()
        self.key_repos = get_public_key_repositories()


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
        if 'HTTP_AUTHORIZATION' not in request.META:
            return request

        # Ensure this auth header was meant for us (it has the JWT auth method).
        try:
            method, header_data = request.META['HTTP_AUTHORIZATION'].split(' ', 1)
        except ValueError:
            return request

        auth_method_setting = get_setting('AUTH_METHOD')
        if method.upper() != auth_method_setting:
            return request

        # Get the (unvalidated!) username that the request is claiming to be
        untrusted_token = UntrustedToken(header_data)
        username = untrusted_token.get_claimed_username()
        if not username:
            return request

        # Get the user model
        user = self.user_repo.get_user(username=username)
        if not user:
            return request

        # Try and validate the token using a key from the key repo
        verified_token = None
        for repo in self.key_repos:
            verified_token = repo.attempt_to_verify_token(user, untrusted_token)
            if verified_token:
                break

        # No keys successfully validated the claim? Abort.
        if not verified_token:
            return request

        # Assign the user to the request
        logger.debug('Successfully authenticated %s using JWT', user.username)
        request._dont_enforce_csrf_checks = True
        request.user = user
        return request
