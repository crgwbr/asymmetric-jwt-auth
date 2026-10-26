from collections.abc import Iterable
from typing import NamedTuple
import functools

from django.contrib.auth import get_user_model
from django.contrib.auth.models import User
from jwt.exceptions import PyJWKClientError
from jwt.utils import base64url_decode

from .. import jwks, keys, models
from ..tokens import Token, UntrustedToken
from .base import BasePublicKeyRepository, BaseUserRepository

#: Sizes in bits of the RSA decoy keys. Users whose RSA keys have other sizes can still be told apart by timing.
_DECOY_RSA_KEY_SIZES = (2048, 3072, 4096)


class _Decoy(NamedTuple):
    key: keys.FacadePublicKey
    pem: bytes


@functools.cache
def _generate_decoys() -> tuple[dict[int, _Decoy], _Decoy]:
    """
    Public keys whose private halves are thrown away, so no token can ever verify against them: RSA keys by the
    length in bytes of their signatures, and an Ed25519 key. They're generated once per process, before any request
    needs them, because generating one while a request waits would show in that request's response time.
    """
    rsa_decoys: dict[int, _Decoy] = {}
    for size in _DECOY_RSA_KEY_SIZES:
        rsa_key = keys.RSAPrivateKey.generate(size=size).public_key
        rsa_decoys[size // 8] = _Decoy(rsa_key, rsa_key.as_pem)
    ed25519_key = keys.Ed25519PrivateKey.generate().public_key
    return rsa_decoys, _Decoy(ed25519_key, ed25519_key.as_pem)


def _get_decoys(signature_length: int) -> list[_Decoy]:
    """
    One decoy of each key type, for a token whose signature is ``signature_length`` bytes long. Checking a forged
    token against these costs the same as checking it against a real key of the same type, as long as a real RSA key
    is of a size in ``_DECOY_RSA_KEY_SIZES``.

    OpenSSL rejects an RSA signature of the wrong length before doing any math. So the RSA decoy is the one whose
    signatures are as long as the token's, or the smallest when none are, which rejects it just as early. A real RSA
    key of the wrong size is swapped for this decoy (see :func:`_is_wrong_size`), so it costs the same.
    """
    rsa_decoys, ed25519_decoy = _generate_decoys()
    smallest = rsa_decoys[_DECOY_RSA_KEY_SIZES[0] // 8]
    return [rsa_decoys.get(signature_length, smallest), ed25519_decoy]


def _get_signature_length(untrusted_token: UntrustedToken) -> int:
    try:
        return len(base64url_decode(untrusted_token.token.rpartition(".")[2]))
    except ValueError:
        return 0


def _is_wrong_size(public_key: keys.FacadePublicKey, signature_length: int) -> bool:
    """
    Whether ``public_key`` is an RSA key that would reject a signature ``signature_length`` bytes long before doing any
    math, so it can't verify the token.
    """
    return isinstance(public_key, keys.RSAPublicKey) and (public_key.key_size + 7) // 8 != signature_length


class DjangoUserRepository(BaseUserRepository):
    def __init__(self) -> None:
        self.User = get_user_model()

    def get_user(self, username: str) -> None | User:
        """
        Get a Django user by username
        """
        try:
            return self.User.objects.get(username=username)
        except self.User.DoesNotExist:
            pass
        return None


class DjangoPublicKeyListRepository(BasePublicKeyRepository):
    supported_algorithms = keys.SUPPORTED_ALGORITHMS

    def __init__(self) -> None:
        _generate_decoys()

    def attempt_to_verify_token(
        self,
        user: User,
        untrusted_token: UntrustedToken,
    ) -> Token | None:
        """
        Attempt to verify a JWT for the given user using public keys from the PublicKey model.
        """
        match = self._verify(models.PublicKey.objects.filter(user=user), untrusted_token)
        if match is None:
            return None
        token, user_key = match
        user_key.update_last_used_datetime()
        return token

    def simulate_attempt_to_verify_token(self, username: str, untrusted_token: UntrustedToken) -> None:
        self._verify(models.PublicKey.objects.filter(user__isnull=True), untrusted_token)

    def _verify(
        self,
        user_keys: Iterable[models.PublicKey],
        untrusted_token: UntrustedToken,
    ) -> tuple[Token, models.PublicKey] | None:
        # Users with no key of some type get checked against a decoy of that type instead, so the work done
        # doesn't depend on which keys (if any) the claimed user has.
        signature_length = _get_signature_length(untrusted_token)
        decoys = _get_decoys(signature_length)
        key_types: set[type[keys.FacadePublicKey]] = set()
        for user_key in user_keys:
            public_key = user_key.get_key()
            key_types.add(type(public_key))
            if _is_wrong_size(public_key, signature_length):
                public_key = decoys[0].key
            token = untrusted_token.verify(public_key=public_key)
            if token:
                return token, user_key
        for decoy in decoys:
            if type(decoy.key) not in key_types:
                untrusted_token.verify(public_key=keys.PublicKey.load_pem(decoy.pem))
        return None


class DjangoJWKSRepository(BasePublicKeyRepository):
    supported_algorithms = keys.SUPPORTED_ALGORITHMS

    def __init__(self) -> None:
        _generate_decoys()

    def attempt_to_verify_token(
        self,
        user: User,
        untrusted_token: UntrustedToken,
    ) -> Token | None:
        """
        Attempt to verify a JWT for the given user using public keys the user's JWKS endpoint.
        """
        match = self._verify(models.JWKSEndpointTrust.objects.filter(user=user), untrusted_token)
        if match is None:
            return None
        token, jwks_endpoint = match
        jwks_endpoint.update_last_used_datetime()
        return token

    def simulate_attempt_to_verify_token(self, username: str, untrusted_token: UntrustedToken) -> None:
        self._verify(models.JWKSEndpointTrust.objects.filter(user__isnull=True), untrusted_token)

    def _verify(
        self,
        jwks_endpoints: Iterable[models.JWKSEndpointTrust],
        untrusted_token: UntrustedToken,
    ) -> tuple[Token, models.JWKSEndpointTrust] | None:
        # Every path does one cache read and one signature check, whether or not a matching key is found
        signature_length = _get_signature_length(untrusted_token)
        decoy_key = self._get_decoy_key(untrusted_token, signature_length)
        endpoints = list(jwks_endpoints)
        if not endpoints:
            jwks.read_decoy()
            untrusted_token.verify(public_key=decoy_key)
        for jwks_endpoint in endpoints:
            try:
                public_key = jwks_endpoint.get_signing_key(untrusted_token)
            except PyJWKClientError:
                public_key = decoy_key
            else:
                # A key that can't verify the token's alg or signature length would reject it before any signature math
                if not untrusted_token.has_supported_algorithm(public_key.allowed_algorithms) or _is_wrong_size(public_key, signature_length):
                    public_key = decoy_key
            token = untrusted_token.verify(public_key=public_key)
            if token:
                return token, jwks_endpoint
        return None

    def _get_decoy_key(self, untrusted_token: UntrustedToken, signature_length: int) -> keys.FacadePublicKey:
        decoys = _get_decoys(signature_length)
        for decoy in decoys:
            if untrusted_token.has_supported_algorithm(decoy.key.allowed_algorithms):
                return decoy.key
        return decoys[0].key
