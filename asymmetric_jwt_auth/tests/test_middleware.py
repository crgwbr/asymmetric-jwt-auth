from datetime import timedelta
from unittest import mock
import base64
import json
import time

from django.contrib.auth.models import User
from django.core.cache import cache
from django.db import connection
from django.http import HttpRequest
from django.test import RequestFactory, TestCase
from django.test.utils import CaptureQueriesContext
from freezegun import freeze_time
from jwt.api_jws import PyJWS
from jwt.exceptions import PyJWKClientConnectionError

from .. import jwks
from ..keys import (
    Ed25519PrivateKey,
    FacadePrivateKey,
    FacadePublicKey,
    RSAPrivateKey,
    RSAPublicKey,
)
from ..middleware import JWTAuthMiddleware
from ..models import JWKSEndpointTrust, PublicKey
from ..tokens import Token, UntrustedToken


def _b64(data: dict[str, object]) -> str:
    return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()


def forged_auth_header(username: str, alg: object, kid: str | None = None, signature_length: int | None = None) -> str:
    """Build an auth header whose JWT claims ``username`` and names ``alg``, signed with no key we trust"""
    header = {"typ": "JWT", "alg": alg}
    if kid is not None:
        header["kid"] = kid
    payload = {"username": username, "time": int(time.time()), "nonce": "forged"}
    signature = _b64({"sig": "forged"})
    if signature_length is not None:
        signature = base64.urlsafe_b64encode(b"\x01" * signature_length).rstrip(b"=").decode()
    return f"JWT {_b64(header)}.{_b64(payload)}.{signature}"


def _describe_key(public_key: FacadePublicKey) -> str:
    return f"RSA-{public_key.key_size}" if isinstance(public_key, RSAPublicKey) else "Ed25519"


class BaseMiddlewareTest(TestCase):
    rfactory: RequestFactory
    run_middleware: JWTAuthMiddleware
    refresh_worker: mock.MagicMock

    def setUp(self) -> None:
        refresh_worker = mock.patch.object(jwks, "_refresh_worker")
        self.refresh_worker = refresh_worker.start()
        self.addCleanup(refresh_worker.stop)
        cache.clear()
        jwks._signing_keys_by_url.clear()
        jwks._last_refresh_by_url.clear()

    def run_counting_work(self, header: str) -> tuple[int, int, int]:
        """Run the middleware, returning the number of DB queries, cache reads, and signature checks it made"""
        request = self.rfactory.get("/", HTTP_AUTHORIZATION=header)
        with (
            CaptureQueriesContext(connection) as queries,
            mock.patch.object(jwks, "cache", mock.MagicMock(wraps=cache)) as counted_cache,
            mock.patch.object(UntrustedToken, "verify", autospec=True, side_effect=UntrustedToken.verify) as counted_verify,
        ):
            self.run_middleware(request)
        self.assertNotLoggedIn(request)
        return len(queries), counted_cache.get.call_count, counted_verify.call_count

    def checked_keys(self, header: str) -> list[str]:
        """Run the middleware, returning the type and size of each key it checked a signature against"""
        request = self.rfactory.get("/", HTTP_AUTHORIZATION=header)
        with mock.patch.object(UntrustedToken, "verify", autospec=True, side_effect=UntrustedToken.verify) as verify:
            self.run_middleware(request)
        self.assertNotLoggedIn(request)
        return sorted(_describe_key(call.kwargs["public_key"]) for call in verify.call_args_list)

    def assertNotLoggedIn(self, request):
        self.assertEqual(getattr(request, "user", None), None)

    def assertLoggedIn(self, request, public_key=None):
        if public_key:
            public_key.refresh_from_db()
            self.assertIsNotNone(public_key.last_used_on)
        self.assertEqual(getattr(request, "user", None), self.user)


class MiddlewareTest(BaseMiddlewareTest):
    def setUp(self):
        super().setUp()
        self.rfactory = RequestFactory()
        self.user = User.objects.create_user(username="foo")
        self.user2 = User.objects.create_user(username="bar")

        self.key_ed25519 = Ed25519PrivateKey.generate()
        self.key_rsa = RSAPrivateKey.generate()

        self.user_key_ed25519 = PublicKey.objects.create(user=self.user, key=self.key_ed25519.public_key.as_pem.decode())
        self.user_key_rsa = PublicKey.objects.create(user=self.user, key=self.key_rsa.public_key.as_pem.decode())

        self.next_middleware = mock.MagicMock()
        self.run_middleware = JWTAuthMiddleware(self.next_middleware)

    def test_no_auth_header(self):
        request = self.rfactory.get("/")
        self.assertNotLoggedIn(request)
        self.run_middleware(request)
        self.assertNotLoggedIn(request)
        self.assertEqual(self.next_middleware.call_count, 1)

    def test_auth_header_missing_type(self):
        request = self.rfactory.get("/", HTTP_AUTHORIZATION="Fooopbar")
        self.assertNotLoggedIn(request)
        self.run_middleware(request)
        self.assertNotLoggedIn(request)
        self.assertEqual(self.next_middleware.call_count, 1)

    def test_auth_header_not_jwt_type(self):
        request = self.rfactory.get("/", HTTP_AUTHORIZATION="Bearer foobar")
        self.assertNotLoggedIn(request)
        self.run_middleware(request)
        self.assertNotLoggedIn(request)
        self.assertEqual(self.next_middleware.call_count, 1)

    def test_header_jwt_missing_username(self):
        header = Token("").create_auth_header(self.key_rsa)
        request = self.rfactory.get("/", HTTP_AUTHORIZATION=header)
        self.assertNotLoggedIn(request)
        self.run_middleware(request)
        self.assertNotLoggedIn(request)
        self.assertEqual(self.next_middleware.call_count, 1)

    def test_header_jwt_claimed_username_doesnt_exist(self):
        header = Token("rusty").create_auth_header(self.key_rsa)
        request = self.rfactory.get("/", HTTP_AUTHORIZATION=header)
        self.assertNotLoggedIn(request)
        self.run_middleware(request)
        self.assertNotLoggedIn(request)
        self.assertEqual(self.next_middleware.call_count, 1)

    def test_unsupported_algorithm_rejected_before_user_lookup(self) -> None:
        for alg in ("none", "HS256", ["RS256"], None):
            for username in (self.user.username, "rusty"):
                with self.subTest(alg=alg, username=username):
                    request = self.rfactory.get("/", HTTP_AUTHORIZATION=forged_auth_header(username, alg))
                    with self.assertNumQueries(0):
                        self.run_middleware(request)
                    self.assertNotLoggedIn(request)
        self.assertEqual(self.next_middleware.call_count, 8)

    def test_custom_repository_algorithms(self) -> None:
        repo = mock.MagicMock(supported_algorithms=frozenset(["HS256"]))
        repo.attempt_to_verify_token.return_value = None
        with mock.patch("asymmetric_jwt_auth.middleware.get_public_key_repositories", return_value=[repo]):
            run_middleware = JWTAuthMiddleware(self.next_middleware)
        request = self.rfactory.get("/", HTTP_AUTHORIZATION=forged_auth_header(self.user.username, "HS256"))
        run_middleware(request)
        self.assertNotLoggedIn(request)
        repo.attempt_to_verify_token.assert_called_once()
        self.assertEqual(self.next_middleware.call_count, 1)

    def test_unknown_user_simulates_key_lookups(self) -> None:
        repo = mock.MagicMock(supported_algorithms=frozenset(["EdDSA"]))
        with mock.patch("asymmetric_jwt_auth.middleware.get_public_key_repositories", return_value=[repo]):
            run_middleware = JWTAuthMiddleware(self.next_middleware)
        request = self.rfactory.get("/", HTTP_AUTHORIZATION=forged_auth_header("rusty", "EdDSA"))
        run_middleware(request)
        self.assertNotLoggedIn(request)
        repo.attempt_to_verify_token.assert_not_called()
        repo.simulate_attempt_to_verify_token.assert_called_once()
        self.assertEqual(repo.simulate_attempt_to_verify_token.call_args.args[0], "rusty")

    def test_forged_token_does_same_work_for_real_and_unknown_users(self) -> None:
        for alg in ("RS256", "EdDSA"):
            for kid in (None, "forged"):
                with self.subTest(alg=alg, kid=kid):
                    real = self.run_counting_work(forged_auth_header(self.user.username, alg, kid))
                    unknown = self.run_counting_work(forged_auth_header("rusty", alg, kid))
                    self.assertEqual(real, unknown)
                    self.assertEqual(real, (3, 1, 3))

    def test_forged_token_does_same_work_for_user_with_one_key(self) -> None:
        self.user_key_ed25519.delete()
        for alg in ("RS256", "EdDSA"):
            with self.subTest(alg=alg):
                real = self.run_counting_work(forged_auth_header(self.user.username, alg))
                unknown = self.run_counting_work(forged_auth_header("rusty", alg))
                self.assertEqual(real, unknown)

    def test_forged_rsa_signature_is_checked_against_same_size_keys_for_real_and_unknown_users(self) -> None:
        self.user_key_rsa.delete()
        for bits in (2048, 3072, 4096):
            user_key = PublicKey.objects.create(user=self.user, key=RSAPrivateKey.generate(size=bits).public_key.as_pem.decode())
            for signature_length in (None, 256, 384, 512):
                with self.subTest(bits=bits, signature_length=signature_length):
                    real = self.checked_keys(forged_auth_header(self.user.username, "RS256", signature_length=signature_length))
                    unknown = self.checked_keys(forged_auth_header("rusty", "RS256", signature_length=signature_length))
                    self.assertEqual(real, unknown)
                    expected_size = 8 * signature_length if signature_length else 2048
                    # One RSA check for each repository: stored keys and JWKS
                    self.assertEqual(real, ["Ed25519", f"RSA-{expected_size}", f"RSA-{expected_size}"])
            user_key.delete()

    def test_authenticate_request_rsa_4096_valid(self) -> None:
        key = RSAPrivateKey.generate(size=4096)
        PublicKey.objects.create(user=self.user, key=key.public_key.as_pem.decode())
        request = self.rfactory.get("/", HTTP_AUTHORIZATION=Token(self.user.username).create_auth_header(key))
        self.run_middleware(request)
        self.assertLoggedIn(request)

    def test_repository_without_declared_algorithms_disables_algorithm_check(self) -> None:
        repo = mock.MagicMock(supported_algorithms=None)
        repo.attempt_to_verify_token.return_value = None
        with mock.patch("asymmetric_jwt_auth.middleware.get_public_key_repositories", return_value=[repo]):
            run_middleware = JWTAuthMiddleware(self.next_middleware)
        self.assertIsNone(run_middleware.supported_algorithms)
        request = self.rfactory.get("/", HTTP_AUTHORIZATION=forged_auth_header(self.user.username, "ES256"))
        run_middleware(request)
        self.assertNotLoggedIn(request)
        repo.attempt_to_verify_token.assert_called_once()

    def test_repository_not_subclassing_base(self) -> None:
        class LegacyRepository:
            def attempt_to_verify_token(self, user: User, untrusted_token: UntrustedToken) -> None:
                return None

        with mock.patch("asymmetric_jwt_auth.middleware.get_public_key_repositories", return_value=[LegacyRepository()]):
            run_middleware = JWTAuthMiddleware(self.next_middleware)
        for username in (self.user.username, "rusty"):
            request = self.rfactory.get("/", HTTP_AUTHORIZATION=forged_auth_header(username, "HS256"))
            run_middleware(request)
            self.assertNotLoggedIn(request)
        self.assertEqual(self.next_middleware.call_count, 2)

    def test_authenticate_request_rsa_valid(self):
        header = Token(self.user.username).create_auth_header(self.key_rsa)
        request = self.rfactory.get("/", HTTP_AUTHORIZATION=header)
        self.assertNotLoggedIn(request)
        self.run_middleware(request)
        self.assertLoggedIn(request, self.user_key_rsa)
        self.assertEqual(self.next_middleware.call_count, 1)

    def test_authenticate_request_rsa_unregistered_key(self):
        # Assign the pub keys to user 2
        self.user_key_ed25519.user = self.user2
        self.user_key_ed25519.save()
        self.user_key_rsa.user = self.user2
        self.user_key_rsa.save()
        # Try to use user2's key to login as user1
        header = Token(self.user.username).create_auth_header(self.key_rsa)
        request = self.rfactory.get("/", HTTP_AUTHORIZATION=header)
        self.assertNotLoggedIn(request)
        self.run_middleware(request)
        self.assertNotLoggedIn(request)
        self.assertEqual(self.next_middleware.call_count, 1)

    def test_authenticate_request_ed25519_valid(self):
        header = Token(self.user.username).create_auth_header(self.key_ed25519)
        request = self.rfactory.get("/", HTTP_AUTHORIZATION=header)
        self.assertNotLoggedIn(request)
        self.run_middleware(request)
        self.assertLoggedIn(request, self.user_key_ed25519)
        self.assertEqual(self.next_middleware.call_count, 1)

    def test_missing_data(self):
        header = Token(self.user.username, timestamp=0).create_auth_header(self.key_ed25519)
        request = self.rfactory.get("/", HTTP_AUTHORIZATION=header)
        self.assertNotLoggedIn(request)
        self.run_middleware(request)
        self.assertNotLoggedIn(request)
        self.assertEqual(self.next_middleware.call_count, 1)

    def test_cant_reuse_nonce(self):
        header = Token(self.user.username).create_auth_header(self.key_ed25519)
        # First use works
        request1 = self.rfactory.get("/", HTTP_AUTHORIZATION=header)
        self.assertNotLoggedIn(request1)
        self.run_middleware(request1)
        self.assertLoggedIn(request1, self.user_key_ed25519)
        self.assertEqual(self.next_middleware.call_count, 1)
        # Second use doesn't
        request2 = self.rfactory.get("/", HTTP_AUTHORIZATION=header)
        self.assertNotLoggedIn(request2)
        self.run_middleware(request2)
        self.assertNotLoggedIn(request2)
        self.assertEqual(self.next_middleware.call_count, 2)


class MiddlewareJWKSTest(BaseMiddlewareTest):
    jwks_url = "https://example.com/.well-known/jwks.json"

    def setUp(self):
        super().setUp()
        self.rfactory = RequestFactory()
        self.user = User.objects.create_user(username="foo")

        self.key_ed25519 = Ed25519PrivateKey.generate()
        self.key_rsa = RSAPrivateKey.generate()

        self.next_middleware = mock.MagicMock()
        self.run_middleware = JWTAuthMiddleware(self.next_middleware)

    @mock.patch("asymmetric_jwt_auth.jwks._fetch_jwks")
    def test_authenticate_request_rsa(self, mock_fetch_data):
        mock_fetch_data.return_value = {
            "keys": [
                self.key_rsa.public_key.as_jwk,
            ],
        }
        JWKSEndpointTrust.objects.create(user=self.user, jwks_url=self.jwks_url)
        header = Token(self.user.username).create_auth_header(self.key_rsa)
        request = self.rfactory.get("/", HTTP_AUTHORIZATION=header)
        self.assertNotLoggedIn(request)
        self.run_middleware(request)
        self.assertLoggedIn(request)
        self.assertEqual(self.next_middleware.call_count, 1)

    @mock.patch("asymmetric_jwt_auth.jwks._fetch_jwks")
    def test_no_matching_key(self, mock_fetch_data):
        # Change the key ID of the JWKS response so it doesn't match the kid in the header JWT
        jwk = self.key_rsa.public_key.as_jwk
        jwk["kid"] = "foobar"
        mock_fetch_data.return_value = {
            "keys": [
                jwk,
            ],
        }
        JWKSEndpointTrust.objects.create(user=self.user, jwks_url=self.jwks_url)
        header = Token(self.user.username).create_auth_header(self.key_rsa)
        request = self.rfactory.get("/", HTTP_AUTHORIZATION=header)
        self.assertNotLoggedIn(request)
        self.run_middleware(request)
        self.assertNotLoggedIn(request)
        self.assertEqual(self.next_middleware.call_count, 1)

    @mock.patch("asymmetric_jwt_auth.jwks._fetch_jwks")
    def test_header_jwt_claimed_username_doesnt_exist(self, mock_fetch_data):
        mock_fetch_data.return_value = {
            "keys": [
                self.key_rsa.public_key.as_jwk,
            ],
        }
        JWKSEndpointTrust.objects.create(user=self.user, jwks_url=self.jwks_url)
        header = Token("rusty").create_auth_header(self.key_rsa)
        request = self.rfactory.get("/", HTTP_AUTHORIZATION=header)
        self.assertNotLoggedIn(request)
        self.run_middleware(request)
        self.assertNotLoggedIn(request)
        self.assertEqual(self.next_middleware.call_count, 1)

    @mock.patch("asymmetric_jwt_auth.jwks._fetch_jwks")
    def test_missing_data(self, mock_fetch_data):
        mock_fetch_data.return_value = {
            "keys": [
                self.key_rsa.public_key.as_jwk,
            ],
        }
        JWKSEndpointTrust.objects.create(user=self.user, jwks_url=self.jwks_url)
        header = Token(self.user.username, timestamp=0).create_auth_header(self.key_rsa)
        request = self.rfactory.get("/", HTTP_AUTHORIZATION=header)
        self.assertNotLoggedIn(request)
        self.run_middleware(request)
        self.assertNotLoggedIn(request)
        self.assertEqual(self.next_middleware.call_count, 1)

    @mock.patch("asymmetric_jwt_auth.jwks._fetch_jwks")
    def test_forged_token_does_same_work_for_real_and_unknown_users(self, mock_fetch_data: mock.MagicMock) -> None:
        mock_fetch_data.return_value = {"keys": [self.key_rsa.public_key.as_jwk]}
        JWKSEndpointTrust.objects.create(user=self.user, jwks_url=self.jwks_url)
        self.authenticate(self.key_rsa)
        self.assertEqual(mock_fetch_data.call_count, 1)
        with mock.patch.object(jwks, "_queue_refresh") as mock_start_refresh:
            for kid in (None, "forged", self.key_rsa.public_key.fingerprint):
                with self.subTest(kid=kid):
                    real = self.run_counting_work(forged_auth_header(self.user.username, "RS256", kid))
                    unknown = self.run_counting_work(forged_auth_header("rusty", "RS256", kid))
                    self.assertEqual(real, unknown)
                    self.assertEqual(real, (3, 1, 3))
        self.assertEqual(mock_fetch_data.call_count, 1)
        mock_start_refresh.assert_not_called()

    @mock.patch("asymmetric_jwt_auth.jwks._fetch_jwks")
    def test_forged_rsa_signature_is_checked_against_same_size_keys_for_real_and_unknown_users(self, mock_fetch_data: mock.MagicMock) -> None:
        key = RSAPrivateKey.generate(size=4096)
        mock_fetch_data.return_value = {"keys": [key.public_key.as_jwk]}
        JWKSEndpointTrust.objects.create(user=self.user, jwks_url=self.jwks_url)
        self.assertLoggedIn(self.authenticate(key))
        kid = key.public_key.fingerprint
        with mock.patch.object(jwks, "_queue_refresh"):
            for signature_length in (None, 256, 384, 512):
                with self.subTest(signature_length=signature_length):
                    real = self.checked_keys(forged_auth_header(self.user.username, "RS256", kid, signature_length))
                    unknown = self.checked_keys(forged_auth_header("rusty", "RS256", kid, signature_length))
                    self.assertEqual(real, unknown)
                    self.assertIn(f"RSA-{8 * signature_length if signature_length else 2048}", real)

    @mock.patch("asymmetric_jwt_auth.jwks._fetch_jwks")
    def test_key_id_of_other_key_type_does_same_signature_checks(self, mock_fetch_data: mock.MagicMock) -> None:
        mock_fetch_data.return_value = {"keys": [self.key_rsa.public_key.as_jwk]}
        JWKSEndpointTrust.objects.create(user=self.user, jwks_url=self.jwks_url)
        self.authenticate(self.key_rsa)
        kid = self.key_rsa.public_key.fingerprint

        def count_signature_checks(username: str) -> int:
            request = self.rfactory.get("/", HTTP_AUTHORIZATION=forged_auth_header(username, "EdDSA", kid))
            with mock.patch.object(PyJWS, "get_algorithm_by_name", autospec=True, side_effect=PyJWS.get_algorithm_by_name) as checks:
                self.run_middleware(request)
            self.assertNotLoggedIn(request)
            return checks.call_count

        with mock.patch.object(jwks, "_queue_refresh"):
            self.assertEqual(count_signature_checks(self.user.username), count_signature_checks("rusty"))

    @mock.patch("asymmetric_jwt_auth.jwks._fetch_jwks")
    def test_expired_key_set_is_not_fetched_inline(self, mock_fetch_data: mock.MagicMock) -> None:
        mock_fetch_data.return_value = {"keys": [self.key_rsa.public_key.as_jwk]}
        JWKSEndpointTrust.objects.create(user=self.user, jwks_url=self.jwks_url)
        with freeze_time() as frozen, mock.patch.object(jwks, "_queue_refresh") as mock_start_refresh:
            self.authenticate(self.key_rsa)
            frozen.tick(timedelta(hours=2))
            for kid in (None, "forged", self.key_rsa.public_key.fingerprint):
                with self.subTest(kid=kid):
                    real = self.run_counting_work(forged_auth_header(self.user.username, "RS256", kid))
                    unknown = self.run_counting_work(forged_auth_header("rusty", "RS256", kid))
                    self.assertEqual(real, unknown)
            self.assertNotLoggedIn(self.authenticate(self.key_rsa))
        self.assertEqual(mock_fetch_data.call_count, 1)
        mock_start_refresh.assert_called_once_with(self.jwks_url)

    @mock.patch("asymmetric_jwt_auth.jwks._fetch_jwks")
    def test_idle_user_stays_trusted_while_timed_refreshes_succeed(self, mock_fetch_data: mock.MagicMock) -> None:
        mock_fetch_data.return_value = {"keys": [self.key_rsa.public_key.as_jwk]}
        JWKSEndpointTrust.objects.create(user=self.user, jwks_url=self.jwks_url)
        with freeze_time() as frozen, mock.patch.object(jwks, "_queue_refresh") as mock_start_refresh:
            self.assertLoggedIn(self.authenticate(self.key_rsa))
            self.refresh_worker.watch.assert_called_with(self.jwks_url)
            for _ in range(15):
                frozen.tick(timedelta(minutes=5))
                jwks._refresh_if_stale(self.jwks_url)
            self.assertLoggedIn(self.authenticate(self.key_rsa))
        self.assertEqual(mock_fetch_data.call_count, 16)
        mock_start_refresh.assert_not_called()

    @mock.patch("asymmetric_jwt_auth.jwks._fetch_jwks")
    def test_one_failed_refresh_doesnt_distrust_an_idle_key_set(self, mock_fetch_data: mock.MagicMock) -> None:
        mock_fetch_data.return_value = {"keys": [self.key_rsa.public_key.as_jwk]}
        JWKSEndpointTrust.objects.create(user=self.user, jwks_url=self.jwks_url)
        with freeze_time() as frozen, mock.patch.object(jwks, "_queue_refresh"):
            self.assertLoggedIn(self.authenticate(self.key_rsa))
            mock_fetch_data.side_effect = [PyJWKClientConnectionError("down"), {"keys": [self.key_rsa.public_key.as_jwk]}]
            for _ in range(2):
                frozen.tick(timedelta(minutes=5))
                jwks._refresh_if_stale(self.jwks_url)
            frozen.tick(timedelta(minutes=59))
            self.assertLoggedIn(self.authenticate(self.key_rsa))
        self.assertEqual(mock_fetch_data.call_count, 3)

    @mock.patch("asymmetric_jwt_auth.jwks._fetch_jwks")
    def test_unsupported_jwks_key_type_is_rejected(self, mock_fetch_data: mock.MagicMock) -> None:
        ec_jwk = {
            "kty": "EC",
            "crv": "P-256",
            "kid": "ec-key",
            "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
            "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
        }
        mock_fetch_data.return_value = {"keys": [ec_jwk, self.key_rsa.public_key.as_jwk]}
        JWKSEndpointTrust.objects.create(user=self.user, jwks_url=self.jwks_url)
        with mock.patch.object(jwks, "_queue_refresh"):
            self.authenticate(self.key_rsa)
            real = self.run_counting_work(forged_auth_header(self.user.username, "RS256", "ec-key"))
            unknown = self.run_counting_work(forged_auth_header("rusty", "RS256", "ec-key"))
        self.assertEqual(real, unknown)

    @mock.patch("asymmetric_jwt_auth.jwks._fetch_jwks")
    def test_unknown_key_id_refreshes_in_background_after_cooldown(self, mock_fetch_data: mock.MagicMock) -> None:
        mock_fetch_data.return_value = {"keys": [self.key_rsa.public_key.as_jwk]}
        JWKSEndpointTrust.objects.create(user=self.user, jwks_url=self.jwks_url)
        with freeze_time() as frozen, mock.patch.object(jwks, "_queue_refresh") as mock_start_refresh:
            self.authenticate(self.key_rsa)
            frozen.tick(timedelta(seconds=31))
            for _ in range(3):
                self.run_counting_work(forged_auth_header(self.user.username, "RS256", "forged"))
        self.assertEqual(mock_fetch_data.call_count, 1)
        mock_start_refresh.assert_called_once_with(self.jwks_url)

    @mock.patch("asymmetric_jwt_auth.jwks._fetch_jwks")
    def test_rotated_key_accepted_once_background_refresh_lands(self, mock_fetch_data: mock.MagicMock) -> None:
        new_key = RSAPrivateKey.generate()
        mock_fetch_data.return_value = {"keys": [self.key_rsa.public_key.as_jwk]}
        JWKSEndpointTrust.objects.create(user=self.user, jwks_url=self.jwks_url)
        with freeze_time() as frozen, mock.patch.object(jwks, "_queue_refresh", side_effect=jwks._refresh_unless_locked):
            self.authenticate(self.key_rsa)
            mock_fetch_data.return_value = {"keys": [new_key.public_key.as_jwk]}
            frozen.tick(timedelta(seconds=31))
            self.assertNotLoggedIn(self.authenticate(new_key))
            self.assertEqual(mock_fetch_data.call_count, 2)
            self.assertLoggedIn(self.authenticate(new_key))
            self.assertNotLoggedIn(self.authenticate(self.key_rsa))

    @mock.patch("asymmetric_jwt_auth.jwks._fetch_jwks")
    def test_stale_key_set_is_used_while_refreshing(self, mock_fetch_data: mock.MagicMock) -> None:
        mock_fetch_data.return_value = {"keys": [self.key_rsa.public_key.as_jwk]}
        JWKSEndpointTrust.objects.create(user=self.user, jwks_url=self.jwks_url)
        with freeze_time() as frozen, mock.patch.object(jwks, "_queue_refresh") as mock_start_refresh:
            self.authenticate(self.key_rsa)
            frozen.tick(timedelta(minutes=6))
            self.assertLoggedIn(self.authenticate(self.key_rsa))
        self.assertEqual(mock_fetch_data.call_count, 1)
        mock_start_refresh.assert_called_once_with(self.jwks_url)

    @mock.patch("asymmetric_jwt_auth.jwks._fetch_jwks")
    def test_failed_refresh_keeps_cached_keys(self, mock_fetch_data: mock.MagicMock) -> None:
        mock_fetch_data.return_value = {"keys": [self.key_rsa.public_key.as_jwk]}
        JWKSEndpointTrust.objects.create(user=self.user, jwks_url=self.jwks_url)
        with freeze_time() as frozen, mock.patch.object(jwks, "_queue_refresh", side_effect=jwks._refresh_unless_locked):
            self.authenticate(self.key_rsa)
            mock_fetch_data.side_effect = PyJWKClientConnectionError("down")
            frozen.tick(timedelta(minutes=6))
            self.assertLoggedIn(self.authenticate(self.key_rsa))
            self.assertLoggedIn(self.authenticate(self.key_rsa))
            self.assertEqual(mock_fetch_data.call_count, 2)
            frozen.tick(timedelta(hours=1))
            self.assertNotLoggedIn(self.authenticate(self.key_rsa))

    @mock.patch("asymmetric_jwt_auth.jwks._fetch_jwks")
    def test_failing_endpoint_is_not_fetched_on_every_request(self, mock_fetch_data: mock.MagicMock) -> None:
        mock_fetch_data.side_effect = PyJWKClientConnectionError("down")
        JWKSEndpointTrust.objects.create(user=self.user, jwks_url=self.jwks_url)
        with mock.patch.object(jwks, "_queue_refresh") as mock_start_refresh:
            for _ in range(3):
                self.assertNotLoggedIn(self.authenticate(self.key_rsa))
        self.assertEqual(mock_fetch_data.call_count, 1)
        mock_start_refresh.assert_not_called()

    def authenticate(self, private_key: FacadePrivateKey) -> HttpRequest:
        request = self.rfactory.get("/", HTTP_AUTHORIZATION=Token(self.user.username).create_auth_header(private_key))
        self.run_middleware(request)
        return request
