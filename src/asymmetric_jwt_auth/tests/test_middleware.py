from unittest import mock
from django.test import RequestFactory, TestCase
from django.contrib.auth.models import User
from ..models import PublicKey, JWKSEndpointTrust
from ..middleware import JWTAuthMiddleware
from ..tokens import Token
from ..keys import RSAPrivateKey, Ed25519PrivateKey


class BaseMiddlewareTest(TestCase):
    def assertNotLoggedIn(self, request):
        self.assertEqual(getattr(request, 'user', None), None)


    def assertLoggedIn(self, request, public_key=None):
        if public_key:
            public_key.refresh_from_db()
            self.assertIsNotNone(public_key.last_used_on)
        self.assertEqual(getattr(request, 'user', None), self.user)


class MiddlewareTest(BaseMiddlewareTest):

    def setUp(self):
        self.rfactory = RequestFactory()
        self.user = User.objects.create_user(username='foo')
        self.user2 = User.objects.create_user(username='bar')

        self.key_ed25519 = Ed25519PrivateKey.generate()
        self.key_rsa = RSAPrivateKey.generate()

        self.user_key_ed25519 = PublicKey.objects.create(
            user=self.user,
            key=self.key_ed25519.public_key.as_pem.decode())
        self.user_key_rsa = PublicKey.objects.create(
            user=self.user,
            key=self.key_rsa.public_key.as_pem.decode())

        self.next_middleware = mock.MagicMock()
        self.run_middleware = JWTAuthMiddleware(self.next_middleware)


    def test_no_auth_header(self):
        request = self.rfactory.get('/')
        self.assertNotLoggedIn(request)
        self.run_middleware(request)
        self.assertNotLoggedIn(request)
        self.assertEqual(self.next_middleware.call_count, 1)


    def test_auth_header_missing_type(self):
        request = self.rfactory.get('/', HTTP_AUTHORIZATION='Fooopbar')
        self.assertNotLoggedIn(request)
        self.run_middleware(request)
        self.assertNotLoggedIn(request)
        self.assertEqual(self.next_middleware.call_count, 1)


    def test_auth_header_not_jwt_type(self):
        request = self.rfactory.get('/', HTTP_AUTHORIZATION='Bearer foobar')
        self.assertNotLoggedIn(request)
        self.run_middleware(request)
        self.assertNotLoggedIn(request)
        self.assertEqual(self.next_middleware.call_count, 1)


    def test_header_jwt_missing_username(self):
        header = Token('').create_auth_header(self.key_rsa)
        request = self.rfactory.get('/', HTTP_AUTHORIZATION=header)
        self.assertNotLoggedIn(request)
        self.run_middleware(request)
        self.assertNotLoggedIn(request)
        self.assertEqual(self.next_middleware.call_count, 1)


    def test_header_jwt_claimed_username_doesnt_exist(self):
        header = Token('rusty').create_auth_header(self.key_rsa)
        request = self.rfactory.get('/', HTTP_AUTHORIZATION=header)
        self.assertNotLoggedIn(request)
        self.run_middleware(request)
        self.assertNotLoggedIn(request)
        self.assertEqual(self.next_middleware.call_count, 1)


    def test_authenticate_request_rsa_valid(self):
        header = Token(self.user.username).create_auth_header(self.key_rsa)
        request = self.rfactory.get('/', HTTP_AUTHORIZATION=header)
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
        request = self.rfactory.get('/', HTTP_AUTHORIZATION=header)
        self.assertNotLoggedIn(request)
        self.run_middleware(request)
        self.assertNotLoggedIn(request)
        self.assertEqual(self.next_middleware.call_count, 1)


    def test_authenticate_request_ed25519_valid(self):
        header = Token(self.user.username).create_auth_header(self.key_ed25519)
        request = self.rfactory.get('/', HTTP_AUTHORIZATION=header)
        self.assertNotLoggedIn(request)
        self.run_middleware(request)
        self.assertLoggedIn(request, self.user_key_ed25519)
        self.assertEqual(self.next_middleware.call_count, 1)


    def test_missing_data(self):
        header = Token(self.user.username, timestamp=0).create_auth_header(self.key_ed25519)
        request = self.rfactory.get('/', HTTP_AUTHORIZATION=header)
        self.assertNotLoggedIn(request)
        self.run_middleware(request)
        self.assertNotLoggedIn(request)
        self.assertEqual(self.next_middleware.call_count, 1)


    def test_cant_reuse_nonce(self):
        header = Token(self.user.username).create_auth_header(self.key_ed25519)
        # First use works
        request1 = self.rfactory.get('/', HTTP_AUTHORIZATION=header)
        self.assertNotLoggedIn(request1)
        self.run_middleware(request1)
        self.assertLoggedIn(request1, self.user_key_ed25519)
        self.assertEqual(self.next_middleware.call_count, 1)
        # Second use doesn't
        request2 = self.rfactory.get('/', HTTP_AUTHORIZATION=header)
        self.assertNotLoggedIn(request2)
        self.run_middleware(request2)
        self.assertNotLoggedIn(request2)
        self.assertEqual(self.next_middleware.call_count, 2)



class MiddlewareJWKSTest(BaseMiddlewareTest):

    def setUp(self):
        self.rfactory = RequestFactory()
        self.user = User.objects.create_user(username='foo')

        self.key_ed25519 = Ed25519PrivateKey.generate()
        self.key_rsa = RSAPrivateKey.generate()

        self.next_middleware = mock.MagicMock()
        self.run_middleware = JWTAuthMiddleware(self.next_middleware)


    @mock.patch('asymmetric_jwt_auth.models.PyJWKClient.fetch_data')
    def test_authenticate_request_rsa(self, mock_fetch_data):
        mock_fetch_data.return_value = {
            "keys": [
                self.key_rsa.public_key.as_jwk,
            ],
        }
        JWKSEndpointTrust.objects.create(
            user=self.user,
            jwks_url='')
        header = Token(self.user.username).create_auth_header(self.key_rsa)
        request = self.rfactory.get('/', HTTP_AUTHORIZATION=header)
        self.assertNotLoggedIn(request)
        self.run_middleware(request)
        self.assertLoggedIn(request)
        self.assertEqual(self.next_middleware.call_count, 1)


    @mock.patch('asymmetric_jwt_auth.models.PyJWKClient.fetch_data')
    def test_no_matching_key(self, mock_fetch_data):
        # Change the key ID of the JWKS response so it doesn't match the kid in the header JWT
        jwk = self.key_rsa.public_key.as_jwk
        jwk['kid'] = 'foobar'
        mock_fetch_data.return_value = {
            "keys": [
                jwk,
            ],
        }
        JWKSEndpointTrust.objects.create(
            user=self.user,
            jwks_url='')
        header = Token(self.user.username).create_auth_header(self.key_rsa)
        request = self.rfactory.get('/', HTTP_AUTHORIZATION=header)
        self.assertNotLoggedIn(request)
        self.run_middleware(request)
        self.assertNotLoggedIn(request)
        self.assertEqual(self.next_middleware.call_count, 1)


    @mock.patch('asymmetric_jwt_auth.models.PyJWKClient.fetch_data')
    def test_header_jwt_claimed_username_doesnt_exist(self, mock_fetch_data):
        mock_fetch_data.return_value = {
            "keys": [
                self.key_rsa.public_key.as_jwk,
            ],
        }
        JWKSEndpointTrust.objects.create(
            user=self.user,
            jwks_url='')
        header = Token('rusty').create_auth_header(self.key_rsa)
        request = self.rfactory.get('/', HTTP_AUTHORIZATION=header)
        self.assertNotLoggedIn(request)
        self.run_middleware(request)
        self.assertNotLoggedIn(request)
        self.assertEqual(self.next_middleware.call_count, 1)


    @mock.patch('asymmetric_jwt_auth.models.PyJWKClient.fetch_data')
    def test_missing_data(self, mock_fetch_data):
        mock_fetch_data.return_value = {
            "keys": [
                self.key_rsa.public_key.as_jwk,
            ],
        }
        JWKSEndpointTrust.objects.create(
            user=self.user,
            jwks_url='')
        header = Token(self.user.username, timestamp=0).create_auth_header(self.key_rsa)
        request = self.rfactory.get('/', HTTP_AUTHORIZATION=header)
        self.assertNotLoggedIn(request)
        self.run_middleware(request)
        self.assertNotLoggedIn(request)
        self.assertEqual(self.next_middleware.call_count, 1)
