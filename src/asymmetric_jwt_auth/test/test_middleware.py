from unittest import mock
from django.test import RequestFactory, TestCase
from django.contrib.auth.models import User
from cryptography.hazmat.primitives import serialization
from ..utils import create_auth_header, generate_ed25519_key_pair, generate_rsa_key_pair
from ..models import PublicKey
from ..middleware import JWTAuthMiddleware


class MiddlewareTest(TestCase):

    def setUp(self):
        self.rfactory = RequestFactory()
        self.user = User.objects.create_user(username='foo')
        self.user2 = User.objects.create_user(username='bar')
        self.user_privkey_ed25519, self.user_pubkey_ed25519 = generate_ed25519_key_pair()
        self.user_privkey_rsa, self.user_pubkey_rsa = generate_rsa_key_pair()
        self.pubkey_ed25519 = PublicKey.objects.create(
            user=self.user,
            key=self.user_pubkey_ed25519)
        self.pubkey_rsa = PublicKey.objects.create(
            user=self.user,
            key=self.user_pubkey_rsa)
        self.next_middleware = mock.MagicMock()
        self.run_middleware = JWTAuthMiddleware(self.next_middleware)


    def assertNotLoggedIn(self, request):
        self.assertEqual(getattr(request, 'user', None), None)


    def assertLoggedIn(self, request, public_key):
        public_key.refresh_from_db()
        self.assertIsNotNone(public_key.last_used_on)
        self.assertEqual(getattr(request, 'user', None), self.user)


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
        header = create_auth_header('',
            key=self.user_privkey_rsa)
        request = self.rfactory.get('/', HTTP_AUTHORIZATION=header)
        self.assertNotLoggedIn(request)
        self.run_middleware(request)
        self.assertNotLoggedIn(request)
        self.assertEqual(self.next_middleware.call_count, 1)


    def test_header_jwt_claimed_username_doesnt_exist(self):
        header = create_auth_header('rusty',
            key=self.user_privkey_rsa)
        request = self.rfactory.get('/', HTTP_AUTHORIZATION=header)
        self.assertNotLoggedIn(request)
        self.run_middleware(request)
        self.assertNotLoggedIn(request)
        self.assertEqual(self.next_middleware.call_count, 1)


    def test_authenticate_request_rsa(self):
        privkey = serialization.load_pem_private_key(self.user_privkey_rsa.encode(), password=None)
        header = create_auth_header(self.user.username,
            key=privkey,
            algorithm='RS512')
        request = self.rfactory.get('/', HTTP_AUTHORIZATION=header)
        self.assertNotLoggedIn(request)
        self.run_middleware(request)
        self.assertLoggedIn(request, self.pubkey_rsa)
        self.assertEqual(self.next_middleware.call_count, 1)


    def test_authenticate_request_rsa_unregistered_key(self):
        self.pubkey_rsa.user = self.user2
        self.pubkey_rsa.save()
        self.pubkey_ed25519.user = self.user2
        self.pubkey_ed25519.save()
        privkey = serialization.load_pem_private_key(self.user_privkey_rsa.encode(), password=None)
        header = create_auth_header(self.user.username,
            key=privkey,
            algorithm='RS512')
        request = self.rfactory.get('/', HTTP_AUTHORIZATION=header)
        self.assertNotLoggedIn(request)
        self.run_middleware(request)
        self.assertNotLoggedIn(request)
        self.assertEqual(self.next_middleware.call_count, 1)


    def test_authenticate_request_ed25519(self):
        header = create_auth_header(self.user.username,
            key=self.user_privkey_ed25519,
            algorithm='EdDSA')
        request = self.rfactory.get('/', HTTP_AUTHORIZATION=header)
        self.assertNotLoggedIn(request)
        self.run_middleware(request)
        self.assertLoggedIn(request, self.pubkey_ed25519)
        self.assertEqual(self.next_middleware.call_count, 1)


    def test_cant_reuse_nonce(self):
        header = create_auth_header(self.user.username,
            key=self.user_privkey_ed25519,
            algorithm='EdDSA')
        # First use works
        request1 = self.rfactory.get('/', HTTP_AUTHORIZATION=header)
        self.assertNotLoggedIn(request1)
        self.run_middleware(request1)
        self.assertLoggedIn(request1, self.pubkey_ed25519)
        self.assertEqual(self.next_middleware.call_count, 1)
        # Second use doesn't
        request2 = self.rfactory.get('/', HTTP_AUTHORIZATION=header)
        self.assertNotLoggedIn(request2)
        self.run_middleware(request2)
        self.assertNotLoggedIn(request2)
        self.assertEqual(self.next_middleware.call_count, 2)
