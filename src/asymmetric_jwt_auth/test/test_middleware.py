from django.test import RequestFactory, TestCase
from django.contrib.auth.models import User
from asymmetric_jwt_auth import create_auth_header
from asymmetric_jwt_auth.models import PublicKey
from asymmetric_jwt_auth.middleware import JWTAuthMiddleware
from unittest import mock
import os.path

BASE = os.path.dirname(os.path.abspath(__file__))
KEY1_PRIVATE = os.path.join(BASE, 'dummy.privkey')
KEY1_PUBLIC = os.path.join(BASE, 'dummy.pub')


class MiddlewareTest(TestCase):

    def setUp(self):
        self.user = User.objects.create_user(username='foo')
        with open(KEY1_PUBLIC, 'r') as pubkey_file:
            key = pubkey_file.read()
        self.public_key = PublicKey.objects.create(
            user=self.user,
            key=key)


    def test_authenticate_request(self):
        header = create_auth_header('foo', key_file=KEY1_PRIVATE)
        rfactory = RequestFactory()
        request = rfactory.get('/', HTTP_AUTHORIZATION=header)

        next_middleware = mock.MagicMock()
        run_middleware = JWTAuthMiddleware(next_middleware)

        self.public_key.refresh_from_db()
        self.assertIsNone(self.public_key.last_used_on)
        self.assertEqual(next_middleware.call_count, 0)
        self.assertEqual(getattr(request, 'user', None), None)

        run_middleware(request)

        self.public_key.refresh_from_db()
        self.assertIsNotNone(self.public_key.last_used_on)
        self.assertEqual(next_middleware.call_count, 1)
        self.assertEqual(getattr(request, 'user', None), self.user)
