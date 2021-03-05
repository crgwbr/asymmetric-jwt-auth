from unittest.mock import patch
from django.contrib.auth.models import User
from django.test import TestCase, override_settings
from freezegun import freeze_time
from datetime import datetime, timedelta
from .. import tokens, keys
from . import data
import jwt



class TokenToken(TestCase):

    def setUp(self):
        self.username = 'rusty'
        self.privkey = keys.Ed25519PrivateKey.generate()


    @patch('time.time')
    @patch('secrets.token_urlsafe')
    def test_create_auth_header(self, mock_get_nonce, mock_time):
        mock_get_nonce.return_value = 'yVJ0MVWhqPQ'
        mock_time.return_value = 1234000.3
        token = tokens.Token(
            username=self.username)
        header = token.create_auth_header(self.privkey)
        self.assertTrue(header.startswith('JWT '))
        data = jwt.decode(
            jwt=header.split(' ')[1],
            key=self.privkey.public_key.as_pem,
            algorithms=self.privkey.public_key.allowed_algorithms)
        self.assertEqual(data, {
            'nonce': 'yVJ0MVWhqPQ',
            'time': 1234000,
            'username': 'rusty',
        })


    @patch('secrets.token_urlsafe')
    def test_create_auth_header_custom_time(self, mock_get_nonce):
        mock_get_nonce.return_value = 'yVJ0MVWhqPQ'
        token = tokens.Token(
            username=self.username,
            timestamp=1614974974)
        header = token.create_auth_header(self.privkey)
        self.assertTrue(header.startswith('JWT '))
        data = jwt.decode(
            jwt=header.split(' ')[1],
            key=self.privkey.public_key.as_pem,
            algorithms=self.privkey.public_key.allowed_algorithms)
        self.assertEqual(data, {
            'nonce': 'yVJ0MVWhqPQ',
            'time': 1614974974,
            'username': 'rusty',
        })


class UntrustedTokenTest(TestCase):
    def setUp(self):
        self.username = 'rusty'
        self.user = User.objects.create(
            username=self.username)
        self.privkey = keys.Ed25519PrivateKey.generate()
        self.token = tokens.Token(
            username=self.username)
        self.jwt_value = self.token.sign(self.privkey)
        self.untrusted_token = tokens.UntrustedToken(self.jwt_value)


    def test_get_claimed_username(self):
        self.assertEqual(self.untrusted_token.get_claimed_username(), self.username)


    def test_verify_valid(self):
        token = self.untrusted_token.verify(self.privkey.public_key)
        self.assertIsInstance(token, tokens.Token)
        self.assertEqual(token.username, self.username)


    def test_verify_key_mismatch(self):
        pubkey = keys.PublicKey.load_pem(data.PEM_PUBLIC_RSA)
        token = self.untrusted_token.verify(pubkey)
        self.assertIsNone(token)


    def test_time_out_of_allowed_range_before(self):
        dt = datetime.now() - timedelta(seconds=30)
        with freeze_time(dt):
            token = self.untrusted_token.verify(self.privkey.public_key)
        self.assertIsNone(token)


    def test_time_out_of_allowed_range_after(self):
        dt = datetime.now() + timedelta(seconds=30)
        with freeze_time(dt):
            token = self.untrusted_token.verify(self.privkey.public_key)
        self.assertIsNone(token)


    def test_nonce_already_used(self):
        token1 = self.untrusted_token.verify(self.privkey.public_key)
        self.assertIsInstance(token1, tokens.Token)
        self.assertEqual(token1.username, self.username)
        # Second attempt fails because nonce was already used
        token2 = self.untrusted_token.verify(self.privkey.public_key)
        self.assertIsNone(token2)


    @override_settings(ASYMMETRIC_JWT_AUTH=dict(NONCE_BACKEND='asymmetric_jwt_auth.nonce.null.NullNonceBackend'))
    def test_nonce_already_used_null_backend(self):
        token1 = self.untrusted_token.verify(self.privkey.public_key)
        self.assertIsInstance(token1, tokens.Token)
        self.assertEqual(token1.username, self.username)
        # Second attempt works becuase null nonce backend doesn't do anything
        token2 = self.untrusted_token.verify(self.privkey.public_key)
        self.assertIsInstance(token2, tokens.Token)
        self.assertEqual(token2.username, self.username)
