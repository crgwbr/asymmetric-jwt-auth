import unittest
import time
from asymmetric_jwt_auth import generate_key_pair
import asymmetric_jwt_auth.token as token


class AuthTest(unittest.TestCase):
    def test_roundtrip(self):
        private, public = generate_key_pair()
        t = token.sign('guido', private)
        token_data = token.verify(t, public)
        self.assertTrue(token_data)
        self.assertEqual(token_data.get('username'), 'guido')

    def test_bad_keys(self):
        private1, public1 = generate_key_pair()
        private2, public2 = generate_key_pair()

        t = token.sign('guido', private1)
        token_data = token.verify(t, public1)
        self.assertTrue(token_data)

        t = token.sign('guido', private2)
        token_data = token.verify(t, public2)
        self.assertTrue(token_data)

        t = token.sign('guido', private1)
        token_data = token.verify(t, public2)
        self.assertFalse(token_data)

        t = token.sign('guido', private2)
        token_data = token.verify(t, public1)
        self.assertFalse(token_data)

    def test_bad_iat(self):
        private, public = generate_key_pair()

        t = token.sign('guido', private, iat=time.time())
        token_data = token.verify(t, public)
        self.assertTrue(token_data)

        # IAT tolerance exists to account for clock drift between disparate systems.
        tolerance = token.TIMESTAMP_TOLERANCE + 1

        t = token.sign('guido', private, iat=time.time() - tolerance)
        token_data = token.verify(t, public)
        self.assertFalse(token_data)

        t = token.sign('guido', private, iat=time.time() + tolerance)
        token_data = token.verify(t, public)
        self.assertFalse(token_data)

    def test_bad_nonce(self):
        private, public = generate_key_pair()

        t = token.sign('guido', private, generate_nonce=lambda username, iat: 1)
        token_data = token.verify(t, public, validate_nonce=lambda username, iat, nonce: nonce == 1)
        self.assertTrue(token_data)

        t = token.sign('guido', private, generate_nonce=lambda username, iat: 1)
        token_data = token.verify(t, public, validate_nonce=lambda username, iat, nonce: nonce == 2)
        self.assertFalse(token_data)

        t = token.sign('guido', private, generate_nonce=lambda username, iat: 2)
        token_data = token.verify(t, public, validate_nonce=lambda username, iat, nonce: nonce == 1)
        self.assertFalse(token_data)

    def test_get_claimed_username(self):
        private, public = generate_key_pair()
        t = token.sign('guido', private)
        self.assertEqual(token.get_claimed_username(t), 'guido')