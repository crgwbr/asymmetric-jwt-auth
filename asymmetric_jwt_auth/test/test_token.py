import unittest
import time
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    PublicFormat,
    NoEncryption
)

import asymmetric_jwt_auth.token as token


class AuthTest(unittest.TestCase):
    def generate_key_pair(self, size=2048):
        private = rsa.generate_private_key(
            public_exponent=65537,
            key_size=size,
            backend=default_backend()
        )
        public = private.public_key()

        pem_private = private.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        pem_public = public.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        return pem_private, pem_public

    def test_roundtrip(self):
        private, public = self.generate_key_pair()
        t = token.sign('guido', private)
        token_data = token.verify(t, public)
        self.assertTrue(token_data)
        self.assertEqual(token_data.get('username'), 'guido')

    def test_bad_keys(self):
        private1, public1 = self.generate_key_pair()
        private2, public2 = self.generate_key_pair()

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
        private, public = self.generate_key_pair()

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
        private, public = self.generate_key_pair()

        t = token.sign('guido', private, generate_nonce=lambda username, iat: 1)
        token_data = token.verify(t, public, validate_nonce=lambda username, iat, nonce: nonce == 1)
        self.assertTrue(token_data)

        t = token.sign('guido', private, generate_nonce=lambda username, iat: 1)
        token_data = token.verify(t, public, validate_nonce=lambda username, iat, nonce: nonce == 2)
        self.assertFalse(token_data)

        t = token.sign('guido', private, generate_nonce=lambda username, iat: 2)
        token_data = token.verify(t, public, validate_nonce=lambda username, iat, nonce: nonce == 1)
        self.assertFalse(token_data)
