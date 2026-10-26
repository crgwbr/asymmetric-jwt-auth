from datetime import UTC, datetime, timedelta
from unittest.mock import patch

from django.contrib.auth.models import User
from django.test import TestCase, override_settings
from freezegun import freeze_time
import jwt

from .. import keys, tokens
from . import data


class TokenToken(TestCase):
    def setUp(self):
        self.username = "rusty"
        self.privkey = keys.Ed25519PrivateKey.generate()

    @patch("time.time")
    @patch("secrets.token_urlsafe")
    def test_create_auth_header(self, mock_get_nonce, mock_time):
        mock_get_nonce.return_value = "yVJ0MVWhqPQ"
        mock_time.return_value = 1234000.3
        token = tokens.Token(username=self.username)
        header = token.create_auth_header(self.privkey)
        self.assertTrue(header.startswith("JWT "))
        data = jwt.decode(
            jwt=header.split(" ")[1],
            key=self.privkey.public_key.as_pem,
            algorithms=self.privkey.public_key.allowed_algorithms,
        )
        self.assertEqual(
            data,
            {
                "nonce": "yVJ0MVWhqPQ",
                "time": 1234000,
                "username": "rusty",
            },
        )

    @patch("secrets.token_urlsafe")
    def test_create_auth_header_custom_time(self, mock_get_nonce):
        mock_get_nonce.return_value = "yVJ0MVWhqPQ"
        token = tokens.Token(username=self.username, timestamp=1614974974)
        header = token.create_auth_header(self.privkey)
        self.assertTrue(header.startswith("JWT "))
        data = jwt.decode(
            jwt=header.split(" ")[1],
            key=self.privkey.public_key.as_pem,
            algorithms=self.privkey.public_key.allowed_algorithms,
        )
        self.assertEqual(
            data,
            {
                "nonce": "yVJ0MVWhqPQ",
                "time": 1614974974,
                "username": "rusty",
            },
        )


class UntrustedTokenTest(TestCase):
    def setUp(self):
        self.username = "rusty"
        self.user = User.objects.create(username=self.username)
        self.privkey = keys.Ed25519PrivateKey.generate()
        self.token = tokens.Token(username=self.username)
        self.jwt_value = self.token.sign(self.privkey)
        self.untrusted_token = tokens.UntrustedToken(self.jwt_value)

    def test_get_claimed_username(self):
        self.assertEqual(self.untrusted_token.get_claimed_username(), self.username)

    def test_get_claimed_key_id(self):
        self.assertEqual(self.untrusted_token.get_claimed_key_id(), self.privkey.public_key.fingerprint)
        no_kid_jwt = jwt.encode({"username": self.username}, key=self.privkey.as_pem, algorithm="EdDSA")
        self.assertIsNone(tokens.UntrustedToken(no_kid_jwt).get_claimed_key_id())
        self.assertIsNone(tokens.UntrustedToken("not-a-jwt").get_claimed_key_id())

    def test_has_supported_algorithm(self):
        self.assertTrue(self.untrusted_token.has_supported_algorithm())
        rsa_key = keys.RSAPrivateKey.generate().as_pem
        for alg in keys.RSA_ALGORITHMS:
            with self.subTest(alg=alg):
                rsa_jwt = jwt.encode({"username": self.username}, key=rsa_key, algorithm=alg)
                self.assertTrue(tokens.UntrustedToken(rsa_jwt).has_supported_algorithm())

    def test_has_supported_algorithm_rejects_unsupported_or_malformed(self):
        hmac_jwt = jwt.encode({"username": self.username}, key="x" * 32, algorithm="HS256")
        unsigned_jwt = jwt.encode({"username": self.username}, key=None, algorithm="none")
        bad_segments = self.jwt_value.split(".")[0] + ".not-a-jwt"
        for value in (hmac_jwt, unsigned_jwt, bad_segments, "not-a-jwt", ""):
            with self.subTest(value=value):
                self.assertFalse(tokens.UntrustedToken(value).has_supported_algorithm())

    def test_has_supported_algorithm_custom_list(self):
        hmac_jwt = jwt.encode({"username": self.username}, key="x" * 32, algorithm="HS256")
        self.assertTrue(tokens.UntrustedToken(hmac_jwt).has_supported_algorithm(["HS256"]))
        self.assertFalse(self.untrusted_token.has_supported_algorithm(["HS256"]))

    def test_verify_valid(self):
        token = self.untrusted_token.verify(self.privkey.public_key)
        self.assertIsInstance(token, tokens.Token)
        self.assertEqual(token.username, self.username)

    def test_verify_key_mismatch(self):
        pubkey = keys.PublicKey.load_pem(data.PEM_PUBLIC_RSA)
        token = self.untrusted_token.verify(pubkey)
        self.assertIsNone(token)

    def test_time_out_of_allowed_range_before(self):
        dt = datetime.now(tz=UTC) - timedelta(seconds=30)
        with freeze_time(dt):
            token = self.untrusted_token.verify(self.privkey.public_key)
        self.assertIsNone(token)

    def test_time_out_of_allowed_range_after(self):
        dt = datetime.now(tz=UTC) + timedelta(seconds=30)
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

    @override_settings(ASYMMETRIC_JWT_AUTH={"NONCE_BACKEND": "asymmetric_jwt_auth.nonce.null.NullNonceBackend"})
    def test_nonce_already_used_null_backend(self):
        token1 = self.untrusted_token.verify(self.privkey.public_key)
        self.assertIsInstance(token1, tokens.Token)
        self.assertEqual(token1.username, self.username)
        # Second attempt works becuase null nonce backend doesn't do anything
        token2 = self.untrusted_token.verify(self.privkey.public_key)
        self.assertIsInstance(token2, tokens.Token)
        self.assertEqual(token2.username, self.username)
