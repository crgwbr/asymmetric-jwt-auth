from django.test import TestCase
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from asymmetric_jwt_auth import utils


class UtilsTest(TestCase):

    def test_generate_new_ed25519_key(self):
        private, public = utils.generate_ed25519_key_pair(as_string=False)
        self.assertIsInstance(private, Ed25519PrivateKey)
        self.assertIsInstance(public, Ed25519PublicKey)


    def test_generate_new_rsa_key(self):
        private, public = utils.generate_rsa_key_pair(as_string=False)
        self.assertIsInstance(private, RSAPrivateKey)
        self.assertIsInstance(public, RSAPublicKey)


    def test_generate_new_rsa_key_as_string(self):
        private, public = utils.generate_rsa_key_pair()
        private = private.strip().split('\n')
        self.assertEqual(private[0], '-----BEGIN PRIVATE KEY-----')
        self.assertEqual(private[27], '-----END PRIVATE KEY-----')
        public = public.strip().split('\n')
        self.assertEqual(public[0], '-----BEGIN PUBLIC KEY-----')
        self.assertEqual(public[8], '-----END PUBLIC KEY-----')
