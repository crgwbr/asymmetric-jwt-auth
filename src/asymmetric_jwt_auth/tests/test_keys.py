from django.test import TestCase
from unittest import mock
from .. import keys
from . import data
import os.path


class PublicKeyTest(TestCase):
    def test_load_pem_rsa(self):
        exc, key = keys.PublicKey.load_serialized_public_key(data.PEM_PUBLIC_RSA)
        self.assertIsNone(exc)
        self.assertIsInstance(key, keys.RSAPublicKey)


    def test_load_pem_ed25519(self):
        exc, key = keys.PublicKey.load_serialized_public_key(data.PEM_PUBLIC_ED25519)
        self.assertIsNone(exc)
        self.assertIsInstance(key, keys.Ed25519PublicKey)


    def test_load_openssh_rsa(self):
        exc, key = keys.PublicKey.load_serialized_public_key(data.OPENSSH_RSA)
        self.assertIsNone(exc)
        self.assertIsInstance(key, keys.RSAPublicKey)


    def test_load_openssh_ed25519(self):
        exc, key = keys.PublicKey.load_serialized_public_key(data.OPENSSH_ED25519)
        self.assertIsNone(exc)
        self.assertIsInstance(key, keys.Ed25519PublicKey)


    def test_load_invalid_pem_rsa(self):
        exc, key = keys.PublicKey.load_serialized_public_key(data.PEM_PUBLIC_RSA_INVALID)
        self.assertIsInstance(exc, Exception)
        self.assertIsNone(key)


    def test_load_invalid_pem_ed25519(self):
        exc, key = keys.PublicKey.load_serialized_public_key(data.PEM_PUBLIC_ED25519_INVALID)
        self.assertIsInstance(exc, Exception)
        self.assertIsNone(key)


    def test_load_invalid_openssh_rsa(self):
        exc, key = keys.PublicKey.load_serialized_public_key(data.OPENSSH_RSA_INVALID)
        self.assertIsInstance(exc, Exception)
        self.assertIsNone(key)


    def test_load_invalid_openssh_ed25519(self):
        exc, key = keys.PublicKey.load_serialized_public_key(data.OPENSSH_ED25519_INVALID)
        self.assertIsInstance(exc, Exception)
        self.assertIsNone(key)


    def test_rsa_as_pem(self):
        exc, key = keys.PublicKey.load_serialized_public_key(data.PEM_PUBLIC_RSA)
        self.assertIsNone(exc)
        pem = key.as_pem.decode().strip().split('\n')
        self.assertEqual(pem[0], '-----BEGIN PUBLIC KEY-----')
        self.assertEqual(pem[-1], '-----END PUBLIC KEY-----')


    def test_ed25519_as_pem(self):
        exc, key = keys.PublicKey.load_serialized_public_key(data.PEM_PUBLIC_RSA)
        self.assertIsNone(exc)
        pem = key.as_pem.decode().strip().split('\n')
        self.assertEqual(pem[0], '-----BEGIN PUBLIC KEY-----')
        self.assertEqual(pem[-1], '-----END PUBLIC KEY-----')


    def test_rsa_fingerprint(self):
        exc, key = keys.PublicKey.load_serialized_public_key(data.PEM_PUBLIC_RSA)
        self.assertIsNone(exc)
        self.assertEqual(key.fingerprint, '53c5b68c5ecba3e25df3f8326de6c0b0befb67e9217651a2f40e388f6567f056')


    def test_ed25519_fingerprint(self):
        exc, key = keys.PublicKey.load_serialized_public_key(data.PEM_PUBLIC_ED25519)
        self.assertIsNone(exc)
        self.assertEqual(key.fingerprint, 'cb10cd75c2eacf7aa2b5195bef9838cccd9d2ae4938601178808cb881b68ec72')


    def test_rsa_allowed_algorithms(self):
        exc, key = keys.PublicKey.load_serialized_public_key(data.PEM_PUBLIC_RSA)
        self.assertIsNone(exc)
        self.assertEqual(key.allowed_algorithms, [
            'RS512',
            'RS384',
            'RS256',
        ])


    def test_ed25519_allowed_algorithms(self):
        exc, key = keys.PublicKey.load_serialized_public_key(data.PEM_PUBLIC_ED25519)
        self.assertIsNone(exc)
        self.assertEqual(key.allowed_algorithms, [
            'EdDSA',
        ])


    def test_unknown_key_type(self):
        with self.assertRaises(TypeError):
            keys.PublicKey.from_cryptography_pubkey(mock.MagicMock())



class PrivateKeyTest(TestCase):
    def test_generate_rsa(self):
        private = keys.RSAPrivateKey.generate()
        self.assertIsInstance(private, keys.RSAPrivateKey)
        self.assertIsInstance(private.public_key, keys.RSAPublicKey)


    def test_generate_ed25519(self):
        private = keys.Ed25519PrivateKey.generate()
        self.assertIsInstance(private, keys.Ed25519PrivateKey)
        self.assertIsInstance(private.public_key, keys.Ed25519PublicKey)


    def test_load_rsa_from_file(self):
        base = os.path.dirname(__file__)
        filepath = os.path.join(base, 'fixtures/dummy_rsa.privkey')
        private = keys.RSAPrivateKey.load_pem_from_file(filepath)
        self.assertIsInstance(private, keys.RSAPrivateKey)


    def test_load_rsa_from_file_encrypted(self):
        base = os.path.dirname(__file__)
        filepath = os.path.join(base, 'fixtures/dummy_rsa_encrypted.privkey')
        private = keys.RSAPrivateKey.load_pem_from_file(filepath,
            password=b'password')
        self.assertIsInstance(private, keys.RSAPrivateKey)


    def test_load_rsa(self):
        priv1 = keys.RSAPrivateKey.generate()
        priv2 = keys.RSAPrivateKey.load_pem(priv1.as_pem)
        self.assertEqual(priv2.as_pem, priv1.as_pem)


    def test_load_ed25519(self):
        priv1 = keys.Ed25519PrivateKey.generate()
        priv2 = keys.Ed25519PrivateKey.load_pem(priv1.as_pem)
        self.assertEqual(priv2.as_pem, priv1.as_pem)


    def test_rsa_as_pem(self):
        private = keys.RSAPrivateKey.generate()
        pem = private.as_pem.decode().strip().split('\n')
        self.assertEqual(pem[0], '-----BEGIN PRIVATE KEY-----')
        self.assertEqual(pem[-1], '-----END PRIVATE KEY-----')


    def test_ed25519_as_pem(self):
        private = keys.Ed25519PrivateKey.generate()
        pem = private.as_pem.decode().strip().split('\n')
        self.assertEqual(pem[0], '-----BEGIN PRIVATE KEY-----')
        self.assertEqual(pem[-1], '-----END PRIVATE KEY-----')


    def test_unknown_key_type(self):
        with self.assertRaises(TypeError):
            keys.PrivateKey.from_cryptography_privkey(mock.MagicMock())
