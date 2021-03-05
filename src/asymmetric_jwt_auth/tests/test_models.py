from django.test import TestCase
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.utils import timezone
from .. import models, keys, tokens
from . import data
import jwt


class ValidatePublicKeyTest(TestCase):

    def test_valid_rsa_pem(self):
        models.validate_public_key(data.PEM_PUBLIC_RSA.decode())


    def test_valid_ed25519_pem(self):
        models.validate_public_key(data.PEM_PUBLIC_ED25519.decode())


    def test_valid_rsa_openssh(self):
        models.validate_public_key(data.OPENSSH_RSA.decode())


    def test_valid_ed25519_openssh(self):
        models.validate_public_key(data.OPENSSH_ED25519.decode())


    def test_invalid_rsa_pem(self):
        with self.assertRaises(ValidationError):
            models.validate_public_key(data.PEM_PUBLIC_RSA_INVALID.decode())


    def test_invalid_ed25519_pem(self):
        with self.assertRaises(ValidationError):
            models.validate_public_key(data.PEM_PUBLIC_ED25519_INVALID.decode())


    def test_invalid_rsa_openssh(self):
        with self.assertRaises(ValidationError):
            models.validate_public_key(data.OPENSSH_RSA_INVALID.decode())


    def test_invalid_ed25519_openssh(self):
        with self.assertRaises(ValidationError):
            models.validate_public_key(data.OPENSSH_ED25519_INVALID.decode())



class PublicKeyTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='foo')


    def test_extract_comment(self):
        pub = models.PublicKey(
            user=self.user,
            key=data.OPENSSH_ED25519,
            comment="")
        pub.save()
        self.assertEqual(pub.comment, 'crgwbr@foo')


    def test_update_last_used_datetime(self):
        pub = models.PublicKey(
            user=self.user,
            key=data.OPENSSH_ED25519)
        pub.save()
        self.assertEqual(pub.last_used_on, None)
        pub.update_last_used_datetime()
        # Check the first 19 digits (year – second precision) of ISO time: 2021-03-03T17:00:24
        self.assertEqual(pub.last_used_on.isoformat()[:19], timezone.now().isoformat()[:19])


    def test_get_key_ed25519(self):
        pub = models.PublicKey(
            user=self.user,
            key=data.OPENSSH_ED25519)
        pub.save()
        self.assertIsInstance(pub.get_key(), keys.Ed25519PublicKey)


    def test_get_loaded_key_rsa(self):
        pub = models.PublicKey(
            user=self.user,
            key=data.OPENSSH_RSA,
            comment="")
        pub.save()
        self.assertIsInstance(pub.get_key(), keys.RSAPublicKey)


    def test_get_loaded_key_invalid(self):
        pub = models.PublicKey(
            user=self.user,
            key=data.OPENSSH_ED25519_INVALID)
        pub.save()
        with self.assertRaises(ValueError):
            pub.get_key()



class JWKSEndpointTrustTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='foo')
        self.jwks = models.JWKSEndpointTrust.objects.create(
            user=self.user,
            jwks_url='https://dev-87evx9ru.auth0.com/.well-known/jwks.json')

    def test_get_signing_key(self):
        untrusted_token = tokens.UntrustedToken(b"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Ik5FRTFRVVJCT1RNNE16STVSa0ZETlRZeE9UVTFNRGcyT0Rnd1EwVXpNVGsxUWpZeVJrUkZRdyJ9.eyJpc3MiOiJodHRwczovL2Rldi04N2V2eDlydS5hdXRoMC5jb20vIiwic3ViIjoiYVc0Q2NhNzl4UmVMV1V6MGFFMkg2a0QwTzNjWEJWdENAY2xpZW50cyIsImF1ZCI6Imh0dHBzOi8vZXhwZW5zZXMtYXBpIiwiaWF0IjoxNTcyMDA2OTU0LCJleHAiOjE1NzIwMDY5NjQsImF6cCI6ImFXNENjYTc5eFJlTFdVejBhRTJINmtEME8zY1hCVnRDIiwiZ3R5IjoiY2xpZW50LWNyZWRlbnRpYWxzIn0.PUxE7xn52aTCohGiWoSdMBZGiYAHwE5FYie0Y1qUT68IHSTXwXVd6hn02HTah6epvHHVKA2FqcFZ4GGv5VTHEvYpeggiiZMgbxFrmTEY0csL6VNkX1eaJGcuehwQCRBKRLL3zKmA5IKGy5GeUnIbpPHLHDxr-GXvgFzsdsyWlVQvPX2xjeaQ217r2PtxDeqjlf66UYl6oY6AqNS8DH3iryCvIfCcybRZkc_hdy-6ZMoKT6Piijvk_aXdm7-QQqKJFHLuEqrVSOuBqqiNfVrG27QzAPuPOxvfXTVLXL2jek5meH6n-VWgrBdoMFH93QEszEDowDAEhQPHVs0xj7SIzA")  # NOQA
        signing_key = self.jwks.get_signing_key(untrusted_token)
        self.assertIsInstance(signing_key, keys.RSAPublicKey)
        data = jwt.decode(
            untrusted_token.token,
            signing_key.as_pem,
            algorithms=["RS256"],
            audience="https://expenses-api",
            options={"verify_exp": False})
        self.assertEqual(data, {
            'iss': 'https://dev-87evx9ru.auth0.com/',
            'sub': 'aW4Cca79xReLWUz0aE2H6kD0O3cXBVtC@clients',
            'aud': 'https://expenses-api',
            'iat': 1572006954,
            'exp': 1572006964,
            'azp': 'aW4Cca79xReLWUz0aE2H6kD0O3cXBVtC',
            'gty': 'client-credentials',
        })
