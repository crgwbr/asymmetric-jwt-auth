from django.test import TestCase
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.utils import timezone
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from .. import models
import jwt


class ValidatePublicKeyTest(TestCase):

    def test_valid_rsa_pem(self):
        pub = """
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAodxbRh5LOtoB3Shf6K3m
Rn7ME7Doo5Qm5h72ITt+E6U0l6qXGdVBTj0XhQVNnGjnZTGzU7IacIw1a/03qVHJ
fcc0Ki7ig7YSPMMl0WSp0m080YlsCZ+9g+WG6DrgjpGQU7yaBhNsKtR5DP20bm84
11S9VLqV2GEOzBKpB10/lwhRZuv/Qj7obwSqdVCzMNb7t5LHqG0MxOF7BeYELXIq
TEKFfWkZytXCAnmC9hk9RtzUZ/lryD1UgCHZ16gPtmPdFV7fuN8FBNrbaQCldz6V
6HVDjsPVxPmVYswV8qInG8kJUpm48s9PAWfgi4HCGmJgn+Irbed2tlRf73jxyCgX
0QIDAQAB
-----END PUBLIC KEY-----
"""
        models.validate_public_key(pub)


    def test_valid_rsa_openssh(self):
        pub = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQChfejJdi6Jbg4ealsjfC8Jwy3ucwU7PcLWDEVhEi+rvgLRmWhIbK1Tt8lOGx2JECu6zymbFpYSH7cacUqpZfp/Bm4LMtFLqxXqeXymsGmH5mAJYqd0jKZtk0IM8RAvbn9iUvWtmqYXDcE734+dhvsfPEu8LDP251TIskslbj8XIKwQd4q1ervNmhG7o6culFSTltsLwDQ5LdopRfp2cu5i3umNXKBpbYcYDfa4YASmTra/rF+cp9YMXQkTTpsGBRn9wOnJmxRpFEdJ0QDBDqL4zAHkY0Fc4GJufl/4HoYmkolYxzkiYku6wd8bDMcU+o4XZ/78eNoYLPrjCHHy0ytPtFDZMuYB+e8DLGkVp3lNGfV+BRX+s/bexrBRLZoA9U2B7YHq7BOaZs8VRFehU/q0AICM0AOqKHFX3dJPKtEEUb4wmeFS/MoZQm2DXHIhkOA64A+ltdklGgHEjy8daQBvjJ0yIx5IfPMGFpZgk8/ETRcqHTEmmbU1ri6CevQrM7PFCGnmk3btFYUDUHTgykaTr9IA2W+yTMLwKKXBpJlr8lA4oRQpaNpdkuwUY9ivWtTycpl0v5YwLFYsJPcFQPJD31G8AXXBp58K/0YXlt2SuA+kg4QAlFHmJdOAfs8LeQLD01fWhlIWFJlLRS1NHKOOvWKT8YM8kx76I6Ck861Dxw== crgwbr@foo"  # NOQA
        models.validate_public_key(pub)


    def test_valid_ed25519_pem(self):
        pub = """
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAhRk96LXVjEtq8yI1I5LiRiv0OHiGvgJKfU0a4SweOe0=
-----END PUBLIC KEY-----
"""
        models.validate_public_key(pub)


    def test_valid_ed25519_openssh(self):
        pub = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDNkE30ChofcWQbPLrWhR+7uJkwEtRO2UCI2WxRiRpU3 crgwbr@foo"
        models.validate_public_key(pub)


    def test_invalid_rsa_pem(self):
        pub = """
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAodxbRh5LOtoB3Shf6K3m
Rn7ME7Doo5Qm5h72ITt+E6U0l6qXGdVBTj0XhQVNnGjnZTGzU7IacIw1a/03qVHJ
11S9VLqV2GEOzBKpB10/lwhRZuv/Qj7obwSqdVCzMNb7t5LHqG0MxOF7BeYELXIq
TEKFfWkZytXCAnmC9hk9RtzUZ/lryD1UgCHZ16gPtmPdFV7fuN8FBNrbaQCldz6V
6HVDjsPVxPmVYswV8qInG8kJUpm48s9PAWfgi4HCGmJgn+Irbed2tlRf73jxyCgX
0QIDAQAB
-----END PUBLIC KEY-----
"""
        with self.assertRaises(ValidationError):
            models.validate_public_key(pub)


    def test_invalid_rsa_openssh(self):
        pub = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQChfejJLRmWhIbK1Tt8lOGx2JECu6zymbFpYSH7cacUqpZfp/Bm4LMtFLqxXqeXymsGmH5mAJYqd0jKZtk0IM8RAvbn9iUvWtmqYXDcE734+dhvsfPEu8LDP251TIskslbj8XIKwQd4q1ervNmhG7o6culFSTltsLwDQ5LdopRfp2cu5i3umNXKBpbYcYDfa4YASmTra/rF+cp9YMXQkTTpsGBRn9wOnJmxRpFEdJ0QDBDqL4zAHkY0Fc4GJufl/4HoYmkolYxzkiYku6wd8bDMcU+o4XZ/78eNoYLPrjCHHy0ytPtFDZMuYB+e8DLGkVp3lNGfV+BRX+s/bexrBRLZoA9U2B7YHq7BOaZs8VRFehU/q0AICM0AOqKHFX3dJPKtEEUb4wmeFS/MoZQm2DXHIhkOA64A+ltdklGgHEjy8daQBvjJ0yIx5IfPMGFpZgk8/ETRcqHTEmmbU1ri6CevQrM7PFCGnmk3btFYUDUHTgykaTr9IA2W+yTMLwKKXBpJlr8lA4oRQpaNpdkuwUY9ivWtTycpl0v5YwLFYsJPcFQPJD31G8AXXBp58K/0YXlt2SuA+kg4QAlFHmJdOAfs8LeQLD01fWhlIWFJlLRS1NHKOOvWKT8YM8kx76I6Ck861Dxw== crgwbr@foo"  # NOQA
        with self.assertRaises(ValidationError):
            models.validate_public_key(pub)


    def test_invalid_ed25519_pem(self):
        pub = """
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAhRk96LXVjEtq8yI1I5Lv0OHiGvgJKfU0a4SweOe0=
-----END PUBLIC KEY-----
"""
        with self.assertRaises(ValidationError):
            models.validate_public_key(pub)


    def test_invalid_ed25519_openssh(self):
        pub = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDNkE30ChohR+7uJkwEtRO2UCI2WxRiRpU3 crgwbr@foo"
        with self.assertRaises(ValidationError):
            models.validate_public_key(pub)



class PublicKeyTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='foo')


    def test_extract_comment(self):
        pub = models.PublicKey(
            user=self.user,
            key="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDNkE30ChofcWQbPLrWhR+7uJkwEtRO2UCI2WxRiRpU3 crgwbr@foo",
            comment="")
        pub.save()
        self.assertEqual(pub.comment, 'crgwbr@foo')


    def test_update_last_used_datetime(self):
        pub = models.PublicKey(
            user=self.user,
            key="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDNkE30ChofcWQbPLrWhR+7uJkwEtRO2UCI2WxRiRpU3 crgwbr@foo")
        pub.save()
        self.assertEqual(pub.last_used_on, None)
        pub.update_last_used_datetime()
        # Check the first 19 digits (year – second precision) of ISO time: 2021-03-03T17:00:24
        self.assertEqual(pub.last_used_on.isoformat()[:19], timezone.now().isoformat()[:19])


    def test_get_allowed_algorithms_eddsa(self):
        pub = models.PublicKey(
            user=self.user,
            key="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDNkE30ChofcWQbPLrWhR+7uJkwEtRO2UCI2WxRiRpU3 crgwbr@foo",
            comment="")
        pub.save()
        self.assertEqual(pub.get_allowed_algorithms(), [
            'EdDSA',
        ])


    def test_get_allowed_algorithms_rsa(self):
        pubstr = """
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAodxbRh5LOtoB3Shf6K3m
Rn7ME7Doo5Qm5h72ITt+E6U0l6qXGdVBTj0XhQVNnGjnZTGzU7IacIw1a/03qVHJ
fcc0Ki7ig7YSPMMl0WSp0m080YlsCZ+9g+WG6DrgjpGQU7yaBhNsKtR5DP20bm84
11S9VLqV2GEOzBKpB10/lwhRZuv/Qj7obwSqdVCzMNb7t5LHqG0MxOF7BeYELXIq
TEKFfWkZytXCAnmC9hk9RtzUZ/lryD1UgCHZ16gPtmPdFV7fuN8FBNrbaQCldz6V
6HVDjsPVxPmVYswV8qInG8kJUpm48s9PAWfgi4HCGmJgn+Irbed2tlRf73jxyCgX
0QIDAQAB
-----END PUBLIC KEY-----
"""
        pub = models.PublicKey(
            user=self.user,
            key=pubstr,
            comment="")
        pub.save()
        self.assertEqual(pub.get_allowed_algorithms(), [
            'RS384',
            'RS256',
            'RS512',
        ])


    def test_get_loaded_key_eddsa(self):
        pub = models.PublicKey(
            user=self.user,
            key="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDNkE30ChofcWQbPLrWhR+7uJkwEtRO2UCI2WxRiRpU3 crgwbr@foo",
            comment="")
        pub.save()
        self.assertIsInstance(pub.get_loaded_key(), Ed25519PublicKey)


    def test_get_loaded_key_rsa(self):
        pubstr = """
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAodxbRh5LOtoB3Shf6K3m
Rn7ME7Doo5Qm5h72ITt+E6U0l6qXGdVBTj0XhQVNnGjnZTGzU7IacIw1a/03qVHJ
fcc0Ki7ig7YSPMMl0WSp0m080YlsCZ+9g+WG6DrgjpGQU7yaBhNsKtR5DP20bm84
11S9VLqV2GEOzBKpB10/lwhRZuv/Qj7obwSqdVCzMNb7t5LHqG0MxOF7BeYELXIq
TEKFfWkZytXCAnmC9hk9RtzUZ/lryD1UgCHZ16gPtmPdFV7fuN8FBNrbaQCldz6V
6HVDjsPVxPmVYswV8qInG8kJUpm48s9PAWfgi4HCGmJgn+Irbed2tlRf73jxyCgX
0QIDAQAB
-----END PUBLIC KEY-----
"""
        pub = models.PublicKey(
            user=self.user,
            key=pubstr,
            comment="")
        pub.save()
        self.assertIsInstance(pub.get_loaded_key(), RSAPublicKey)


    def test_get_loaded_key_invalid(self):
        pub = models.PublicKey(
            user=self.user,
            key="ssh-ed25519 AAAAC3Nza+7uJkwEtRO2UCI2WxRiRpU3 crgwbr@foo",
            comment="")
        pub.save()
        with self.assertRaises(ValueError):
            pub.get_loaded_key()



class JWKSEndpointTrustTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='foo')
        self.jwks = models.JWKSEndpointTrust.objects.create(
            user=self.user,
            jwks_url='https://dev-87evx9ru.auth0.com/.well-known/jwks.json')

    def test_get_signing_key(self):
        token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Ik5FRTFRVVJCT1RNNE16STVSa0ZETlRZeE9UVTFNRGcyT0Rnd1EwVXpNVGsxUWpZeVJrUkZRdyJ9.eyJpc3MiOiJodHRwczovL2Rldi04N2V2eDlydS5hdXRoMC5jb20vIiwic3ViIjoiYVc0Q2NhNzl4UmVMV1V6MGFFMkg2a0QwTzNjWEJWdENAY2xpZW50cyIsImF1ZCI6Imh0dHBzOi8vZXhwZW5zZXMtYXBpIiwiaWF0IjoxNTcyMDA2OTU0LCJleHAiOjE1NzIwMDY5NjQsImF6cCI6ImFXNENjYTc5eFJlTFdVejBhRTJINmtEME8zY1hCVnRDIiwiZ3R5IjoiY2xpZW50LWNyZWRlbnRpYWxzIn0.PUxE7xn52aTCohGiWoSdMBZGiYAHwE5FYie0Y1qUT68IHSTXwXVd6hn02HTah6epvHHVKA2FqcFZ4GGv5VTHEvYpeggiiZMgbxFrmTEY0csL6VNkX1eaJGcuehwQCRBKRLL3zKmA5IKGy5GeUnIbpPHLHDxr-GXvgFzsdsyWlVQvPX2xjeaQ217r2PtxDeqjlf66UYl6oY6AqNS8DH3iryCvIfCcybRZkc_hdy-6ZMoKT6Piijvk_aXdm7-QQqKJFHLuEqrVSOuBqqiNfVrG27QzAPuPOxvfXTVLXL2jek5meH6n-VWgrBdoMFH93QEszEDowDAEhQPHVs0xj7SIzA"  # NOQA
        signing_key = self.jwks.get_signing_key(token)
        data = jwt.decode(
            token,
            signing_key.key,
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
