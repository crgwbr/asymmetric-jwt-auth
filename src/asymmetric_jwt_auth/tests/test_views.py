from django.core.cache import cache
from django.test import TestCase, Client, override_settings
from django.urls import reverse
from . import data
from ..keys import PublicKey
import json


class JWKSViewTest(TestCase):

    def setUp(self):
        cache.clear()


    def test_no_keys(self):
        client = Client()
        response = client.get(reverse('asymmetric_jwt_auth:jwks'))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(json.loads(response.content), {
            "keys": [],
        })


    @override_settings(ASYMMETRIC_JWT_AUTH=dict(
        SIGNING_PUBLIC_KEYS=[
            data.PEM_PUBLIC_RSA,
            data.PEM_PUBLIC_RSA
        ],
    ))
    def test_pem_keys(self):
        client = Client()
        response = client.get(reverse('asymmetric_jwt_auth:jwks'))
        self.assertEqual(response.status_code, 200)
        jwk = {
            'alg': 'RS512',
            'e': 'AQAB',
            'kid': '53c5b68c5ecba3e25df3f8326de6c0b0befb67e9217651a2f40e388f6567f056',
            'kty': 'RSA',
            'n': 'odxbRh5LOtoB3Shf6K3mRn7ME7Doo5Qm5h72ITt-E6U0l6qXGdVBTj0XhQVNnGjnZTGzU7IacIw1a_03qVHJfcc0Ki7ig7YSPMMl0WSp0m080YlsCZ-9g-WG6DrgjpGQU7yaBhNsKtR5DP20bm8411S9VLqV2GEOzBKpB10_lwhRZuv_Qj7obwSqdVCzMNb7t5LHqG0MxOF7BeYELXIqTEKFfWkZytXCAnmC9hk9RtzUZ_lryD1UgCHZ16gPtmPdFV7fuN8FBNrbaQCldz6V6HVDjsPVxPmVYswV8qInG8kJUpm48s9PAWfgi4HCGmJgn-Irbed2tlRf73jxyCgX0Q',  # NOQA
            'use': 'sig',
        }
        self.assertEqual(json.loads(response.content), {
            "keys": [
                jwk,
                jwk,
            ],
        })


    @override_settings(ASYMMETRIC_JWT_AUTH=dict(
        SIGNING_PUBLIC_KEYS=[
            PublicKey.load_pem(data.PEM_PUBLIC_RSA),
        ],
    ))
    def test_loaded_keys(self):
        client = Client()
        response = client.get(reverse('asymmetric_jwt_auth:jwks'))
        self.assertEqual(response.status_code, 200)
        jwk = {
            'alg': 'RS512',
            'e': 'AQAB',
            'kid': '53c5b68c5ecba3e25df3f8326de6c0b0befb67e9217651a2f40e388f6567f056',
            'kty': 'RSA',
            'n': 'odxbRh5LOtoB3Shf6K3mRn7ME7Doo5Qm5h72ITt-E6U0l6qXGdVBTj0XhQVNnGjnZTGzU7IacIw1a_03qVHJfcc0Ki7ig7YSPMMl0WSp0m080YlsCZ-9g-WG6DrgjpGQU7yaBhNsKtR5DP20bm8411S9VLqV2GEOzBKpB10_lwhRZuv_Qj7obwSqdVCzMNb7t5LHqG0MxOF7BeYELXIqTEKFfWkZytXCAnmC9hk9RtzUZ_lryD1UgCHZ16gPtmPdFV7fuN8FBNrbaQCldz6V6HVDjsPVxPmVYswV8qInG8kJUpm48s9PAWfgi4HCGmJgn-Irbed2tlRf73jxyCgX0Q',  # NOQA
            'use': 'sig',
        }
        self.assertEqual(json.loads(response.content), {
            "keys": [
                jwk,
            ],
        })


    @override_settings(ASYMMETRIC_JWT_AUTH=dict(
        SIGNING_PUBLIC_KEYS=[
            data.PEM_PUBLIC_RSA_INVALID,
        ],
    ))
    def test_invalid_pem_keys(self):
        client = Client()
        response = client.get(reverse('asymmetric_jwt_auth:jwks'))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(json.loads(response.content), {
            "keys": [
            ],
        })
