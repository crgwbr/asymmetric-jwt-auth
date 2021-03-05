from django.views import View
from django.http import JsonResponse
from . import get_setting
from .keys import PublicKey


class JWKSEndpointView(View):

    def get(self, request):
        keys = self.list_pub_keys()
        data = {
            "keys": [key.as_jwk for key in keys],
        }
        return JsonResponse(data)


    def list_pub_keys(self):
        keys = []
        for _key in get_setting('SIGNING_PUBLIC_KEYS'):
            if isinstance(_key, PublicKey):
                keys.append(_key)
            else:
                exc, key = PublicKey.load_serialized_public_key(_key)
                if key is not None:
                    keys.append(key)
        return keys
