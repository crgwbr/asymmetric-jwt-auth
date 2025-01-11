from django.http import HttpRequest, JsonResponse
from django.views import View

from . import get_setting
from .keys import FacadePublicKey, PublicKey


class JWKSEndpointView(View):
    def get(self, request: HttpRequest) -> JsonResponse:
        keys = self.list_pub_keys()
        data = {
            "keys": [key.as_jwk for key in keys],
        }
        return JsonResponse(data)

    def list_pub_keys(self) -> list[FacadePublicKey]:
        keys: list[FacadePublicKey] = []
        for _key in get_setting("SIGNING_PUBLIC_KEYS"):
            if isinstance(_key, PublicKey):
                keys.append(_key)  # type:ignore[arg-type]
            else:
                exc, key = PublicKey.load_serialized_public_key(_key)
                if key is not None:
                    keys.append(key)
        return keys
