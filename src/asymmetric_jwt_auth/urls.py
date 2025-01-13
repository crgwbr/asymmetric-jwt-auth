from django.urls import path
from django.views.decorators.cache import cache_page

from . import get_setting
from .views import JWKSEndpointView

_cache_jwks = cache_page(get_setting("JWKS_VIEW_TTL"))

app_name = "asymmetric_jwt_auth"
urlpatterns = [
    path(".well-known/jwks.json", _cache_jwks(JWKSEndpointView.as_view()), name="jwks"),
]
