from django.utils.module_loading import import_string
from .. import get_setting
from .base import BaseNonceBackend


def get_nonce_backend() -> BaseNonceBackend:
    backend_path = get_setting('NONCE_BACKEND')
    Backend = import_string(backend_path)
    return Backend()
