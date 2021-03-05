from typing import List
from django.utils.module_loading import import_string
from .. import get_setting
from .base import BaseUserRepository, BasePublicKeyRepository


def get_user_repository() -> BaseUserRepository:
    Repo = import_string(get_setting('USER_REPOSITORY'))
    return Repo()


def get_public_key_repositories() -> List[BasePublicKeyRepository]:
    repos = []
    for cls_path in get_setting('PUBLIC_KEY_REPOSITORIES'):
        Repo = import_string(cls_path)
        repo = Repo()
        repos.append(repo)
    return repos
