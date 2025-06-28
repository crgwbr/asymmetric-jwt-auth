from django.utils.module_loading import import_string

from .. import get_setting
from .base import BasePublicKeyRepository, BaseUserRepository


def get_user_repository() -> BaseUserRepository:
    Repo: type[BaseUserRepository] = import_string(get_setting("USER_REPOSITORY"))
    return Repo()


def get_public_key_repositories() -> list[BasePublicKeyRepository]:
    repos = []
    for cls_path in get_setting("PUBLIC_KEY_REPOSITORIES"):
        Repo = import_string(cls_path)
        repo = Repo()
        repos.append(repo)
    return repos
