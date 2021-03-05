import secrets


class BaseNonceBackend:

    def validate_nonce(self, username: str, timestamp: int, nonce: str) -> bool:  # pragma: no cover
        raise NotImplementedError()


    def log_used_nonce(self, username: str, timestamp: int, nonce: str) -> None:  # pragma: no cover
        raise NotImplementedError()


    def generate_nonce(self) -> str:
        return secrets.token_urlsafe(nbytes=8)
