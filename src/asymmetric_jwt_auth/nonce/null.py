from . import BaseNonceBackend


class NullNonceBackend(BaseNonceBackend):
    """
    Nonce backend which doesn't actually do anything
    """

    def validate_nonce(self, username: str, timestamp: int, nonce: str) -> bool:
        """
        Confirm that the given nonce hasn't already been used.
        """
        return True


    def log_used_nonce(self, username: str, timestamp: int, nonce: str) -> None:
        """
        Log a nonce as being used, and therefore henceforth invalid.
        """
        pass
