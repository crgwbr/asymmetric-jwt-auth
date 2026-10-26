"""
A key set cache shared between processes through Django's cache, for keys fetched from JWKS endpoints.

Fetching a key set while a request waits would make the response time depend on whether the user a token claims
to be trusts a JWKS endpoint, which tells anyone timing the response that the user exists. So requests only read
the cache, and refreshes run in a background thread. A URL with nothing cached at all is the one exception.
"""

from typing import Any, TypedDict
import hashlib
import logging
import os
import queue
import threading
import time

from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from django.core.cache import cache
from jwt import PyJWK, PyJWKClient, PyJWKSet
from jwt.exceptions import PyJWKClientError, PyJWTError

from . import get_setting

logger = logging.getLogger(__name__)

#: Bump when ``CachedKeySet`` changes, so entries written by other versions read as a cache miss.
_CACHE_KEY_PREFIX = "asymmetric_jwt_auth-jwks-v2"
DECOY_CACHE_KEY = f"{_CACHE_KEY_PREFIX}-decoy"


class CachedKeySet(TypedDict):
    fetched_at: float
    #: ``None`` when the endpoint has never returned a usable response.
    jwks: dict[str, Any] | None


class _RefreshWorker:
    """
    One background thread per process, so scheduling a refresh costs a queue put rather than a thread start.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._pid: int | None = None
        self._queue: queue.SimpleQueue[str] = queue.SimpleQueue()
        self._pending: set[str] = set()

    def submit(self, jwks_url: str) -> None:
        with self._lock:
            if self._pid != os.getpid() and not self._start():
                return
            if jwks_url in self._pending:
                return
            self._pending.add(jwks_url)
            self._queue.put(jwks_url)

    def _start(self) -> bool:
        self._queue = queue.SimpleQueue()
        self._pending = set()
        thread = threading.Thread(
            target=self._run,
            args=(self._queue, self._pending),
            name="asymmetric-jwt-auth-jwks-refresh",
            daemon=True,
        )
        try:
            thread.start()
        except RuntimeError:
            logger.exception("Failed to start the JWKS refresh thread")
            return False
        self._pid = os.getpid()
        return True

    def _run(self, urls: "queue.SimpleQueue[str]", pending: set[str]) -> None:
        while True:
            jwks_url = urls.get()
            _refresh_unless_locked(jwks_url)
            with self._lock:
                pending.discard(jwks_url)


_refresh_worker = _RefreshWorker()
_signing_keys_by_url: dict[str, tuple[float, list[PyJWK]]] = {}
_last_refresh_by_url: dict[str, float] = {}


def get_signing_key(jwks_url: str, kid: str | None) -> PyJWK:
    """
    Get the signing key with the given key ID from the key set published at ``jwks_url``.

    A stale key set or an unknown key ID schedules a background refresh but is answered from the cache, so a
    token signed with a just-published key can be rejected until that refresh lands. A key set that hasn't been
    refreshed for ``JWKS_CACHE_MAX_AGE`` is no longer trusted. Signing keys without an ID are never used, so a
    ``kid`` of ``None`` never matches.

    :raises PyJWKClientError: if no trusted signing key has the given key ID.
    """
    entry: CachedKeySet | None = cache.get(_cache_key(jwks_url))
    if entry is None:
        entry = _refresh(jwks_url)
    age = time.time() - entry["fetched_at"]
    signing_key = None
    if kid is not None and age < get_setting("JWKS_CACHE_MAX_AGE"):
        signing_key = next((key for key in _get_signing_keys(jwks_url, entry) if key.key_id == kid), None)
    if (signing_key is None and kid is not None) or age >= get_setting("JWKS_CACHE_TTL"):
        _refresh_in_background(jwks_url, entry)
    if signing_key is None:
        raise PyJWKClientError(f'Unable to find a signing key that matches: "{kid}"')
    return signing_key


def read_decoy() -> None:
    """
    Do the cache read that :func:`get_signing_key` does, for a token whose claimed user has no JWKS endpoint.
    """
    cache.get(DECOY_CACHE_KEY)


def _cache_key(jwks_url: str) -> str:
    return f"{_CACHE_KEY_PREFIX}-{hashlib.sha256(jwks_url.encode()).hexdigest()}"


def _get_signing_keys(jwks_url: str, entry: CachedKeySet) -> list[PyJWK]:
    parsed = _signing_keys_by_url.get(jwks_url)
    if parsed is not None and parsed[0] == entry["fetched_at"]:
        return parsed[1]
    signing_keys = _parse_signing_keys(entry["jwks"])
    _signing_keys_by_url[jwks_url] = (entry["fetched_at"], signing_keys)
    return signing_keys


def _parse_signing_keys(jwks: dict[str, Any] | None) -> list[PyJWK]:
    if jwks is None:
        return []
    try:
        key_set = PyJWKSet.from_dict(jwks)
    except PyJWTError:
        return []
    return [
        key for key in key_set.keys if key.public_key_use in ("sig", None) and key.key_id and isinstance(key.key, rsa.RSAPublicKey | ed25519.Ed25519PublicKey)
    ]


def _refresh(jwks_url: str) -> CachedKeySet:
    """
    Fetch the key set and cache it. A failed fetch never replaces a cached key set.
    """
    jwks: dict[str, Any] | None
    try:
        data = PyJWKClient(jwks_url, cache_jwk_set=False, timeout=get_setting("JWKS_FETCH_TIMEOUT")).fetch_data()
    except (PyJWTError, ValueError) as e:
        logger.warning("Failed to fetch JWKS from %s: %s", jwks_url, e)
        jwks = None
    else:
        jwks = data if isinstance(data, dict) and isinstance(data.get("keys"), list) else None
    key = _cache_key(jwks_url)
    entry = CachedKeySet(fetched_at=time.time(), jwks=jwks)
    if jwks is not None:
        # The decoy copy makes cache reads for users without a JWKS endpoint return a real-sized value
        cache.set_many({key: entry, DECOY_CACHE_KEY: entry}, None)
        return entry
    if cache.add(key, entry, None):
        return entry
    existing: CachedKeySet | None = cache.get(key)
    return entry if existing is None else existing


def _refresh_in_background(jwks_url: str, entry: CachedKeySet) -> None:
    now = time.time()
    last_refresh = max(entry["fetched_at"], _last_refresh_by_url.get(jwks_url, 0.0))
    if now - last_refresh < get_setting("JWKS_REFRESH_COOLDOWN"):
        return
    _last_refresh_by_url[jwks_url] = now
    _queue_refresh(jwks_url)


def _queue_refresh(jwks_url: str) -> None:
    _refresh_worker.submit(jwks_url)


def _refresh_unless_locked(jwks_url: str) -> None:
    try:
        lock_key = f"{_cache_key(jwks_url)}-lock"
        if cache.add(lock_key, True, get_setting("JWKS_REFRESH_COOLDOWN")):
            _refresh(jwks_url)
    except Exception:
        logger.exception("Failed to refresh JWKS from %s", jwks_url)
