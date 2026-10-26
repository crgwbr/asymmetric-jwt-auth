"""
A key set cache shared between processes through Django's cache, for keys fetched from JWKS endpoints.

Fetching a key set while a request waits would make the response time depend on whether the user a token claims
to be trusts a JWKS endpoint, which tells anyone timing the response that the user exists. So requests only read
the cache, and refreshes run in a background thread. A URL with nothing cached at all is the one exception.

The thread also refreshes every key set its process has used on a timer, not only when a request finds one stale.
That keeps idle key sets fresh, so a key set can be distrusted once it is older than ``JWKS_CACHE_MAX_AGE``, which
bounds how long a key removed from its endpoint is still accepted.
"""

from typing import TYPE_CHECKING, TypedDict
from urllib.error import HTTPError
from urllib.parse import urlparse
import hashlib
import http.client
import io
import json
import logging
import os
import queue
import socket
import threading
import time
import urllib.request

from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from django.core.cache import cache
from django.db import close_old_connections
from jwt import PyJWK, PyJWKSet
from jwt.exceptions import PyJWKClientConnectionError, PyJWKClientError, PyJWTError

if TYPE_CHECKING:
    from _typeshed import WriteableBuffer

from . import get_setting

logger = logging.getLogger(__name__)

#: Bump when ``CachedKeySet`` changes, so entries written by other versions read as a cache miss.
_CACHE_KEY_PREFIX = "asymmetric_jwt_auth-jwks-v2"
DECOY_CACHE_KEY = f"{_CACHE_KEY_PREFIX}-decoy"
#: Multiple of ``JWKS_CACHE_MAX_AGE`` that a key set can go unused before its process stops refreshing it.
_UNWATCH_AFTER_MAX_AGES = 24


class CachedKeySet(TypedDict):
    fetched_at: float
    #: ``None`` when the endpoint has never returned a usable response.
    jwks: dict[str, object] | None


class _RefreshWorker:
    """
    One background thread per process, so scheduling a refresh costs a queue put rather than a thread start.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._pid: int | None = None
        self._queue: queue.SimpleQueue[str] = queue.SimpleQueue()
        self._pending: set[str] = set()
        #: Each watched URL, and when a request last used it.
        self._watched: dict[str, float] = {}

    def watch(self, jwks_url: str) -> None:
        """
        Refresh the key set at ``jwks_url`` whenever it goes stale, until this process has gone
        ``_UNWATCH_AFTER_MAX_AGES`` times ``JWKS_CACHE_MAX_AGE`` without a request using it. Otherwise a deleted or
        abandoned endpoint would be fetched until the process restarts.
        """
        if self._pid == os.getpid() and jwks_url in self._watched:
            self._watched[jwks_url] = time.monotonic()
            return
        with self._lock:
            if self._pid != os.getpid() and not self._start():
                return
            self._watched[jwks_url] = time.monotonic()

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
        self._watched = {}
        thread = threading.Thread(
            target=self._run,
            args=(self._queue, self._pending, self._watched),
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

    def _run(self, urls: "queue.SimpleQueue[str]", pending: set[str], watched: dict[str, float]) -> None:
        next_sweep = time.monotonic() + _sweep_interval()
        while True:
            # Checked before waiting, so a busy queue can't starve the sweep
            if time.monotonic() >= next_sweep:
                next_sweep = time.monotonic() + _sweep_interval()
                unused_since = time.monotonic() - get_setting("JWKS_CACHE_MAX_AGE") * _UNWATCH_AFTER_MAX_AGES
                with self._lock:
                    for watched_url, last_used in list(watched.items()):
                        if last_used < unused_since:
                            del watched[watched_url]
                    swept = list(watched)
                for watched_url in swept:
                    _close_old_connections()
                    _refresh_if_stale(watched_url)
            try:
                jwks_url = urls.get(timeout=max(next_sweep - time.monotonic(), 0.0))
            except queue.Empty:
                continue
            _close_old_connections()
            _refresh_unless_locked(jwks_url)
            with self._lock:
                pending.discard(jwks_url)


def _sweep_interval() -> float:
    # A key set fetched just after a sweep is still fresh at the next one, so sweeping every TTL would leave it for 2 TTLs
    ttl: float = get_setting("JWKS_CACHE_TTL")
    return ttl / 2


def _close_old_connections() -> None:
    """
    Do for the refresh thread what Django does around each request, so a database cache backend recovers from a
    dropped connection.
    """
    try:
        close_old_connections()
    except Exception:
        logger.exception("Failed to close old database connections")


_refresh_worker = _RefreshWorker()
_signing_keys_by_url: dict[str, tuple[float, list[PyJWK]]] = {}
_last_refresh_by_url: dict[str, float] = {}


def get_signing_key(jwks_url: str, kid: str | None) -> PyJWK:
    """
    Get the signing key with the given key ID from the key set published at ``jwks_url``.

    A stale key set or an unknown key ID schedules a background refresh but is answered from the cache, so a
    token signed with a just-published key can be rejected until that refresh lands. A key set last fetched
    ``JWKS_CACHE_MAX_AGE`` or more ago is no longer trusted. Signing keys without an ID are never used, so a
    ``kid`` of ``None`` never matches.

    :raises PyJWKClientError: if no trusted signing key has the given key ID.
    """
    _refresh_worker.watch(jwks_url)
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


def _parse_signing_keys(jwks: dict[str, object] | None) -> list[PyJWK]:
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
    jwks: dict[str, object] | None
    try:
        data = _fetch_jwks(jwks_url)
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


def _fetch_jwks(jwks_url: str) -> object:
    """
    Download and decode the JSON document at ``jwks_url``.

    ``JWKS_FETCH_TIMEOUT`` limits the whole download rather than each socket read, and the whole response, headers
    included, is capped at ``JWKS_MAX_RESPONSE_BYTES``. Otherwise an endpoint that answers slowly or sends too much could hold up the
    refresh worker, and with it the refreshes of every other key set, for as long as it liked.

    :raises PyJWKClientConnectionError: if the download fails, runs out of time, or is too large.
    :raises ValueError: if the body isn't JSON, or nests too deeply to decode.
    """
    # Never follow file:// or other schemes urllib would otherwise open
    if urlparse(jwks_url).scheme.lower() not in ("http", "https"):
        raise PyJWKClientConnectionError(f"Unsupported JWKS URL: {jwks_url}")
    timeout: float = get_setting("JWKS_FETCH_TIMEOUT")
    max_bytes: int = get_setting("JWKS_MAX_RESPONSE_BYTES")
    opener = urllib.request.build_opener(_NoRedirectHandler(), *_limited_handlers(time.monotonic() + timeout, max_bytes))
    try:
        with opener.open(jwks_url, timeout=timeout) as response:
            body: bytes = response.read(max_bytes)
    except (OSError, http.client.HTTPException) as e:
        if isinstance(e, HTTPError):
            e.close()
        raise PyJWKClientConnectionError(f"Failed to fetch JWKS: {e}") from e
    try:
        result: object = json.loads(body)
    except RecursionError as e:
        raise ValueError("JWKS response is nested too deeply") from e
    return result


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: object,
        code: int,
        msg: str,
        headers: object,
        newurl: str,
    ) -> None:
        return None


class _LimitedReader(io.RawIOBase):
    """
    Gives each socket read only the time left before the deadline, and fails once more than ``max_bytes`` have
    arrived. A socket timeout alone limits each read, so a response sent a byte at a time could last forever. And
    http.client can read past the size it was asked for, for example when a chunked body claims a negative size.
    """

    def __init__(self, raw: io.RawIOBase, sock: socket.socket, deadline: float, max_bytes: int) -> None:
        super().__init__()
        self._raw = raw
        self._sock = sock
        self._deadline = deadline
        self._max_bytes = max_bytes
        self._bytes_read = 0

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: "WriteableBuffer") -> int | None:
        self._sock.settimeout(_time_left(self._deadline))
        count = self._raw.readinto(buffer)
        self._bytes_read += count or 0
        if self._bytes_read > self._max_bytes:
            raise OSError(f"JWKS response is larger than {self._max_bytes} bytes")
        return count

    def close(self) -> None:
        self._raw.close()
        super().close()


def _time_left(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("Ran out of time to fetch the JWKS")
    return remaining


def _connect_by_deadline(address: tuple[str, int], source_address: tuple[str, int] | None, deadline: float) -> socket.socket:
    """
    Like :func:`socket.create_connection`, except that every address shares the time left before the deadline, rather
    than each getting the full timeout. The socket keeps only the time that's left, which also bounds the TLS
    handshake that may follow, since the stdlib runs the whole handshake under one socket timeout.
    """
    host, port = address
    error: OSError | None = None
    for family, kind, proto, _, sockaddr in socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM):
        remaining = _time_left(deadline)
        sock: socket.socket | None = None
        try:
            sock = socket.socket(family, kind, proto)
            sock.settimeout(remaining)
            if source_address:
                sock.bind(source_address)
            sock.connect(sockaddr)
            sock.settimeout(_time_left(deadline))
        except OSError as e:
            if sock is not None:
                sock.close()
            error = e
            continue
        return sock
    raise error if error is not None else OSError(f"No addresses found for {host}")


def _limited_handlers(deadline: float, max_bytes: int) -> list[urllib.request.BaseHandler]:
    """
    urllib handlers that open their connections with :func:`_connect_by_deadline` and read their responses,
    including status lines and headers, with a :class:`_LimitedReader`.
    """

    def create_connection(address: tuple[str, int], timeout: float | None, source_address: tuple[str, int] | None) -> socket.socket:
        return _connect_by_deadline(address, source_address, deadline)

    class Response(http.client.HTTPResponse):
        def __init__(self, sock: socket.socket, debuglevel: int = 0, method: str | None = None, url: str | None = None) -> None:
            super().__init__(sock, debuglevel, method, url)
            self.fp = io.BufferedReader(_LimitedReader(self.fp.detach(), sock, deadline, max_bytes))

    # http.client opens every connection, including the one an HTTPS connection wraps, through _create_connection
    class HTTPConnection(http.client.HTTPConnection):
        response_class = Response

        def connect(self) -> None:
            self._create_connection = create_connection
            super().connect()

    class HTTPSConnection(http.client.HTTPSConnection):
        response_class = Response

        def connect(self) -> None:
            self._create_connection = create_connection
            super().connect()

    class HTTPHandler(urllib.request.HTTPHandler):
        def http_open(self, req: urllib.request.Request) -> http.client.HTTPResponse:
            return self.do_open(HTTPConnection, req)

    class HTTPSHandler(urllib.request.HTTPSHandler):
        def https_open(self, req: urllib.request.Request) -> http.client.HTTPResponse:
            return self.do_open(HTTPSConnection, req)

    return [HTTPHandler(), HTTPSHandler()]


def _refresh_in_background(jwks_url: str, entry: CachedKeySet) -> None:
    now = time.time()
    last_refresh = max(entry["fetched_at"], _last_refresh_by_url.get(jwks_url, 0.0))
    if now - last_refresh < get_setting("JWKS_REFRESH_COOLDOWN"):
        return
    _last_refresh_by_url[jwks_url] = now
    _queue_refresh(jwks_url)


def _queue_refresh(jwks_url: str) -> None:
    _refresh_worker.submit(jwks_url)


def _refresh_if_stale(jwks_url: str) -> None:
    try:
        entry: CachedKeySet | None = cache.get(_cache_key(jwks_url))
    except Exception:
        logger.exception("Failed to read the cached JWKS for %s", jwks_url)
        return
    if entry is None or time.time() - entry["fetched_at"] >= get_setting("JWKS_CACHE_TTL"):
        _refresh_unless_locked(jwks_url)


def _refresh_unless_locked(jwks_url: str) -> None:
    try:
        lock_key = f"{_cache_key(jwks_url)}-lock"
        if cache.add(lock_key, True, get_setting("JWKS_REFRESH_COOLDOWN")):
            _refresh(jwks_url)
    except Exception:
        logger.exception("Failed to refresh JWKS from %s", jwks_url)
