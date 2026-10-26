from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock
import ipaddress
import json
import os
import queue
import socket
import socketserver
import ssl
import tempfile
import threading
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from django.core.cache import cache
from django.db import DatabaseError
from django.test import SimpleTestCase, TestCase, override_settings
from freezegun import freeze_time
from jwt.exceptions import PyJWKClientConnectionError, PyJWKClientError

from .. import jwks
from ..keys import RSAPrivateKey


@mock.patch("asymmetric_jwt_auth.jwks._fetch_jwks")
class JWKSCacheTest(TestCase):
    jwks_url = "https://example.com/.well-known/jwks.json"

    def setUp(self) -> None:
        refresh_worker = mock.patch.object(jwks, "_refresh_worker")
        refresh_worker.start()
        self.addCleanup(refresh_worker.stop)
        cache.clear()
        jwks._signing_keys_by_url.clear()
        jwks._last_refresh_by_url.clear()
        self.key = RSAPrivateKey.generate().public_key

    def test_refresh_worker_updates_cache(self, mock_fetch_data: mock.MagicMock) -> None:
        mock_fetch_data.return_value = {"keys": [self.key.as_jwk]}
        worker = jwks._RefreshWorker()
        worker.submit(self.jwks_url)
        deadline = time.monotonic() + 5
        while cache.get(jwks._cache_key(self.jwks_url)) is None and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertEqual(mock_fetch_data.call_count, 1)
        with mock.patch.object(jwks, "_queue_refresh") as mock_start_refresh:
            self.assertEqual(jwks.get_signing_key(self.jwks_url, self.key.fingerprint).key_id, self.key.fingerprint)
        self.assertEqual(mock_fetch_data.call_count, 1)
        mock_start_refresh.assert_not_called()

    def test_refresh_worker_skips_urls_already_queued(self, mock_fetch_data: mock.MagicMock) -> None:
        fetching = threading.Event()
        release = threading.Event()

        def slow_fetch(jwks_url: str) -> dict[str, object]:
            fetching.set()
            release.wait(5)
            return {"keys": [self.key.as_jwk]}

        mock_fetch_data.side_effect = slow_fetch
        worker = jwks._RefreshWorker()
        worker.submit(self.jwks_url)
        self.assertTrue(fetching.wait(5))
        worker.submit(self.jwks_url)
        self.assertEqual(worker._queue.qsize(), 0)
        release.set()
        deadline = time.monotonic() + 5
        while self.jwks_url in worker._pending and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertNotIn(self.jwks_url, worker._pending)
        self.assertEqual(mock_fetch_data.call_count, 1)

    def test_refresh_lock_prevents_duplicate_fetches(self, mock_fetch_data: mock.MagicMock) -> None:
        mock_fetch_data.return_value = {"keys": [self.key.as_jwk]}
        jwks._refresh_unless_locked(self.jwks_url)
        jwks._refresh_unless_locked(self.jwks_url)
        self.assertEqual(mock_fetch_data.call_count, 1)

    def test_refresh_errors_are_logged(self, mock_fetch_data: mock.MagicMock) -> None:
        broken_cache = mock.MagicMock()
        broken_cache.add.side_effect = ConnectionError("cache down")
        with (
            mock.patch.object(jwks, "cache", broken_cache),
            self.assertLogs("asymmetric_jwt_auth.jwks", level="ERROR"),
        ):
            jwks._refresh_unless_locked(self.jwks_url)
        mock_fetch_data.assert_not_called()

    def test_missing_key_id_never_matches_or_refreshes(self, mock_fetch_data: mock.MagicMock) -> None:
        jwk = self.key.as_jwk
        del jwk["kid"]
        mock_fetch_data.return_value = {"keys": [jwk]}
        with mock.patch.object(jwks, "_queue_refresh") as mock_start_refresh, self.assertRaises(PyJWKClientError):
            jwks.get_signing_key(self.jwks_url, None)
        mock_start_refresh.assert_not_called()

    def test_unusable_key_set(self, mock_fetch_data: mock.MagicMock) -> None:
        payloads: list[object] = [{"keys": []}, {"keys": [{"kty": "nope"}]}, ["not", "a", "dict"]]
        for payload in payloads:
            with self.subTest(payload=payload):
                self.setUp()
                mock_fetch_data.return_value = payload
                with self.assertRaises(PyJWKClientError):
                    jwks.get_signing_key(self.jwks_url, self.key.fingerprint)

    def test_malformed_response_doesnt_replace_cached_key_set(self, mock_fetch_data: mock.MagicMock) -> None:
        mock_fetch_data.return_value = {"keys": [self.key.as_jwk]}
        fetched_at = jwks._refresh(self.jwks_url)["fetched_at"]
        for payload in ({"error": "temporarily unavailable"}, {"keys": "nope"}):
            with self.subTest(payload=payload):
                mock_fetch_data.return_value = payload
                jwks._refresh(self.jwks_url)
                entry = cache.get(jwks._cache_key(self.jwks_url))
                self.assertEqual(entry["fetched_at"], fetched_at)
                self.assertEqual(jwks.get_signing_key(self.jwks_url, self.key.fingerprint).key_id, self.key.fingerprint)

    def test_refresh_worker_survives_thread_start_failure(self, mock_fetch_data: mock.MagicMock) -> None:
        worker = jwks._RefreshWorker()
        with (
            mock.patch.object(jwks.threading.Thread, "start", side_effect=RuntimeError("can't start new thread")),
            self.assertLogs("asymmetric_jwt_auth.jwks", level="ERROR"),
        ):
            worker.submit(self.jwks_url)
        self.assertIsNone(worker._pid)

    def test_failed_fetch_doesnt_replace_cached_key_set(self, mock_fetch_data: mock.MagicMock) -> None:
        mock_fetch_data.return_value = {"keys": [self.key.as_jwk]}
        jwks._refresh(self.jwks_url)
        fetched_at = cache.get(jwks._cache_key(self.jwks_url))["fetched_at"]
        mock_fetch_data.side_effect = PyJWKClientConnectionError("down")
        with freeze_time() as frozen:
            frozen.tick(timedelta(minutes=1))
            jwks._refresh(self.jwks_url)
        entry = cache.get(jwks._cache_key(self.jwks_url))
        self.assertIsNotNone(entry["jwks"])
        self.assertEqual(entry["fetched_at"], fetched_at)

    def test_refresh_if_stale(self, mock_fetch_data: mock.MagicMock) -> None:
        mock_fetch_data.return_value = {"keys": [self.key.as_jwk]}
        with freeze_time() as frozen:
            jwks._refresh_if_stale(self.jwks_url)
            frozen.tick(timedelta(minutes=4))
            jwks._refresh_if_stale(self.jwks_url)
            self.assertEqual(mock_fetch_data.call_count, 1)
            frozen.tick(timedelta(minutes=1))
            jwks._refresh_if_stale(self.jwks_url)
        self.assertEqual(mock_fetch_data.call_count, 2)

    def test_refresh_worker_sweeps_watched_urls_on_a_timer(self, mock_fetch_data: mock.MagicMock) -> None:
        class StopWorker(Exception):
            pass

        worker = jwks._RefreshWorker()
        with (
            freeze_time() as frozen,
            mock.patch.object(jwks, "close_old_connections"),
            mock.patch.object(jwks, "_refresh_if_stale") as mock_refresh_if_stale,
        ):

            def wait_for_url(timeout: float) -> str:
                if mock_refresh_if_stale.call_count:
                    raise StopWorker
                self.assertEqual(timeout, 150)
                frozen.tick(timedelta(seconds=timeout))
                raise queue.Empty

            urls = mock.MagicMock()
            urls.get.side_effect = wait_for_url
            with self.assertRaises(StopWorker):
                worker._run(urls, set(), {self.jwks_url: time.monotonic()})
        mock_refresh_if_stale.assert_called_once_with(self.jwks_url)

    def test_refresh_worker_recycles_database_connections(self, mock_fetch_data: mock.MagicMock) -> None:
        class StopWorker(Exception):
            pass

        urls = mock.MagicMock()
        urls.get.side_effect = [self.jwks_url, StopWorker]
        events = mock.MagicMock()
        with (
            mock.patch.object(jwks, "close_old_connections", events.close_old_connections),
            mock.patch.object(jwks, "_refresh_unless_locked", events.refresh),
            self.assertRaises(StopWorker),
        ):
            events.close_old_connections.side_effect = DatabaseError
            with self.assertLogs(jwks.logger, "ERROR"):
                jwks._RefreshWorker()._run(urls, set(), set())
        self.assertEqual(events.mock_calls, [mock.call.close_old_connections(), mock.call.refresh(self.jwks_url)])

    def test_refresh_worker_refreshes_idle_key_sets_within_one_and_a_half_ttls(self, mock_fetch_data: mock.MagicMock) -> None:
        class StopWorker(Exception):
            pass

        refreshed_at: list[float] = []
        with (
            freeze_time() as frozen,
            mock.patch.object(jwks, "close_old_connections"),
            mock.patch.object(jwks, "_refresh_unless_locked", side_effect=lambda url: refreshed_at.append(time.time())),
        ):
            started = time.time()
            # Fetched a moment after the worker sets its first sweep timer, so the next sweep finds it just under TTL old
            cache.set(jwks._cache_key(self.jwks_url), jwks.CachedKeySet(fetched_at=started + 1, jwks={"keys": []}), None)

            def wait_for_url(timeout: float) -> str:
                if refreshed_at:
                    raise StopWorker
                frozen.tick(timedelta(seconds=timeout))
                raise queue.Empty

            urls = mock.MagicMock()
            urls.get.side_effect = wait_for_url
            with self.assertRaises(StopWorker):
                jwks._RefreshWorker()._run(urls, set(), {self.jwks_url: time.monotonic()})
        self.assertLessEqual(refreshed_at[0] - started, 1.5 * 300 + 1)

    def test_refresh_worker_stops_sweeping_urls_no_request_uses(self, mock_fetch_data: mock.MagicMock) -> None:
        class StopWorker(Exception):
            pass

        unused_url = "https://unused.example.com/.well-known/jwks.json"
        worker = jwks._RefreshWorker()
        with (
            freeze_time() as frozen,
            mock.patch.object(jwks.threading, "Thread"),
            mock.patch.object(jwks, "close_old_connections"),
            mock.patch.object(jwks, "_refresh_if_stale") as mock_refresh_if_stale,
        ):
            worker.watch(unused_url)
            worker.watch(self.jwks_url)
            frozen.tick(timedelta(hours=23))
            worker.watch(self.jwks_url)
            frozen.tick(timedelta(hours=1, seconds=1))

            def wait_for_url(timeout: float) -> str:
                if mock_refresh_if_stale.call_count:
                    raise StopWorker
                frozen.tick(timedelta(seconds=timeout))
                raise queue.Empty

            urls = mock.MagicMock()
            urls.get.side_effect = wait_for_url
            with self.assertRaises(StopWorker):
                worker._run(urls, set(), worker._watched)
            mock_refresh_if_stale.assert_called_once_with(self.jwks_url)
            self.assertEqual(list(worker._watched), [self.jwks_url])

            worker.watch(unused_url)
        self.assertEqual(set(worker._watched), {self.jwks_url, unused_url})

    def test_watch_starts_worker_once_per_process(self, mock_fetch_data: mock.MagicMock) -> None:
        worker = jwks._RefreshWorker()
        with (
            mock.patch.object(jwks.threading, "Thread"),
            mock.patch.object(worker, "_start", wraps=worker._start) as mock_start,
        ):
            worker.watch(self.jwks_url)
            worker.watch(self.jwks_url)
            worker.submit(self.jwks_url)
        mock_start.assert_called_once_with()
        self.assertEqual(list(worker._watched), [self.jwks_url])


_JWKS_BODY = json.dumps({"keys": []}).encode()


def _drip(data: bytes) -> Iterator[bytes]:
    """Yield ``data`` a byte at a time, each well inside the socket timeout but together past the budget"""
    for i in range(len(data)):
        time.sleep(0.02)
        yield data[i : i + 1]


class _JWKSHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        try:
            if self.path == "/slow-headers":
                for part in _drip(b"HTTP/1.0 200 OK\r\nX-Padding: " + b"x" * 200 + b"\r\n\r\n"):
                    self.wfile.write(part)
                return
            if self.path == "/negative-chunk":
                self.wfile.write(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n-1\r\n" + b"x" * 100_000)
                return
            if self.path == "/redirect":
                self.send_response(302)
                self.send_header("Location", "/jwks")
                self.end_headers()
                return
            body = _JWKS_BODY
            if self.path == "/big":
                body = b" " * 1000 + _JWKS_BODY
            elif self.path == "/deep":
                body = b"[" * 1_000_000
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body) * (200 if self.path == "/slow-body" else 1)))
            self.end_headers()
            if self.path == "/slow-body":
                for part in _drip(body * 200):
                    self.wfile.write(part)
                    self.wfile.flush()
            else:
                self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def log_message(self, format: str, *args: object) -> None:
        pass


class _StallingTLSHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        sock = self.request
        assert isinstance(sock, socket.socket)
        try:
            sock.recv(4096)
            # A handshake record header promising 16 KiB, so the client keeps waiting for the rest
            sock.sendall(bytes([0x16, 0x03, 0x03, 0x40, 0x00]))
            for part in _drip(b"\0" * 100):
                sock.sendall(part)
        except OSError:
            pass


def _tls_contexts(directory: str) -> tuple[ssl.SSLContext, ssl.SSLContext]:
    """A server context with a self-signed certificate for 127.0.0.1, and a client context that trusts only it"""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    cert_path = os.path.join(directory, "cert.pem")
    key_path = os.path.join(directory, "key.pem")
    with open(cert_path, "wb") as f:
        f.write(cert_pem)
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(cert_path, key_path)
    client_context = ssl.create_default_context(cadata=cert_pem.decode())
    return server_context, client_context


@override_settings(ASYMMETRIC_JWT_AUTH={"JWKS_FETCH_TIMEOUT": 0.3, "JWKS_MAX_RESPONSE_BYTES": 500})
class JWKSFetchTest(SimpleTestCase):
    server: ThreadingHTTPServer
    https_server: ThreadingHTTPServer
    tls_server: socketserver.ThreadingTCPServer
    client_tls_context: ssl.SSLContext

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _JWKSHandler)
        cls.https_server = ThreadingHTTPServer(("127.0.0.1", 0), _JWKSHandler)
        with tempfile.TemporaryDirectory() as directory:
            server_tls_context, cls.client_tls_context = _tls_contexts(directory)
        # The handshake then runs on each request's thread, not the one accepting connections
        cls.https_server.socket = server_tls_context.wrap_socket(cls.https_server.socket, server_side=True, do_handshake_on_connect=False)
        cls.tls_server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _StallingTLSHandler)
        for server in (cls.server, cls.https_server, cls.tls_server):
            server.daemon_threads = True
            threading.Thread(target=server.serve_forever, daemon=True).start()
            cls.addClassCleanup(server.server_close)
            cls.addClassCleanup(server.shutdown)

    def url(self, path: str) -> str:
        return f"http://127.0.0.1:{self.server.server_address[1]}{path}"

    def test_fetch(self) -> None:
        self.assertEqual(jwks._fetch_jwks(self.url("/jwks")), {"keys": []})

    def test_slow_body_runs_out_of_time(self) -> None:
        started = time.monotonic()
        with self.assertRaises(PyJWKClientConnectionError):
            jwks._fetch_jwks(self.url("/slow-body"))
        self.assertLess(time.monotonic() - started, 1)

    def test_https(self) -> None:
        url = f"https://127.0.0.1:{self.https_server.server_address[1]}"
        with mock.patch.object(ssl, "_create_default_https_context", lambda: self.client_tls_context):
            self.assertEqual(jwks._fetch_jwks(f"{url}/jwks"), {"keys": []})
            started = time.monotonic()
            with self.assertRaises(PyJWKClientConnectionError):
                jwks._fetch_jwks(f"{url}/slow-body")
            self.assertLess(time.monotonic() - started, 1)
        with self.assertRaises(PyJWKClientConnectionError):
            jwks._fetch_jwks(f"{url}/jwks")

    def test_slow_headers_run_out_of_time(self) -> None:
        started = time.monotonic()
        with self.assertRaises(PyJWKClientConnectionError):
            jwks._fetch_jwks(self.url("/slow-headers"))
        self.assertLess(time.monotonic() - started, 1)

    @override_settings(ASYMMETRIC_JWT_AUTH={"JWKS_FETCH_TIMEOUT": 0.6})
    def test_slow_connect_leaves_less_time_for_tls_handshake(self) -> None:
        connect = socket.socket.connect

        def slow_connect(sock: socket.socket, address: tuple[str, int]) -> None:
            time.sleep(0.5)
            connect(sock, address)

        started = time.monotonic()
        with (
            mock.patch.object(socket.socket, "connect", slow_connect),
            self.assertRaises(PyJWKClientConnectionError),
        ):
            jwks._fetch_jwks(f"https://127.0.0.1:{self.tls_server.server_address[1]}/")
        self.assertLess(time.monotonic() - started, 0.85)

    @override_settings(ASYMMETRIC_JWT_AUTH={"JWKS_FETCH_TIMEOUT": 0.6})
    def test_connect_timeouts_share_the_budget(self) -> None:
        address = ("127.0.0.1", 9)

        def blackholed_connect(sock: socket.socket, address: tuple[str, int]) -> None:
            timeout = sock.gettimeout()
            assert timeout is not None
            time.sleep(timeout)
            raise TimeoutError("timed out")

        started = time.monotonic()
        with (
            mock.patch.object(socket, "getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", address)] * 2),
            mock.patch.object(socket.socket, "connect", blackholed_connect),
            self.assertRaises(PyJWKClientConnectionError),
        ):
            jwks._fetch_jwks("http://jwks.example.com/")
        self.assertLess(time.monotonic() - started, 0.85)

    def test_unusable_address_is_skipped(self) -> None:
        address = self.server.server_address[:2]
        unsupported_family = (9999, socket.SOCK_STREAM, 6, "", address)
        supported_family = (socket.AF_INET, socket.SOCK_STREAM, 6, "", address)
        with mock.patch.object(socket, "getaddrinfo", return_value=[unsupported_family, supported_family]):
            self.assertEqual(jwks._fetch_jwks("http://jwks.example.com/jwks"), {"keys": []})

    def test_oversized_body_is_rejected(self) -> None:
        with self.assertRaisesMessage(PyJWKClientConnectionError, "larger than 500 bytes"):
            jwks._fetch_jwks(self.url("/big"))

    @override_settings(ASYMMETRIC_JWT_AUTH={"JWKS_MAX_RESPONSE_BYTES": 2_000_000})
    def test_deeply_nested_body_is_a_failed_fetch(self) -> None:
        with mock.patch.object(jwks, "cache") as mock_cache:
            mock_cache.add.return_value = True
            self.assertIsNone(jwks._refresh(self.url("/deep"))["jwks"])

    def test_negative_chunk_size_cant_bypass_the_size_cap(self) -> None:
        with self.assertRaisesMessage(PyJWKClientConnectionError, "larger than 500 bytes"):
            jwks._fetch_jwks(self.url("/negative-chunk"))

    def test_redirects_are_not_followed(self) -> None:
        with self.assertRaises(PyJWKClientConnectionError):
            jwks._fetch_jwks(self.url("/redirect"))

    def test_only_http_urls_are_fetched(self) -> None:
        with self.assertRaises(PyJWKClientConnectionError):
            jwks._fetch_jwks("file:///etc/passwd")

    def test_failed_fetch_keeps_cached_key_set(self) -> None:
        good: jwks.CachedKeySet = {"fetched_at": 1.0, "jwks": {"keys": []}}
        with mock.patch.object(jwks, "cache") as mock_cache:
            mock_cache.add.return_value = False
            mock_cache.get.return_value = good
            for path in ("/slow-body", "/big"):
                with self.subTest(path=path):
                    self.assertIs(jwks._refresh(self.url(path)), good)
        mock_cache.set_many.assert_not_called()
