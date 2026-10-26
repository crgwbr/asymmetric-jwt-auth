from unittest import mock
import threading
import time

from django.core.cache import cache
from django.test import TestCase
from jwt.exceptions import PyJWKClientConnectionError, PyJWKClientError

from .. import jwks
from ..keys import RSAPrivateKey


@mock.patch("asymmetric_jwt_auth.models.PyJWKClient.fetch_data")
class JWKSCacheTest(TestCase):
    jwks_url = "https://example.com/.well-known/jwks.json"

    def setUp(self):
        cache.clear()
        jwks._signing_keys_by_url.clear()
        jwks._last_refresh_by_url.clear()
        self.key = RSAPrivateKey.generate().public_key

    def test_refresh_worker_updates_cache(self, mock_fetch_data):
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

    def test_refresh_worker_skips_urls_already_queued(self, mock_fetch_data):
        fetching = threading.Event()
        release = threading.Event()

        def slow_fetch() -> dict[str, object]:
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

    def test_fetch_uses_configured_timeout(self, mock_fetch_data):
        with mock.patch.object(jwks, "PyJWKClient", wraps=jwks.PyJWKClient) as mock_client:
            mock_fetch_data.return_value = {"keys": [self.key.as_jwk]}
            jwks._refresh(self.jwks_url)
        self.assertEqual(mock_client.call_args.kwargs["timeout"], 5)

    def test_refresh_lock_prevents_duplicate_fetches(self, mock_fetch_data):
        mock_fetch_data.return_value = {"keys": [self.key.as_jwk]}
        jwks._refresh_unless_locked(self.jwks_url)
        jwks._refresh_unless_locked(self.jwks_url)
        self.assertEqual(mock_fetch_data.call_count, 1)

    def test_refresh_errors_are_logged(self, mock_fetch_data):
        broken_cache = mock.MagicMock()
        broken_cache.add.side_effect = ConnectionError("cache down")
        with (
            mock.patch.object(jwks, "cache", broken_cache),
            self.assertLogs("asymmetric_jwt_auth.jwks", level="ERROR"),
        ):
            jwks._refresh_unless_locked(self.jwks_url)
        mock_fetch_data.assert_not_called()

    def test_missing_key_id_never_matches_or_refreshes(self, mock_fetch_data):
        jwk = self.key.as_jwk
        del jwk["kid"]
        mock_fetch_data.return_value = {"keys": [jwk]}
        with mock.patch.object(jwks, "_queue_refresh") as mock_start_refresh, self.assertRaises(PyJWKClientError):
            jwks.get_signing_key(self.jwks_url, None)
        mock_start_refresh.assert_not_called()

    def test_unusable_key_set(self, mock_fetch_data):
        for payload in ({"keys": []}, {"keys": [{"kty": "nope"}]}, ["not", "a", "dict"]):
            with self.subTest(payload=payload):
                self.setUp()
                mock_fetch_data.return_value = payload
                with self.assertRaises(PyJWKClientError):
                    jwks.get_signing_key(self.jwks_url, self.key.fingerprint)

    def test_malformed_response_doesnt_replace_cached_key_set(self, mock_fetch_data):
        mock_fetch_data.return_value = {"keys": [self.key.as_jwk]}
        fetched_at = jwks._refresh(self.jwks_url)["fetched_at"]
        for payload in ({"error": "temporarily unavailable"}, {"keys": "nope"}):
            with self.subTest(payload=payload):
                mock_fetch_data.return_value = payload
                jwks._refresh(self.jwks_url)
                entry = cache.get(jwks._cache_key(self.jwks_url))
                self.assertEqual(entry["fetched_at"], fetched_at)
                self.assertEqual(jwks.get_signing_key(self.jwks_url, self.key.fingerprint).key_id, self.key.fingerprint)

    def test_refresh_worker_survives_thread_start_failure(self, mock_fetch_data):
        worker = jwks._RefreshWorker()
        with (
            mock.patch.object(jwks.threading.Thread, "start", side_effect=RuntimeError("can't start new thread")),
            self.assertLogs("asymmetric_jwt_auth.jwks", level="ERROR"),
        ):
            worker.submit(self.jwks_url)
        self.assertIsNone(worker._pid)

    def test_failed_fetch_doesnt_replace_cached_key_set(self, mock_fetch_data):
        mock_fetch_data.return_value = {"keys": [self.key.as_jwk]}
        jwks._refresh(self.jwks_url)
        mock_fetch_data.side_effect = PyJWKClientConnectionError("down")
        jwks._refresh(self.jwks_url)
        entry = cache.get(jwks._cache_key(self.jwks_url))
        self.assertIsNotNone(entry["jwks"])
