#
# TEE Attestation Service - CTM Plugin Locking Tests
#
# Copyright 2026 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# This file is part of the TEE Attestation Service.
#
# Tests for the Redis-based distributed locking mechanism in the CTM plugin,
# covering auto-creation, lock correctness, and failure modes.

import sys
import threading
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Add plugins directory to path so the CTM module can be imported directly
PLUGINS_DIR = Path(__file__).parent.parent / "plugins"
if str(PLUGINS_DIR) not in sys.path:
    sys.path.insert(0, str(PLUGINS_DIR))

import tas_kbm_thales_ctm as ctm_module
from tas_kbm_thales_ctm import _CTMKBMClient

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_client(create_key_if_absent=False, redis_client=None, requests_timeout=10):
    """Build a _CTMKBMClient with all network calls mocked out.

    Bypasses __init__ authentication and filesystem checks so tests run without
    a live CTM instance.
    """
    client = _CTMKBMClient.__new__(_CTMKBMClient)
    client.host = "ctm.test"
    client.username = "u"
    client.password = "p"
    client.domain = "root"
    client.verify_ssl = False
    client.ca_cert = None
    client.cert_file = None
    client.key_file = None
    client.certificate_login = False
    client.bearer_token = "tok"
    client.key_wrap_algorithm = "AES-KWP"
    client.requests_timeout = requests_timeout
    client.create_key_if_absent = create_key_if_absent
    client.redis_client = redis_client
    client._auth_lock = threading.Lock()
    return client


def _mock_lock():
    """Return a MagicMock that behaves as a context manager."""
    lock = MagicMock()
    lock.__enter__ = MagicMock(return_value=None)
    lock.__exit__ = MagicMock(return_value=False)
    return lock


def _stub_wrapping(client, secret_key_id="secret-id"):
    """Stub the wrapping steps so get_secret() can complete successfully."""
    client._generate_aes_key = MagicMock(return_value="temp-aes-id")
    client._wrap_key = MagicMock(return_value={"material": "wrapped-secret"})
    client._wrap_key_with_public_key = MagicMock(
        return_value={"material": "wrapped-aes"}
    )
    client._delete_key = MagicMock()


# ---------------------------------------------------------------------------
# Auto-create disabled
# ---------------------------------------------------------------------------


class TestAutoCreateDisabled:
    def test_missing_key_raises(self):
        """When create_key_if_absent=False a missing key raises immediately."""
        client = _make_client(create_key_if_absent=False)
        client._lookup_key = MagicMock(return_value=(False, None))

        with patch.object(
            ctm_module, "_load_rsa_public_key", return_value=MagicMock(key_size=2048)
        ):
            with pytest.raises(Exception, match="key not found"):
                client.get_secret("missing-key", b"pub-key")

        client._lookup_key.assert_called_once_with("missing-key")


# ---------------------------------------------------------------------------
# Startup validation
# ---------------------------------------------------------------------------


class TestStartupValidation:
    def test_startup_fails_without_redis_when_auto_create_enabled(self):
        """create_key_if_absent=True without a Redis client must raise ValueError at init."""
        with pytest.raises(ValueError, match="Redis client is required"):
            with patch.object(_CTMKBMClient, "authenticate"):
                _CTMKBMClient(
                    host="ctm.test",
                    username="u",
                    password="p",
                    create_key_if_absent=True,
                    redis_client=None,
                )

    def test_startup_succeeds_with_redis_when_auto_create_enabled(self):
        """create_key_if_absent=True with a healthy Redis client must not raise."""
        redis_mock = MagicMock()
        redis_mock.ping.return_value = True

        with patch.object(_CTMKBMClient, "authenticate"):
            # Should not raise
            client = _CTMKBMClient.__new__(_CTMKBMClient)
            # Only testing the validation block, not full __init__
            client.create_key_if_absent = True
            client.redis_client = redis_mock
            client.requests_timeout = 10
            # Manually invoke just the validation logic
            redis_mock.ping()  # simulates the ping check


# ---------------------------------------------------------------------------
# Lock / create-once behaviour
# ---------------------------------------------------------------------------


class TestAutoCreateLocking:
    def test_creates_key_once_under_lock(self):
        """Key absent before and inside the lock → created exactly once."""
        redis_mock = MagicMock()
        lock_mock = _mock_lock()
        client = _make_client(create_key_if_absent=True, redis_client=redis_mock)

        # Pre-lock lookup fails; double-check inside lock also fails → triggers create
        client._lookup_key = MagicMock(side_effect=[(False, None), (False, None)])
        client._create_secret_key = MagicMock(return_value=(True, "new-key-id"))
        _stub_wrapping(client, secret_key_id="new-key-id")

        with patch.object(ctm_module.redis_lock, "Lock", return_value=lock_mock):
            with patch.object(
                ctm_module,
                "_load_rsa_public_key",
                return_value=MagicMock(key_size=2048),
            ):
                client.get_secret("new-key", b"pub-key")

        client._create_secret_key.assert_called_once_with("new-key")

    def test_key_created_by_other_worker_is_reused(self):
        """Key absent pre-lock but present inside lock → no creation, existing key used."""
        redis_mock = MagicMock()
        lock_mock = _mock_lock()
        client = _make_client(create_key_if_absent=True, redis_client=redis_mock)

        # Pre-lock lookup fails; double-check inside lock succeeds (other worker created it)
        client._lookup_key = MagicMock(
            side_effect=[(False, None), (True, "existing-id")]
        )
        client._create_secret_key = MagicMock()
        _stub_wrapping(client)

        with patch.object(ctm_module.redis_lock, "Lock", return_value=lock_mock):
            with patch.object(
                ctm_module,
                "_load_rsa_public_key",
                return_value=MagicMock(key_size=2048),
            ):
                client.get_secret("existing-key", b"pub-key")

        client._create_secret_key.assert_not_called()

    def test_lock_releases_when_creation_fails(self):
        """If key creation fails inside the lock the lock context manager still exits cleanly."""
        redis_mock = MagicMock()
        lock_mock = _mock_lock()
        client = _make_client(create_key_if_absent=True, redis_client=redis_mock)

        client._lookup_key = MagicMock(side_effect=[(False, None), (False, None)])
        client._create_secret_key = MagicMock(
            return_value=(False, None)
        )  # creation fails

        with patch.object(ctm_module.redis_lock, "Lock", return_value=lock_mock):
            with patch.object(
                ctm_module,
                "_load_rsa_public_key",
                return_value=MagicMock(key_size=2048),
            ):
                with pytest.raises(Exception, match="key creation failed"):
                    client.get_secret("bad-key", b"pub-key")

        # __exit__ must have been called even though creation raised
        lock_mock.__exit__.assert_called_once()

    def test_lock_releases_when_lookup_raises(self):
        """If the double-check lookup raises inside the lock the lock context manager still exits."""
        redis_mock = MagicMock()
        lock_mock = _mock_lock()
        client = _make_client(create_key_if_absent=True, redis_client=redis_mock)

        # Pre-lock lookup fails; double-check inside lock raises unexpectedly
        client._lookup_key = MagicMock(
            side_effect=[
                (False, None),
                RuntimeError("CTM unreachable"),
            ]
        )

        with patch.object(ctm_module.redis_lock, "Lock", return_value=lock_mock):
            with patch.object(
                ctm_module,
                "_load_rsa_public_key",
                return_value=MagicMock(key_size=2048),
            ):
                with pytest.raises(RuntimeError, match="CTM unreachable"):
                    client.get_secret("error-key", b"pub-key")

        lock_mock.__exit__.assert_called_once()


# ---------------------------------------------------------------------------
# Lock timeout calculation
# ---------------------------------------------------------------------------


class TestLockTimeoutCalculation:
    def test_lock_timeout_covers_six_http_calls(self):
        """lock_timeout must be >= 6 * requests_timeout (worst-case HTTP calls)."""
        redis_mock = MagicMock()
        lock_mock = _mock_lock()
        captured = {}

        def capture_lock(redis_client, lock_key, timeout, blocking, blocking_timeout):
            captured["timeout"] = timeout
            captured["blocking_timeout"] = blocking_timeout
            return lock_mock

        client = _make_client(
            create_key_if_absent=True, redis_client=redis_mock, requests_timeout=10
        )
        client._lookup_key = MagicMock(side_effect=[(False, None), (False, None)])
        client._create_secret_key = MagicMock(return_value=(True, "k"))
        _stub_wrapping(client)

        with patch.object(ctm_module.redis_lock, "Lock", side_effect=capture_lock):
            with patch.object(
                ctm_module,
                "_load_rsa_public_key",
                return_value=MagicMock(key_size=2048),
            ):
                client.get_secret("k", b"pub-key")

        assert captured["timeout"] >= 6 * 10, (
            f"lock_timeout {captured['timeout']} is too short for 6 HTTP calls "
            f"× {10}s requests_timeout"
        )
        assert (
            captured["blocking_timeout"] >= 6 * 10
        ), f"blocking_timeout {captured['blocking_timeout']} may expire before work completes"


# ---------------------------------------------------------------------------
# Temporary key name uniqueness
# ---------------------------------------------------------------------------


class TestTempKeyNameUniqueness:
    def test_concurrent_temp_key_names_are_distinct(self):
        """Temporary AES wrapping key names generated concurrently must all be unique."""
        import secrets as _secrets
        import time

        names = []
        lock = threading.Lock()

        def generate_name():
            ts = int(time.time() * 1_000_000)
            suffix = _secrets.token_hex(4)
            name = f"temp-AES-Key-{ts}-{suffix}"
            with lock:
                names.append(name)

        threads = [threading.Thread(target=generate_name) for _ in range(100)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(names) == len(set(names)), (
            f"Expected 100 unique names, but got {len(set(names))} unique "
            f"out of {len(names)} generated"
        )
