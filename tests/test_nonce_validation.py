#
# TEE Attestation Service - Tests for Atomic Nonce Validation (F-01)
#
# Copyright 2026 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# This file is part of the TEE Attestation Service.
#

import base64

import pytest

from tas.nonce import check_redis_version, store_nonce, validate_nonce


class FakeRedis:
    """Minimal in-memory Redis stub with GETDEL support."""

    def __init__(self):
        self._store = {}

    def setex(self, key, ttl, value):
        self._store[key] = value

    def getdel(self, key):
        return self._store.pop(key, None)

    def get(self, key):
        return self._store.get(key)

    def info(self, section=None):
        return {"redis_version": "7.2.0"}

    def ping(self):
        return True


@pytest.fixture()
def fake_redis():
    return FakeRedis()


# ---------------------------------------------------------------------------
# Unit tests for atomic nonce consumption (real production functions)
# ---------------------------------------------------------------------------

NONCE_EXPIRATION_SECONDS = 600


class TestStoreAndValidateNonce:
    """Test the real store_nonce / validate_nonce from tas.nonce."""

    def test_valid_nonce_consumed(self, fake_redis):
        """A stored nonce is consumed on first validation."""
        nonce = "aabbccdd" * 8
        store_nonce(fake_redis, nonce, NONCE_EXPIRATION_SECONDS)
        is_valid, err = validate_nonce(fake_redis, nonce)
        assert is_valid is True
        assert err is None

    def test_replay_rejected(self, fake_redis):
        """A nonce cannot be validated twice (replay prevention)."""
        nonce = "aabbccdd" * 8
        store_nonce(fake_redis, nonce, NONCE_EXPIRATION_SECONDS)
        validate_nonce(fake_redis, nonce)
        is_valid, err = validate_nonce(fake_redis, nonce)
        assert is_valid is False
        assert err == "Invalid or expired nonce"

    def test_unknown_nonce_rejected(self, fake_redis):
        """A nonce that was never stored is rejected."""
        is_valid, err = validate_nonce(fake_redis, "nonexistent")
        assert is_valid is False
        assert err == "Invalid or expired nonce"

    def test_expired_nonce_rejected(self, fake_redis):
        """A nonce that expired (removed by Redis TTL) is rejected."""
        nonce = "expired1" * 8
        store_nonce(fake_redis, nonce, NONCE_EXPIRATION_SECONDS)
        # Simulate TTL expiration by removing the key
        fake_redis._store.pop(nonce, None)
        is_valid, err = validate_nonce(fake_redis, nonce)
        assert is_valid is False
        assert err == "Invalid or expired nonce"

    def test_getdel_atomicity(self, fake_redis):
        """GETDEL returns and removes in one call - no window for races."""
        nonce = "atomic01" * 8
        store_nonce(fake_redis, nonce, NONCE_EXPIRATION_SECONDS)
        # After getdel the key must be gone
        result = fake_redis.getdel(nonce)
        assert result == "1"
        assert fake_redis.get(nonce) is None


class TestRedisVersionCheck:
    """Test the real check_redis_version from tas.nonce."""

    def test_version_ok(self):
        r = FakeRedis()
        r.info = lambda section=None: {"redis_version": "7.2.0"}
        assert check_redis_version(r) == "7.2.0"

    def test_version_exactly_6_2(self):
        r = FakeRedis()
        r.info = lambda section=None: {"redis_version": "6.2.0"}
        assert check_redis_version(r) == "6.2.0"

    def test_version_too_old(self):
        r = FakeRedis()
        r.info = lambda section=None: {"redis_version": "6.0.16"}
        with pytest.raises(RuntimeError, match="requires Redis 6.2"):
            check_redis_version(r)

    def test_version_5_series(self):
        r = FakeRedis()
        r.info = lambda section=None: {"redis_version": "5.0.14"}
        with pytest.raises(RuntimeError, match="requires Redis 6.2"):
            check_redis_version(r)


# ──────────────────────────────────────────────────────────────────────────
# Tests: Nonce Redis client routing (get_nonce_redis / get_redis split)
# ──────────────────────────────────────────────────────────────────────────

from unittest.mock import MagicMock, patch

from flask import Flask

from tas.client_routes import client_bp, get_nonce_redis, get_redis


def _make_app(with_ephemeral=False):
    """Create a minimal Flask app with optional ephemeral Redis extension."""
    app = Flask(__name__)
    app.config.update(
        TESTING=True,
        TAS_API_KEY="k" * 64,
        TAS_MANAGEMENT_API_KEY="m" * 64,
        TAS_API_KEY_MIN_LENGTH=64,
        TAS_MANAGEMENT_API_KEY_MIN_LENGTH=64,
        TAS_VERSION="0.1.0-test",
        TAS_NONCE_EXPIRATION_SECONDS=120,
    )
    primary = MagicMock(name="primary_redis")
    app.extensions["redis"] = primary
    if with_ephemeral:
        ephemeral = MagicMock(name="ephemeral_redis")
        app.extensions["redis_ephemeral"] = ephemeral
    app.register_blueprint(client_bp)
    return app


class TestNonceRedisRouting:
    """Verify get_nonce_redis returns the correct client."""

    def test_returns_ephemeral_when_configured(self):
        app = _make_app(with_ephemeral=True)
        with app.app_context():
            result = get_nonce_redis()
            assert result is app.extensions["redis_ephemeral"]

    def test_returns_primary_when_no_ephemeral(self):
        app = _make_app(with_ephemeral=False)
        with app.app_context():
            result = get_nonce_redis()
            assert result is app.extensions["redis"]

    def test_get_redis_always_returns_primary(self):
        app = _make_app(with_ephemeral=True)
        with app.app_context():
            result = get_redis()
            assert result is app.extensions["redis"]

    def test_primary_extension_unchanged_with_ephemeral(self):
        app = _make_app(with_ephemeral=True)
        with app.app_context():
            primary = get_redis()
            nonce = get_nonce_redis()
            assert primary is not nonce
            assert primary is app.extensions["redis"]

    def test_get_secret_uses_ephemeral_for_nonce_and_primary_for_vm_verify(self):
        app = _make_app(with_ephemeral=True)
        app.extensions["kbm_client"] = MagicMock(name="kbm_client")
        app.extensions["kbm_get_secret"] = MagicMock(return_value="wrapped-secret")

        request_body = {
            "tee-type": "amd-sev-snp",
            "nonce": "abc123",
            "tee-evidence": "evidence",
            "policy-id": "policy:test",
            "report-data-binding": True,
            "wrapping-key": base64.b64encode(b"pk").decode("ascii"),
        }

        with (
            patch("tas.client_routes.authenticate_request", return_value=None),
            patch(
                "tas.client_routes.validate_nonce", return_value=(True, None)
            ) as validate_nonce_mock,
            patch(
                "tas.client_routes.vm_verify", return_value=(True, "key-id", None)
            ) as vm_verify_mock,
        ):
            with app.test_client() as client:
                response = client.post("/kb/v0/get_secret", json=request_body)

        assert response.status_code == 200
        assert (
            validate_nonce_mock.call_args.args[0] is app.extensions["redis_ephemeral"]
        )
        assert vm_verify_mock.call_args.args[0] is app.extensions["redis"]
