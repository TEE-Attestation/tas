#
# TEE Attestation Service - Tests for Atomic Nonce Validation
#
# Copyright 2026 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# This file is part of the TEE Attestation Service.
#

import base64
import logging

import pytest

from tas.nonce import NONCE_KEY_PREFIX, check_redis_version, store_nonce, validate_nonce


class FakeRedis:
    """Minimal in-memory Redis stub with SET (EX/NX) and GETDEL support."""

    def __init__(self):
        self._store = {}
        self._ttls = {}

    def set(self, key, value, ex=None, nx=False):
        if nx and key in self._store:
            return None
        self._store[key] = value
        if ex is not None:
            self._ttls[key] = ex
        return True

    def setex(self, key, ttl, value):
        self._store[key] = value
        self._ttls[key] = ttl
        return True

    def getdel(self, key):
        self._ttls.pop(key, None)
        return self._store.pop(key, None)

    def get(self, key):
        return self._store.get(key)

    def ttl(self, key):
        return self._ttls.get(key)

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
VALID_NONCE = "aabbccdd" * 8
VALID_NONCE_2 = "0123456789abcdef" * 4


class TestStoreAndValidateNonce:
    """Test the real store_nonce / validate_nonce from tas.nonce."""

    def test_valid_nonce_stored_with_namespace_and_ttl_and_consumed(self, fake_redis):
        """A stored nonce uses the nonce: namespace, records TTL, and is consumed once."""
        store_nonce(fake_redis, VALID_NONCE, NONCE_EXPIRATION_SECONDS)
        redis_key = f"{NONCE_KEY_PREFIX}{VALID_NONCE}"
        assert fake_redis.get(redis_key) == "1"
        assert fake_redis.ttl(redis_key) == NONCE_EXPIRATION_SECONDS
        assert fake_redis.get(VALID_NONCE) is None

        is_valid, err = validate_nonce(fake_redis, VALID_NONCE)
        assert is_valid is True
        assert err is None
        assert fake_redis.get(redis_key) is None

    def test_bytes_sentinel_accepted(self, fake_redis):
        """Redis clients returning bytes (decode_responses=False) are accepted."""
        fake_redis.set(
            f"{NONCE_KEY_PREFIX}{VALID_NONCE}", b"1", ex=NONCE_EXPIRATION_SECONDS
        )
        is_valid, err = validate_nonce(fake_redis, VALID_NONCE)
        assert is_valid is True
        assert err is None

    def test_replay_rejected(self, fake_redis):
        """A nonce cannot be validated twice (replay prevention)."""
        store_nonce(fake_redis, VALID_NONCE, NONCE_EXPIRATION_SECONDS)
        validate_nonce(fake_redis, VALID_NONCE)
        is_valid, err = validate_nonce(fake_redis, VALID_NONCE)
        assert is_valid is False
        assert err == "Invalid or expired nonce"

    def test_unknown_nonce_rejected(self, fake_redis):
        """A well-formed nonce that was never stored is rejected."""
        is_valid, err = validate_nonce(fake_redis, VALID_NONCE_2)
        assert is_valid is False
        assert err == "Invalid or expired nonce"

    def test_expired_nonce_rejected(self, fake_redis):
        """A nonce that expired (removed by Redis TTL) is rejected."""
        store_nonce(fake_redis, VALID_NONCE_2, NONCE_EXPIRATION_SECONDS)
        # Simulate TTL expiration by removing the namespaced key
        fake_redis._store.pop(f"{NONCE_KEY_PREFIX}{VALID_NONCE_2}", None)
        is_valid, err = validate_nonce(fake_redis, VALID_NONCE_2)
        assert is_valid is False
        assert err == "Invalid or expired nonce"

    def test_getdel_atomicity(self, fake_redis):
        """GETDEL returns and removes the namespaced key in one call."""
        store_nonce(fake_redis, VALID_NONCE, NONCE_EXPIRATION_SECONDS)
        redis_key = f"{NONCE_KEY_PREFIX}{VALID_NONCE}"
        result = fake_redis.getdel(redis_key)
        assert result == "1"
        assert fake_redis.get(redis_key) is None

    @pytest.mark.parametrize(
        "malformed_nonce",
        [
            None,
            123,
            int("1" * 64),
            True,
            False,
            [VALID_NONCE],
            {"nonce": VALID_NONCE},
            "",
            "a" * 63,
            "a" * 65,
            "A" * 64,
            "g" * 64,
            ("a" * 63) + "!",
            f'"{VALID_NONCE}"',
            f"{NONCE_KEY_PREFIX}{VALID_NONCE}",
            "policy:sev:default",
        ],
    )
    def test_validate_nonce_rejects_malformed_without_redis_delete(
        self, fake_redis, malformed_nonce
    ):
        """Malformed nonces fail before touching Redis."""
        fake_redis.set(str(malformed_nonce), "1")
        fake_redis.set("policy:sev:default", '{"metadata":{"policy_id":"default"}}')
        is_valid, err = validate_nonce(fake_redis, malformed_nonce)
        assert is_valid is False
        assert err == "Invalid or expired nonce"
        assert (
            fake_redis.get("policy:sev:default")
            == '{"metadata":{"policy_id":"default"}}'
        )
        if str(malformed_nonce) != "policy:sev:default":
            assert fake_redis.get(str(malformed_nonce)) == "1"

    def test_policy_key_preserved_when_challenged_as_nonce(self, fake_redis):
        """Regression test: policy keys in shared Redis cannot be consumed as nonces."""
        policy_key = "policy:sev:prod-policy"
        policy_hex_key = f"policy:{VALID_NONCE}"
        fake_redis.set(policy_key, '{"policy":"important"}')
        fake_redis.set(policy_hex_key, '{"policy":"hex-named"}')
        # Even an unprefixed raw 64-hex key outside the nonce: namespace is untouched
        fake_redis.set(VALID_NONCE, '{"raw":"unprefixed"}')

        is_valid_1, err_1 = validate_nonce(fake_redis, policy_key)
        is_valid_2, err_2 = validate_nonce(fake_redis, VALID_NONCE)

        assert (is_valid_1, err_1) == (False, "Invalid or expired nonce")
        assert (is_valid_2, err_2) == (False, "Invalid or expired nonce")
        assert fake_redis.get(policy_key) == '{"policy":"important"}'
        assert fake_redis.get(policy_hex_key) == '{"policy":"hex-named"}'
        assert fake_redis.get(VALID_NONCE) == '{"raw":"unprefixed"}'

    @pytest.mark.parametrize(
        "malformed_nonce",
        [
            None,
            123,
            "",
            "a" * 63,
            "a" * 65,
            "A" * 64,
            "g" * 64,
        ],
    )
    def test_store_nonce_rejects_malformed_nonce(self, fake_redis, malformed_nonce):
        """store_nonce refuses to write non-canonical nonces."""
        with pytest.raises(ValueError, match="64 lowercase hexadecimal"):
            store_nonce(fake_redis, malformed_nonce, NONCE_EXPIRATION_SECONDS)
        assert fake_redis._store == {}

    @pytest.mark.parametrize(
        "bad_expiration",
        [0, -1, -600, True, False, "600", None, 12.5],
    )
    def test_store_nonce_rejects_invalid_expiration(self, fake_redis, bad_expiration):
        """store_nonce requires a positive non-boolean integer TTL."""
        with pytest.raises(ValueError, match="positive integer"):
            store_nonce(fake_redis, VALID_NONCE, bad_expiration)
        assert fake_redis._store == {}

    def test_store_nonce_nx_collision_raises(self, fake_redis):
        """store_nonce raises RuntimeError if SET NX reports an existing key."""
        store_nonce(fake_redis, VALID_NONCE, NONCE_EXPIRATION_SECONDS)
        with pytest.raises(RuntimeError, match="key already exists"):
            store_nonce(fake_redis, VALID_NONCE, NONCE_EXPIRATION_SECONDS)

    @pytest.mark.parametrize("unexpected_sentinel", ["0", b"0", "true", '{"a": 1}'])
    def test_validate_nonce_rejects_unexpected_sentinel(
        self, fake_redis, unexpected_sentinel
    ):
        """Only sentinel '1' or b'1' is accepted as a valid stored nonce."""
        fake_redis.set(
            f"{NONCE_KEY_PREFIX}{VALID_NONCE}",
            unexpected_sentinel,
            ex=NONCE_EXPIRATION_SECONDS,
        )
        is_valid, err = validate_nonce(fake_redis, VALID_NONCE)
        assert is_valid is False
        assert err == "Invalid or expired nonce"


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
            "nonce": VALID_NONCE,
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
        assert validate_nonce_mock.call_args.args[1] == VALID_NONCE
        assert vm_verify_mock.call_args.args[0] is app.extensions["redis"]

    @pytest.mark.parametrize(
        "bad_nonce",
        [
            int("1" * 64),
            f'"{VALID_NONCE}"',
            [VALID_NONCE],
            "policy:sev:test-policy",
        ],
    )
    def test_get_secret_does_not_coerce_non_string_or_quoted_nonce(self, bad_nonce):
        """get_secret passes the raw JSON nonce value to validate_nonce without coercion."""
        app = _make_app(with_ephemeral=False)
        fake = FakeRedis()
        fake.set("policy:sev:test-policy", '{"metadata":{"policy_id":"test-policy"}}')
        fake.set(f"{NONCE_KEY_PREFIX}{'1' * 64}", "1", ex=120)
        fake.set(f"{NONCE_KEY_PREFIX}{VALID_NONCE}", "1", ex=120)
        app.extensions["redis"] = fake

        request_body = {
            "tee-type": "amd-sev-snp",
            "nonce": bad_nonce,
            "tee-evidence": "evidence",
            "policy-id": "policy:sev:test-policy",
            "report-data-binding": True,
            "wrapping-key": base64.b64encode(b"pk").decode("ascii"),
        }

        with patch("tas.client_routes.authenticate_request", return_value=None):
            with app.test_client() as client:
                response = client.post("/kb/v0/get_secret", json=request_body)

        assert response.status_code == 401
        assert response.get_json() == {"error": "Invalid or expired nonce"}
        assert (
            fake.get("policy:sev:test-policy")
            == '{"metadata":{"policy_id":"test-policy"}}'
        )
        assert fake.get(f"{NONCE_KEY_PREFIX}{'1' * 64}") == "1"
        assert fake.get(f"{NONCE_KEY_PREFIX}{VALID_NONCE}") == "1"


class TestNonceAuditLogging:
    """Verify full-nonce audit logging at INFO/WARNING across issuance and validation."""

    @pytest.mark.parametrize("endpoint", ["/kb/v0/get_nonce", "/alphav1/nonce"])
    def test_get_nonce_logs_full_nonce_at_info(self, caplog, endpoint):
        app = _make_app(with_ephemeral=False)
        app.extensions["redis"] = FakeRedis()

        with (
            patch("tas.client_routes.authenticate_request", return_value=None),
            caplog.at_level(logging.INFO),
        ):
            with app.test_client() as client:
                response = client.get(endpoint)

        assert response.status_code == 200
        issued_nonce = response.get_json()["nonce"]
        assert f"Generated nonce: {issued_nonce}" in caplog.text
        assert f"Nonce stored successfully: {issued_nonce}" in caplog.text
        assert f"Nonce generated and stored successfully: {issued_nonce}" in caplog.text

    def test_validate_nonce_logs_full_nonce_at_info_and_warning_on_replay(
        self, fake_redis, caplog
    ):
        with caplog.at_level(logging.INFO, logger="tas.nonce"):
            store_nonce(fake_redis, VALID_NONCE, NONCE_EXPIRATION_SECONDS)
            is_valid, err = validate_nonce(fake_redis, VALID_NONCE)
            assert (is_valid, err) == (True, None)

            is_valid_replay, err_replay = validate_nonce(fake_redis, VALID_NONCE)
            assert (is_valid_replay, err_replay) == (False, "Invalid or expired nonce")

        assert (
            f"Nonce stored successfully: {VALID_NONCE} (expiration: {NONCE_EXPIRATION_SECONDS}s)"
            in caplog.text
        )
        assert f"Validating nonce: {VALID_NONCE}" in caplog.text
        assert (
            f"Nonce validation successful (consumed atomically): {VALID_NONCE}"
            in caplog.text
        )
        assert (
            f"Nonce validation failed for nonce {VALID_NONCE}: Invalid or expired nonce"
            in caplog.text
        )

    def test_validate_nonce_does_not_log_malformed_input(self, fake_redis, caplog):
        malformed = "malformed-untrusted-nonce\nFORGED_LOG_ENTRY"
        with caplog.at_level(logging.DEBUG, logger="tas.nonce"):
            is_valid, err = validate_nonce(fake_redis, malformed)

        assert (is_valid, err) == (False, "Invalid or expired nonce")
        assert "Nonce validation failed: Malformed nonce" in caplog.text
        assert "FORGED_LOG_ENTRY" not in caplog.text
