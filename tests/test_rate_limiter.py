#
# TEE Attestation Service - Tests for Rate Limiting
#
# Copyright 2026 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# This file is part of the TEE Attestation Service.
# See LICENSE file for details.
#
# This module contains tests for the rate limiting functionality.


import pytest
from flask import Flask

from tas.auth import init_client_auth, init_management_auth
from tas.client_routes import client_bp
from tas.config_loader import resolve_ratelimit_storage
from tas.management_routes import management_bp
from tas.rate_limiter import setup_rate_limiter


def _build_app(extra_config=None):
    """Create a minimal Flask app with client + management blueprints and
    rate limiting configured with memory:// storage for testing."""
    app = Flask(__name__)
    app.config.update(
        TESTING=True,
        TAS_API_KEY="k" * 64,
        TAS_MANAGEMENT_API_KEY="m" * 64,
        TAS_API_KEY_MIN_LENGTH=64,
        TAS_MANAGEMENT_API_KEY_MIN_LENGTH=64,
        TAS_VERSION="0.1.0-test",
        TAS_NONCE_EXPIRATION_SECONDS=120,
        TAS_CLIENT_RATE_LIMIT="3 per minute",
        TAS_TRUST_X_FORWARDED_FOR=False,
        RATELIMIT_ENABLED=True,
        RATELIMIT_HEADERS_ENABLED=True,
        RATELIMIT_STRATEGY="fixed-window",
        RATELIMIT_SWALLOW_ERRORS=False,
        RATELIMIT_KEY_PREFIX="test_ratelimit:",
        RATELIMIT_STORAGE_URI="memory://",
    )
    if extra_config:
        app.config.update(extra_config)

    init_client_auth(app)
    init_management_auth(app)

    setup_rate_limiter(app, client_bp, app.config["RATELIMIT_STORAGE_URI"], {})

    app.register_blueprint(management_bp)
    app.register_blueprint(client_bp)

    return app


# ── Test: Client route exceeds limit -> 429 ────────────────────────


class TestClientRouteRateLimiting:
    def test_client_route_returns_429_after_limit(self):
        """Hitting /version beyond the limit should return 429 JSON."""
        app = _build_app()
        headers = {"X-API-KEY": "k" * 64}
        with app.test_client() as client:
            for _ in range(3):
                resp = client.get("/version", headers=headers)
                assert resp.status_code == 200

            resp = client.get("/version", headers=headers)
            assert resp.status_code == 429
            data = resp.get_json()
            assert data["error"] == "rate_limit_exceeded"


# ── Test: Management route is unaffected ────────────────────────────


class TestManagementRouteUnlimited:
    def test_management_route_not_rate_limited(self):
        """Management routes should not have a rate limit."""
        app = _build_app()
        # Stub Redis for management routes
        from unittest.mock import MagicMock

        mock_redis = MagicMock()
        mock_redis.keys.return_value = []
        app.extensions["redis"] = mock_redis

        mgmt_headers = {"X-MANAGEMENT-API-KEY": "m" * 64}
        with app.test_client() as client:
            # Hit management route more than 3 times (client limit)
            for i in range(5):
                resp = client.get("/management/policy/v0/list", headers=mgmt_headers)
                assert (
                    resp.status_code == 200
                ), f"Request {i + 1} to management route was rate limited"


# ── Test: Rate limit headers present ───────────────────────────────


class TestRateLimitHeaders:
    def test_ratelimit_headers_present(self):
        """RateLimit-* headers should be present when enabled."""
        app = _build_app()
        headers = {"X-API-KEY": "k" * 64}
        with app.test_client() as client:
            resp = client.get("/version", headers=headers)
            assert resp.status_code == 200
            # Flask-Limiter adds these headers
            assert (
                "RateLimit-Limit" in resp.headers or "X-RateLimit-Limit" in resp.headers
            )


# ── Test: Kill switch disables limiting ────────────────────────────


class TestKillSwitch:
    def test_ratelimit_disabled(self):
        """When RATELIMIT_ENABLED=False, no rate limiting should occur."""
        app = _build_app(extra_config={"RATELIMIT_ENABLED": False})
        headers = {"X-API-KEY": "k" * 64}
        with app.test_client() as client:
            for _ in range(10):
                resp = client.get("/version", headers=headers)
                assert resp.status_code == 200


# ── Test: Proxy-aware keying ───────────────────────────────────────


class TestProxyAwareKeying:
    def test_x_forwarded_for_keying(self):
        """When TAS_TRUST_X_FORWARDED_FOR=True, different X-Forwarded-For
        values should have independent rate limit buckets."""
        app = _build_app(extra_config={"TAS_TRUST_X_FORWARDED_FOR": True})
        headers = {"X-API-KEY": "k" * 64}
        with app.test_client() as client:
            # Exhaust limit for IP 10.0.0.1
            for _ in range(3):
                resp = client.get(
                    "/version",
                    headers={**headers, "X-Forwarded-For": "10.0.0.1"},
                )
                assert resp.status_code == 200

            # 4th request from 10.0.0.1 should be limited
            resp = client.get(
                "/version",
                headers={**headers, "X-Forwarded-For": "10.0.0.1"},
            )
            assert resp.status_code == 429

            # Request from different IP should still succeed
            resp = client.get(
                "/version",
                headers={**headers, "X-Forwarded-For": "10.0.0.2"},
            )
            assert resp.status_code == 200


# ── Test: Dedicated storage URI override ──────────────────────────


class TestStorageUriOverride:
    def test_explicit_storage_uri_used(self):
        """When RATELIMIT_STORAGE_URI is set, limiter uses it instead of
        reusing the nonce/policy Redis connection."""
        app = _build_app(extra_config={"RATELIMIT_STORAGE_URI": "memory://dedicated"})
        with app.test_client() as client:
            # Should still work — limiter honours the explicit URI
            resp = client.get("/version", headers={"X-API-KEY": "k" * 64})
            assert resp.status_code == 200


# ── Tests: Ratelimit storage resolution precedence ─────────────────


class TestResolveRatelimitStorage:
    """Test _resolve_ratelimit_storage three-state precedence."""

    def _resolve(self, app_config, primary_client=None):
        """Load and execute the production helper from app.py."""
        from unittest.mock import MagicMock

        if primary_client is None:
            primary_client = MagicMock()
            primary_client.connection_pool = MagicMock()

        return resolve_ratelimit_storage(app_config, primary_client)

    def test_user_override_wins_over_ephemeral(self):
        """Explicit RATELIMIT_STORAGE_URI wins even when TAS_EPHEMERAL_REDIS_URI is set."""
        uri, opts, mode = self._resolve(
            {
                "RATELIMIT_STORAGE_URI": "redis://dedicated:6380/0",
                "TAS_EPHEMERAL_REDIS_URI": "redis://ephemeral:6381/0",
            }
        )
        assert uri == "redis://dedicated:6380/0"
        assert opts == {}
        assert mode == "user override"

    def test_ephemeral_used_when_no_user_override(self):
        """TAS_EPHEMERAL_REDIS_URI used when RATELIMIT_STORAGE_URI is absent."""
        uri, opts, mode = self._resolve(
            {"TAS_EPHEMERAL_REDIS_URI": "redis://ephemeral:6381/0"}
        )
        assert uri == "redis://ephemeral:6381/0"
        assert opts == {}
        assert mode == "derived ephemeral"

    def test_primary_pool_when_nothing_set(self):
        """Falls back to shared primary pool when neither is set."""
        from unittest.mock import MagicMock

        mock_client = MagicMock()
        uri, opts, mode = self._resolve({}, primary_client=mock_client)
        assert uri == "redis://"
        assert opts["connection_pool"] is mock_client.connection_pool
        assert mode == "shared primary pool"

    def test_empty_ratelimit_uri_does_not_suppress_fallback(self):
        """Empty string RATELIMIT_STORAGE_URI should not suppress ephemeral fallback."""
        uri, opts, mode = self._resolve(
            {
                "RATELIMIT_STORAGE_URI": "",
                "TAS_EPHEMERAL_REDIS_URI": "redis://ephemeral:6381/0",
            }
        )
        assert uri == "redis://ephemeral:6381/0"
        assert mode == "derived ephemeral"

    def test_whitespace_ratelimit_uri_does_not_suppress_fallback(self):
        """Whitespace-only RATELIMIT_STORAGE_URI should not suppress fallback."""
        uri, opts, mode = self._resolve(
            {
                "RATELIMIT_STORAGE_URI": "   ",
                "TAS_EPHEMERAL_REDIS_URI": "redis://ephemeral:6381/0",
            }
        )
        assert uri == "redis://ephemeral:6381/0"
        assert mode == "derived ephemeral"

    def test_none_ratelimit_uri_does_not_suppress_fallback(self):
        """None RATELIMIT_STORAGE_URI (YAML null) should not suppress fallback."""
        uri, opts, mode = self._resolve(
            {
                "RATELIMIT_STORAGE_URI": None,
                "TAS_EPHEMERAL_REDIS_URI": "redis://ephemeral:6381/0",
            }
        )
        assert uri == "redis://ephemeral:6381/0"
        assert mode == "derived ephemeral"

    def test_empty_ephemeral_falls_to_primary(self):
        """Empty TAS_EPHEMERAL_REDIS_URI should fall to shared primary pool."""
        from unittest.mock import MagicMock

        mock_client = MagicMock()
        uri, opts, mode = self._resolve(
            {"TAS_EPHEMERAL_REDIS_URI": ""}, primary_client=mock_client
        )
        assert uri == "redis://"
        assert mode == "shared primary pool"

    def test_shared_primary_returns_connection_pool_storage_options(self):
        """Shared-primary mode must provide storage_options with the primary pool."""
        from unittest.mock import MagicMock

        mock_client = MagicMock()
        uri, opts, mode = self._resolve({}, primary_client=mock_client)
        assert uri == "redis://"
        assert opts == {"connection_pool": mock_client.connection_pool}
        assert mode == "shared primary pool"
