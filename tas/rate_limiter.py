#
# TEE Attestation Service
#
# Copyright 2026 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# This file is part of the TEE Attestation Service.
# See LICENSE file for details.
#
# This module sets up the Flask-Limiter extension for rate limiting client requests.

import logging
import math
import time

import limits
from flask import jsonify, request
from flask_limiter import Limiter
from limits.storage import storage_from_string
from limits.strategies import FixedWindowRateLimiter

logger = logging.getLogger(__name__)


def setup_rate_limiter(app, client_blueprint, storage_uri, storage_options):
    """Encapsulates limiter construction and error handler registration."""

    def _get_client_ip():
        if app.config.get("TAS_TRUST_X_FORWARDED_FOR"):
            return request.access_route[0]
        return request.remote_addr

    limiter = Limiter(
        app=app,
        key_func=_get_client_ip,
        storage_uri=storage_uri,
        storage_options=storage_options,
        enabled=app.config.get("RATELIMIT_ENABLED", True),
        strategy=app.config.get("RATELIMIT_STRATEGY", "fixed-window"),
        headers_enabled=app.config.get("RATELIMIT_HEADERS_ENABLED", True),
        swallow_errors=app.config.get("RATELIMIT_SWALLOW_ERRORS", True),
        key_prefix=app.config.get("RATELIMIT_KEY_PREFIX", "tas_ratelimit:"),
    )

    client_rate_limit = app.config.get("TAS_CLIENT_RATE_LIMIT", "200 per minute")
    limiter.limit(client_rate_limit)(client_blueprint)

    @app.errorhandler(429)
    def ratelimit_handler(e):
        response = jsonify(
            {"error": "rate_limit_exceeded", "message": str(e.description)}
        )
        response.status_code = 429
        retry_after = e.response.headers.get("Retry-After") if e.response else None
        if retry_after:
            response.headers["Retry-After"] = retry_after
        return response

    return limiter


class AttestBudget:
    """Global budget of TAS-attestation reports (e.g. "2 per minute").

    Report generation is an expensive, serialised firmware/quote request, so
    the budget is one bucket shared by all callers rather than per client IP.
    It is consulted and consumed by the route *inside* the slot lock: a
    check-then-act across concurrent requests (what a before-request limiter
    does) would admit a whole burst at the start of each window. Only served
    reports are consumed. Uses the same `limits` storage as Flask-Limiter, so
    it is shared across processes when that storage is Redis.
    """

    KEY = "tas-attest"

    def __init__(self, rate, storage_uri, storage_options=None, swallow_errors=True):
        self.rate = rate
        self.item = limits.parse(rate)
        self.strategy = FixedWindowRateLimiter(
            storage_from_string(storage_uri, **(storage_options or {}))
        )
        self.swallow_errors = swallow_errors

    def _guard(self, op, default):
        try:
            return op()
        except Exception as e:  # storage outage: degrade like Flask-Limiter does
            if not self.swallow_errors:
                raise
            logger.warning(f"Attestation budget storage unavailable ({e}); allowing")
            return default

    def available(self):
        """True if a report may be served now (does not consume)."""
        return self._guard(lambda: self.strategy.test(self.item, self.KEY), True)

    def consume(self):
        """Count one served report."""
        return self._guard(lambda: self.strategy.hit(self.item, self.KEY), True)

    def retry_after(self):
        """Whole seconds until the current window resets (>= 1)."""

        def _seconds():
            stats = self.strategy.get_window_stats(self.item, self.KEY)
            return max(1, math.ceil(stats.reset_time - time.time()))

        return self._guard(_seconds, 1)


def setup_attest_budget(app, storage_uri, storage_options):
    """Create the TAS-attestation budget from app config; None when rate limiting is off."""
    if not app.config.get("RATELIMIT_ENABLED", True):
        logger.info("TAS-attestation budget disabled (RATELIMIT_ENABLED=false)")
        app.extensions["tas_attest_budget"] = None
        return None
    budget = AttestBudget(
        app.config.get("TAS_ATTEST_RATE_LIMIT", "2 per minute"),
        storage_uri,
        storage_options,
        swallow_errors=app.config.get("RATELIMIT_SWALLOW_ERRORS", True),
    )
    app.extensions["tas_attest_budget"] = budget
    logger.info(f"TAS-attestation report budget (global): {budget.rate}")
    return budget
