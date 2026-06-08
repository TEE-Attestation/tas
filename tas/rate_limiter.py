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

from flask import jsonify, request
from flask_limiter import Limiter

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
