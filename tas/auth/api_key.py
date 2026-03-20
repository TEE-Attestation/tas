#
# TEE Attestation Service - API Key Authenticator
#
# Copyright 2026 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# This file is part of the TEE Attestation Service.
#
# API key authentication mechanism using constant-time comparison.
#

import secrets

from flask import current_app, jsonify

from ..tas_logging import get_logger
from .base import BaseAuthenticator

logger = get_logger(__name__)


class ApiKeyAuthenticator(BaseAuthenticator):
    """Authenticate requests by comparing a header value to a configured key.

    Uses secrets.compare_digest() for constant-time comparison to prevent
    timing attacks.
    """

    def __init__(self, config_key, header_name):
        """
        Args:
            config_key: Flask config key holding the expected API key
                        (e.g. "TAS_API_KEY").
            header_name: HTTP header to read the presented key from
                         (e.g. "X-API-KEY").
        """
        self.config_key = config_key
        self.header_name = header_name

    def authenticate(self, request):
        api_key = request.headers.get(self.header_name)
        expected = current_app.config.get(self.config_key, "")

        if not api_key or not secrets.compare_digest(str(api_key), str(expected)):
            logger.warning(
                f"Unauthorized request from {request.remote_addr}: "
                f"Invalid or missing {self.header_name}"
            )
            return False, (jsonify({"error": "Unauthorized"}), 401)

        return True, None
