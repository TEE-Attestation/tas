#
# TEE Attestation Service - Management Authentication
#
# Copyright 2026 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# This file is part of the TEE Attestation Service.
#
# Authentication for management routes (/management/policy/v0/*).
#

from flask import request

from ..tas_logging import get_logger
from .api_key import ApiKeyAuthenticator

logger = get_logger(__name__)

_authenticator = None


def init_management_auth(app):
    """Initialise the management authenticator from app config.

    Called once during application startup.
    """
    global _authenticator
    _authenticator = ApiKeyAuthenticator(
        config_key="TAS_MANAGEMENT_API_KEY",
        header_name="X-MANAGEMENT-API-KEY",
    )
    logger.info("Management authentication initialised (API key)")


def authenticate_management_request():
    """Authenticate a management API request.

    Returns None on success, or a Flask error response tuple on failure.
    """
    ok, error = _authenticator.authenticate(request)
    if not ok:
        return error
