#
# TEE Attestation Service - Client Authentication
#
# Copyright 2026 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# This file is part of the TEE Attestation Service.
#
# Authentication for client/attestation routes (/kb/v0/*, /version).
#

from flask import request

from ..tas_logging import get_logger
from .api_key import ApiKeyAuthenticator

logger = get_logger(__name__)

_authenticator = None


def init_client_auth(app):
    """Initialise the client authenticator from app config.

    Called once during application startup.
    """
    global _authenticator
    _authenticator = ApiKeyAuthenticator(
        config_key="TAS_API_KEY",
        header_name="X-API-KEY",
    )
    logger.info("Client authentication initialised (API key)")


def authenticate_request():
    """Authenticate an attestation/client API request.

    Returns None on success, or a Flask error response tuple on failure.
    """
    ok, error = _authenticator.authenticate(request)
    if not ok:
        return error
