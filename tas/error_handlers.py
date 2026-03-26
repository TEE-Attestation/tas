#
# TEE Attestation Service
#
# Copyright 2026 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# This file is part of the TEE Attestation Service.
# See LICENSE file for details.
#

import logging

from flask import jsonify, request
from werkzeug.exceptions import HTTPException

logger = logging.getLogger("tas")


def handle_exception(e):
    """Global exception handler for the TAS Flask application.

    Returns proper HTTP status codes for client errors (4xx)
    and generic 500 for genuine server errors.
    """
    # Handle Flask/Werkzeug HTTP exceptions
    if isinstance(e, HTTPException):
        logger.warning(
            f"HTTP {e.code}: {request.method} {request.path} - {e.description}"
        )
        return jsonify({"error": e.description or "Request error"}), e.code

    # All other exceptions are server errors
    logger.error(
        f"Unhandled exception in {request.method} {request.path}: {e}", exc_info=True
    )
    return jsonify({"error": "Internal server error"}), 500


def register_error_handlers(app):
    """Register the global exception handler on a Flask app."""
    app.register_error_handler(Exception, handle_exception)
