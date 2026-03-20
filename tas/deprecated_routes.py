#
# TEE Attestation Service - Deprecated Policy Routes
#
# Copyright 2026 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# This file is part of the TEE Attestation Service.
#
# This module provides backward-compatible /policy/v0/* routes that
# delegate to the canonical /management/policy/v0/* handlers while
# emitting deprecation warnings and HTTP headers.
#
# These routes will be removed in a future release.
#

import json

from flask import Blueprint, make_response, request

from .management_routes import delete_policy, get_policy, list_policies, store_policy
from .tas_logging import get_logger

logger = get_logger(__name__)

deprecated_policy_bp = Blueprint("deprecated_policy", __name__, url_prefix="/policy")

# Target removal date for deprecated routes
_SUNSET_DATE = "Tue, 31 Mar 2026 23:59:59 GMT"


def _add_deprecation_headers(response, successor_path):
    """Add standard deprecation headers to a response.

    Headers follow RFC 8594 (Sunset) and the draft Deprecation header spec.
    """
    response.headers["Deprecation"] = "true"
    response.headers["Sunset"] = _SUNSET_DATE
    response.headers["Link"] = f'<{successor_path}>; rel="successor-version"'
    response.headers["Warning"] = (
        f'299 - "This endpoint is deprecated. Use {successor_path} instead. '
        f'It will be removed after {_SUNSET_DATE}."'
    )

    # Inject deprecation_warning into JSON response body if applicable
    if response.content_type and "application/json" in response.content_type:
        try:
            data = json.loads(response.get_data(as_text=True))
            data["deprecation_warning"] = (
                f"This endpoint is deprecated. Use {successor_path} instead. "
                f"It will be removed after {_SUNSET_DATE}."
            )
            response.set_data(json.dumps(data))
        except (json.JSONDecodeError, TypeError):
            pass

    return response


@deprecated_policy_bp.route("/v0/store", methods=["POST"])
def store_policy_deprecated():
    logger.warning(
        "DEPRECATED: /policy/v0/store called from %s. "
        "Use /management/policy/v0/store instead.",
        request.remote_addr,
    )
    result = store_policy()
    if isinstance(result, tuple):
        response = make_response(result[0], result[1])
    else:
        response = make_response(result)
    return _add_deprecation_headers(response, "/management/policy/v0/store")


@deprecated_policy_bp.route("/v0/get/<policy_key>", methods=["GET"])
def get_policy_deprecated(policy_key):
    logger.warning(
        "DEPRECATED: /policy/v0/get/%s called from %s. "
        "Use /management/policy/v0/get/%s instead.",
        policy_key,
        request.remote_addr,
        policy_key,
    )
    result = get_policy(policy_key)
    if isinstance(result, tuple):
        response = make_response(result[0], result[1])
    else:
        response = make_response(result)
    return _add_deprecation_headers(response, f"/management/policy/v0/get/{policy_key}")


@deprecated_policy_bp.route("/v0/list", methods=["GET"])
def list_policies_deprecated():
    logger.warning(
        "DEPRECATED: /policy/v0/list called from %s. "
        "Use /management/policy/v0/list instead.",
        request.remote_addr,
    )
    result = list_policies()
    if isinstance(result, tuple):
        response = make_response(result[0], result[1])
    else:
        response = make_response(result)
    return _add_deprecation_headers(response, "/management/policy/v0/list")


@deprecated_policy_bp.route("/v0/delete/<policy_key>", methods=["DELETE"])
def delete_policy_deprecated(policy_key):
    logger.warning(
        "DEPRECATED: /policy/v0/delete/%s called from %s. "
        "Use /management/policy/v0/delete/%s instead.",
        policy_key,
        request.remote_addr,
        policy_key,
    )
    result = delete_policy(policy_key)
    if isinstance(result, tuple):
        response = make_response(result[0], result[1])
    else:
        response = make_response(result)
    return _add_deprecation_headers(
        response, f"/management/policy/v0/delete/{policy_key}"
    )
