#
# TEE Attestation Service - Experimental Routes
#
# Copyright 2026 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# This file is part of the TEE Attestation Service.
#
# This module provides the experimental API blueprint.
# Routes live under /experimental/v0/*.
# These routes require the same authorisation as management routes.
#

import json

import redis
from flask import Blueprint, current_app, jsonify, request

from .auth import authenticate_management_request
from .policy_helper import (
    POLICY_KEY_COMPONENT_RE,
    canonicalize_policy,
    validate_policy_key,
    verify_policy_signature,
)
from .tas_logging import get_logger

logger = get_logger(__name__)

experimental_bp = Blueprint("experimental", __name__, url_prefix="/experimental")


def _get_redis():
    """Retrieve the Redis client from the application extensions."""
    return current_app.extensions["redis"]


@experimental_bp.route("/policy/v0/add", methods=["POST"])
def add_policy():
    """Create a new policy in Redis or increment its count if it already exists."""
    logger.info(f"Received policy add request from {request.remote_addr}")
    auth_response = authenticate_management_request()
    if auth_response:
        return auth_response

    policy = request.get_json()
    if not policy:
        logger.error("Policy add request missing JSON body")
        return jsonify({"error": "Request body is required"}), 400

    if not isinstance(policy, dict):
        logger.error("Policy data is not a valid JSON object")
        return jsonify({"error": "Policy must be a JSON object"}), 400

    if "metadata" not in policy:
        logger.error("Policy missing required 'metadata' section")
        return jsonify({"error": "Policy must contain 'metadata' section"}), 400

    if "validation_rules" not in policy:
        logger.error("Policy missing required 'validation_rules' section")
        return jsonify({"error": "Policy must contain 'validation_rules' section"}), 400

    metadata = policy["metadata"]

    policy_type = metadata.get("policy_type")
    if not policy_type:
        logger.error("Policy metadata missing policy_type")
        return (
            jsonify({"error": "Policy type is required in metadata (e.g. SEV, TDX)"}),
            400,
        )

    if not POLICY_KEY_COMPONENT_RE.match(str(policy_type)):
        logger.error(f"Invalid policy_type: {policy_type}")
        return (
            jsonify(
                {
                    "error": "Invalid policy_type. Use only alphanumeric characters, hyphens, underscores, and dots"
                }
            ),
            400,
        )

    key_id = metadata.get("key_id")
    if not key_id:
        logger.error("Policy metadata missing key_id")
        return jsonify({"error": "Key ID is required in metadata"}), 400

    if not POLICY_KEY_COMPONENT_RE.match(str(key_id)):
        logger.error(f"Invalid key_id: {key_id}")
        return (
            jsonify(
                {
                    "error": "Invalid key_id. Use only alphanumeric characters, hyphens, underscores, and dots"
                }
            ),
            400,
        )

    is_signed = "signature" in policy
    warning_message = None
    if not is_signed:
        logger.error("Unsigned incrementable policies are not allowed")
        return (
            jsonify({"error": "Unsigned incrementable policies are not allowed"}),
            400,
        )
    else:
        logger.info(f"Policy {policy_type}:{key_id} is signed")
        if not current_app.config.get("TAS_ENFORCE_SIGNED_POLICIES", True):
            logger.warning(
                "Signed policy not verified - policy signature check is disabled"
            )
            warning_message = "WARNING: Signed policy not verified - policy signature check is disabled"
        else:
            if not verify_policy_signature(
                policy, current_app.config.get("TAS_TRUSTED_KEYS", [])
            ):
                logger.error("Policy signature verification failed")
                return jsonify({"error": "Policy signature verification failed"}), 400
            logger.info("Policy signature verification successful")

    try:
        redis_client = _get_redis()
        policy_key = f"policy:{policy_type}:{key_id}"

        # Using pipeline with watch on policy_key to ensure atomic read-modify-write for incrementing
        with redis_client.pipeline() as pipe:
            while True:
                try:
                    pipe.watch(policy_key)
                    existing_policy_str = pipe.get(policy_key)

                    if not existing_policy_str:
                        policy["signature"]["count"] = 1
                        new_policy_str = json.dumps(policy)
                        pipe.multi()
                        pipe.set(policy_key, new_policy_str)
                        pipe.execute()
                        logger.info(f"Stored policy '{policy_key}' in Redis")
                        response_data = {
                            "message": f"Policy '{policy_key}' created successfully"
                        }
                    else:
                        try:
                            existing_policy = json.loads(existing_policy_str)
                        except json.JSONDecodeError as e:
                            logger.error(f"Failed to parse policy JSON: {e}")
                            raise ValueError("Invalid policy format")

                        existing_sig = existing_policy.get("signature", {})
                        if "count" not in existing_sig:
                            logger.error(
                                f"Policy '{policy_key}' is not an incrementable policy (no count in signature)"
                            )
                            return (
                                jsonify(
                                    {
                                        "error": "Existing policy is not incrementable (missing count)"
                                    }
                                ),
                                409,
                            )

                        # Canonicalize both policies (excluding signature) using RFC 8785 JCS
                        if canonicalize_policy(policy) != canonicalize_policy(
                            existing_policy
                        ):
                            logger.error(
                                f"Policy '{policy_key}' content mismatch — new policy does not match existing, increment failed"
                            )
                            return (
                                jsonify(
                                    {
                                        "error": "Policy content does not match the existing policy"
                                    }
                                ),
                                409,
                            )

                        existing_sig["count"] += 1
                        existing_policy["signature"] = existing_sig
                        new_policy_str = json.dumps(existing_policy)
                        pipe.multi()
                        pipe.set(policy_key, new_policy_str)
                        pipe.execute()
                        logger.info(
                            f"Incremented count for policy '{policy_key}' in Redis"
                        )
                        response_data = {
                            "message": f"Policy '{policy_key}' already exists, count incremented to {existing_sig['count']}"
                        }

                    break  # success, exit retry loop

                except redis.WatchError:
                    logger.warning(
                        f"Concurrent modification of '{policy_key}', retrying"
                    )
                    continue

        if warning_message:
            response_data["warning"] = warning_message

        return jsonify(response_data), 201

    except Exception as e:
        logger.error(f"Error storing policy: {e}")
        return jsonify({"error": "Failed to store policy in Redis"}), 500


@experimental_bp.route("/policy/v0/remove/<policy_key>", methods=["DELETE"])
def remove_policy(policy_key):
    """Decrement the count of a policy, or delete it entirely if the count would reach zero."""
    logger.info(
        f"Received policy remove request for '{policy_key}' from {request.remote_addr}"
    )
    auth_response = authenticate_management_request()
    if auth_response:
        return auth_response

    is_valid, error_message = validate_policy_key(policy_key)
    if not is_valid:
        logger.error(f"Invalid policy key '{policy_key}': {error_message}")
        return jsonify({"error": error_message}), 400

    try:
        redis_client = _get_redis()

        with redis_client.pipeline() as pipe:
            while True:
                try:
                    pipe.watch(policy_key)
                    policy_str = pipe.get(policy_key)

                    if not policy_str:
                        logger.warning(f"Policy '{policy_key}' not found for removal")
                        return (
                            jsonify({"error": f"Policy '{policy_key}' not found"}),
                            404,
                        )

                    try:
                        policy = json.loads(policy_str)
                    except json.JSONDecodeError as e:
                        logger.error(f"Failed to parse policy JSON: {e}")
                        return jsonify({"error": "Invalid policy data in Redis"}), 500

                    sig = policy.get("signature", {})
                    if "count" not in sig:
                        logger.error(
                            f"Policy '{policy_key}' is not an incrementable policy (no count in signature)"
                        )
                        return (
                            jsonify(
                                {"error": "Policy is not incrementable (missing count)"}
                            ),
                            409,
                        )

                    pipe.multi()
                    if sig["count"] <= 1:
                        pipe.delete(policy_key)
                        pipe.execute()
                        logger.info(
                            f"Deleted policy '{policy_key}' from Redis (count reached zero)"
                        )
                        response_data = {
                            "message": f"Policy '{policy_key}' removed and deleted (last reference)"
                        }
                    else:
                        sig["count"] -= 1
                        policy["signature"] = sig
                        pipe.set(policy_key, json.dumps(policy))
                        pipe.execute()
                        logger.info(
                            f"Decremented count for policy '{policy_key}' to {sig['count']}"
                        )
                        response_data = {
                            "message": f"Policy '{policy_key}' count decremented to {sig['count']}"
                        }

                    break

                except redis.WatchError:
                    logger.warning(
                        f"Concurrent modification of '{policy_key}', retrying"
                    )
                    continue

        return jsonify(response_data), 200

    except Exception as e:
        logger.error(f"Error removing policy: {e}")
        return jsonify({"error": "Failed to remove policy from Redis"}), 500
