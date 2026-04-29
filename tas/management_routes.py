#
# TEE Attestation Service - Management Routes
#
# Copyright 2026 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# This file is part of the TEE Attestation Service.
#
# This module provides the management API blueprint for policy operations.
# Canonical routes live under /management/policy/v0/*.
#

import json

from flask import Blueprint, current_app, jsonify, request

from .auth import authenticate_management_request
from .policy_helper import (
    POLICY_KEY_COMPONENT_RE,
    validate_policy_key,
    verify_policy_signature,
)
from .tas_logging import get_logger

logger = get_logger(__name__)

management_bp = Blueprint("management", __name__, url_prefix="/management")


def _get_redis():
    """Retrieve the Redis client from the application extensions."""
    return current_app.extensions["redis"]


@management_bp.route("/policy/v0/store", methods=["POST"])
def store_policy():
    """Store a security policy in Redis for later use in attestation validation."""
    logger.info(f"Received policy store request from {request.remote_addr}")
    auth_response = authenticate_management_request()
    if auth_response:
        return auth_response

    policy = request.get_json()
    if not policy:
        logger.error("Policy store request missing JSON body")
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
        logger.warning(f"Policy {policy_type}:{key_id} is not signed")
        warning_message = (
            "WARNING: Policy is not signed and cannot be verified for integrity"
        )
        if current_app.config.get("TAS_ENFORCE_SIGNED_POLICIES", True):
            logger.error("Unsigned policies are not allowed by configuration")
            return (
                jsonify(
                    {"error": "Unsigned policies are not allowed by configuration"}
                ),
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

        if redis_client.get(policy_key) is not None:
            logger.error(f"Policy '{policy_key}' already exists in Redis")
            return jsonify({"error": f"Policy '{policy_key}' already exists"}), 409

        policy_json = json.dumps(policy)
        redis_client.set(policy_key, policy_json)

        logger.info(f"Stored policy '{policy_key}' in Redis")

        response_data = {"message": f"Policy '{policy_key}' stored successfully"}
        if warning_message:
            response_data["warning"] = warning_message

        return jsonify(response_data), 201

    except Exception as e:
        logger.error(f"Error storing policy: {e}")
        return jsonify({"error": "Failed to store policy in Redis"}), 500


@management_bp.route("/policy/v0/get/<policy_key>", methods=["GET"])
def get_policy(policy_key):
    """Retrieve a security policy from Redis."""
    logger.info(
        f"Received policy get request for '{policy_key}' from {request.remote_addr}"
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
        logger.debug(f"Retrieving policy '{policy_key}' from Redis")
        policy_json = redis_client.get(policy_key)

        if not policy_json:
            logger.warning(f"Policy '{policy_key}' not found in Redis")
            return jsonify({"error": f"Policy '{policy_key}' not found"}), 404

        policy = json.loads(policy_json)
        logger.info(f"Successfully retrieved policy '{policy_key}'")

        response_data = {"policy_key": policy_key, "policy": policy}
        if "signature" not in policy:
            logger.warning(f"Retrieved policy '{policy_key}' is not signed")
            response_data[
                "warning"
            ] = "WARNING: Policy is not signed and cannot be verified for integrity"

        return jsonify(response_data), 200

    except json.JSONDecodeError as e:
        logger.error(f"Error parsing policy JSON: {e}")
        return jsonify({"error": "Invalid policy data in Redis"}), 500
    except Exception as e:
        logger.error(f"Error retrieving policy: {e}")
        return jsonify({"error": "Failed to retrieve policy from Redis"}), 500


@management_bp.route("/policy/v0/list", methods=["GET"])
def list_policies():
    """List all stored policies in Redis."""
    logger.info(f"Received policy list request from {request.remote_addr}")
    auth_response = authenticate_management_request()
    if auth_response:
        return auth_response

    try:
        redis_client = _get_redis()
        logger.debug("Retrieving all policy keys from Redis")
        policy_keys = redis_client.keys("policy:*")
        logger.debug(f"Found {len(policy_keys)} policy keys in Redis")

        policies = []
        for key in policy_keys:
            policy_json = redis_client.get(key)

            if policy_json:
                try:
                    policy = json.loads(policy_json)
                    metadata = policy.get("metadata", {})
                    policy_info = {
                        "policy_key": key,
                        "name": metadata.get("name", "Unknown"),
                        "version": metadata.get("version", "Unknown"),
                        "description": metadata.get("description", "No description"),
                        "signed": "signature" in policy,
                    }
                    policies.append(policy_info)
                    logger.debug(f"Added policy to list: {key}")
                except json.JSONDecodeError:
                    logger.warning(f"Skipping invalid policy with key: {key}")
                    continue

        logger.info(f"Successfully listed {len(policies)} policies")
        return jsonify({"policies": policies, "count": len(policies)}), 200

    except Exception as e:
        logger.error(f"Error listing policies: {e}")
        return jsonify({"error": "Failed to list policies"}), 500


@management_bp.route("/policy/v0/delete/<policy_key>", methods=["DELETE"])
def delete_policy(policy_key):
    """Delete a security policy from Redis."""
    logger.info(
        f"Received policy delete request for '{policy_key}' from {request.remote_addr}"
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
        logger.debug(f"Attempting to delete policy with key: {policy_key}")
        deleted_count = redis_client.delete(policy_key)

        if deleted_count == 0:
            logger.warning(f"Policy '{policy_key}' not found for deletion")
            return jsonify({"error": f"Policy '{policy_key}' not found"}), 404

        logger.info(f"Deleted policy '{policy_key}' from Redis")

        return jsonify({"message": f"Policy '{policy_key}' deleted successfully"}), 200

    except Exception as e:
        logger.error(f"Error deleting policy: {e}")
        return jsonify({"error": "Failed to delete policy from Redis"}), 500


@management_bp.route("/status", methods=["GET"])
def status():
    """Return operational status of the TAS management plane."""
    auth_response = authenticate_management_request()
    if auth_response:
        return auth_response

    redis_client = _get_redis()
    try:
        aof_config = redis_client.config_get("appendonly")
        persistence_active = aof_config.get("appendonly") == "yes"
    except Exception:
        persistence_active = "unknown"

    config_rewrite_ok = current_app.extensions.get("redis_config_rewrite_ok")

    return jsonify(
        {
            "redis_persistence_active": persistence_active,
            "config_rewrite_succeeded": config_rewrite_ok,
        }
    )
