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
from contextlib import closing

from flask import Blueprint, current_app, jsonify, request

from .auth import authenticate_management_request
from .policy_helper import (
    check_signature_for_store,
    is_policy_signed,
    validate_policy_key,
    validate_policy_metadata,
)
from .policy_store import POLICY_NAMESPACE, PolicyAlreadyExists
from .tas_logging import get_logger

logger = get_logger(__name__)

management_bp = Blueprint("management", __name__, url_prefix="/management")


def _get_redis():
    """Retrieve the Redis client from the application extensions."""
    return current_app.extensions["redis"]


def _get_policy_store():
    """Retrieve the configured policy store from the application extensions."""
    return current_app.extensions["policy_store"]


@management_bp.route("/policy/v0/store", methods=["POST"])
def store_policy():
    """Store a security policy for later use in attestation validation."""
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

    is_valid, error = validate_policy_metadata(policy)
    if not is_valid:
        logger.error(f"Policy metadata validation failed: {error}")
        return jsonify({"error": error}), 400

    policy_id = policy["metadata"]["policy_id"]

    is_valid, error, warning_message = check_signature_for_store(
        policy,
        current_app.config.get("TAS_ENFORCE_SIGNED_POLICIES", True),
        current_app.config.get("TAS_TRUSTED_KEYS", []),
    )
    if not is_valid:
        logger.error(f"Policy signature check failed: {error}")
        return jsonify({"error": error}), 400

    policy_key = f"{POLICY_NAMESPACE}:{policy_id}"
    try:
        policy_store = _get_policy_store()
        policy_json = json.dumps(policy)
        policy_store.create(POLICY_NAMESPACE, policy_id, policy_json)

        logger.info(f"Stored policy '{policy_key}'")

        response_data = {"message": f"Policy '{policy_key}' stored successfully"}
        if warning_message:
            response_data["warning"] = warning_message

        return jsonify(response_data), 201

    except PolicyAlreadyExists:
        logger.error(f"Policy '{policy_key}' already exists")
        return jsonify({"error": f"Policy '{policy_key}' already exists"}), 409
    except Exception as e:
        logger.error(f"Error storing policy: {e}")
        return jsonify({"error": "Failed to store policy"}), 500


@management_bp.route("/policy/v0/get/<policy_id>", methods=["GET"])
def get_policy(policy_id):
    """Retrieve a security policy from the configured policy store."""
    logger.info(
        f"Received policy get request for '{policy_id}' from {request.remote_addr}"
    )
    auth_response = authenticate_management_request()
    if auth_response:
        return auth_response

    policy_key = f"{POLICY_NAMESPACE}:{policy_id}"
    is_valid, error_message = validate_policy_key(policy_key)
    if not is_valid:
        logger.error(f"Invalid policy key '{policy_key}': {error_message}")
        return jsonify({"error": error_message}), 400

    try:
        policy_store = _get_policy_store()
        logger.debug(f"Retrieving policy '{policy_key}'")
        policy_json = policy_store.get(POLICY_NAMESPACE, policy_id)

        if not policy_json:
            logger.warning(f"Policy '{policy_key}' not found")
            return jsonify({"error": f"Policy '{policy_key}' not found"}), 404

        policy = json.loads(policy_json)
        logger.info(f"Successfully retrieved policy '{policy_key}'")

        response_data = {"policy_key": policy_key, "policy": policy}
        if not is_policy_signed(policy):
            logger.warning(f"Retrieved policy '{policy_key}' is not signed")
            response_data["warning"] = (
                "WARNING: Policy is not signed and cannot be verified for integrity"
            )

        return jsonify(response_data), 200

    except json.JSONDecodeError as e:
        logger.error(f"Error parsing policy JSON: {e}")
        return jsonify({"error": "Invalid policy data in policy store"}), 500
    except Exception as e:
        logger.error(f"Error retrieving policy: {e}")
        return jsonify({"error": "Failed to retrieve policy"}), 500


@management_bp.route("/policy/v0/list", methods=["GET"])
def list_policies():
    """List all stored policies in the configured policy store."""
    logger.info(f"Received policy list request from {request.remote_addr}")
    auth_response = authenticate_management_request()
    if auth_response:
        return auth_response

    try:
        policy_store = _get_policy_store()
        logger.debug("Retrieving all policies from policy store")
        policies = []
        with closing(policy_store.list(POLICY_NAMESPACE)) as policy_documents:
            for policy_json in policy_documents:
                if policy_json:
                    try:
                        policy = json.loads(policy_json)
                        metadata = policy.get("metadata", {})
                        policy_info = {
                            "policy_id": metadata.get("policy_id", "Unknown"),
                            "name": metadata.get("name", "Unknown"),
                            "policy_type": metadata.get("policy_type", "Unknown"),
                            "key_id": metadata.get("key_id", "Unknown"),
                            "version": metadata.get("version", "Unknown"),
                            "description": metadata.get(
                                "description", "No description"
                            ),
                            "signed": is_policy_signed(policy),
                        }
                        policies.append(policy_info)
                    except json.JSONDecodeError:
                        logger.warning(
                            "Skipping invalid policy document in policy store"
                        )
                        continue

        logger.info(f"Successfully listed {len(policies)} policies")
        return jsonify({"policies": policies, "count": len(policies)}), 200

    except Exception as e:
        logger.error(f"Error listing policies: {e}")
        return jsonify({"error": "Failed to list policies"}), 500


@management_bp.route("/policy/v0/delete/<policy_id>", methods=["DELETE"])
def delete_policy(policy_id):
    """Delete a security policy from the configured policy store."""
    logger.info(
        f"Received policy delete request for '{policy_id}' from {request.remote_addr}"
    )
    auth_response = authenticate_management_request()
    if auth_response:
        return auth_response

    policy_key = f"{POLICY_NAMESPACE}:{policy_id}"
    is_valid, error_message = validate_policy_key(policy_key)
    if not is_valid:
        logger.error(f"Invalid policy key '{policy_key}': {error_message}")
        return jsonify({"error": error_message}), 400

    try:
        policy_store = _get_policy_store()
        logger.debug(f"Attempting to delete policy with key: {policy_key}")
        deleted = policy_store.delete(POLICY_NAMESPACE, policy_id)

        if not deleted:
            logger.warning(f"Policy '{policy_key}' not found for deletion")
            return jsonify({"error": f"Policy '{policy_key}' not found"}), 404

        logger.info(f"Deleted policy '{policy_key}'")

        return jsonify({"message": f"Policy '{policy_key}' deleted successfully"}), 200

    except Exception as e:
        logger.error(f"Error deleting policy: {e}")
        return jsonify({"error": "Failed to delete policy"}), 500


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

    policy_store = current_app.extensions.get("policy_store")
    backend_name = (
        policy_store.backend_name
        if policy_store is not None and getattr(policy_store, "backend_name", "")
        else current_app.config.get("TAS_POLICY_BACKEND", "redis")
    )
    reachable = bool(policy_store.is_reachable()) if policy_store is not None else False
    return jsonify(
        {
            "redis_persistence_active": persistence_active,
            "config_rewrite_succeeded": config_rewrite_ok,
            "policy_storage": {
                "backend": backend_name,
                "reachable": reachable,
            },
        }
    )
