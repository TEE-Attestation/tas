#
# TEE Attestation Service - Certify-flow Policy Management Routes
#
# Copyright 2026 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# This file is part of the TEE Attestation Service.
#
# Management API for the certify flow's domain-policies and certify-policies.
# These objects live in the "domain-policy:{id}" and "certify-policy:{id}"
# Redis keyspaces, kept completely separate from the secret-release "policy:*"
# store. The blueprint is only registered when TAS_CERTIFY_ENABLED is true.
#

import json

from flask import Blueprint, current_app, jsonify, request

from ..auth import authenticate_management_request
from ..policy_helper import (
    check_signature_for_store,
    is_policy_signed,
    validate_key_component,
    validate_policy_metadata,
)
from ..tas_logging import get_logger
from ..tas_vm import POLICY_TYPE_BY_TEE, SUPPORTED_TEE_TYPES

logger = get_logger(__name__)

certify_policy_bp = Blueprint("certify_policy", __name__, url_prefix="/management")

DOMAIN_POLICY_PREFIX = "domain-policy:"
CERTIFY_POLICY_PREFIX = "certify-policy:"

UNSIGNED_WARNING = "WARNING: Object is not signed and cannot be verified for integrity"


def _get_redis():
    """Retrieve the Redis client from the application extensions."""
    return current_app.extensions["redis"]


def _enforce_config():
    """Return the (enforce_signed, trusted_keys) tuple from app config."""
    return (
        current_app.config.get("TAS_ENFORCE_SIGNED_POLICIES", True),
        current_app.config.get("TAS_TRUSTED_KEYS", []),
    )


# --------------------------------------------------------------------------- #
# Certify-policies (attestation policies referenced by domain-policies)
# --------------------------------------------------------------------------- #


@certify_policy_bp.route("/certify-policy/v0/store", methods=["POST"])
def store_certify_policy():
    """Store a certify-policy for later use in the certify flow."""
    logger.info(f"Received certify-policy store request from {request.remote_addr}")
    auth_response = authenticate_management_request()
    if auth_response:
        return auth_response

    policy = request.get_json(silent=True)
    if not policy:
        return jsonify({"error": "Request body is required"}), 400
    if not isinstance(policy, dict):
        return jsonify({"error": "Certify-policy must be a JSON object"}), 400

    # key_id names a KMS secret for the secret-release flow; the certify flow
    # does not release secrets, so certify-policies may omit it.
    is_valid, error = validate_policy_metadata(policy, require_key_id=False)
    if not is_valid:
        logger.error(f"Certify-policy validation failed: {error}")
        return jsonify({"error": error}), 400

    policy_id = policy["metadata"]["policy_id"]

    enforce_signed, trusted_keys = _enforce_config()
    is_valid, error, warning_message = check_signature_for_store(
        policy, enforce_signed, trusted_keys
    )
    if not is_valid:
        logger.error(f"Certify-policy signature check failed: {error}")
        return jsonify({"error": error}), 400

    try:
        redis_client = _get_redis()
        policy_key = f"{CERTIFY_POLICY_PREFIX}{policy_id}"
        if not redis_client.set(policy_key, json.dumps(policy), nx=True):
            return (
                jsonify({"error": f"Certify-policy '{policy_id}' already exists"}),
                409,
            )
        logger.info(f"Stored certify-policy '{policy_key}' in Redis")

        response_data = {"message": f"Certify-policy '{policy_id}' stored successfully"}
        if warning_message:
            response_data["warning"] = warning_message
        return jsonify(response_data), 201
    except Exception as e:
        logger.error(f"Error storing certify-policy: {e}")
        return jsonify({"error": "Failed to store certify-policy in Redis"}), 500


@certify_policy_bp.route("/certify-policy/v0/get/<policy_id>", methods=["GET"])
def get_certify_policy(policy_id):
    """Retrieve a certify-policy from Redis."""
    logger.info(f"Received certify-policy get request for '{policy_id}'")
    auth_response = authenticate_management_request()
    if auth_response:
        return auth_response

    is_valid, error = validate_key_component(policy_id, "certify policy id")
    if not is_valid:
        return jsonify({"error": error}), 400

    try:
        redis_client = _get_redis()
        raw = redis_client.get(f"{CERTIFY_POLICY_PREFIX}{policy_id}")
        if not raw:
            return jsonify({"error": f"Certify-policy '{policy_id}' not found"}), 404

        policy = json.loads(raw)
        response_data = {"policy_id": policy_id, "certify_policy": policy}
        if not is_policy_signed(policy):
            response_data["warning"] = UNSIGNED_WARNING
        return jsonify(response_data), 200
    except json.JSONDecodeError as e:
        logger.error(f"Error parsing certify-policy JSON: {e}")
        return jsonify({"error": "Invalid certify-policy data in Redis"}), 500
    except Exception as e:
        logger.error(f"Error retrieving certify-policy: {e}")
        return jsonify({"error": "Failed to retrieve certify-policy from Redis"}), 500


@certify_policy_bp.route("/certify-policy/v0/list", methods=["GET"])
def list_certify_policies():
    """List all stored certify-policies."""
    logger.info("Received certify-policy list request")
    auth_response = authenticate_management_request()
    if auth_response:
        return auth_response

    try:
        redis_client = _get_redis()

        policies = []
        for key in redis_client.scan_iter(match=f"{CERTIFY_POLICY_PREFIX}*", count=100):
            raw = redis_client.get(key)
            if not raw:
                continue
            try:
                policy = json.loads(raw)
            except json.JSONDecodeError:
                logger.warning(f"Skipping invalid certify-policy with key: {key}")
                continue
            metadata = policy.get("metadata", {})
            policies.append(
                {
                    "policy_id": metadata.get("policy_id", "Unknown"),
                    "name": metadata.get("name", "Unknown"),
                    "policy_type": metadata.get("policy_type", "Unknown"),
                    "key_id": metadata.get("key_id", "Unknown"),
                    "signed": is_policy_signed(policy),
                }
            )

        return jsonify({"certify_policies": policies, "count": len(policies)}), 200
    except Exception as e:
        logger.error(f"Error listing certify-policies: {e}")
        return jsonify({"error": "Failed to list certify-policies"}), 500


@certify_policy_bp.route("/certify-policy/v0/delete/<policy_id>", methods=["DELETE"])
def delete_certify_policy(policy_id):
    """Delete a certify-policy from Redis."""
    logger.info(f"Received certify-policy delete request for '{policy_id}'")
    auth_response = authenticate_management_request()
    if auth_response:
        return auth_response

    is_valid, error = validate_key_component(policy_id, "certify policy id")
    if not is_valid:
        return jsonify({"error": error}), 400

    try:
        redis_client = _get_redis()
        deleted = redis_client.delete(f"{CERTIFY_POLICY_PREFIX}{policy_id}")
        if deleted == 0:
            return jsonify({"error": f"Certify-policy '{policy_id}' not found"}), 404
        logger.info(f"Deleted certify-policy '{policy_id}' from Redis")
        return (
            jsonify({"message": f"Certify-policy '{policy_id}' deleted successfully"}),
            200,
        )
    except Exception as e:
        logger.error(f"Error deleting certify-policy: {e}")
        return jsonify({"error": "Failed to delete certify-policy from Redis"}), 500


# --------------------------------------------------------------------------- #
# Domain-policies (named collections of certify-policy ids, OR-evaluated)
# --------------------------------------------------------------------------- #


def _validate_domain_policy(policy):
    """Validate the structure of a domain-policy document.

    Returns (True, policy_id, None) if valid, else (False, None, error_message).
    """
    if not isinstance(policy, dict):
        return False, None, "Domain policy must be a JSON object"

    metadata = policy.get("metadata")
    if not isinstance(metadata, dict):
        return False, None, "Domain policy must contain 'metadata' section"

    is_valid, error = validate_key_component(
        metadata.get("policy_id"), "domain policy id"
    )
    if not is_valid:
        return False, None, error
    policy_id = metadata["policy_id"]

    certify_policies = policy.get("certify_policies")
    if not isinstance(certify_policies, dict) or not certify_policies:
        return (
            False,
            None,
            "Domain policy must contain a non-empty 'certify_policies' object "
            "keyed by TEE type",
        )

    max_members = current_app.config.get("TAS_CERTIFY_MAX_POLICIES", 32)

    # Reject oversized requests before validating every member id.
    total = sum(len(ids) for ids in certify_policies.values() if isinstance(ids, list))
    if total > max_members:
        return (
            False,
            None,
            f"Domain policy may reference at most {max_members} certify policies",
        )

    for tee_type, ids in certify_policies.items():
        if tee_type not in SUPPORTED_TEE_TYPES:
            return (
                False,
                None,
                f"Unsupported TEE type '{tee_type}' in certify_policies "
                f"(expected one of: {', '.join(sorted(SUPPORTED_TEE_TYPES))})",
            )
        if not isinstance(ids, list) or not ids:
            return (
                False,
                None,
                f"certify_policies['{tee_type}'] must be a non-empty list",
            )
        for member_id in ids:
            is_valid, error = validate_key_component(member_id, "certify policy id")
            if not is_valid:
                return False, None, error
        if len(set(ids)) != len(ids):
            return (
                False,
                None,
                f"certify_policies['{tee_type}'] must not contain duplicates",
            )

    return True, policy_id, None


@certify_policy_bp.route("/domain-policy/v0/store", methods=["POST"])
def store_domain_policy():
    """Store a domain-policy referencing one or more certify-policies."""
    logger.info(f"Received domain-policy store request from {request.remote_addr}")
    auth_response = authenticate_management_request()
    if auth_response:
        return auth_response

    policy = request.get_json(silent=True)
    if not policy:
        return jsonify({"error": "Request body is required"}), 400

    is_valid, policy_id, error = _validate_domain_policy(policy)
    if not is_valid:
        logger.error(f"Domain-policy validation failed: {error}")
        return jsonify({"error": error}), 400

    enforce_signed, trusted_keys = _enforce_config()
    is_valid, error, warning_message = check_signature_for_store(
        policy, enforce_signed, trusted_keys
    )
    if not is_valid:
        logger.error(f"Domain-policy signature check failed: {error}")
        return jsonify({"error": error}), 400

    try:
        redis_client = _get_redis()
        policy_key = f"{DOMAIN_POLICY_PREFIX}{policy_id}"

        # Referenced certify-policies may be added after the domain-policy; warn
        # rather than reject so the two stores can be populated in any order.
        # Also warn when a referenced policy's declared type does not match the
        # TEE-type group it is listed under.
        missing = []
        type_mismatches = []
        for tee_type, ids in policy["certify_policies"].items():
            expected_type = POLICY_TYPE_BY_TEE.get(tee_type)
            for member_id in ids:
                raw = redis_client.get(f"{CERTIFY_POLICY_PREFIX}{member_id}")
                if raw is None:
                    missing.append(member_id)
                    continue
                try:
                    member_type = (
                        json.loads(raw).get("metadata", {}).get("policy_type", "")
                    )
                except (json.JSONDecodeError, AttributeError):
                    member_type = ""
                if (
                    expected_type
                    and member_type
                    and member_type.upper() != expected_type
                ):
                    type_mismatches.append(
                        f"{member_id} ({member_type}, expected {expected_type} "
                        f"for {tee_type})"
                    )

        if not redis_client.set(policy_key, json.dumps(policy), nx=True):
            return (
                jsonify({"error": f"Domain policy '{policy_id}' already exists"}),
                409,
            )
        logger.info(f"Stored domain-policy '{policy_key}' in Redis")

        warnings = []
        if warning_message:
            warnings.append(warning_message)
        if missing:
            warnings.append(
                "Referenced certify-policies not found (they can be added later): "
                + ", ".join(sorted(missing))
            )
        if type_mismatches:
            warnings.append(
                "Referenced certify-policies whose type does not match their TEE "
                "group: " + ", ".join(sorted(type_mismatches))
            )

        response_data = {"message": f"Domain policy '{policy_id}' stored successfully"}
        if warnings:
            response_data["warning"] = " | ".join(warnings)
        return jsonify(response_data), 201
    except Exception as e:
        logger.error(f"Error storing domain-policy: {e}")
        return jsonify({"error": "Failed to store domain policy in Redis"}), 500


@certify_policy_bp.route("/domain-policy/v0/get/<policy_id>", methods=["GET"])
def get_domain_policy(policy_id):
    """Retrieve a domain-policy from Redis."""
    logger.info(f"Received domain-policy get request for '{policy_id}'")
    auth_response = authenticate_management_request()
    if auth_response:
        return auth_response

    is_valid, error = validate_key_component(policy_id, "domain policy id")
    if not is_valid:
        return jsonify({"error": error}), 400

    try:
        redis_client = _get_redis()
        raw = redis_client.get(f"{DOMAIN_POLICY_PREFIX}{policy_id}")
        if not raw:
            return jsonify({"error": f"Domain policy '{policy_id}' not found"}), 404

        policy = json.loads(raw)
        response_data = {"policy_id": policy_id, "domain_policy": policy}
        if not is_policy_signed(policy):
            response_data["warning"] = UNSIGNED_WARNING
        return jsonify(response_data), 200
    except json.JSONDecodeError as e:
        logger.error(f"Error parsing domain-policy JSON: {e}")
        return jsonify({"error": "Invalid domain policy data in Redis"}), 500
    except Exception as e:
        logger.error(f"Error retrieving domain-policy: {e}")
        return jsonify({"error": "Failed to retrieve domain policy from Redis"}), 500


@certify_policy_bp.route("/domain-policy/v0/list", methods=["GET"])
def list_domain_policies():
    """List all stored domain-policies."""
    logger.info("Received domain-policy list request")
    auth_response = authenticate_management_request()
    if auth_response:
        return auth_response

    try:
        redis_client = _get_redis()

        domain_policies = []
        for key in redis_client.scan_iter(match=f"{DOMAIN_POLICY_PREFIX}*", count=100):
            raw = redis_client.get(key)
            if not raw:
                continue
            try:
                policy = json.loads(raw)
            except json.JSONDecodeError:
                logger.warning(f"Skipping invalid domain-policy with key: {key}")
                continue
            metadata = policy.get("metadata", {})
            domain_policies.append(
                {
                    "policy_id": metadata.get("policy_id", "Unknown"),
                    "description": metadata.get("description", "No description"),
                    "certify_policies": policy.get("certify_policies", {}),
                    "signed": is_policy_signed(policy),
                }
            )

        return (
            jsonify(
                {"domain_policies": domain_policies, "count": len(domain_policies)}
            ),
            200,
        )
    except Exception as e:
        logger.error(f"Error listing domain-policies: {e}")
        return jsonify({"error": "Failed to list domain policies"}), 500


@certify_policy_bp.route("/domain-policy/v0/delete/<policy_id>", methods=["DELETE"])
def delete_domain_policy(policy_id):
    """Delete a domain-policy from Redis."""
    logger.info(f"Received domain-policy delete request for '{policy_id}'")
    auth_response = authenticate_management_request()
    if auth_response:
        return auth_response

    is_valid, error = validate_key_component(policy_id, "domain policy id")
    if not is_valid:
        return jsonify({"error": error}), 400

    try:
        redis_client = _get_redis()
        deleted = redis_client.delete(f"{DOMAIN_POLICY_PREFIX}{policy_id}")
        if deleted == 0:
            return jsonify({"error": f"Domain policy '{policy_id}' not found"}), 404
        logger.info(f"Deleted domain-policy '{policy_id}' from Redis")
        return (
            jsonify({"message": f"Domain policy '{policy_id}' deleted successfully"}),
            200,
        )
    except Exception as e:
        logger.error(f"Error deleting domain-policy: {e}")
        return jsonify({"error": "Failed to delete domain policy from Redis"}), 500
