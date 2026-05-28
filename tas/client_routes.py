#
# TEE Attestation Service - Client Routes
#
# Copyright 2026 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# This file is part of the TEE Attestation Service.
#
# This module provides the client API blueprint for attestation operations.
# Routes: /kb/v0/get_nonce, /kb/v0/get_secret, /version
#

import base64
import secrets

from flask import Blueprint, current_app, jsonify, request

from .auth import authenticate_request
from .nonce import store_nonce, validate_nonce
from .tas_logging import get_logger
from .tas_vm import vm_verify

logger = get_logger(__name__)

client_bp = Blueprint("client", __name__)


def get_redis():
    """Retrieve the primary Redis client from the application extensions."""
    return current_app.extensions["redis"]


def get_nonce_redis():
    """Retrieve the Redis client for nonce operations.

    Returns the ephemeral Redis client when configured, otherwise the primary.
    """
    return current_app.extensions.get(
        "redis_ephemeral", current_app.extensions["redis"]
    )


@client_bp.route("/kb/v0/get_nonce", methods=["GET"])
def get_nonce():
    logger.info(f"Received nonce request from {request.remote_addr}")
    auth_response = authenticate_request()
    if auth_response:
        return auth_response

    # Generate a random nonce
    nonce = secrets.token_hex(32)  # Generate a 64-character nonce
    logger.debug(f"Generated nonce: {nonce}")

    # Store the nonce in Redis
    redis_client = get_nonce_redis()
    expiration = current_app.config["TAS_NONCE_EXPIRATION_SECONDS"]
    store_nonce(redis_client, nonce, expiration)
    logger.info("Nonce generated and stored successfully")

    return jsonify({"nonce": nonce})


@client_bp.route("/kb/v0/get_secret", methods=["POST"])
def get_secret():
    logger.info(f"Received secret request from {request.remote_addr}")
    auth_response = authenticate_request()
    if auth_response:
        return auth_response

    # Get the JSON data from the request
    data = request.get_json()
    if not data:
        logger.error("Secret request missing JSON body")
        return jsonify({"error": "Request body is required"}), 400

    # Validate the "tee-type" field early
    tee_type = data.get("tee-type")
    if tee_type not in ["amd-sev-snp", "intel-tdx"]:
        logger.error(f"Invalid TEE type received: {tee_type}")
        return jsonify({"error": "Invalid or missing 'tee-type' field"}), 400

    # Validate the "nonce" field
    nonce = data.get("nonce")
    if not nonce:
        logger.error("Secret request missing nonce field")
        return jsonify({"error": "Nonce is required"}), 400

    nonce = str(nonce).strip('"')
    nonce_client = get_nonce_redis()
    is_valid, error_message = validate_nonce(nonce_client, nonce)
    if not is_valid:
        logger.error(f"Nonce validation failed: {error_message}")
        return jsonify({"error": error_message}), 401

    # Validate the "tee-evidence" field
    tee_evidence = data.get("tee-evidence")
    if not tee_evidence:
        logger.error("Secret request missing TEE evidence")
        return jsonify({"error": "TEE evidence is required"}), 400

    # Validate the "policy-id" field
    policy_id = data.get("policy-id")
    if not policy_id:
        logger.error("Secret request missing policy ID")
        return jsonify({"error": "Policy ID is required"}), 400

    # Log the fields for debugging
    logger.debug(f"Received TEE evidence: {tee_evidence}")
    logger.debug(f"Received Policy ID: {policy_id}")

    # Report data binding is required for this route,
    # create a new route for non-binding use cases if needed in the future
    report_data_binding = data.get("report-data-binding")
    if report_data_binding is None:
        logger.error("Secret request missing report data binding")
        return jsonify({"error": "Report data binding is required"}), 400

    logger.debug(f"Received report data binding: {report_data_binding}")

    # Optional GPU evidence for Phase 2 - if provided, it will be passed to the vm_verify function
    gpu_evidence = data.get("gpu-evidence", None)  # Phase 2

    # Get client's wrapping key (RSA public key) from the request
    # The public key is expected to be in base64 format
    wrapping_key = data.get("wrapping-key")
    if not wrapping_key:
        logger.error("Secret request missing wrapping key")
        return jsonify({"error": "Client's wrapping key is required"}), 400

    # Decode the public key from base64
    try:
        wrapping_key = base64.b64decode(wrapping_key)
        logger.debug("Successfully decoded wrapping key from base64")
    except (TypeError, ValueError):
        logger.error("Failed to decode wrapping key from base64")
        return jsonify({"error": "Invalid encoding format for wrapping key"}), 400

    # Log the public key for debugging
    logger.debug(f"Received public key: {wrapping_key.hex()}")

    # Validate the public key
    if not isinstance(wrapping_key, bytes):
        logger.error("Invalid wrapping key format: not bytes")
        return jsonify({"error": "Invalid wrapping key format"}), 400

    # Call vm_verify to validate the parameters — always uses primary Redis
    # for policy lookup, cert caching, and collateral caching
    redis_client = get_redis()
    logger.info(f"Starting TEE verification for type: {tee_type}")
    is_verified, key_id, verify_error = vm_verify(
        redis_client,
        nonce,
        tee_type,
        tee_evidence,
        policy_id,
        wrapping_key=wrapping_key,
        report_data_binding=report_data_binding,
        gpu_evidence=gpu_evidence,  # NEW (for Phase 2)
    )
    if not is_verified:
        logger.error(f"TEE verification failed: {verify_error}")
        return jsonify({"error": "TEE verification failed"}), 400

    # Retrieve the secret from the KMIP Broker Module
    logger.info(f"Retrieving secret for key ID: {key_id}")
    kbm_get_secret = current_app.extensions["kbm_get_secret"]
    kbm_client = current_app.extensions["kbm_client"]
    try:
        secret = kbm_get_secret(kbm_client, key_id, wrapping_key)
        logger.info("Secret retrieval successful")
    except ValueError as e:
        logger.error(f"Secret retrieval failed: {str(e)}")
        return jsonify({"error": "Secret retrieval failed"}), 404

    # Return the secret
    logger.info(f"Successfully completed secret request for {request.remote_addr}")
    return jsonify({"secret_key": secret})


@client_bp.route("/version")
def version():
    logger.info(f"Received version request from {request.remote_addr}")
    auth_response = authenticate_request()
    if auth_response:
        return auth_response
    tas_version = current_app.config["TAS_VERSION"]
    logger.debug(f"Returning TAS version: {tas_version}")
    return jsonify({"version": tas_version})
