#
# TEE Attestation Service
#
# Copyright 2025 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# This file is part of the TEE Attestation Service.
# See LICENSE file for details.
#

import base64
import importlib
import json
import os
import pkgutil
import secrets
import sys
import time

import redis
from flask import Flask, jsonify, request

from tas.config_loader import load_configuration
from tas.policy_helper import verify_policy_signature
from tas.tas_logging import configure_external_logging, setup_logging
from tas.tas_vm import vm_verify

# Initialize Flask app and load configuration
app = Flask(__name__)

# Set up basic logging first so config_loader can use it
logger = setup_logging(name="tas", level="INFO", cli_mode=True)
logger.debug("Loading in config")

# Load configuration
load_configuration(app)

# Reconfigure logging with settings from config if available
tas_config = app.config.get("TAS", {})
log_config = tas_config.get("logging", {}) if isinstance(tas_config, dict) else {}

if log_config:
    # Get logging configuration with defaults
    log_level = log_config.get("level", "INFO")
    log_file = log_config.get("file", None)
    verbose = log_config.get("verbose", False)
    quiet = log_config.get("quiet", False)
    cli = log_config.get("cli", False)

    # Reconfigure the root "tas" logger with settings from config
    logger = setup_logging(
        name="tas",
        level=log_level,
        cli_mode=cli,
        verbose=verbose,
        quiet=quiet,
        log_file=log_file,
    )
else:
    logger.debug("No TAS logging configuration found, using defaults")

# Include logging settings in external loggers
configure_external_logging()


# add ./plugins in sys.path
fpath = os.path.join(os.path.dirname(__file__), "plugins")
sys.path.append(fpath)
logger.debug(sys.path)

logger.info("TAS application initialized successfully")


# Add request logging middleware
@app.before_request
def log_request_info():
    logger.info(f"Request: {request.method} {request.path} from {request.remote_addr}")
    if request.is_json and request.get_json():
        # Log request data without sensitive fields
        data = request.get_json()
        safe_data = {
            k: v
            for k, v in data.items()
            if k not in ["nonce", "wrapping-key", "tee-evidence"]
        }
        if safe_data:
            logger.debug(f"Request data: {safe_data}")


@app.after_request
def log_response_info(response):
    logger.info(f"Response: {response.status_code} for {request.method} {request.path}")
    return response


@app.errorhandler(Exception)
def handle_exception(e):
    logger.error(
        f"Unhandled exception in {request.method} {request.path}: {e}", exc_info=True
    )
    return jsonify({"error": "Internal server error"}), 500


# Optionally add an extra plugin directory to sys.path
extra_plugin_dir = app.config.get("TAS_EXTRA_PLUGIN_DIR")
if extra_plugin_dir:
    if os.path.isdir(extra_plugin_dir):
        sys.path.append(extra_plugin_dir)
        logger.info(f"Added extra plugin directory to sys.path: {extra_plugin_dir}")
    else:
        raise RuntimeError(f"Extra plugin directory does not exist: {extra_plugin_dir}")

# TEE Attestation Service version information
TAS_VERSION = "0.1.0"

# Retrieve the API key from configuration
TAS_API_KEY = app.config["TAS_API_KEY"]

if not TAS_API_KEY:
    raise RuntimeError("TAS_API_KEY environment variable is not set")

# Internal variables
NONCE_EXPIRATION_SECONDS = app.config["TAS_NONCE_EXPIRATION_SECONDS"]

# Plugin discovery: respect prefix defined in the configuration
# This allows for dynamic loading of plugins that follow the
# naming convention defined in plugin_prefix.
plugin_prefix = app.config["TAS_PLUGIN_PREFIX"]
discovered_plugins = {
    name: importlib.import_module(name)
    for finder, name, ispkg in pkgutil.iter_modules()
    if name.startswith(plugin_prefix)
}

# Initialize Redis client
try:
    redis_client = redis.StrictRedis(
        host=app.config["TAS_REDIS_HOST"],  # Redis server address
        port=app.config["TAS_REDIS_PORT"],  # Redis server port
        decode_responses=True,  # Ensures responses are returned as strings
    )
    # Test the connection to ensure Redis is reachable
    redis_client.ping()
    logger.info("Successful Connection to Redis Server")
except redis.ConnectionError as e:
    raise RuntimeError(f"Failed to connect to the Redis server: {e}")
except Exception as e:
    raise RuntimeError(f"An unexpected error occurred while initializing Redis: {e}")

# log discovered plugins for debugging
logger.debug("Discovered plugins:")
tas_kbm_plugin = None
for plugin_name in discovered_plugins:
    logger.debug(f" - {plugin_name}")
    if plugin_name == app.config["TAS_KBM_PLUGIN"]:
        tas_kbm_plugin = discovered_plugins[plugin_name]
if not tas_kbm_plugin:
    raise RuntimeError("tas_kbm plugin not found in discovered plugins")

# log the selected tas_kbm plugin for debugging
logger.info(f"Using tas_kbm plugin: {app.config['TAS_KBM_PLUGIN']}")


# Ensure the tas_kbm plugin has the required functions
required_functions = [
    "kbm_get_secret",
    "kbm_close_client_connection",
    "kbm_open_client_connection",
]
for func in required_functions:
    if not hasattr(tas_kbm_plugin, func):
        raise RuntimeError(f"Required function '{func}' not found in tas_kbm plugin")

# import the required functions from the tas_kbm plugin
kbm_get_secret = tas_kbm_plugin.kbm_get_secret
kbm_close_client_connection = tas_kbm_plugin.kbm_close_client_connection
kbm_open_client_connection = tas_kbm_plugin.kbm_open_client_connection
# Initialize the KBM client
logger.info("Initializing KBM client connection")
try:
    # use the tas_kbm plugin to open the KBM client connection
    kbm_client = kbm_open_client_connection(
        config_file=app.config["TAS_KBM_CONFIG_FILE"]
    )
    logger.info("KBM client connection established successfully")
except Exception as e:
    logger.error(f"Failed to initialize KBM client: {e}")
    raise RuntimeError(f"Failed to open KBM client connection: {e}")


# Function to store a nonce with an expiration time
def store_nonce(nonce):
    logger.debug(f"Storing nonce with expiration: {NONCE_EXPIRATION_SECONDS}s")
    redis_client.setex(nonce, NONCE_EXPIRATION_SECONDS, int(time.time()))
    logger.debug("Nonce stored successfully")


# Function to validate a nonce
def validate_nonce(nonce):
    logger.debug(f"Validating nonce: {nonce[:8]}...")
    timestamp = redis_client.get(nonce)
    if not timestamp:
        logger.warning("Nonce validation failed: Invalid or expired nonce")
        return False, "Invalid or expired nonce"

    # Check if the nonce has expired
    current_time = int(time.time())
    if current_time - int(timestamp) > NONCE_EXPIRATION_SECONDS:
        logger.warning("Nonce validation failed: Nonce has expired")
        redis_client.delete(nonce)
        return False, "Nonce has expired"

    # Nonce is valid
    logger.debug("Nonce validation successful, removing from Redis")
    redis_client.delete(nonce)  # Remove nonce after successful validation
    return True, None


# Function to check API key
def authenticate_request():
    api_key = request.headers.get("X-API-KEY")
    if api_key != TAS_API_KEY:
        logger.warning(
            f"Unauthorized request from {request.remote_addr}: Invalid API key"
        )
        return jsonify({"error": "Unauthorized"}), 401


# Endpoint to generate and send a nonce
@app.route("/kb/v0/get_nonce", methods=["GET"])
def get_nonce():
    logger.info(f"Received nonce request from {request.remote_addr}")
    auth_response = authenticate_request()
    if auth_response:
        return auth_response

    # Generate a random nonce
    nonce = secrets.token_hex(32)  # Generate a 64-character nonce
    logger.debug(f"Generated nonce: {nonce}")

    # Store the nonce in Redis
    store_nonce(nonce)
    logger.info("Nonce generated and stored successfully")

    return jsonify({"nonce": nonce})


# Endpoint to validate the nonce and return the secret key
@app.route("/kb/v0/get_secret", methods=["POST"])
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
    is_valid, error_message = validate_nonce(nonce)
    if not is_valid:
        logger.error(f"Nonce validation failed: {error_message}")
        return jsonify({"error": error_message}), 401

    # Validate the "tee-evidence" field
    tee_evidence = data.get("tee-evidence")
    if not tee_evidence:
        logger.error("Secret request missing TEE evidence")
        return jsonify({"error": "TEE evidence is required"}), 400

    # Validate the "key-id" field
    key_id = data.get("key-id")
    if not key_id:
        logger.error("Secret request missing key ID")
        return jsonify({"error": "Key ID is required"}), 400

    # Log the fields for debugging
    logger.debug(f"Received TEE evidence: {tee_evidence}")
    logger.debug(f"Received Key ID: {key_id}")

    # Call vm_verify to validate the parameters
    logger.info(f"Starting TEE verification for type: {tee_type}")
    is_verified, verify_error = vm_verify(
        redis_client, nonce, tee_type, tee_evidence, key_id
    )
    if not is_verified:
        logger.error(f"TEE verification failed: {verify_error}")
        return jsonify({"error": "TEE verification failed"}), 400
    logger.info("TEE verification successful")

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
        return jsonify({"error": "Invalid econding format for wrapping key"}), 400

    # Log the public key for debugging
    logger.debug(f"Received public key: {wrapping_key.hex()}")

    # Validate the public key
    if not isinstance(wrapping_key, bytes):
        logger.error("Invalid wrapping key format: not bytes")
        return jsonify({"error": "Invalid wrapping key format"}), 400

    # Retrieve the secret from the KMIP Broker Module
    logger.info(f"Retrieving secret for key ID: {key_id}")
    try:
        secret = kbm_get_secret(kbm_client, key_id, wrapping_key)
        logger.info("Secret retrieval successful")
    except ValueError as e:
        logger.error(f"Secret retrieval failed: {str(e)}")
        return jsonify({"error": "Secret retrieval failed"}), 404

    # Return the secret
    logger.info(f"Successfully completed secret request for {request.remote_addr}")
    return jsonify({"secret_key": secret})


# Endpoint to store a policy in Redis
@app.route("/policy/v0/store", methods=["POST"])
def store_policy():
    """
    Store a security policy in Redis for later use in attestation validation.

    Expected JSON payload:
    {
        "policy_type": "SEV|TDX",
        "key_id": "my-key-1",
        "policy": {
            "metadata": {
                "name": "My Security Policy",
                "version": "1.0",
                "description": "Custom security policy"
            },
            "validation_rules": {
                "host_data": {
                    "exact_match": "..."
                },
                "policy": {
                    "debug_allowed": false,
                    "migrate_ma_allowed": false
                }
            }
        }
    }
    """
    logger.info(f"Received policy store request from {request.remote_addr}")
    auth_response = authenticate_request()
    if auth_response:
        return auth_response

    # Get the JSON data from the request
    data = request.get_json()
    if not data:
        logger.error("Policy store request missing JSON body")
        return jsonify({"error": "Request body is required"}), 400

    # Validate required fields
    policy_type = data.get("policy_type")
    if not policy_type:
        logger.error("Policy store request missing policy_type")
        return jsonify({"error": "Policy type is required (e.g. SEV, TDX)"}), 400

    key_id = data.get("key_id")
    if not key_id:
        logger.error("Policy store request missing key_id")
        return jsonify({"error": "Key ID is required"}), 400

    policy = data.get("policy")
    if not policy:
        logger.error("Policy store request missing policy data")
        return jsonify({"error": "Policy data is required"}), 400

    # Validate policy structure
    if not isinstance(policy, dict):
        logger.error("Policy data is not a valid JSON object")
        return jsonify({"error": "Policy must be a JSON object"}), 400

    # Check for required policy sections
    if "metadata" not in policy:
        logger.error("Policy missing required 'metadata' section")
        return jsonify({"error": "Policy must contain 'metadata' section"}), 400

    if "validation_rules" not in policy:
        logger.error("Policy missing required 'validation_rules' section")
        return jsonify({"error": "Policy must contain 'validation_rules' section"}), 400

    # Check if policy is signed
    is_signed = "signature" in policy
    warning_message = None
    if not is_signed:
        logger.warning(f"Policy {policy_type}:{key_id} is not signed")
        warning_message = (
            "WARNING: Policy is not signed and cannot be verified for integrity"
        )
        if app.config.get("TAS_ENFORCE_SIGNED_POLICIES", True):
            logger.error("Unsigned policies are not allowed by configuration")
            return (
                jsonify(
                    {"error": "Unsigned policies are not allowed by configuration"}
                ),
                400,
            )
    else:
        logger.info(f"Policy {policy_type}:{key_id} is signed")
        if not verify_policy_signature(policy, app.config.get("TAS_TRUSTED_KEYS", [])):
            logger.error("Policy signature verification failed")
            return jsonify({"error": "Policy signature verification failed"}), 400
        logger.info("Policy signature verification successful")

    try:
        # Store the policy in Redis with a descriptive key
        policy_key = f"policy:{policy_type}:{key_id}"
        policy_json = json.dumps(policy)

        # Store with no expiration (policies should persist)
        redis_client.set(policy_key, policy_json)

        logger.info(f"Stored policy '{policy_key}' in Redis")

        response_data = {"message": f"Policy '{policy_key}' stored successfully"}
        if warning_message:
            response_data["warning"] = warning_message

        return jsonify(response_data), 201

    except Exception as e:
        logger.error(f"Error storing policy: {e}")
        return jsonify({"error": "Failed to store policy in Redis"}), 500


# Endpoint to retrieve a policy from Redis
@app.route("/policy/v0/get/<policy_key>", methods=["GET"])
def get_policy(policy_key):
    """
    Retrieve a security policy from Redis.
    """
    logger.info(
        f"Received policy get request for '{policy_key}' from {request.remote_addr}"
    )
    auth_response = authenticate_request()
    if auth_response:
        return auth_response

    try:
        # Retrieve the policy from Redis
        logger.debug(f"Retrieving policy '{policy_key}' from Redis")
        policy_json = redis_client.get(policy_key)

        if not policy_json:
            logger.warning(f"Policy '{policy_key}' not found in Redis")
            return jsonify({"error": f"Policy '{policy_key}' not found"}), 404

        policy = json.loads(policy_json)
        logger.info(f"Successfully retrieved policy '{policy_key}'")

        # Check if policy is signed and add warning if not
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


# Endpoint to list all stored policies
@app.route("/policy/v0/list", methods=["GET"])
def list_policies():
    """
    List all stored policies in Redis.
    """
    logger.info(f"Received policy list request from {request.remote_addr}")
    auth_response = authenticate_request()
    if auth_response:
        return auth_response

    try:
        # Get all policy keys from Redis
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
                    # Skip invalid policies
                    logger.warning(f"Skipping invalid policy with key: {key}")
                    continue

        logger.info(f"Successfully listed {len(policies)} policies")
        return jsonify({"policies": policies, "count": len(policies)}), 200

    except Exception as e:
        logger.error(f"Error listing policies: {e}")
        return jsonify({"error": "Failed to list policies"}), 500


# Endpoint to delete a policy from Redis
@app.route("/policy/v0/delete/<policy_name>", methods=["DELETE"])
def delete_policy(policy_name):
    """
    Delete a security policy from Redis.
    """
    logger.info(
        f"Received policy delete request for '{policy_name}' from {request.remote_addr}"
    )
    auth_response = authenticate_request()
    if auth_response:
        return auth_response

    try:
        # Delete the policy from Redis
        policy_key = f"policy:{policy_name}"
        logger.debug(f"Attempting to delete policy with key: {policy_key}")
        deleted_count = redis_client.delete(policy_key)

        if deleted_count == 0:
            logger.warning(f"Policy '{policy_name}' not found for deletion")
            return jsonify({"error": f"Policy '{policy_name}' not found"}), 404

        logger.info(f"Deleted policy '{policy_name}' from Redis")

        return jsonify({"message": f"Policy '{policy_name}' deleted successfully"}), 200

    except Exception as e:
        logger.error(f"Error deleting policy: {e}")
        return jsonify({"error": "Failed to delete policy from Redis"}), 500


# Endpoint to retrieve the version information
@app.route("/version")
def version():
    logger.info(f"Received version request from {request.remote_addr}")
    auth_response = authenticate_request()
    if auth_response:
        return auth_response
    logger.debug(f"Returning TAS version: {TAS_VERSION}")
    return jsonify({"version": TAS_VERSION})


if __name__ == "__main__":
    # Note: This is a simplified example and should not be used in production
    # without proper security measures such as HTTPS, nonce expiration, etc.
    # In a real-world scenario, you would also want to implement
    # proper error handling and logging to ensure that the service is robust and secure
    # and to prevent abuse of the nonce generation and validation process.
    try:
        logger.info(
            f"Starting TAS server on {app.config.get('SERVER_BIND_HOST', '0.0.0.0')}:{app.config.get('SERVER_PORT', 5000)}"
        )
        logger.info(f"Debug mode: {app.config['DEBUG']}")
        app.run(
            host=app.config.get("SERVER_BIND_HOST", "0.0.0.0"),
            port=app.config.get("SERVER_PORT", 5000),
            debug=app.config["DEBUG"],
        )
    except Exception as e:
        logger.error(f"Failed to start TAS server: {e}")
        raise
    finally:
        # Ensure the KMIP client connection is closed when the application exits
        try:
            kbm_close_client_connection(kbm_client)
            logger.info("KMIP client connection closed.")
        except Exception as e:
            logger.error(f"Error closing KMIP client connection: {e}")
