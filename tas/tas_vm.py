#
# TEE Attestation Service - Verification Module
#
# Copyright 2025 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# This file is part of the TEE Attestation Service.
#
# This module is responsible for verifying the TEE evidence.
#

import base64
import json
import os

import redis
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from flask import current_app
from sev_pytools import AttestationPolicy, AttestationReport, fetch, verify

from tas.policy_helper import verify_policy_signature
from tas.tas_logging import get_logger, log_function_entry, log_function_exit

# Setup logging for verification output
logger = get_logger(__name__)


def fetch_certs_from_redis(redis_client: redis.StrictRedis, decoded_evidence):
    """
    Fetches certificates (VCEK, ASK, ARK) from Redis based on the provided TEE evidence.
    This function decodes base64-encoded TEE evidence, parses the SEV-SNP report to extract
    chip ID and reported TCB information, then uses these values to construct a Redis
    key for fetching the corresponding certificates.
        redis_client (redis.StrictRedis): Redis client instance for database operations.
        tee_evidence (str): Base64-encoded TEE (Trusted Execution Environment) evidence
                           containing SEV-SNP report data.
        list or None: A list containing three certificate strings [vcek, ask, ark] if
                     all certificates are found in Redis, None otherwise.
    Raises:
        Does not raise exceptions directly, but catches and logs various exceptions:
        - SEV-SNP report parsing errors
    Notes:
        - The Redis key format is "certs:<chip_id>:<reported_tcb>"
        - All three certificates (VCEK, ASK, ARK) must be present for a successful return
        - Error messages are logged
    """
    log_function_entry("fetch_certs_from_redis")

    # parse the decoded evidence and extract the necessary information
    try:
        report = AttestationReport.unpack(decoded_evidence)
    except Exception as e:
        logger.error(f"Failed to parse SEV-SNP report: {e}")
        return None, None

    # Use the chip_id and reported_tcb to fetch the VCEK from Redis
    # Assuming the Redis key is structured as "vcek:<chip_id>:<reported_tcb>"
    redis_key = f"certs:{report.chip_id}:{report.reported_tcb}"
    logger.info(f"Fetching certificates from Redis")
    certs = redis_client.hgetall(redis_key)
    # Check for at least 3 certs, we don't mind if the CRL has expired.
    if len(certs) < 3:
        logger.info(f"Certificates not found in Redis for key: {redis_key}")
        return None, None
    crl = None
    if "crl" in certs:
        crl = x509.load_pem_x509_crl(certs.pop("crl").encode("utf-8"))

    for key in certs:
        certs[key] = x509.load_pem_x509_certificate(certs[key].encode("utf-8"))

    redis_key_crl = f"crl:{report.chip_id}:{report.reported_tcb}"
    redis_crl = redis_client.hget(redis_key_crl, "crl")
    if redis_crl is None:
        try:
            logger.info("CRL has expired, attempting to refresh and store in Redis")
            new_crl = fetch.request_crl_kds(
                fetch.ProcType.GENOA, fetch.Endorsement.VCEK
            )
            _ = redis_client.hset(
                redis_key_crl,
                mapping={
                    "crl": crl.public_bytes(serialization.Encoding.PEM),
                },
            )
            expire = redis_client.expire(
                redis_key_crl, 60 * 60 * 24 * 2, nx=True
            )  # Set expiration of crl key to 48 hours
            logger.info(f"Set expiration for CRL in Redis to 48 hours: {expire}")
            crl = new_crl
        except Exception as e:
            logger.warning(
                f"WARNING: Using a CRL older than 48 hours due to error: {e}"
            )
    else:
        crl = x509.load_pem_x509_crl(redis_crl.encode("utf-8"))

    log_function_exit("fetch_certs_from_redis", "certificates and CRL")
    return certs, crl


def save_certs_to_redis(
    redis_client: redis.StrictRedis, decoded_evidence, vcek, ask, ark, crl
):
    """
    Saves the provided certificates (VCEK, ASK, ARK) to Redis based on the TEE evidence.

    Parameters:
        redis_client (redis.StrictRedis): Redis client instance for database operations.
        tee_evidence (bytes): TEE evidence containing SEV-SNP report data.
        vcek (bytes): The VCEK certificate to save.
        ask (bytes): The ASK certificate to save.
        ark (bytes): The ARK certificate to save.

    Returns:
        bool: True if saving is successful, False otherwise.
    """
    log_function_entry("save_certs_to_redis")

    # check if the provided certificates are valid
    if not vcek or not ask or not ark:
        logger.error("One or more certificates are invalid or empty")
        return False
    if not decoded_evidence:
        logger.error("TEE evidence is empty")
        return False

    # Parse the decoded evidence and extract chip_id and reported_tcb
    try:
        report = AttestationReport.unpack(decoded_evidence)
    except Exception as e:
        logger.error(f"Failed to parse SEV-SNP report: {e}")
        return False

    chip_id = report.chip_id
    reported_tcb = report.reported_tcb

    logger.info(
        f"Attempting to save certificates for chip_id: {chip_id}, reported_tcb: {reported_tcb}"
    )
    logger.debug("Checking for existing entries for the chip_id")
    # Check if any entry exists for this chip_id in Redis
    # and delete them if they exist
    # We need to remove any exiting entries for this chip_id
    # to stop tee reports with old reported_tcb from
    # passing verification in the future.
    # Use a pattern to match all keys for the given chip_id
    # This assumes the keys are structured as "certs:<chip_id>:*"
    # where * can be any reported_tcb or other suffixes
    # This will return a list of keys matching the pattern
    # and we will delete them to avoid stale entries
    # Note: scan_iter is used to avoid blocking the Redis server
    chip_pattern = f"certs:{chip_id}:*"
    existing_keys = list(redis_client.scan_iter(match=chip_pattern, count=1))
    if existing_keys:
        logger.info(f"Found existing entries for chip_id, deleting keys")
        # Delete all existing keys for this chip_id
        redis_client.delete(*existing_keys)

    # Save the certificates to Redis
    redis_key = f"certs:{chip_id}:{reported_tcb}"
    keys = redis_client.hset(
        redis_key,
        mapping={
            "vcek": vcek.public_bytes(serialization.Encoding.PEM),
            "ask": ask.public_bytes(serialization.Encoding.PEM),
            "ark": ark.public_bytes(serialization.Encoding.PEM),
            "crl": crl.public_bytes(serialization.Encoding.PEM),
        },
    )

    redis_key_crl = f"crl:{chip_id}:{reported_tcb}"
    _ = redis_client.hset(
        redis_key_crl,
        mapping={
            "crl": crl.public_bytes(serialization.Encoding.PEM),
        },
    )
    expire = redis_client.expire(
        redis_key_crl, 60 * 60 * 24 * 2, nx=True
    )  # Set expiration of crl key to 48 hours
    logger.info(f"Set expiration for CRL in Redis to 48 hours: {expire}")

    if keys == 4:
        # Successfully saved all four certificates
        # This requires redis version 7.4.0 or later. For the moment we will not expire the CRL and instead expire the whole key
        # expire = redis_client.hexpire(redis_key, 60 * 60 * 24 * 2, "crl", nx=True)  # Set expiration of crl to 48 hours
        # logger.info(f"Set expiration for CRL in Redis to 48 hours: {expire}")
        log_function_exit("save_certs_to_redis", True)
        return True
    else:
        logger.warning(
            f"Failed to save all certificates to Redis with key: {redis_key}"
        )
        logger.warning("It may be that certificates are already present in Redis")
        log_function_exit("save_certs_to_redis", False)
        return False


def get_policy_from_redis(redis_client: redis.StrictRedis, policy_key: str):
    """
    Fetches the policy from Redis based on the policy key.

    Parameters:
        redis_client (redis.StrictRedis): Redis client instance for database operations.
        policy_key (str): The Redis key for the policy to fetch.

    Returns:
        dict: The policy JSON if found and valid

    Raises:
        ValueError: If policy is not found, invalid JSON, not signed when required, or signature verification fails
    """
    logger.info(f"Fetching policy from Redis with key: {policy_key}")
    policy_json_str = redis_client.get(policy_key)
    if not policy_json_str:
        logger.error(f"Policy '{policy_key}' not found in Redis")
        raise ValueError("Policy not found")

    try:
        policy_json = json.loads(policy_json_str)
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse policy JSON: {e}")
        raise ValueError("Invalid policy format")

    if not policy_json.get("signature"):
        # Policy is not signed
        if current_app.config.get("TAS_POLICY_REQUIRE_SIGNED", True):
            logger.error(f"Policy '{policy_key}' is not signed and signing is required")
            raise ValueError("Policy not signed")
        else:
            logger.warning(f"WARNING: Policy '{policy_key}' is not signed")
    else:
        # Verify policy signature
        logger.info("Verifying policy signature")

        signature_valid = verify_policy_signature(
            policy_json, current_app.config.get("TAS_TRUSTED_KEYS", [])
        )

        if not signature_valid:
            logger.error(
                f"Policy signature verification failed for policy '{policy_key}'"
            )
            raise ValueError("Policy signature verification failed")
        else:
            logger.info(
                f"Policy signature verification successful for policy '{policy_key}'"
            )
    return policy_json


def vm_verify_sev(redis_client: redis.StrictRedis, nonce, decoded_evidence):
    """
    Verifies the decoded evidence for AMD SEV-SNP.

    Parameters:
        nonce (str): The nonce to verify.
        decoded_evidence (bytes): The decoded TEE evidence.

    Returns:
        bool: True if verification is successful, False otherwise.
        str: An error message if verification fails, None otherwise.
    """
    log_function_entry("vm_verify_sev")

    if not nonce:
        return False, "Nonce is invalid"

    if not decoded_evidence:
        return False, "Decoded TEE evidence is empty"

    report = AttestationReport.unpack(decoded_evidence)

    # Fetch the VCEK and other certificates from Redis
    certs, crl = fetch_certs_from_redis(redis_client, decoded_evidence)
    if certs is None:
        logger.info("No certificates found in Redis for the provided TEE evidence")
        logger.info("Fetching the certificates from the AMD key server")

        ca_certs = fetch.request_ca_kds(fetch.ProcType.GENOA, fetch.Endorsement.VCEK)
        ark = ca_certs[1]
        ask = ca_certs[0]

        vcek = fetch.request_vcek_kds(fetch.ProcType.GENOA, report=report)

        crl = fetch.request_crl_kds(fetch.ProcType.GENOA, fetch.Endorsement.VCEK)

        # Save the fetched VCEK to Redis for future use
        # Don't return an error if the save fails so that verfication can continue
        logger.info("Saving certificates to Redis for future use")
        if not save_certs_to_redis(redis_client, decoded_evidence, vcek, ask, ark, crl):
            logger.warning("Failed to save certificates to Redis")
        else:
            logger.info("Certificates saved to Redis successfully")
        certs = {"vcek": vcek, "ask": ask, "ark": ark}
    else:
        if crl is None:
            logger.warning("CRL not found in Redis, fetching from AMD key server")
            crl = x509.load_pem_x509_certificate(certs["crl"])

    # Fetch policy from Redis
    policy_key = f"policy:SEV:{report.measurement.hex()}"

    try:
        policy_json = get_policy_from_redis(redis_client, policy_key)
    except ValueError as e:
        logger.error(f"Policy validation failed: {e}")
        return False, str(e)

    # Verify the TEE evidence
    try:
        policy = AttestationPolicy(policy_json)
        logger.debug("Starting sev_pytools attestation verification")
        verified = verify.verify_attestation_report(
            report,
            certificates=certs,
            crl=crl,
            policy=policy,
            report_data=nonce.encode("utf-8"),
        )
        logger.debug("Completed sev_pytools attestation verification")

        if verified:
            logger.info("AMD SEV-SNP evidence verification successful")
            log_function_exit("vm_verify_sev", "success")
            return True, None
        else:
            logger.error("AMD SEV-SNP evidence verification failed")
            return False, "Attestation verification failed"

    except Exception as e:
        logger.error(f"Exception during attestation verification: {e}")
        return False, f"Verification error: {str(e)}"


def vm_verify_tdx(nonce, decoded_evidence):
    """
    Verifies the decoded evidence for Intel TDX.

    Parameters:
        nonce (str): The nonce to verify.
        decoded_evidence (bytes): The decoded TEE evidence.

    Returns:
        bool: True if verification is successful, False otherwise.
        str: An error message if verification fails, None otherwise.
    """
    log_function_entry("vm_verify_tdx")
    # TODO: Implement actual TDX verification
    logger.info("TDX evidence verification not performed (placeholder implementation)")
    log_function_exit("vm_verify_tdx", "success")
    return False, None


def vm_verify(redis_client, nonce, tee_type, tee_evidence):
    """
    Verifies the provided nonce, TEE type, and TEE evidence.

    Parameters:
        nonce (str): The nonce to verify.
        tee_type (str): The type of TEE (e.g., "amd-sev-snp", "intel-tdx").
        tee_evidence (str): Base64-encoded TEE evidence.

    Returns:
        bool: True if verification is successful, False otherwise.
        str: An error message if verification fails, None otherwise.
    """
    log_function_entry("vm_verify", nonce="***", tee_type=tee_type)

    # Example verification logic (replace with actual verification logic)
    if not nonce:
        logger.error("Nonce is invalid")
        return False, "Nonce is invalid"

    if tee_type not in ["amd-sev-snp", "intel-tdx"]:
        logger.error(f"Invalid TEE type: {tee_type}")
        return False, "TEE type is invalid"

    try:
        # Decode the base64-encoded TEE evidence
        decoded_evidence = base64.b64decode(tee_evidence)
    except Exception as e:
        logger.error(f"Failed to decode TEE evidence: {e}")
        return False, "TEE evidence is invalid"

    # Check if the decoded evidence is non-empty
    if not decoded_evidence:
        logger.error("Decoded TEE evidence is empty")
        return False, "Decoded TEE evidence is empty"

    logger.info(f"Verifying evidence for TEE type: {tee_type}")

    # Call the appropriate verification function based on tee_type
    if tee_type == "amd-sev-snp":
        result = vm_verify_sev(redis_client, nonce, decoded_evidence)
    elif tee_type == "intel-tdx":
        result = vm_verify_tdx(nonce, decoded_evidence)
    else:
        logger.error(f"Unsupported TEE type: {tee_type}")
        return False, "Unsupported TEE type"

    log_function_exit("vm_verify", result)
    return result
