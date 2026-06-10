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
import datetime
import hashlib
import json
import os
from urllib.parse import unquote

import redis
import sev_pytools as sev
import tdx_pytools as tdx
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, utils
from flask import current_app

try:
    from tas.components.gpu_nvidia import gpu_vm_verify

    GPU_ATTESTATION_AVAILABLE = True
except ImportError:
    GPU_ATTESTATION_AVAILABLE = False

    def gpu_vm_verify(
        gpu_tee_type, gpu_evidence_b64, device_index, expected_nonce=None
    ):
        return (
            False,
            None,
            (
                f"GPU {device_index}: GPU attestation not available "
                "(nvidia_pytools not installed)"
            ),
        )


from tas.policy_helper import is_policy_signed, verify_policy_signature
from tas.tas_logging import get_logger, log_function_entry, log_function_exit

# Setup logging for verification output
logger = get_logger(__name__)


def sev_fetch_certs_from_redis(redis_client: redis.StrictRedis, report):
    """
    Fetches certificates (VCEK, ASK, ARK) from Redis based on the provided TEE evidence.
    This function decodes base64-encoded TEE evidence, parses the SEV-SNP report to extract
    chip ID and reported TCB information, then uses these values to construct a Redis
    key for fetching the corresponding certificates.
    Args:
        redis_client (redis.StrictRedis): Redis client instance for database operations.
        report (sev.AttestationReport): Parsed SEV-SNP attestation report.
    Returns:
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
    log_function_entry("sev_fetch_certs_from_redis")

    # Use the chip_id and reported_tcb to fetch the VCEK from Redis
    # Redis key is structured as "vcek:<chip_id>:<reported_tcb>"
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
            new_crl = sev.fetch.request_crl_kds(
                sev.fetch.ProcType.GENOA, sev.fetch.Endorsement.VCEK
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

    log_function_exit("sev_fetch_certs_from_redis", "certificates and CRL")
    return certs, crl


def sev_save_certs_to_redis(
    redis_client: redis.StrictRedis, report, vcek, ask, ark, crl
):
    """
    Saves the provided certificates (VCEK, ASK, ARK) to Redis based on the TEE evidence.

    Parameters:
        redis_client (redis.StrictRedis): Redis client instance for database operations.
        report (sev.AttestationReport): Parsed SEV-SNP attestation report.
        vcek (bytes): The VCEK certificate to save.
        ask (bytes): The ASK certificate to save.
        ark (bytes): The ARK certificate to save.

    Returns:
        bool: True if saving is successful, False otherwise.
    """
    log_function_entry("sev_save_certs_to_redis")

    # check if the provided certificates are valid
    if not vcek or not ask or not ark:
        logger.error("One or more certificates are invalid or empty")
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
        log_function_exit("sev_save_certs_to_redis", True)
        return True
    else:
        logger.warning(
            f"Failed to save all certificates to Redis with key: {redis_key}"
        )
        logger.warning("It may be that certificates are already present in Redis")
        log_function_exit("sev_save_certs_to_redis", False)
        return False


def tdx_get_collateral_from_redis(
    redis_client: redis.StrictRedis, fmspc: str, update: str
):
    """
    Fetches TDX collateral (certificates and CRLs) from Redis based on FMSPC and update parameters.

    Args:
        redis_client (redis.StrictRedis): Redis client instance for database operations.
        fmspc (str): The FMSPC identifier.
        update (str): The update level (e.g., "standard", "early").

    Returns:
        dict or None: A dictionary containing collateral if found in Redis, None otherwise.

    Notes:
        - The Redis key format is "tdx_collateral:<fmspc>:<update>"
        - Certificates and CRLs are automatically loaded from PEM format
    """
    log_function_entry("tdx_get_collateral_from_redis")

    redis_key = f"tdx_collateral:{fmspc}:{update}"
    logger.info(f"Fetching TDX collateral from Redis with key: {redis_key}")

    collateral_data = redis_client.hgetall(redis_key)

    if not collateral_data:
        logger.info(f"TDX collateral not found in Redis for key: {redis_key}")
        log_function_exit("tdx_get_collateral_from_redis", None)
        return None

    try:
        # Reconstruct collateral dictionary with proper certificate/CRL objects
        collateral = {
            "fmspc": fmspc,
            "update": update,
        }

        # Load certificates and CRLs from PEM format
        if "root_cert" in collateral_data:
            collateral["root_cert"] = x509.load_pem_x509_certificate(
                collateral_data["root_cert"].encode("utf-8")
            )

        if "root_crl" in collateral_data:
            collateral["root_crl"] = x509.load_pem_x509_crl(
                collateral_data["root_crl"].encode("utf-8")
            )

        if "leaf_crl" in collateral_data:
            collateral["leaf_crl"] = x509.load_pem_x509_crl(
                collateral_data["leaf_crl"].encode("utf-8")
            )

        # Load QE identity certificates
        if "qe_identity_certs" in collateral_data:
            collateral["qe_identity_certs"] = x509.load_pem_x509_certificates(
                collateral_data["qe_identity_certs"].encode("utf-8")
            )

        # Load TCB info certificates
        if "tcb_info_certs" in collateral_data:
            collateral["tcb_info_certs"] = x509.load_pem_x509_certificates(
                collateral_data["tcb_info_certs"].encode("utf-8")
            )

        # Load raw data (stored as strings)
        if "qe_identity_raw" in collateral_data:
            collateral["qe_identity_raw"] = collateral_data["qe_identity_raw"]

        if "tcb_info_raw" in collateral_data:
            collateral["tcb_info_raw"] = collateral_data["tcb_info_raw"]

        # Validate that all required items are present
        required_items = [
            "root_cert",
            "root_crl",
            "leaf_crl",
            "qe_identity_raw",
            "qe_identity_certs",
            "tcb_info_raw",
            "tcb_info_certs",
        ]
        missing_items = [item for item in required_items if item not in collateral]
        if missing_items:
            logger.error(
                f"TDX collateral from Redis is missing required items: {missing_items}"
            )
            logger.info("Returning None to force re-fetch from Intel KDS")
            log_function_exit("tdx_get_collateral_from_redis", None)
            return None

        logger.info(f"Successfully loaded TDX collateral from Redis")
        logger.debug(f"Collateral keys loaded: {list(collateral.keys())}")
        log_function_exit("tdx_get_collateral_from_redis", "collateral loaded")
        return collateral

    except Exception as e:
        logger.error(f"Failed to parse TDX collateral from Redis: {e}")
        log_function_exit("tdx_get_collateral_from_redis", None)
        return None


def tdx_save_collateral_to_redis(
    redis_client: redis.StrictRedis, fmspc: str, update: str, collateral: dict
):
    """
    Saves TDX collateral (certificates and CRLs) to Redis.

    Args:
        redis_client (redis.StrictRedis): Redis client instance for database operations.
        fmspc (str): The FMSPC identifier.
        update (str): The update level (e.g., "standard", "early").
        collateral (dict): Dictionary containing collateral data including certificates and CRLs.

    Returns:
        bool: True if saving is successful, False otherwise.

    Notes:
        - Removes any existing collateral for the same FMSPC to prevent stale data
        - Certificates and CRLs are stored in PEM format
        - Sets expiration for collateral to prevent indefinite storage
    """
    log_function_entry("tdx_save_collateral_to_redis")

    if not collateral:
        logger.error("Collateral data is empty or invalid")
        log_function_exit("tdx_save_collateral_to_redis", False)
        return False

    logger.info(
        f"Attempting to save TDX collateral for FMSPC: {fmspc}, update: {update}"
    )

    # Remove existing entries for this FMSPC to prevent stale data
    fmspc_pattern = f"tdx_collateral:{fmspc}:*"
    existing_keys = list(redis_client.scan_iter(match=fmspc_pattern, count=1))
    if existing_keys:
        logger.info(f"Found existing TDX collateral entries for FMSPC, deleting keys")
        redis_client.delete(*existing_keys)

    redis_key = f"tdx_collateral:{fmspc}:{update}"

    try:
        # Prepare data for storage
        storage_data = {}

        # Store certificates in PEM format
        if "root_cert" in collateral:
            storage_data["root_cert"] = collateral["root_cert"].public_bytes(
                serialization.Encoding.PEM
            )

        if "root_crl" in collateral:
            storage_data["root_crl"] = collateral["root_crl"].public_bytes(
                serialization.Encoding.PEM
            )

        if "leaf_crl" in collateral:
            storage_data["leaf_crl"] = collateral["leaf_crl"].public_bytes(
                serialization.Encoding.PEM
            )

        # Store certificate collections
        if "qe_identity_certs" in collateral:
            # Concatenate multiple PEM certificates
            qe_certs_pem = b"".join(
                [
                    cert.public_bytes(serialization.Encoding.PEM)
                    for cert in collateral["qe_identity_certs"]
                ]
            )
            storage_data["qe_identity_certs"] = qe_certs_pem

        if "tcb_info_certs" in collateral:
            # Concatenate multiple PEM certificates
            tcb_certs_pem = b"".join(
                [
                    cert.public_bytes(serialization.Encoding.PEM)
                    for cert in collateral["tcb_info_certs"]
                ]
            )
            storage_data["tcb_info_certs"] = tcb_certs_pem

        # Store raw data as strings
        if "qe_identity_raw" in collateral:
            storage_data["qe_identity_raw"] = collateral["qe_identity_raw"]

        if "tcb_info_raw" in collateral:
            storage_data["tcb_info_raw"] = collateral["tcb_info_raw"]

        # Save to Redis
        logger.debug(
            f"Saving TDX collateral fields to Redis: {list(storage_data.keys())}"
        )
        keys_set = redis_client.hset(redis_key, mapping=storage_data)

        # Set expiration for collateral (48 hours as contains CRLs)
        expire = redis_client.expire(redis_key, 60 * 60 * 24 * 2, nx=True)
        logger.info(f"Set expiration for TDX collateral in Redis to 48 hours: {expire}")

        if keys_set > 0:
            logger.info(
                f"Successfully saved TDX collateral to Redis with key: {redis_key}"
            )
            log_function_exit("tdx_save_collateral_to_redis", True)
            return True
        else:
            logger.warning(
                f"No new fields were set for TDX collateral key: {redis_key}"
            )
            logger.warning("Collateral may already exist in Redis")
            log_function_exit("tdx_save_collateral_to_redis", False)
            return False

    except Exception as e:
        logger.error(f"Failed to save TDX collateral to Redis: {e}")
        log_function_exit("tdx_save_collateral_to_redis", False)
        return False


def get_policy_from_redis(redis_client: redis.StrictRedis, policy_id: str):
    """
    Fetches the policy from Redis based on the policy id.

    Parameters:
        redis_client (redis.StrictRedis): Redis client instance for database operations.
        policy_id (str): The policy ID to fetch from Redis.

    Returns:
        policy (dict): The policy JSON if found and valid
        key_id (str): The key ID to fetch if the policy used for verification is successful.


    Raises:
        ValueError: If policy is not found, invalid JSON, not signed when required, or signature verification fails
    """
    policy_key = f"policy:{policy_id}"
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

    if not is_policy_signed(policy_json):
        # Policy is not signed
        if current_app.config.get("TAS_ENFORCE_SIGNED_POLICIES", True):
            logger.error(f"Policy '{policy_key}' is not signed and signing is required")
            raise ValueError("Policy not signed")
        else:
            logger.warning(f"Policy '{policy_key}' is not signed")
    else:
        if not current_app.config.get("TAS_ENFORCE_SIGNED_POLICIES", True):
            logger.warning(
                f"Policy '{policy_key}' is signed but signature verification is disabled in configuration"
            )
        else:
            # Verify policy signature
            logger.info("Verifying policy signature")

            signature_valid = verify_policy_signature(
                policy_json, current_app.config.get("TAS_TRUSTED_KEYS", [])
            )

            if not signature_valid:
                logger.error(
                    f"Policy signature verification failed for: '{policy_key}'"
                )
                raise ValueError("Policy signature verification failed")
            else:
                logger.info(
                    f"Policy signature verification successful for: '{policy_key}'"
                )
    return policy_json, policy_json.get("metadata", {}).get("key_id")


def sev_vm_verify(
    redis_client: redis.StrictRedis,
    nonce,
    decoded_evidence,
    policy_id,
    expected_report_data=None,
):
    """
    Verifies the decoded evidence for AMD SEV-SNP.

    Parameters:
        redis_client (redis.StrictRedis): Redis client instance for database operations.
        nonce (str): The nonce to verify.
        decoded_evidence (bytes): The decoded TEE evidence.
        policy_id (str): The policy ID to fetch from Redis.
        expected_report_data (bytes, optional): Pre-computed expected report data.
            When provided, used directly for verification instead of encoding
            the nonce. Typically a SHA-512 digest from vm_verify's binding logic.

    Returns:
        is_verified (bool): True if verification is successful, False otherwise.
        key_id (str or None): The key ID to fetch if the policy used for verification is successful, None otherwise.
        verify_error (str or None): An error message if verification fails, None otherwise.
    """
    log_function_entry("sev_vm_verify")
    if not nonce:
        return False, None, "Nonce is invalid"

    if not decoded_evidence:
        return False, None, "Decoded TEE evidence is empty"

    report = sev.AttestationReport.unpack(decoded_evidence)

    # Fetch the VCEK and other certificates from Redis
    certs, crl = sev_fetch_certs_from_redis(redis_client, report)
    if certs is None:
        logger.info("No certificates found in Redis for the provided TEE evidence")
        logger.info("Fetching the certificates from the AMD key server")

        ca_certs = sev.fetch.request_ca_kds(
            sev.fetch.ProcType.GENOA, sev.fetch.Endorsement.VCEK
        )
        ark = ca_certs[1]
        ask = ca_certs[0]

        vcek = sev.fetch.request_vcek_kds(sev.fetch.ProcType.GENOA, report=report)

        crl = sev.fetch.request_crl_kds(
            sev.fetch.ProcType.GENOA, sev.fetch.Endorsement.VCEK
        )

        # Save the fetched VCEK to Redis for future use
        # Don't return an error if the save fails so that verfication can continue
        logger.info("Saving certificates to Redis for future use")
        if not sev_save_certs_to_redis(redis_client, report, vcek, ask, ark, crl):
            logger.warning("Failed to save certificates to Redis")
        else:
            logger.info("Certificates saved to Redis successfully")
        certs = {"vcek": vcek, "ask": ask, "ark": ark}
    else:
        if crl is None:
            logger.warning("CRL not found in Redis, fetching from AMD key server")
            crl = x509.load_pem_x509_certificate(certs["crl"])

    # Fetch policy from Redis
    try:
        policy_json, key_id = get_policy_from_redis(redis_client, policy_id)
    except ValueError as e:
        logger.error(f"Policy fetching failed for: '{policy_id}': {e}")
        return False, None, str(e)

    # Use provided report_data or fall back to nonce
    if expected_report_data is not None:
        report_data = expected_report_data
    else:
        report_data = nonce.encode("utf-8")

    # Verify the TEE evidence
    try:
        policy = sev.AttestationPolicy(policy_json)
        logger.debug("Starting sev_pytools attestation verification")
        verified = sev.verify.verify_attestation_report(
            report,
            certificates=certs,
            crl=crl,
            policy=policy,
            report_data=report_data,
        )
        logger.debug("Completed sev_pytools attestation verification")

        if verified:
            logger.info("AMD SEV-SNP evidence verification successful")
            log_function_exit("sev_vm_verify", "success")
            return True, key_id, None
        else:
            logger.error("AMD SEV-SNP evidence verification failed")
            log_function_exit("sev_vm_verify", "failure")
            return False, None, "Attestation verification failed"

    except Exception as e:
        logger.error(f"Exception during attestation verification: {e}")
        log_function_exit("sev_vm_verify", "error")
        return False, None, f"Verification error: {str(e)}"


def tdx_vm_verify(
    redis_client: redis.StrictRedis,
    nonce,
    decoded_evidence,
    policy_id,
    expected_report_data=None,
):
    """
    Verifies the decoded evidence for Intel TDX.

    Parameters:
        redis_client (redis.StrictRedis): Redis client instance for database operations.
        nonce (str): The nonce to verify.
        decoded_evidence (bytes): The decoded TEE evidence.
        policy_id (str): The policy ID to fetch from Redis.
        expected_report_data (bytes, optional): Pre-computed expected report data.
            When provided, used directly for verification instead of encoding
            the nonce. Typically a SHA-512 digest from vm_verify's binding logic.

    Returns:
        is_verified (bool): True if verification is successful, False otherwise.
        key_id (str or None): The key ID to fetch if the policy used for verification is successful, None otherwise.
        verify_error (str or None): An error message if verification fails, None otherwise.
    """
    log_function_entry("tdx_vm_verify")

    if not nonce:
        return False, None, "Nonce is invalid"

    if not decoded_evidence:
        return False, None, "Decoded TEE evidence is empty"

    quote = tdx.Quote.unpack(decoded_evidence)

    # Fetch policy from Redis
    try:
        policy_json, key_id = get_policy_from_redis(redis_client, policy_id)
    except ValueError as e:
        logger.error(f"Policy fetching failed for: '{policy_id}': {e}")
        return False, None, str(e)
    update = (
        policy_json.get("validation_rules", {}).get("tcb", {}).get("update", "standard")
    )
    policy = tdx.AttestationPolicy(policy_json)

    # Extract FMSPC from quote to fetch collateral
    pck_cert_chain = quote.signature_data.qe_cert_data.pck_cert_chain
    sgx_exts = pck_cert_chain.get_sgx_extensions()
    fmspc_hex = sgx_exts["FMSPC"].hex()
    logger.debug(f"FMSPC: {fmspc_hex}")
    fmspc = tdx.fetch.validate_fmspc(fmspc_hex)

    collateral = tdx_get_collateral_from_redis(redis_client, fmspc, update)
    if collateral is None:
        logger.info("No collateral found in Redis, fetching from Intel KDS")
        # Get cert and CRL materials from Intel KDS
        root_cert = tdx.fetch.request_root_ca_certificate()
        leaf_crl = tdx.fetch.request_pck_crl()
        root_crl = tdx.fetch.request_root_ca_crl(root_cert)
        # Get raw QE response and parse
        qe_identity_raw, qe_certs_string = tdx.fetch.request_qe_identity(update)
        qe_certs_string_decoded = unquote(qe_certs_string)
        qe_certs = x509.load_pem_x509_certificates(qe_certs_string_decoded.encode())
        # Get raw TCB info and parse
        tcb_info_raw, tcb_certs_string = tdx.fetch.request_tcb_info(fmspc, update)
        tcb_certs_string_decoded = unquote(tcb_certs_string)
        tcb_certs = x509.load_pem_x509_certificates(tcb_certs_string_decoded.encode())
        collateral = {
            "root_cert": root_cert,
            "root_crl": root_crl,
            "leaf_crl": leaf_crl,
            "qe_identity_raw": qe_identity_raw,
            "qe_identity_certs": qe_certs,
            "tcb_info_raw": tcb_info_raw,
            "tcb_info_certs": tcb_certs,
            "sgx_extensions": sgx_exts,
            "fmspc": fmspc,
            "update": update,
        }
        tdx_save_collateral_to_redis(redis_client, fmspc, update, collateral)

    collateral["sgx_extensions"] = sgx_exts
    _, tcb_dict, combined_status = tdx.verify.perform_verification_checks(
        quote, collateral
    )
    logger.info(f"TDX combined status: {combined_status}")

    # Use provided report_data or fall back to nonce
    if expected_report_data is not None:
        report_data = expected_report_data
    else:
        report_data = nonce.encode("utf-8")

    try:
        verified = policy.validate_quote(quote, tcb_dict, report_data)
        logger.info("Policy validation successful for TDX quote")
        log_function_exit("tdx_vm_verify", "success")
        return verified, key_id, None
    except Exception as e:
        logger.error(f"Policy validation failed for TDX quote: {e}")
        log_function_exit("tdx_vm_verify", "failure")
        return False, None, "Policy validation failed for TDX quote"
    return False, None, None


def vm_verify(
    redis_client,
    nonce,
    tee_type,
    tee_evidence,
    policy_id,
    wrapping_key=None,
    report_data_binding=False,
    gpu_list=None,
):
    """
    Verifies the provided nonce, TEE type, and TEE evidence, with optional
    wrapping key binding and GPU attestation.

    Parameters:
        redis_client (redis.StrictRedis): Redis client instance for database operations.
        nonce (str): The nonce to verify.
        tee_type (str): The type of TEE (e.g., "amd-sev-snp", "intel-tdx").
        tee_evidence (str): Base64-encoded TEE evidence.
        policy_id (str): The policy ID to fetch from Redis.
        wrapping_key (bytes, optional): The wrapping key for report data binding.
        report_data_binding (bool, optional): When True (and wrapping_key is provided),
            the expected report_data is computed as SHA-512(nonce || wrapping_key
            [|| SHA-512(gpu0_evidence) || SHA-512(gpu1_evidence) || ...])
            instead of using the raw nonce. Must be provided
            in the request; cannot be None.
        gpu_list (list, optional): List of per-GPU attestation evidence dicts,
            each containing:
                - "type"      (str): GPU TEE type (e.g., "gpu-nvidia").
                - "evidence"  (str): Base64-encoded GPU attestation evidence.
                - "device-index"  (int): GPU device index (used for ordering).
            When present and report_data_binding is True, each GPU is verified
            independently via gpu_vm_verify and its SHA-512 evidence hash is
            appended to the report_data binding computation.

    Returns:
        is_verified (bool): True if verification is successful, False otherwise.
        key_id (str or None): The key ID to fetch if the policy used for verification is successful, None otherwise.
        verify_error (str or None): An error message if verification fails, None otherwise.
    """
    log_function_entry("vm_verify", nonce="***", tee_type=tee_type)

    if not nonce:
        logger.error("Nonce is invalid")
        return False, None, "Nonce is invalid"

    if tee_type not in ["amd-sev-snp", "intel-tdx"]:
        logger.error(f"Invalid TEE type: {tee_type}")
        return False, None, "TEE type is invalid"

    try:
        decoded_evidence = base64.b64decode(tee_evidence)
    except Exception as e:
        logger.error(f"Failed to decode TEE evidence: {e}")
        return False, None, "TEE evidence is invalid"

    if not decoded_evidence:
        logger.error("Decoded TEE evidence is empty")
        return False, None, "Decoded TEE evidence is empty"

    # --- Compute expected report_data ---
    if report_data_binding and wrapping_key:
        # Recompute the same SHA-512 binding the agent used
        hash_input = nonce.encode("utf-8") + wrapping_key

        # Include per-GPU evidence hashes
        if gpu_list:
            if len(gpu_list) > 16:
                logger.error(f"Too many GPU evidence entries: {len(gpu_list)}")
                return False, None, "Too many GPU evidence entries (max 16)"

            gpu_list_sorted = sorted(gpu_list, key=lambda e: e["device-index"])

            # Verify each GPU and build hash chain in a single pass
            gpu_hashes = []
            for gpu_entry in gpu_list_sorted:
                gpu_ok, _, gpu_err = gpu_vm_verify(
                    gpu_entry.get("type", "unknown"),
                    gpu_entry.get("evidence", ""),
                    gpu_entry.get("device-index", -1),
                    expected_nonce=nonce,
                )
                if not gpu_ok:
                    return False, None, gpu_err

                # Hash the inner raw evidence (the binary GPU attestation report).
                # Decode outer base64 → JSON envelope → decode inner "evidence" → raw bytes.
                gpu_envelope_raw = base64.b64decode(gpu_entry["evidence"])
                gpu_envelope = json.loads(gpu_envelope_raw)
                inner_evidence_raw = base64.b64decode(gpu_envelope["evidence"])
                gpu_hashes.append(hashlib.sha512(inner_evidence_raw).digest())

            # Append SHA-512 hashes: SHA512(gpu0_raw) || SHA512(gpu1_raw) || ...
            for h in gpu_hashes:
                hash_input += h

        expected_report_data = hashlib.sha512(hash_input).digest()  # 64 bytes
    else:
        expected_report_data = nonce.encode("utf-8")

    logger.info(f"Verifying evidence for TEE type: {tee_type}")

    if tee_type == "amd-sev-snp":
        result = sev_vm_verify(
            redis_client,
            nonce,
            decoded_evidence,
            policy_id,
            expected_report_data=expected_report_data,
        )
    elif tee_type == "intel-tdx":
        result = tdx_vm_verify(
            redis_client,
            nonce,
            decoded_evidence,
            policy_id,
            expected_report_data=expected_report_data,
        )
    else:
        logger.error(f"Unsupported TEE type: {tee_type}")
        return False, None, "Unsupported TEE type"

    log_function_exit("vm_verify", result)
    return result
