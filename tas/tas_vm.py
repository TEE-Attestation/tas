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
    from tas.components.gpu_nvidia import (
        gpu_get_collateral_refs,
        gpu_new_collateral,
        gpu_validate_claims,
        gpu_vm_verify,
    )

    GPU_ATTESTATION_AVAILABLE = True
except ImportError:
    GPU_ATTESTATION_AVAILABLE = False

    def gpu_vm_verify(
        gpu_tee_type,
        gpu_evidence_b64,
        device_index,
        expected_nonce=None,
        gpu_policy=None,
        mode="remote",
        collateral=None,
    ):
        return (
            False,
            None,
            (
                f"GPU {device_index}: GPU attestation not available "
                "(nvidia_pytools not installed)"
            ),
        )

    def gpu_get_collateral_refs(gpu_evidence_b64, device_index=0):
        return None

    def gpu_new_collateral(rims=None):
        return None

    def gpu_validate_claims(gpu_policy, claims, device_index=0):
        return (
            False,
            (
                f"GPU {device_index}: GPU attestation not available "
                "(nvidia_pytools not installed)"
            ),
        )


from tas.policy_helper import is_policy_signed, verify_policy_signature
from tas.tas_logging import get_logger, log_function_entry, log_function_exit

# Setup logging for verification output
logger = get_logger(__name__)

# Maps a request TEE type to the certify-policy ``metadata.policy_type`` value it
# must carry. Keeps AMD and Intel certify-policies from being evaluated against
# each other's evidence in the certify flow.
POLICY_TYPE_BY_TEE = {"amd-sev-snp": "SEV", "intel-tdx": "TDX"}
SUPPORTED_TEE_TYPES = frozenset(POLICY_TYPE_BY_TEE)


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
    if redis_crl is not None:
        crl = x509.load_pem_x509_crl(redis_crl.encode("utf-8"))

    # Refresh the CRL if the short-lived TTL key has expired or the cached CRL
    # is past its next_update, otherwise an expired CRL would fail verification.
    now = datetime.datetime.now(datetime.timezone.utc)
    crl_expired = crl is None or (
        crl.next_update_utc is not None and now > crl.next_update_utc
    )
    if redis_crl is None or crl_expired:
        try:
            logger.info("CRL has expired, attempting to refresh and store in Redis")
            new_crl = sev.fetch.request_crl_kds(
                sev.fetch.ProcType.GENOA, sev.fetch.Endorsement.VCEK
            )
            _ = redis_client.hset(
                redis_key_crl,
                mapping={
                    "crl": new_crl.public_bytes(serialization.Encoding.PEM),
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

        # Force a re-fetch if either cached CRL is past its next_update,
        # otherwise an expired CRL would fail verification instead of refreshing.
        now = datetime.datetime.now(datetime.timezone.utc)
        for crl_name in ("root_crl", "leaf_crl"):
            crl = collateral[crl_name]
            if crl.next_update_utc is not None and now > crl.next_update_utc:
                logger.info(
                    f"Cached TDX {crl_name} is expired (next update was "
                    f"{crl.next_update_utc}); returning None to force re-fetch "
                    "from Intel KDS"
                )
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


def gpu_get_rims_from_redis(redis_client: redis.StrictRedis, rim_ids):
    """
    Fetches cached NVIDIA RIM collateral from Redis.

    Args:
        redis_client (redis.StrictRedis): Redis client instance for database operations.
        rim_ids (Iterable[str]): RIM IDs to look up (e.g. driver and VBIOS RIM IDs).

    Returns:
        dict: Mapping of rim_id -> raw RIM XML bytes for those present in the cache.

    Notes:
        - The Redis key format is "gpu_rim:<rim_id>" with hash field "rim"
          holding the base64-encoded RIM XML.
        - RIM content is immutable for a given driver/VBIOS version, so a cache
          hit can be reused directly; the verifier re-checks its signature and
          certificate chain on every use.
    """
    log_function_entry("gpu_get_rims_from_redis")

    rims = {}
    for rim_id in rim_ids:
        data = redis_client.hget(f"gpu_rim:{rim_id}", "rim")
        if data:
            try:
                rims[rim_id] = base64.b64decode(data)
            except Exception as e:
                logger.warning(f"Failed to decode cached RIM {rim_id}: {e}")

    logger.info(f"Loaded {len(rims)} RIM(s) from Redis cache")
    log_function_exit("gpu_get_rims_from_redis", f"{len(rims)} rims")
    return rims


def gpu_save_rims_to_redis(redis_client: redis.StrictRedis, rims):
    """
    Saves NVIDIA RIM collateral to Redis for reuse by future attestations.

    Args:
        redis_client (redis.StrictRedis): Redis client instance for database operations.
        rims (dict): Mapping of rim_id -> raw RIM XML bytes to store.

    Returns:
        bool: True if all RIMs were saved without error, False otherwise.

    Notes:
        - The Redis key format is "gpu_rim:<rim_id>" with hash field "rim".
        - A 48h TTL bounds how long unused RIM entries persist.
    """
    log_function_entry("gpu_save_rims_to_redis")

    ok = True
    for rim_id, xml_bytes in rims.items():
        redis_key = f"gpu_rim:{rim_id}"
        try:
            redis_client.hset(
                redis_key,
                mapping={"rim": base64.b64encode(xml_bytes)},
            )
            # Set expiration to 48 hours (only if not already set)
            redis_client.expire(redis_key, 60 * 60 * 24 * 2, nx=True)
        except Exception as e:
            logger.warning(f"Failed to save RIM {rim_id} to Redis: {e}")
            ok = False

    logger.info(f"Saved {len(rims)} RIM(s) to Redis cache")
    log_function_exit("gpu_save_rims_to_redis", ok)
    return ok


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
    policy_json = _load_signed_object(redis_client, f"policy:{policy_id}", "Policy")
    return policy_json, policy_json.get("metadata", {}).get("key_id")


def _load_signed_object(redis_client: redis.StrictRedis, redis_key: str, kind: str):
    """Fetch, JSON-parse, and signature-verify a signed object from Redis.

    Applies the same signing enforcement as :func:`get_policy_from_redis`
    (``TAS_ENFORCE_SIGNED_POLICIES`` + ``TAS_TRUSTED_KEYS``). Used by the
    certify flow's separate domain-policy and certify-policy stores.

    Args:
        redis_client: Redis client instance.
        redis_key: Fully-qualified Redis key to load.
        kind: Human-readable object kind used in log and error messages.

    Raises:
        ValueError: If the object is missing, invalid JSON, unsigned when
            signing is required, or fails signature verification.
    """
    logger.info(f"Fetching {kind.lower()} from Redis with key: {redis_key}")
    raw = redis_client.get(redis_key)
    if not raw:
        logger.error(f"{kind} '{redis_key}' not found in Redis")
        raise ValueError(f"{kind} not found")

    try:
        obj = json.loads(raw)
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse {kind.lower()} JSON: {e}")
        raise ValueError(f"Invalid {kind.lower()} format")

    enforce = current_app.config.get("TAS_ENFORCE_SIGNED_POLICIES", True)
    if not is_policy_signed(obj):
        if enforce:
            logger.error(f"{kind} '{redis_key}' is not signed and signing is required")
            raise ValueError(f"{kind} not signed")
        logger.warning(f"{kind} '{redis_key}' is not signed")
    elif not enforce:
        logger.warning(
            f"{kind} '{redis_key}' is signed but signature verification is "
            "disabled in configuration"
        )
    else:
        logger.info(f"Verifying {kind.lower()} signature")
        if not verify_policy_signature(
            obj, current_app.config.get("TAS_TRUSTED_KEYS", [])
        ):
            logger.error(f"{kind} signature verification failed for: '{redis_key}'")
            raise ValueError(f"{kind} signature verification failed")
        logger.info(f"{kind} signature verification successful for: '{redis_key}'")

    return obj


def get_domain_policy_from_redis(redis_client: redis.StrictRedis, policy_id: str):
    """Fetch and signature-verify a domain-policy by id.

    Domain-policies live in the ``domain-policy:{id}`` keyspace, separate
    from the secret-release ``policy:*`` store.

    Returns:
        dict: The domain-policy JSON.

    Raises:
        ValueError: If missing, invalid, unsigned when required, or the
            signature fails verification.
    """
    return _load_signed_object(
        redis_client, f"domain-policy:{policy_id}", "Domain policy"
    )


def get_certify_policy_from_redis(redis_client: redis.StrictRedis, policy_id: str):
    """Fetch and signature-verify a certify-policy by id.

    Certify-policies share the structure of secret-release policies but live in
    the separate ``certify-policy:{id}`` keyspace and are only used by the
    certify flow.

    Returns:
        tuple[dict, str | None]: The certify-policy JSON and its metadata key_id.

    Raises:
        ValueError: If missing, invalid, unsigned when required, or the
            signature fails verification.
    """
    policy_json = _load_signed_object(
        redis_client, f"certify-policy:{policy_id}", "Certify policy"
    )
    return policy_json, policy_json.get("metadata", {}).get("key_id")


def sev_vm_verify(
    redis_client: redis.StrictRedis,
    nonce,
    decoded_evidence,
    policy_json,
    expected_report_data=None,
):
    """
    Verifies the decoded evidence for AMD SEV-SNP.

    Parameters:
        redis_client (redis.StrictRedis): Redis client instance for database operations.
        nonce (str): The nonce to verify.
        decoded_evidence (bytes): The decoded TEE evidence.
        policy_json (dict): The policy JSON, already fetched and verified by the caller.
        expected_report_data (bytes, optional): Pre-computed expected report data.
            When provided, used directly for verification instead of encoding
            the nonce. Typically a SHA-512 digest from vm_verify's binding logic.

    Returns:
        is_verified (bool): True if verification is successful, False otherwise.
        verify_error (str or None): An error message if verification fails, None otherwise.
    """
    log_function_entry("sev_vm_verify")
    if not nonce:
        return False, "Nonce is invalid"

    if not decoded_evidence:
        return False, "Decoded TEE evidence is empty"

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
            return True, None
        else:
            logger.error("AMD SEV-SNP evidence verification failed")
            log_function_exit("sev_vm_verify", "failure")
            return False, "Attestation verification failed"

    except Exception as e:
        logger.error(f"Exception during attestation verification: {e}")
        log_function_exit("sev_vm_verify", "error")
        return False, f"Verification error: {str(e)}"


def tdx_vm_verify(
    redis_client: redis.StrictRedis,
    nonce,
    decoded_evidence,
    policy_json,
    expected_report_data=None,
):
    """
    Verifies the decoded evidence for Intel TDX.

    Parameters:
        redis_client (redis.StrictRedis): Redis client instance for database operations.
        nonce (str): The nonce to verify.
        decoded_evidence (bytes): The decoded TEE evidence.
        policy_json (dict): The policy JSON, already fetched and verified by the caller.
        expected_report_data (bytes, optional): Pre-computed expected report data.
            When provided, used directly for verification instead of encoding
            the nonce. Typically a SHA-512 digest from vm_verify's binding logic.

    Returns:
        is_verified (bool): True if verification is successful, False otherwise.
        verify_error (str or None): An error message if verification fails, None otherwise.
    """
    log_function_entry("tdx_vm_verify")

    if not nonce:
        return False, "Nonce is invalid"

    if not decoded_evidence:
        return False, "Decoded TEE evidence is empty"

    quote = tdx.Quote.unpack(decoded_evidence)

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
        return verified, None
    except Exception as e:
        logger.error(f"Policy validation failed for TDX quote: {e}")
        log_function_exit("tdx_vm_verify", "failure")
        return False, "Policy validation failed for TDX quote"


def _validate_attestation_inputs(nonce, tee_type, tee_evidence):
    """
    Validate the nonce, TEE type and evidence shared by all verification paths.

    Returns:
        (error, decoded_evidence): ``error`` is None when the inputs are valid,
        in which case ``decoded_evidence`` holds the base64-decoded evidence;
        otherwise ``error`` is the message and ``decoded_evidence`` is None.
    """
    if not nonce:
        logger.error("Nonce is invalid")
        return "Nonce is invalid", None

    if tee_type not in ["amd-sev-snp", "intel-tdx"]:
        logger.error(f"Invalid TEE type: {tee_type}")
        return "TEE type is invalid", None

    try:
        decoded_evidence = base64.b64decode(tee_evidence)
    except Exception as e:
        logger.error(f"Failed to decode TEE evidence: {e}")
        return "TEE evidence is invalid", None

    if not decoded_evidence:
        logger.error("Decoded TEE evidence is empty")
        return "Decoded TEE evidence is empty", None

    return None, decoded_evidence


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
    Fetches the verification policy by ID from Redis, then delegates the
    attestation checks to verify.

    Parameters:
        policy_id (str): The policy ID to fetch from Redis. All other
            parameters are passed through unchanged to :func:`verify`.

    Returns:
        is_verified (bool): True if verification is successful, False otherwise.
        key_id (str or None): The key ID to fetch if the policy used for verification is successful, None otherwise.
        verify_error (str or None): An error message if verification fails, None otherwise.
    """
    log_function_entry("vm_verify", nonce="***", tee_type=tee_type)

    input_error, _ = _validate_attestation_inputs(nonce, tee_type, tee_evidence)
    if input_error:
        return False, None, input_error

    try:
        policy_json, key_id = get_policy_from_redis(redis_client, policy_id)
    except ValueError as e:
        logger.error(f"Policy fetching failed for: '{policy_id}': {e}")
        return False, None, str(e)

    verified, verify_error = verify(
        redis_client,
        nonce,
        tee_type,
        tee_evidence,
        policy_json,
        wrapping_key=wrapping_key,
        report_data_binding=report_data_binding,
        gpu_list=gpu_list,
    )
    result = (verified, key_id if verified else None, verify_error)
    log_function_exit("vm_verify", result)
    return result


def _resolve_gpu_verification_mode():
    """
    Return the service-wide GPU verification mode ("local" or "remote").

    Falls back to "remote" when there is no active application context (e.g.
    when verification is exercised directly in unit tests).
    """
    try:
        return current_app.config.get("TAS_NVIDIA_GPU_VERIFICATION_MODE", "remote")
    except RuntimeError:
        return "remote"


def _verify_gpu_evidence_list(redis_client, gpu_list, nonce):
    """
    Verify every GPU's attestation evidence once, independent of any policy.

    The evidence checks (signature, certificate chain, RIM measurements, nonce
    freshness) do not depend on a certify-policy, so in the certify/domain flow
    they are run a single time and the extracted claims are reused when each
    candidate certify-policy's GPU claims are evaluated (see
    :func:`_apply_gpu_claims_policy`).

    Returns:
        (ok, error, results): On success ``results`` is a list of per-GPU dicts
        sorted by device-index, each with ``device_index``, ``type``, ``claims``
        and ``evidence_hash`` (SHA-512 of the inner raw evidence). On failure
        ``ok`` is False, ``error`` is set and ``results`` is None.
    """
    if len(gpu_list) > 16:
        logger.error(f"Too many GPU evidence entries: {len(gpu_list)}")
        return False, "Too many GPU evidence entries (max 16)", None

    gpu_mode = _resolve_gpu_verification_mode()
    gpu_list_sorted = sorted(gpu_list, key=lambda e: e["device-index"])

    results = []
    for gpu_entry in gpu_list_sorted:
        # GPU policy is keyed by device type (e.g. "gpu-nvidia")
        gpu_type = gpu_entry.get("type", "gpu-nvidia")
        gpu_evidence = gpu_entry.get("evidence", "")
        gpu_device_index = gpu_entry.get("device-index", -1)

        # In local mode, pre-fetch cached RIM collateral from Redis so the
        # verifier only downloads from NVIDIA what is missing. The report is
        # parsed just enough (via nvidia_pytools) to derive the RIM IDs.
        gpu_collateral = None
        cached_rim_ids = set()
        if gpu_mode == "local":
            try:
                refs = gpu_get_collateral_refs(gpu_evidence, gpu_device_index)
                if refs is not None:
                    cached_rims = gpu_get_rims_from_redis(
                        redis_client,
                        [refs.driver_rim_id, refs.vbios_rim_id],
                    )
                    cached_rim_ids = set(cached_rims.keys())
                    gpu_collateral = gpu_new_collateral(cached_rims)
            except Exception as e:
                logger.warning(
                    f"GPU {gpu_device_index}: RIM collateral pre-fetch skipped: {e}"
                )

        # Verify evidence only; per-policy claims are applied by the caller so
        # that a domain-policy's members do not each repeat this expensive work.
        gpu_ok, claims, gpu_err = gpu_vm_verify(
            gpu_type,
            gpu_evidence,
            gpu_device_index,
            expected_nonce=nonce,
            gpu_policy=None,
            mode=gpu_mode,
            collateral=gpu_collateral,
        )
        if not gpu_ok:
            return False, gpu_err, None

        # Persist any RIMs the verifier had to fetch (i.e. cache misses) so
        # future attestations on the same driver/VBIOS reuse them.
        if gpu_mode == "local" and gpu_collateral is not None:
            new_rims = {
                rid: xml
                for rid, xml in gpu_collateral.rims.items()
                if rid not in cached_rim_ids
            }
            if new_rims:
                gpu_save_rims_to_redis(redis_client, new_rims)

        # Hash the inner raw evidence (the binary GPU attestation report).
        # Decode outer base64 → JSON envelope → decode inner "evidence" → raw bytes.
        gpu_envelope_raw = base64.b64decode(gpu_entry["evidence"])
        gpu_envelope = json.loads(gpu_envelope_raw)
        inner_evidence_raw = base64.b64decode(gpu_envelope["evidence"])
        evidence_hash = hashlib.sha512(inner_evidence_raw).digest()

        results.append(
            {
                "device_index": gpu_device_index,
                "type": gpu_type,
                "claims": claims,
                "evidence_hash": evidence_hash,
            }
        )

    return True, None, results


def _apply_gpu_claims_policy(gpu_component_policy, gpu_results):
    """
    Evaluate a certify-policy's GPU claims requirements against already-verified
    GPU evidence.

    ``gpu_results`` comes from :func:`_verify_gpu_evidence_list`; only the
    (cheap, in-memory) claims check runs here, so this is safe to call once per
    candidate certify-policy without repeating evidence verification.

    Returns:
        (ok, error): ``ok`` True when every GPU satisfies the policy (or the
        policy has no rule for that device type), else False with an error.
    """
    if not isinstance(gpu_component_policy, dict):
        return True, None

    for result in gpu_results:
        gpu_policy_for_device = gpu_component_policy.get(result["type"])
        if not gpu_policy_for_device:
            continue
        ok, error = gpu_validate_claims(
            gpu_policy_for_device, result["claims"], result["device_index"]
        )
        if not ok:
            return False, error

    return True, None


def verify(
    redis_client,
    nonce,
    tee_type,
    tee_evidence,
    policy_json,
    wrapping_key=None,
    report_data_binding=False,
    gpu_list=None,
    gpu_results=None,
):
    """
    Verifies the provided nonce, TEE type, and TEE evidence, with optional
    wrapping key binding and GPU attestation.

    Parameters:
        redis_client (redis.StrictRedis): Redis client instance for database operations.
        nonce (str): The nonce to verify.
        tee_type (str): The type of TEE (e.g., "amd-sev-snp", "intel-tdx").
        tee_evidence (str): Base64-encoded TEE evidence.
        policy_json (dict): The policy JSON.
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
        gpu_results (list, optional): Pre-verified GPU evidence produced by
            :func:`_verify_gpu_evidence_list`. When provided, per-GPU evidence is
            not re-verified here; only this policy's GPU claims are applied. This
            lets a domain-policy verify shared GPU evidence once across members.

    Returns:
        is_verified (bool): True if verification is successful, False otherwise.
        verify_error (str or None): An error message if verification fails, None otherwise.
    """
    log_function_entry("verify", nonce="***", tee_type=tee_type)

    input_error, decoded_evidence = _validate_attestation_inputs(
        nonce, tee_type, tee_evidence
    )
    if input_error:
        return False, input_error

    # Extract GPU component policy (if present)
    gpu_component_policy = None
    components = policy_json.get("components")
    if components and isinstance(components, dict):
        gpu_component_policy = components.get("gpu")

    # Validate: if GPU policy requires GPUs but none were provided
    if gpu_component_policy and not gpu_list:
        logger.error("Policy requires GPU attestation but no GPU evidence provided")
        return (
            False,
            "Policy requires GPU attestation but no GPU evidence provided",
        )

    # If GPU evidence provided but no GPU policy, log warning (still verify GPUs)
    if gpu_list and not gpu_component_policy:
        logger.warning(
            "GPU evidence provided but policy has no 'components.gpu' section — "
            "GPU attestation will proceed without policy validation"
        )

    # --- Compute expected report_data ---
    if report_data_binding and wrapping_key:
        # Recompute the same SHA-512 binding the agent used
        hash_input = nonce.encode("utf-8") + wrapping_key

        # Include per-GPU evidence hashes
        if gpu_list:
            # Evidence verification is policy-independent. In the certify/domain
            # flow the caller verifies the GPUs once and passes the results in,
            # so here we only (re)apply this policy's GPU claims.
            if gpu_results is None:
                gpu_ok, gpu_err, gpu_results = _verify_gpu_evidence_list(
                    redis_client, gpu_list, nonce
                )
                if not gpu_ok:
                    return False, gpu_err

            policy_ok, policy_err = _apply_gpu_claims_policy(
                gpu_component_policy, gpu_results
            )
            if not policy_ok:
                return False, policy_err

            # Append SHA-512 hashes: SHA512(gpu0_raw) || SHA512(gpu1_raw) || ...
            for result in gpu_results:
                hash_input += result["evidence_hash"]

        expected_report_data = hashlib.sha512(hash_input).digest()  # 64 bytes
    else:
        expected_report_data = nonce.encode("utf-8")

    logger.info(f"Verifying evidence for TEE type: {tee_type}")

    if tee_type == "amd-sev-snp":
        verified, verify_error = sev_vm_verify(
            redis_client,
            nonce,
            decoded_evidence,
            policy_json,
            expected_report_data=expected_report_data,
        )
    elif tee_type == "intel-tdx":
        verified, verify_error = tdx_vm_verify(
            redis_client,
            nonce,
            decoded_evidence,
            policy_json,
            expected_report_data=expected_report_data,
        )
    else:
        logger.error(f"Unsupported TEE type: {tee_type}")
        return False, "Unsupported TEE type"

    result = (verified, verify_error)
    log_function_exit("verify", result)
    return result


def domain_verify(
    redis_client,
    nonce,
    tee_type,
    tee_evidence,
    domain_policy_id,
    requested_policy_id=None,
    wrapping_key=None,
    report_data_binding=False,
    gpu_list=None,
):
    """
    Verifies certify-flow attestation against a domain-policy by id.

    Resolves the domain-policy by id, selects the certify-policies registered
    for the request ``tee_type`` (the domain-policy groups its members by TEE
    type), then evaluates the attestation against each in turn, succeeding as
    soon as one passes (logical OR). Members whose declared ``policy_type`` does
    not match the evidence are skipped. The domain-policy and certify-policy
    stores are separate from the secret-release ``policy:*`` store.

    Parameters:
        redis_client (redis.StrictRedis): Redis client instance for database operations.
        nonce (str): The nonce to verify.
        tee_type (str): The type of TEE (e.g., "amd-sev-snp", "intel-tdx").
        tee_evidence (str): Base64-encoded TEE evidence.
        domain_policy_id (str): Id of the domain-policy the agent must satisfy.
        requested_policy_id (str, optional): When provided, the attestation is
            evaluated only against this certify-policy, which must be one of the
            ids the domain-policy registers for the request ``tee_type``. When
            None, every such certify-policy is tried until one passes.
        wrapping_key (bytes, optional): The wrapping key for report data binding.
        report_data_binding (bool, optional): See :func:`verify`.
        gpu_list (list, optional): See :func:`verify`.

    Returns:
        is_verified (bool): True if the attestation satisfied one referenced
            certify-policy, False otherwise.
        key_id (str or None): The key ID of the satisfied certify-policy, or None.
        verify_error (str or None): An error message if verification fails, None otherwise.
    """
    log_function_entry("domain_verify", nonce="***", tee_type=tee_type)

    try:
        domain_policy = get_domain_policy_from_redis(redis_client, domain_policy_id)
    except ValueError as e:
        logger.error(f"Domain policy lookup failed for '{domain_policy_id}': {e}")
        return False, None, str(e)

    certify_policies = domain_policy.get("certify_policies")
    if not isinstance(certify_policies, dict) or not certify_policies:
        logger.error(
            f"Domain policy '{domain_policy_id}' references no certify policies"
        )
        return False, None, "Domain policy references no certify policies"

    # Only policies registered for this TEE type are eligible. Grouping members
    # by TEE type avoids fetching/evaluating (e.g.) Intel policies for AMD
    # evidence, which would only ever fail.
    type_policy_ids = certify_policies.get(tee_type)
    if not isinstance(type_policy_ids, list) or not type_policy_ids:
        logger.error(
            f"Domain policy '{domain_policy_id}' has no certify policies for "
            f"TEE type '{tee_type}'"
        )
        return (
            False,
            None,
            f"Domain policy has no certify policies for TEE type '{tee_type}'",
        )

    max_members = current_app.config.get("TAS_CERTIFY_MAX_POLICIES", 32)
    if len(type_policy_ids) > max_members:
        logger.error(
            f"Domain policy '{domain_policy_id}' references too many certify "
            f"policies for '{tee_type}': {len(type_policy_ids)} > {max_members}"
        )
        return False, None, "Domain policy references too many certify policies"

    # Optional fast path: evaluate only the agent-requested policy, provided the
    # domain-policy permits it for this TEE type.
    if requested_policy_id is not None:
        if requested_policy_id not in type_policy_ids:
            logger.error(
                f"Requested certify policy '{requested_policy_id}' is not permitted "
                f"by domain policy '{domain_policy_id}' for TEE type '{tee_type}'"
            )
            return (
                False,
                None,
                "Requested policy-id is not permitted by the domain policy for this TEE type",
            )
        candidate_policy_ids = [requested_policy_id]
    else:
        candidate_policy_ids = type_policy_ids

    # GPU evidence verification is policy-independent, so verify it once here
    # rather than repeating the (potentially remote) work inside verify() for
    # every candidate certify-policy. Each policy still re-checks its own GPU
    # claims against these results. A GPU evidence failure is terminal: no
    # certify-policy could pass against invalid GPU evidence.
    gpu_results = None
    if report_data_binding and wrapping_key and gpu_list:
        gpu_ok, gpu_err, gpu_results = _verify_gpu_evidence_list(
            redis_client, gpu_list, nonce
        )
        if not gpu_ok:
            logger.error(
                f"GPU evidence verification failed for domain "
                f"'{domain_policy_id}': {gpu_err}"
            )
            result = (False, None, gpu_err)
            log_function_exit("domain_verify", result)
            return result

    expected_policy_type = POLICY_TYPE_BY_TEE.get(tee_type)
    last_error = None
    for policy_id in candidate_policy_ids:
        try:
            policy_json, key_id = get_certify_policy_from_redis(redis_client, policy_id)
        except ValueError as e:
            logger.warning(
                f"Skipping certify policy '{policy_id}' for domain "
                f"'{domain_policy_id}': {e}"
            )
            last_error = str(e)
            continue

        # Defense in depth: a mis-grouped member must not be evaluated against
        # the wrong TEE's evidence.
        member_type = policy_json.get("metadata", {}).get("policy_type", "")
        if (
            expected_policy_type
            and member_type
            and member_type.upper() != expected_policy_type
        ):
            logger.warning(
                f"Skipping certify policy '{policy_id}' for domain "
                f"'{domain_policy_id}': policy_type '{member_type}' does not "
                f"match TEE type '{tee_type}'"
            )
            last_error = "certify policy type does not match the attestation evidence"
            continue

        verified, verify_error = verify(
            redis_client,
            nonce,
            tee_type,
            tee_evidence,
            policy_json,
            wrapping_key=wrapping_key,
            report_data_binding=report_data_binding,
            gpu_list=gpu_list,
            gpu_results=gpu_results,
        )
        if verified:
            logger.info(
                f"Attestation satisfied certify policy '{policy_id}' for domain "
                f"'{domain_policy_id}'"
            )
            result = (True, key_id, None)
            log_function_exit("domain_verify", result)
            return result

        logger.info(
            f"Attestation did not satisfy certify policy '{policy_id}' for domain "
            f"'{domain_policy_id}': {verify_error}"
        )
        last_error = verify_error

    result = (
        False,
        None,
        last_error or "Attestation did not satisfy any referenced certify policy",
    )
    log_function_exit("domain_verify", result)
    return result
