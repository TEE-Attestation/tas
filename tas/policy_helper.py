#
# TEE Attestation Service - Policy Helper Module
#
# Copyright 2025 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# This file is part of the TEE Attestation Service.
#
# This module is responsible for providing functions to deal with policies.
#

import base64
import json
import logging
import re

import rfc8785
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from .components import SUPPORTED_COMPONENT_TYPES, SUPPORTED_GPU_TYPES
from .tas_logging import get_logger

# Get logger for this module
logger = get_logger(__name__)


def is_policy_signed(policy_data):
    """Determine if a policy is signed.

    A policy is considered signed only if it has a 'signature' field
    containing a 'value' sub-field. A policy missing 'signature' entirely,
    or having 'signature' without 'value', is considered unsigned.

    Args:
        policy_data: The policy data dict.

    Returns:
        bool: True if the policy has a signature with a value, False otherwise.
    """
    signature = policy_data.get("signature")
    if not isinstance(signature, dict):
        return False
    return "value" in signature


def verify_policy_signature(policy_data, public_keys):
    """Verify the signature in a policy against a list of public keys.

    Args:
        policy_data: The policy data containing signature and validation_rules
        public_keys: List of tuples (key_type, key_path, public_key_object)

    Returns:
        bool: True if signature verifies with any of the public keys, False otherwise
    """
    logger.info(
        f"Starting policy signature verification with {len(public_keys)} public keys."
    )

    try:
        # Extract signature information
        if "signature" not in policy_data:
            logger.error("No signature found in policy data")
            return False

        signature_info = policy_data["signature"]
        if "value" not in signature_info:
            logger.error("No signature value found in policy data")
            return False

        logger.debug(
            f"Found signature with algorithm: {signature_info.get('algorithm', 'unknown')}"
        )
        logger.debug(
            f"Signature padding scheme: {signature_info.get('padding', 'PSS')}"
        )

        # Reject deprecated signed_data field
        if "signed_data" in signature_info:
            logger.error(
                "The 'signed_data' field in the signature object is deprecated and no longer supported. "
                "Policies must be re-signed so that the signature covers all top-level fields except 'signature'."
            )
            return False

        # Decode the signature
        signature_b64 = signature_info["value"]
        signature = base64.b64decode(signature_b64)
        logger.debug(f"Decoded signature length: {len(signature)} bytes")

        signed_json = canonicalize_policy(policy_data)
        logger.debug(
            f"Prepared data for verification, length: {len(signed_json)} bytes"
        )

        # Determine padding scheme from signature info
        padding_scheme = signature_info.get("padding", "PSS")
        logger.info(f"Using {padding_scheme} padding scheme for verification")

        # Try verification with each public key
        for i, (key_type, key_path, public_key) in enumerate(public_keys):
            logger.debug(
                f"Attempting verification with {key_type} {i+1}/{len(public_keys)} from: {key_path}"
            )
            try:
                if padding_scheme == "PSS":
                    logger.debug("Using PSS padding for verification")
                    public_key.verify(
                        signature,
                        signed_json,
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA384()),
                            salt_length=padding.PSS.MAX_LENGTH,
                        ),
                        hashes.SHA384(),
                    )
                else:  # PKCS1v15
                    logger.debug("Using PKCS1v15 padding for verification")
                    public_key.verify(
                        signature,
                        signed_json,
                        padding.PKCS1v15(),
                        hashes.SHA384(),
                    )

                logger.info(
                    f"Signature verification SUCCESSFUL with {key_type} {i+1} from: {key_path}"
                )
                return True

            except Exception as verify_error:
                logger.debug(
                    f"Verification failed with {key_type} {i+1} from {key_path}: {verify_error}"
                )
                continue

        # If we get here, none of the keys worked
        logger.error(
            f"Signature verification FAILED with all {len(public_keys)} public keys"
        )
        return False
    except Exception as e:
        logger.error(f"Error during verification: {e}")
        return False


# Regex for validating policy key components (type and policy_id)
# Only allows alphanumeric characters, hyphens, underscores, and dots.
# Rejects Redis-special characters (*, ?, [, ], \) and whitespace.
POLICY_KEY_COMPONENT_RE = re.compile(r"^[A-Za-z0-9_.-]+\Z")

# Regex for validating a full policy key: policy:{policy_id}
POLICY_KEY_RE = re.compile(r"^policy:[A-Za-z0-9_.-]+\Z")


def canonicalize_policy(policy_data):
    """Return the RFC 8785 (JCS) canonical bytes of a policy, excluding the signature field."""
    return rfc8785.dumps({k: v for k, v in policy_data.items() if k != "signature"})


def validate_policy_key(policy_key):
    """
    Validate that a policy key matches the expected structure
    'policy:{policy_id}' and contains no dangerous characters.

    Returns (True, None) if valid, (False, error_message) if not.
    """
    if not policy_key or not isinstance(policy_key, str):
        return False, "Policy key is required"

    if not POLICY_KEY_RE.match(policy_key):
        return False, (
            "Invalid policy key format. "
            "Expected format: 'policy:{policy_id}' "
            "using only alphanumeric characters, hyphens, underscores, and dots"
        )

    return True, None


def validate_key_component(value, label):
    """Validate a Redis key component (e.g. policy id or domain name) is safe.

    Rejects empty values and any characters outside the allowed set so the
    value can be embedded in a Redis key without introducing pattern-matching
    or injection hazards.

    Returns (True, None) if valid, else (False, error_message).
    """
    if not value or not isinstance(value, str):
        return False, f"{label} is required"
    if not POLICY_KEY_COMPONENT_RE.match(value):
        return False, (
            f"Invalid {label}. Use only alphanumeric characters, hyphens, "
            "underscores, and dots"
        )
    return True, None


def validate_policy_components(policy):
    """Validate the optional ``components`` section of a TAS policy.

    ``components`` carries requirements for attestable devices beyond the CPU
    TEE (today only ``gpu``). The verifier reads it as a dict keyed by
    component type, then device type, then an NVIDIA attestation policy, so a
    value of the wrong shape must be rejected at store time rather than be
    silently read as "no rules" when a policy is evaluated.

    Rules (only applied when ``components`` is present):

    - ``components`` is an object whose keys are all supported component types.
    - ``components.gpu`` is a non-empty object whose keys are all supported GPU
      device types.
    - Each device-type entry is an object with an ``authorization-rules``
      object; its optional ``overall-claims`` / ``detached-claims`` are objects.

    Returns (True, None) if valid, else (False, error_message).
    """
    if "components" not in policy:
        return True, None

    components = policy["components"]
    if not isinstance(components, dict):
        return False, "Policy 'components' must be an object"

    unsupported = sorted(set(components) - SUPPORTED_COMPONENT_TYPES)
    if unsupported:
        return (
            False,
            f"Policy 'components' contains unsupported component type(s): "
            f"{', '.join(unsupported)}",
        )

    if "gpu" not in components:
        return True, None

    gpu_section = components["gpu"]
    if not isinstance(gpu_section, dict) or not gpu_section:
        return False, "Policy 'components.gpu' must be a non-empty object"

    unsupported = sorted(set(gpu_section) - SUPPORTED_GPU_TYPES)
    if unsupported:
        return (
            False,
            f"Policy 'components.gpu' contains unsupported device type(s): "
            f"{', '.join(unsupported)}",
        )

    for device_type, device_policy in gpu_section.items():
        label = f"components.gpu.{device_type}"
        if not isinstance(device_policy, dict):
            return False, f"Policy '{label}' must be an object"
        auth_rules = device_policy.get("authorization-rules")
        if not isinstance(auth_rules, dict):
            return (
                False,
                f"Policy '{label}' must contain an 'authorization-rules' object",
            )
        for rules_key in ("overall-claims", "detached-claims"):
            if rules_key in auth_rules and not isinstance(auth_rules[rules_key], dict):
                return (
                    False,
                    f"Policy '{label}.authorization-rules.{rules_key}' must be an object",
                )

    return True, None


def validate_policy_metadata(policy, require_key_id=True):
    """Validate the structural requirements shared by TAS policy documents.

    Checks the presence of the ``metadata`` and ``validation_rules`` sections
    and the required ``policy_type`` and ``policy_id`` metadata fields,
    including ``policy_id`` character safety, and the shape of the optional
    ``components`` section (see :func:`validate_policy_components`).
    ``key_id`` names the KMS secret a secret-release policy authorises, so it
    is required by default; the certify flow does not release secrets and
    passes ``require_key_id=False`` to make it optional for certify-policies.

    Returns (True, None) if valid, else (False, error_message).
    """
    if "metadata" not in policy:
        return False, "Policy must contain 'metadata' section"
    if "validation_rules" not in policy:
        return False, "Policy must contain 'validation_rules' section"

    metadata = policy["metadata"]
    if not isinstance(metadata, dict):
        return False, "Policy 'metadata' must be an object"

    if not metadata.get("policy_type"):
        return False, "Policy type is required in metadata (e.g. SEV, TDX)"
    if require_key_id and not metadata.get("key_id"):
        return False, "Key ID is required in metadata"
    if not metadata.get("policy_id"):
        return False, "Policy ID is required in metadata"

    is_valid, error = validate_policy_components(policy)
    if not is_valid:
        return False, error

    return validate_key_component(str(metadata["policy_id"]), "policy_id")


def check_signature_for_store(policy, enforce_signed, trusted_keys):
    """Validate a policy's signature at store time per configuration.

    Rejects the deprecated ``signed_data`` field, enforces signing when
    required, and verifies the signature against the trusted keys. The check is
    structure-agnostic (the signature covers all top-level fields except
    ``signature``), so it applies to policies and domain-policies alike.

    Returns ``(ok, error_message, warning_message)``. ``error_message`` is set
    when the policy must be rejected; ``warning_message`` is set for a
    non-fatal condition (an unsigned policy permitted by configuration).
    """
    is_signed = is_policy_signed(policy)

    if is_signed and "signed_data" in policy.get("signature", {}):
        return (
            False,
            "The 'signed_data' field in the signature object is deprecated and no "
            "longer supported. Please re-sign the policy so that the signature "
            "covers all top-level fields.",
            None,
        )

    if not is_signed:
        if enforce_signed:
            return False, "Unsigned policies are not allowed by configuration", None
        return (
            True,
            None,
            "WARNING: Policy is not signed and cannot be verified for integrity",
        )

    if not verify_policy_signature(policy, trusted_keys):
        return False, "Policy signature verification failed", None

    return True, None, None
