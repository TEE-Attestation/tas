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

from .tas_logging import get_logger

# Get logger for this module
logger = get_logger(__name__)


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

        # Decode the signature
        signature_b64 = signature_info["value"]
        signature = base64.b64decode(signature_b64)
        logger.debug(f"Decoded signature length: {len(signature)} bytes")

        # Determine what data is covered by the signature
        signed_data_spec = signature_info.get("signed_data")

        if signed_data_spec is not None:
            # signed_data specified: sign only those fields
            if isinstance(signed_data_spec, str):
                signed_data_spec = [signed_data_spec]

            if not isinstance(signed_data_spec, list) or not signed_data_spec:
                logger.error(
                    "signed_data must be a non-empty string or list of strings"
                )
                return False

            logger.debug(f"Signature covers specified fields: {signed_data_spec}")
            if len(signed_data_spec) == 1:
                # Single field: canonicalize the field value directly (backward compatible)
                field = signed_data_spec[0]
                if field not in policy_data:
                    logger.error(
                        f"signed_data field '{field}' not found in policy data"
                    )
                    return False
                data_to_verify = policy_data[field]
            else:
                # Multiple fields: build a dict of the specified fields
                data_to_verify = {}
                for field in sorted(signed_data_spec):
                    if field not in policy_data:
                        logger.error(
                            f"signed_data field '{field}' not found in policy data"
                        )
                        return False
                    data_to_verify[field] = policy_data[field]
        else:
            # Default: signature covers all top-level fields except "signature"
            logger.debug(
                "No signed_data specified, signature covers all fields except 'signature'"
            )
            data_to_verify = {k: v for k, v in policy_data.items() if k != "signature"}

        signed_json = rfc8785.dumps(data_to_verify)
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


# Regex for validating policy key components (type and key_id)
# Only allows alphanumeric characters, hyphens, underscores, and dots.
# Rejects Redis-special characters (*, ?, [, ], \) and whitespace.
POLICY_KEY_COMPONENT_RE = re.compile(r"^[A-Za-z0-9_.-]+\Z")

# Regex for validating a full policy key: policy:{type}:{key_id}
POLICY_KEY_RE = re.compile(r"^policy:[A-Za-z0-9_-]+:[A-Za-z0-9_.-]+\Z")


def validate_policy_key(policy_key):
    """
    Validate that a policy key matches the expected structure
    'policy:{type}:{key_id}' and contains no dangerous characters.

    Returns (True, None) if valid, (False, error_message) if not.
    """
    if not policy_key or not isinstance(policy_key, str):
        return False, "Policy key is required"

    if not POLICY_KEY_RE.match(policy_key):
        return False, (
            "Invalid policy key format. "
            "Expected format: 'policy:{type}:{key_id}' "
            "using only alphanumeric characters, hyphens, underscores, and dots"
        )

    return True, None
