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

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from .tas_logging import get_logger

# Get logger for this module
logger = get_logger(__name__)


def sort_dict_recursively(obj):
    """Recursively sort dictionaries and their nested dictionaries."""
    # logger.debug(f"Sorting object of type: {type(obj)}")
    if isinstance(obj, dict):
        # logger.debug(f"Sorting dictionary with {len(obj)} keys")
        return dict(sorted((k, sort_dict_recursively(v)) for k, v in obj.items()))
    elif isinstance(obj, list):
        # logger.debug(f"Sorting list with {len(obj)} items")
        return [sort_dict_recursively(item) for item in obj]
    else:
        return obj


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

        # Extract and sort the validation rules (same as signing process)
        logger.debug("Extracting and sorting validation rules")
        measurements = policy_data["validation_rules"]
        sorted_measurements = sort_dict_recursively(measurements)
        measurements_json = json.dumps(
            sorted_measurements, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        logger.debug(
            f"Prepared data for verification, length: {len(measurements_json)} bytes"
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
                        measurements_json,
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
                        measurements_json,
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
