#
# TEE Attestation Service - RSA Wrapping Key Validation
#
# Copyright 2026 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# This file is part of the TEE Attestation Service.

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    load_der_public_key,
    load_pem_public_key,
)


def load_rsa_public_key(raw: bytes) -> rsa.RSAPublicKey:
    """Parse a PEM/DER RSA wrapping key and require at least 2048 bits."""
    try:
        try:
            key = load_pem_public_key(raw)
        except ValueError:
            key = load_der_public_key(raw)
    except (ValueError, UnsupportedAlgorithm) as e:
        raise ValueError("Invalid RSA public key format") from e

    if not isinstance(key, rsa.RSAPublicKey):
        raise ValueError(
            f"Invalid public key type: expected an RSA public key (RSAPublicKey), got {type(key).__name__}. "
            "Only RSA public keys are supported for secret wrapping."
        )

    if key.key_size < 2048:
        raise ValueError(
            f"RSA public key size ({key.key_size} bits) is insufficient. "
            "Minimum required RSA key size is 2048 bits."
        )

    return key
