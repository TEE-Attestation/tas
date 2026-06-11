#
# TEE Attestation Service - Certificate CSR Utilities
#
# Copyright 2026 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# This file is part of the TEE Attestation Service.
#
# This module provides utilities for sanitizing and validating Certificate Signing Requests (CSRs)
# according to strict policies. It ensures that CSRs are well-formed, contain valid proof of possession,
# and adhere to allowed key types and subject name constraints.

import re
from typing import Optional, Sequence

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtensionOID, NameOID

# RFC 1035 / DNS-safe rough charset for CN: alphanumeric, dashes, dots.
CN_CHARSET_RE = re.compile(r"^[a-zA-Z0-9.-]+$")


def _is_dns_safe(value: str) -> bool:
    """Return True if value is a DNS-safe hostname (RFC 1035 labels).

    Rejects empty strings, wildcards, IP literals, leading/trailing dots,
    empty labels, labels longer than 63 chars, and names longer than 253 chars.
    """
    if not value or len(value) > 253:
        return False
    if not CN_CHARSET_RE.match(value):
        return False
    if value.startswith(".") or value.endswith("."):
        return False
    labels = value.split(".")
    for label in labels:
        if not label or len(label) > 63:
            return False
        if label.startswith("-") or label.endswith("-"):
            return False
    # Reject bare IPv4 literals (all numeric, dotted-quad form).
    if len(labels) == 4 and all(label.isdigit() for label in labels):
        return False
    return True


def sanitize_csr(
    csr_bytes: bytes,
    allowed_key_types: Sequence[str],
    max_bytes: int = 10000,
) -> tuple[
    rsa.RSAPublicKey | ec.EllipticCurvePublicKey, bytes, Optional[str], list[str]
]:
    """Validate and sanitize a CSR for certificate issuance.

    Args:
        csr_bytes: CSR payload in PEM or DER encoding.
        allowed_key_types: Allowed key families, for example ["RSA", "EC"].
        max_bytes: Maximum accepted CSR size in bytes.

    Returns:
        A tuple of (public_key, spki_der, subject_cn_or_none, dns_names) where
        dns_names is a de-duplicated, order-preserving list of DNS-safe SAN
        entries extracted from the CSR (empty when none are present/valid).

    Raises:
        ValueError: If the CSR is malformed or violates policy constraints.
    """
    if len(csr_bytes) > max_bytes:
        raise ValueError(f"CSR exceeds maximum allowed size of {max_bytes} bytes")

    try:
        if b"-----BEGIN CERTIFICATE REQUEST-----" in csr_bytes:
            csr = x509.load_pem_x509_csr(csr_bytes)
        else:
            csr = x509.load_der_x509_csr(csr_bytes)
    except Exception as e:
        raise ValueError(f"Failed to parse CSR: {e}")

    if not csr.is_signature_valid:
        raise ValueError("CSR signature (proof of possession) is invalid")

    public_key = csr.public_key()

    # Enforce allowed key types/sizes
    is_valid_key = False
    if isinstance(public_key, rsa.RSAPublicKey):
        if "RSA" in allowed_key_types and public_key.key_size >= 3072:
            is_valid_key = True
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        if "EC" in allowed_key_types and public_key.key_size in (256, 384):
            is_valid_key = True

    if not is_valid_key:
        raise ValueError("Public key type or size is not allowed by policy")

    spki_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # Extract CN, strictly ignoring everything else
    subject_cn = None
    cn_rdns = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if cn_rdns:
        if len(cn_rdns) > 1:
            raise ValueError("CSR MUST NOT contain multiple Common Name RDNs")

        cn_value = cn_rdns[0].value
        if not isinstance(cn_value, str):
            raise ValueError("CSR Common Name must be a string")
        if len(cn_value) > 63:
            raise ValueError("CSR Common Name exceeds 63 characters")
        if "\0" in cn_value or not cn_value.isprintable():
            raise ValueError("CSR Common Name contains invalid characters")
        if not CN_CHARSET_RE.match(cn_value):
            raise ValueError(
                "CSR Common Name contains forbidden characters (only alphanumeric, dots, and hyphens allowed)"
            )
        subject_cn = cn_value

    # Extract and sanitize dNSName SAN entries (optional, classic-TLS support).
    # Invalid/unsafe entries (wildcards, IP literals, bad charset) are dropped.
    dns_names: list[str] = []
    try:
        san_ext = csr.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        for dns_value in san_ext.value.get_values_for_type(x509.DNSName):
            if (
                isinstance(dns_value, str)
                and _is_dns_safe(dns_value)
                and dns_value not in dns_names
            ):
                dns_names.append(dns_value)
    except x509.ExtensionNotFound:
        pass

    return public_key, spki_der, subject_cn, dns_names
