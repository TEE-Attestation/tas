#
# TEE Attestation Service - Certificate Renewal Validation
#
# Copyright 2026 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# This file is part of the TEE Attestation Service.
#
# This module provides functions to validate a renewal certificate against the current TAS CA and the original CSR.
import uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import ExtensionOID


class RenewalError(ValueError):
    """Raised when a renewal certificate fails continuity validation."""


def _aware_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _not_valid_before(cert: x509.Certificate) -> datetime:
    if hasattr(cert, "not_valid_before_utc"):
        return cert.not_valid_before_utc
    return _aware_utc(cert.not_valid_before)


def _not_valid_after(cert: x509.Certificate) -> datetime:
    if hasattr(cert, "not_valid_after_utc"):
        return cert.not_valid_after_utc
    return _aware_utc(cert.not_valid_after)


def _parse_spiffe_uri(spiffe_uri: str) -> tuple[str, str, uuid.UUID]:
    parts = urlsplit(spiffe_uri)
    if parts.scheme != "spiffe" or not parts.netloc:
        raise RenewalError("Current cerftificate's SPIFFE URI is malformed")
    if parts.query or parts.fragment:
        raise RenewalError(
            "Current cerftificate's SPIFFE URI must not contain query or fragment"
        )

    path_parts = [part for part in parts.path.split("/") if part]
    if len(path_parts) != 2:
        raise RenewalError(
            "Current cerftificate's SPIFFE URI must be spiffe://<trust-domain>/<policy-domain>/<uuid>"
        )

    policy_domain, uuid_str = path_parts
    try:
        parsed_uuid = uuid.UUID(uuid_str, version=4)
    except ValueError as exc:
        raise RenewalError(
            "Current cerftificate's SPIFFE URI UUID is malformed"
        ) from exc
    if str(parsed_uuid) != uuid_str.lower() or parsed_uuid.version != 4:
        raise RenewalError(
            "Current cerftificate's SPIFFE URI UUID must be a canonical v4 UUID"
        )

    return parts.netloc, policy_domain, parsed_uuid


def _verify_signed_by_ca(cert: x509.Certificate, ca_cert_der: bytes) -> None:
    try:
        ca_cert = x509.load_der_x509_certificate(ca_cert_der)
    except Exception as exc:
        raise RenewalError("TAS CA certificate is malformed") from exc

    ca_public_key = ca_cert.public_key()
    signature_hash = cert.signature_hash_algorithm
    try:
        if isinstance(ca_public_key, ec.EllipticCurvePublicKey):
            ca_public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                ec.ECDSA(signature_hash),
            )
        elif isinstance(ca_public_key, rsa.RSAPublicKey):
            ca_public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                signature_hash,
            )
        else:
            raise RenewalError("Unsupported TAS CA public key type")
    except RenewalError:
        raise
    except Exception as exc:
        raise RenewalError(
            "Current cerftificate was not signed by the active TAS CA"
        ) from exc


def validate_renewal_cert(
    renew_cert_pem: str,
    ca_info: dict,
    requested_policy_domain: str,
    trust_domain: str,
    csr_spki_der: bytes,
    clock_skew_seconds: int,
) -> uuid.UUID:
    """Validate renewal continuity and return the UUID to reuse."""
    try:
        cert = x509.load_pem_x509_certificate(renew_cert_pem.encode("ascii"))
    except Exception as exc:
        raise RenewalError(
            "Current certificate must be a PEM-encoded X.509 certificate"
        ) from exc

    try:
        basic_constraints = cert.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS
        ).value
    except x509.ExtensionNotFound as exc:
        raise RenewalError("Current certificate must contain basicConstraints") from exc
    if basic_constraints.ca:
        raise RenewalError("Current certificate must be a leaf certificate (CA:false)")

    try:
        san = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        ).value
    except x509.ExtensionNotFound as exc:
        raise RenewalError("Current certificate must contain a SPIFFE URI SAN") from exc

    uri_sans = san.get_values_for_type(x509.UniformResourceIdentifier)
    if len(uri_sans) != 1:
        raise RenewalError("Current certificate must contain exactly one URI SAN")
    prior_trust_domain, prior_policy_domain, prior_uuid = _parse_spiffe_uri(uri_sans[0])

    if prior_trust_domain != trust_domain:
        raise RenewalError(
            "Current certificate SPIFFE trust domain does not match TAS trust domain"
        )
    if prior_policy_domain != requested_policy_domain:
        raise RenewalError(
            "Current certificate policy domain does not match requested policy-domain"
        )

    skew = timedelta(seconds=clock_skew_seconds)
    now = datetime.now(timezone.utc)
    if now < _not_valid_before(cert) - skew:
        raise RenewalError("Current certificate is not yet valid")
    if now > _not_valid_after(cert) + skew:
        raise RenewalError("Current certificate is expired")

    _verify_signed_by_ca(cert, ca_info["ca_cert_der"])

    prior_spki_der = cert.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if prior_spki_der != csr_spki_der:
        raise RenewalError(
            "Current certificate's public key does not match CSR public key"
        )

    return prior_uuid
