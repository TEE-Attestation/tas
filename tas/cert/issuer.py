#
# TEE Attestation Service - Certificate Issuer
#
# Copyright 2026 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# This file is part of the TEE Attestation Service.
#
# This module provides functions to create X.509 certificates with custom extensions.

import datetime
import hashlib
import json
from typing import Any, Sequence

from asn1crypto import core, keys, pem, x509

TAS_OID_DOMAIN = "1.3.6.1.4.1.65993.1"
TAS_OID_DIGEST = "1.3.6.1.4.1.65993.2"
TAS_OID_PLATFORMS = "1.3.6.1.4.1.65993.3"
TAS_OID_ATTESTATION = "1.3.6.1.4.1.65993.4"
TAS_OID_EVIDENCE = "1.3.6.1.4.1.65993.5"


def _canonicalize_evidence_entry(entry: dict[str, Any]) -> dict[str, Any]:
    """Normalize and validate a single evidence digest entry."""
    raw_evidence = entry.get("raw_evidence")
    if not isinstance(raw_evidence, bytes) or not raw_evidence:
        raise ValueError("Evidence entry must include non-empty raw_evidence bytes")

    locator_fields = [field for field in ("role", "slot") if field in entry]
    if len(locator_fields) != 1:
        raise ValueError("Evidence entry must include exactly one locator field")

    platform_id = entry.get("platform_id")
    evidence_type = entry.get("evidence_type")
    if not isinstance(platform_id, str) or not platform_id.strip():
        raise ValueError("Evidence entry platform_id is required")
    if not isinstance(evidence_type, str) or not evidence_type.strip():
        raise ValueError("Evidence entry evidence_type is required")

    canonical_entry: dict[str, Any] = {
        "digest": hashlib.sha512(raw_evidence).hexdigest(),
        "digest_alg": "sha-512",
        "evidence_type": evidence_type.strip().lower(),
        "platform_id": platform_id.strip().lower(),
    }

    if "role" in entry:
        role = entry.get("role")
        if not isinstance(role, str) or not role.strip():
            raise ValueError("Evidence entry role must be a non-empty string")
        canonical_entry["role"] = role.strip().lower()
    else:
        slot = entry.get("slot")
        if not isinstance(slot, int) or slot < 0:
            raise ValueError("Evidence entry slot must be a non-negative integer")
        canonical_entry["slot"] = slot

    evidence_version = entry.get("evidence_version")
    if evidence_version is not None:
        if not isinstance(evidence_version, str) or not evidence_version.strip():
            raise ValueError(
                "Evidence entry evidence_version must be a non-empty string"
            )
        canonical_entry["evidence_version"] = evidence_version.strip().lower()

    return canonical_entry


def _evidence_sort_key(entry: dict[str, Any]) -> tuple[int, Any, str, str, str]:
    """Sort by locator, then platform_id, evidence_type, and digest."""
    if "role" in entry:
        return (
            0,
            entry["role"],
            entry["platform_id"],
            entry["evidence_type"],
            entry["digest"],
        )
    return (
        1,
        entry["slot"],
        entry["platform_id"],
        entry["evidence_type"],
        entry["digest"],
    )


def compute_evidence_digests(
    evidence_entries: Sequence[dict[str, Any]],
    *,
    max_entries: int = 17,
    max_encoded_bytes: int = 4096,
) -> str:
    """Build canonical evidence digest metadata JSON.

    Args:
        evidence_entries: Verified evidence objects that contributed to issuance.
        max_entries: Maximum number of evidence entries permitted.
        max_encoded_bytes: Maximum JSON byte length permitted.

    Returns:
        A canonical JSON string describing evidence digest entries.
    """
    if not evidence_entries:
        raise ValueError("At least one evidence entry is required")
    if len(evidence_entries) > max_entries:
        raise ValueError("Evidence digest entry count exceeds configured maximum")

    canonical_entries = [
        _canonicalize_evidence_entry(entry) for entry in evidence_entries
    ]
    entry_keys = {
        json.dumps(entry, separators=(",", ":"), sort_keys=True)
        for entry in canonical_entries
    }
    if len(entry_keys) != len(canonical_entries):
        raise ValueError("Duplicate evidence digest entries are not allowed")

    evidence_json = {
        "version": 1,
        "entries": sorted(canonical_entries, key=_evidence_sort_key),
    }
    encoded = json.dumps(evidence_json, separators=(",", ":"), sort_keys=True)
    if len(encoded.encode("utf-8")) > max_encoded_bytes:
        raise ValueError("Evidence digest JSON exceeds configured maximum size")
    return encoded


def build_tas_extensions(
    policy_domain: str,
    policy_digest_hex: str,
    platforms_verified: Sequence[str],
    evidence_digests_json: str,
) -> list[dict[str, Any]]:
    """Construct TAS custom certificate extensions.

    Args:
        policy_domain: Domain name used for policy evaluation.
        policy_digest_hex: Hex SHA-512 digest representing evaluated policy.
        platforms_verified: Verified platform identifiers.
        evidence_digests_json: Canonical JSON digest document for evidence.

    Returns:
        Extension dictionaries consumable by asn1crypto TBS builder.
    """
    exts: list[dict[str, Any]] = []

    exts.append(
        {
            "extn_id": TAS_OID_DOMAIN,
            "critical": False,
            "extn_value": core.UTF8String(policy_domain).dump(),
        }
    )

    exts.append(
        {
            "extn_id": TAS_OID_DIGEST,
            "critical": False,
            "extn_value": core.OctetString(bytes.fromhex(policy_digest_hex)).dump(),
        }
    )

    platforms_json = json.dumps(
        sorted([p.lower() for p in platforms_verified]), separators=(",", ":")
    )
    exts.append(
        {
            "extn_id": TAS_OID_PLATFORMS,
            "critical": False,
            "extn_value": core.UTF8String(platforms_json).dump(),
        }
    )

    now_utc = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    exts.append(
        {
            "extn_id": TAS_OID_ATTESTATION,
            "critical": False,
            "extn_value": core.GeneralizedTime(now_utc).dump(),
        }
    )

    exts.append(
        {
            "extn_id": TAS_OID_EVIDENCE,
            "critical": False,
            "extn_value": core.UTF8String(evidence_digests_json).dump(),
        }
    )

    return exts


def build_tbs_der(
    spki_der: bytes,
    ski_digest: bytes,
    subject_cn: str,
    spiffe_uri: str,
    validity_start: datetime.datetime,
    validity_end: datetime.datetime,
    serial: int,
    ca_info: dict[str, Any],
    tas_exts: list[dict[str, Any]],
    dns_names: Sequence[str] | None = None,
) -> x509.TbsCertificate:
    """Build an X.509 v3 TBS certificate object.

    This function sets SPIFFE/X509-SVID-friendly leaf extensions:
    - Subject Alternative Name with exactly one URI SAN (SPIFFE ID)
    - Optional DNS SAN entries for classic TLS hostname verification
    - Basic Constraints CA=false
    - Key Usage critical with digitalSignature
    - Extended Key Usage with clientAuth and serverAuth

    Args:
        spki_der: Subject public key info DER bytes.
        ski_digest: Subject key identifier digest bytes.
        subject_cn: Subject common name.
        spiffe_uri: SPIFFE URI SAN value.
        validity_start: Certificate not-before time.
        validity_end: Certificate not-after time.
        serial: Certificate serial number.
        ca_info: Issuer metadata returned by cert plugin.
        tas_exts: TAS custom extension set.
        dns_names: Optional DNS SAN entries added alongside the single SPIFFE URI.

    Returns:
        asn1crypto TbsCertificate object ready for external signing.
    """
    spki = keys.PublicKeyInfo.load(spki_der)

    exts: list[dict[str, Any]] = []
    exts.append(
        {
            "extn_id": "key_identifier",
            "critical": False,
            "extn_value": ski_digest,
        }
    )

    exts.append(
        {
            "extn_id": "authority_key_identifier",
            "critical": False,
            "extn_value": {"key_identifier": ca_info["authority_key_identifier"]},
        }
    )

    exts.append(
        {
            "extn_id": "basic_constraints",
            "critical": True,
            "extn_value": {"ca": False},
        }
    )

    exts.append(
        {
            "extn_id": "key_usage",
            "critical": True,
            "extn_value": {"digital_signature"},
        }
    )

    # URI SAN carries exactly one SPIFFE ID for leaf X509-SVID. Optional DNS
    # SAN entries are added alongside it for classic TLS hostname verification.
    san_values: list[x509.GeneralName] = [
        x509.GeneralName({"uniform_resource_identifier": spiffe_uri})
    ]
    if dns_names:
        seen: set[str] = set()
        for name in dns_names:
            if name not in seen:
                seen.add(name)
                san_values.append(x509.GeneralName({"dns_name": name}))
    exts.append(
        {
            "extn_id": "subject_alt_name",
            "critical": False,
            "extn_value": san_values,
        }
    )

    exts.append(
        {
            "extn_id": "extended_key_usage",
            "critical": False,
            "extn_value": ["client_auth", "server_auth"],
        }
    )

    exts.extend(tas_exts)

    return x509.TbsCertificate(
        {
            "version": "v3",
            "serial_number": serial,
            "signature": ca_info["signature_suite"],
            "issuer": ca_info["issuer_dn"],
            "validity": {
                "not_before": x509.Time({"utc_time": validity_start}),
                "not_after": x509.Time({"utc_time": validity_end}),
            },
            "subject": x509.Name.build({"common_name": subject_cn}),
            "subject_public_key_info": spki,
            "extensions": exts,
        }
    )


def assemble_certificate(
    tbs: x509.TbsCertificate,
    signature_suite: dict[str, Any],
    signature_value: bytes,
) -> bytes:
    """Assemble and PEM-encode a full certificate from TBS and signature.

    Args:
        tbs: ASN.1 TBS certificate structure.
        signature_suite: Signature algorithm descriptor.
        signature_value: Signature bytes from the signing plugin.

    Returns:
        PEM-encoded certificate bytes.
    """
    cert = x509.Certificate(
        {
            "tbs_certificate": tbs,
            "signature_algorithm": signature_suite,
            "signature_value": signature_value,
        }
    )
    return pem.armor("CERTIFICATE", cert.dump())
