#
# TEE Attestation Service - Certificate Routes
#
# Copyright 2026 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# This file is part of the TEE Attestation Service.
#
# This module implements the /alphav1/certify endpoint, which handles certificate requests.
# It performs request authentication, CSR sanitization, nonce validation, attestation
# verification, and certificate construction/signing through the configured cert provider
# plugin.

import base64
import binascii
import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import Blueprint, Response, current_app, jsonify, request

from ..auth import authenticate_request
from ..client_routes import get_nonce_redis
from ..nonce import validate_nonce
from ..tas_logging import get_logger
from ..tas_vm import vm_verify
from .csr import sanitize_csr
from .issuer import (
    assemble_certificate,
    build_tas_extensions,
    build_tbs_der,
    compute_evidence_digests,
)
from .renewal import RenewalError, validate_renewal_cert

logger = get_logger(__name__)

cert_bp = Blueprint("cert", __name__)


TEE_EVIDENCE_TYPES = {
    "amd-sev-snp": "sev-snp-report",
    "intel-tdx": "tdx-report",
}
GPU_EVIDENCE_TYPE = "gpu-attestation-report"


def _build_evidence_entries(
    tee_type: str,
    tee_evidence: str,
    gpu_evidence: list[dict[str, Any]] | None,
) -> tuple[list[dict[str, Any]], list[str]]:
    """Build evidence digest inputs from verified request evidence."""
    entries: list[dict[str, Any]] = [
        {
            "platform_id": tee_type,
            "role": "cpu",
            "evidence_type": TEE_EVIDENCE_TYPES.get(tee_type, "tee-report"),
            "raw_evidence": base64.b64decode(tee_evidence, validate=True),
        }
    ]
    platforms_verified = [tee_type]

    if gpu_evidence is None:
        return entries, platforms_verified
    if not isinstance(gpu_evidence, list):
        raise ValueError("gpu-evidence must be a list")

    for gpu in sorted(gpu_evidence, key=lambda item: item.get("device-index", -1)):
        gpu_type = gpu.get("type")
        gpu_evidence_b64 = gpu.get("evidence")
        device_index = gpu.get("device-index")
        if not isinstance(gpu_type, str) or not gpu_type:
            raise ValueError("GPU evidence entry missing type")
        if not isinstance(gpu_evidence_b64, str) or not gpu_evidence_b64:
            raise ValueError("GPU evidence entry missing evidence")
        if not isinstance(device_index, int) or device_index < 0:
            raise ValueError("GPU evidence entry missing valid device-index")

        entries.append(
            {
                "platform_id": gpu_type,
                "slot": device_index,
                "evidence_type": GPU_EVIDENCE_TYPE,
                "raw_evidence": base64.b64decode(gpu_evidence_b64, validate=True),
            }
        )
        if gpu_type not in platforms_verified:
            platforms_verified.append(gpu_type)

    return entries, platforms_verified


@cert_bp.route("/alphav1/certify", methods=["POST"])
def certify() -> tuple[Response, int]:
    """Issue or renew an attestation-bound workload certificate.

    Expected JSON payload fields are:
    - tee-type
    - nonce
    - tee-evidence
    - csr
    - policy-domain
    - gpu-evidence (optional)
    - renew_cert (optional)

    Returns:
        A Flask JSON response containing PEM certificate and CA chain.
    """
    logger.info(f"Received certify request from {request.remote_addr}")
    auth_response = authenticate_request()
    if auth_response:
        return auth_response

    data = request.get_json()
    if not data:
        return jsonify({"error": "Request body must be JSON"}), 400

    tee_type = data.get("tee-type")
    nonce = data.get("nonce")
    tee_evidence = data.get("tee-evidence")
    csr_b64 = data.get("csr")
    policy_domain = data.get("policy-domain")
    gpu_evidence = data.get("gpu-evidence")
    renew_cert = data.get("renew_cert")

    if not all([tee_type, nonce, tee_evidence, csr_b64, policy_domain]):
        return jsonify({"error": "Missing required fields"}), 400
    if renew_cert is not None and not isinstance(renew_cert, str):
        return jsonify({"error": "renew_cert must be a PEM string"}), 400
    if isinstance(renew_cert, str) and not renew_cert.strip():
        return jsonify({"error": "renew_cert must not be empty"}), 400

    try:
        csr_bytes = base64.b64decode(csr_b64, validate=True)
    except (binascii.Error, ValueError, TypeError):
        return jsonify({"error": "Invalid base64 encoding for CSR"}), 400

    try:
        allowed_types = current_app.config.get(
            "TAS_CERT_ALLOWED_KEY_TYPES", ["RSA", "EC"]
        )
        max_bytes = current_app.config.get("TAS_CERT_MAX_CSR_BYTES", 10000)
        (
            public_key,
            spki_der,
            subject_cn,
            dns_names,
            ip_addresses,
            email_addresses,
        ) = sanitize_csr(csr_bytes, allowed_types, max_bytes)
        ski_digest = x509.SubjectKeyIdentifier.from_public_key(public_key).digest
    except ValueError as e:
        logger.error(f"CSR sanitization failed: {e}")
        return jsonify({"error": str(e)}), 400

    if not subject_cn:
        subject_cn = f"tas.{secrets.token_hex(4)}"

    nonce_client = get_nonce_redis()
    is_valid, error_message = validate_nonce(nonce_client, nonce)
    if not is_valid:
        return jsonify({"error": error_message}), 403

    # The agent computes report-data as SHA-512(nonce || public_key_der).
    # For RSA keys the binding uses PKCS#1 DER; for other key types SPKI DER.
    if isinstance(public_key, rsa.RSAPublicKey):
        binding_key = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.PKCS1,
        )
    else:
        binding_key = spki_der

    is_verified, key_id, verify_error = vm_verify(
        current_app.extensions["redis"],
        nonce,
        tee_type,
        tee_evidence,
        policy_domain,
        wrapping_key=binding_key,
        report_data_binding=True,
        gpu_list=gpu_evidence,
    )

    if not is_verified:
        logger.error(f"Attestation verification failed: {verify_error}")
        return jsonify({"error": verify_error}), 403

    try:
        evidence_entries, platforms_verified = _build_evidence_entries(
            tee_type,
            tee_evidence,
            gpu_evidence,
        )
        evidence_digests_str = compute_evidence_digests(
            evidence_entries,
            max_entries=current_app.config.get(
                "TAS_CERT_EVIDENCE_DIGEST_MAX_ENTRIES", 17
            ),
            max_encoded_bytes=current_app.config.get(
                "TAS_CERT_EVIDENCE_DIGEST_MAX_BYTES", 4096
            ),
        )
    except (binascii.Error, ValueError) as e:
        logger.error(f"Evidence digest construction failed: {e}")
        return jsonify({"error": str(e)}), 400

    policy_digest_hex = hashlib.sha512(b'{"allow_all":true}').hexdigest()

    tas_exts = build_tas_extensions(
        policy_domain,
        policy_digest_hex,
        platforms_verified,
        evidence_digests_str,
    )

    clock_skew = current_app.config.get("TAS_CERT_CLOCK_SKEW_SECONDS", 90)
    validity_ttl = current_app.config.get("TAS_CERT_VALIDITY_SECONDS", 300)
    valid_start = datetime.now(timezone.utc) - timedelta(seconds=clock_skew)
    valid_end = datetime.now(timezone.utc) + timedelta(seconds=validity_ttl)

    serial_number = secrets.randbits(128)

    ca_info: dict[str, Any] = current_app.extensions["cert_get_ca_info"](
        current_app.extensions["cert_client"]
    )
    trust_domain = current_app.config.get("TAS_CERT_TRUST_DOMAIN", "example.org")
    if renew_cert:
        try:
            spiffe_uuid = validate_renewal_cert(
                renew_cert,
                ca_info,
                policy_domain,
                trust_domain,
                spki_der,
                clock_skew,
            )
            logger.info("Renewal accepted for SPIFFE UUID %s", spiffe_uuid)
        except RenewalError as e:
            logger.error("Renewal validation failed: %s", e)
            return jsonify({"error": str(e)}), 400
    else:
        spiffe_uuid = uuid.uuid4()

    spiffe_uri = f"spiffe://{trust_domain}/{policy_domain}/{spiffe_uuid}"

    tbs_der = build_tbs_der(
        spki_der,
        ski_digest,
        subject_cn,
        spiffe_uri,
        valid_start,
        valid_end,
        serial_number,
        ca_info,
        tas_exts,
        dns_names=dns_names,
        ip_addresses=ip_addresses,
        email_addresses=email_addresses,
    )

    try:
        signature_value = current_app.extensions["cert_sign"](
            current_app.extensions["cert_client"],
            tbs_der.dump(),
            ca_info["signature_suite"],
        )
    except Exception as e:
        logger.error(f"Signing failed: {e}")
        return jsonify({"error": "Failed to sign certificate"}), 500

    final_cert_pem = assemble_certificate(
        tbs_der, ca_info["signature_suite"], signature_value
    )

    ca_chain = [
        b.decode("ascii") if isinstance(b, bytes) else b for b in ca_info["chain"]
    ]

    # return 200 with the certificate, ordered CA chain, and a convenience
    # concatenated bundle (intermediate + root) for classic-TLS/SPIFFE clients.
    return jsonify(
        {
            "certificate": final_cert_pem.decode("ascii"),
            "ca_chain": ca_chain,
            "ca_bundle": "".join(ca_chain),
        }
    )
