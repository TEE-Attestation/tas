#
# TEE Attestation Service - Certificate Test Utilities
#
# Copyright 2026 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# This file is part of the TEE Attestation Service.
#

import base64
from typing import Any

API_HEADERS = {"X-API-Key": "a" * 64}


def get_nonce(test_client) -> str:
    """Fetch a fresh nonce from the certificate alpha API."""
    response = test_client.get("/alphav1/nonce", headers=API_HEADERS)
    assert response.status_code == 200
    nonce = response.json.get("nonce")
    assert nonce
    return nonce


def build_certify_payload(nonce: str, csr_b64: str, **overrides: Any) -> dict[str, Any]:
    """Build a baseline certify request payload with optional overrides."""
    payload: dict[str, Any] = {
        "tee-type": "amd-sev-snp",
        "nonce": nonce,
        "tee-evidence": base64.b64encode(b"fake_raw_evidence_bytes").decode("ascii"),
        "csr": csr_b64,
        "policy-domain": "staging",
    }
    payload.update(overrides)
    return payload
