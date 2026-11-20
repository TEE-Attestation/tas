#
# TEE Attestation Service - Shared Type Definitions
#
# Copyright 2026 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# This file is part of the TEE Attestation Service.
#

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, Protocol, TypedDict, runtime_checkable

import asn1crypto.x509
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.types import PublicKeyTypes

if TYPE_CHECKING:
    from nvidia_pytools import GpuClaims

TrustedPublicKey = tuple[str, str, PublicKeyTypes]

VerificationResult = tuple[bool, str | None]
DomainVerificationResult = tuple[bool, str | None, str | None]


GpuEvidenceEntry = TypedDict(
    "GpuEvidenceEntry",
    {
        "type": str,
        "evidence": str,
        "device-index": int,
    },
)


class VerifiedGpuResult(TypedDict):
    device_index: int
    type: str
    claims: GpuClaims
    evidence_hash: bytes


class _TDXCollateralRequired(TypedDict):
    root_cert: x509.Certificate
    root_crl: x509.CertificateRevocationList
    leaf_crl: x509.CertificateRevocationList
    qe_identity_raw: str
    qe_identity_certs: list[x509.Certificate]
    tcb_info_raw: str
    tcb_info_certs: list[x509.Certificate]
    fmspc: str
    update: str


class TDXCollateral(_TDXCollateralRequired, total=False):
    sgx_extensions: dict[str, Any]


class _EvidenceEntryRequired(TypedDict):
    platform_id: str
    evidence_type: str
    raw_evidence: bytes


class EvidenceEntry(_EvidenceEntryRequired, total=False):
    role: str
    slot: int
    evidence_version: str


class _SignatureSuiteRequired(TypedDict):
    algorithm: str


class SignatureSuite(_SignatureSuiteRequired, total=False):
    parameters: Any


class CAInfo(TypedDict):
    issuer_dn: asn1crypto.x509.Name
    authority_key_identifier: bytes
    ca_cert_der: bytes
    chain: list[bytes]
    signature_suite: SignatureSuite


class _KBMWrappedSecretRequired(TypedDict):
    wrapped_key: str
    blob: str
    iv: str
    tag: str


class KBMWrappedSecret(_KBMWrappedSecretRequired, total=False):
    algorithm: str


@runtime_checkable
class KBMPluginProtocol(Protocol):
    def kbm_open_client_connection(self, config_file: str | None = None) -> Any: ...
    def kbm_close_client_connection(self, client: Any, /) -> None: ...
    def kbm_get_secret(
        self,
        client: Any,
        /,
        key_id: str,
        wrapping_key: bytes,
    ) -> KBMWrappedSecret: ...


@runtime_checkable
class CertProviderPluginProtocol(Protocol):
    def cert_open_client_connection(
        self,
        config_file: str | None = None,
        trust_domain: str | None = None,
    ) -> Any: ...
    def cert_close_client_connection(self, client: Any, /) -> None: ...
    def cert_get_ca_info(self, client: Any, /) -> CAInfo: ...
    def cert_sign(
        self,
        client: Any,
        /,
        tbs_der: bytes,
        signature_suite: SignatureSuite | Mapping[str, Any],
    ) -> bytes: ...
