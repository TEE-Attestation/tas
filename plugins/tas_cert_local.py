#
# TEE Attestation Service - Local Certificate Plugin
#
# Copyright 2026 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# This file is part of the TEE Attestation Service.
#

import datetime
import hashlib
from typing import Any

import yaml
from asn1crypto import x509 as x509_asn1
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from tas.tas_logging import get_logger

logger = get_logger("tas.plugins.tas_cert_local")

# In-memory singleton state for the 2-tier CA hierarchy:
#   root (self-signed) -> intermediate (issuing CA) -> leaves
_ROOT_PRIVATE_KEY: ec.EllipticCurvePrivateKey | None = None
_ROOT_CERTIFICATE: x509.Certificate | None = None
_INT_PRIVATE_KEY: ec.EllipticCurvePrivateKey | None = None
_INT_CERTIFICATE: x509.Certificate | None = None
_CA_TRUST_DOMAIN = "example.org"
_CA_SUBJECT_CN = f"ca.{_CA_TRUST_DOMAIN}"


def _ca_key_usage() -> x509.KeyUsage:
    """KeyUsage common to CA certificates (keyCertSign + cRLSign)."""
    return x509.KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=True,
        crl_sign=True,
        encipher_only=False,
        decipher_only=False,
    )


def cert_open_client_connection(
    config_file: str | None = None, trust_domain: str | None = None
) -> str:
    """Initialize the local ephemeral root+intermediate CA and return a handle.

    Builds a self-signed root CA (pathlen=1) that signs an intermediate issuing
    CA (pathlen=0). The intermediate is the issuer for all leaf certificates.

    Args:
        config_file: Optional YAML config path containing `ca_subject_cn` and `ca_trust_domain`.
        trust_domain: Optional trust domain (e.g. from TAS_CERT_TRUST_DOMAIN). Takes
            precedence over the YAML `ca_trust_domain` value when provided.

    Returns:
        A static local client handle identifier.
    """
    global _ROOT_PRIVATE_KEY, _ROOT_CERTIFICATE
    global _INT_PRIVATE_KEY, _INT_CERTIFICATE
    global _CA_SUBJECT_CN, _CA_TRUST_DOMAIN

    explicit_cn = False

    if config_file:
        try:
            with open(config_file, "r", encoding="utf-8") as f:
                cfg = yaml.safe_load(f)
                if isinstance(cfg, dict):
                    if "ca_trust_domain" in cfg:
                        _CA_TRUST_DOMAIN = cfg["ca_trust_domain"]
                    if "ca_subject_cn" in cfg:
                        _CA_SUBJECT_CN = cfg["ca_subject_cn"]
                        explicit_cn = True
        except Exception:
            pass

    # Flask config (TAS_CERT_TRUST_DOMAIN) is the source of truth and overrides YAML.
    if trust_domain:
        _CA_TRUST_DOMAIN = trust_domain

    # CN derives from the trust domain unless explicitly overridden in YAML.
    if not explicit_cn:
        _CA_SUBJECT_CN = f"ca.{_CA_TRUST_DOMAIN}"

    logger.info("Initializing local root+intermediate CA")
    if config_file:
        logger.info("Loading cert plugin config from: %s", config_file)

    if _INT_PRIVATE_KEY is None:
        spiffe_san = x509.SubjectAlternativeName(
            [x509.UniformResourceIdentifier(f"spiffe://{_CA_TRUST_DOMAIN}")]
        )
        now = datetime.datetime.now(datetime.timezone.utc)
        not_after = now + datetime.timedelta(days=365)

        # --- Root CA: self-signed, pathlen=1 (may issue exactly one CA below) ---
        _ROOT_PRIVATE_KEY = ec.generate_private_key(ec.SECP384R1())
        root_public_key = _ROOT_PRIVATE_KEY.public_key()
        root_name = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, f"ca-root.{_CA_TRUST_DOMAIN}")]
        )
        _ROOT_CERTIFICATE = (
            x509.CertificateBuilder()
            .subject_name(root_name)
            .issuer_name(root_name)
            .public_key(root_public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(not_after)
            .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
            .add_extension(_ca_key_usage(), critical=True)
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(root_public_key),
                critical=False,
            )
            .add_extension(spiffe_san, critical=False)
            .sign(_ROOT_PRIVATE_KEY, hashes.SHA512())
        )

        # --- Intermediate (issuing) CA: signed by root, pathlen=0 (leaves only) ---
        _INT_PRIVATE_KEY = ec.generate_private_key(ec.SECP384R1())
        int_public_key = _INT_PRIVATE_KEY.public_key()
        int_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, _CA_SUBJECT_CN)])
        _INT_CERTIFICATE = (
            x509.CertificateBuilder()
            .subject_name(int_name)
            .issuer_name(root_name)
            .public_key(int_public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(not_after)
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(_ca_key_usage(), critical=True)
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(int_public_key),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(root_public_key),
                critical=False,
            )
            .add_extension(spiffe_san, critical=False)
            .sign(_ROOT_PRIVATE_KEY, hashes.SHA512())
        )
        logger.info(
            "Local root+intermediate CA initialized with trust domain: %s",
            _CA_TRUST_DOMAIN,
        )

    return "ephemeral_local_ca"


def cert_get_ca_info(client: str) -> dict[str, Any]:
    """Return issuer metadata required by certificate assembly.

    Args:
        client: Plugin client handle returned by `cert_open_client_connection`.

    Returns:
        Dictionary with issuer DN, AKI, CA certificate, chain, and signature suite.

    Raises:
        RuntimeError: If CA state has not been initialized.
    """
    # We don't actually use the client handle, but we keep it in the signature for consistency with other plugins.
    del client

    if _INT_CERTIFICATE is None or _ROOT_CERTIFICATE is None:
        raise RuntimeError("Local CA is not initialized")

    int_der = _INT_CERTIFICATE.public_bytes(serialization.Encoding.DER)

    asn1_cert = x509_asn1.Certificate.load(int_der)
    aki = hashlib.sha1(
        asn1_cert["tbs_certificate"]["subject_public_key_info"]["public_key"].native
    ).digest()

    return {
        "issuer_dn": asn1_cert["tbs_certificate"]["subject"],
        "authority_key_identifier": aki,
        "ca_cert_der": int_der,
        "chain": [
            _INT_CERTIFICATE.public_bytes(serialization.Encoding.PEM),
            _ROOT_CERTIFICATE.public_bytes(serialization.Encoding.PEM),
        ],
        "signature_suite": {"algorithm": "sha512_ecdsa"},
    }


def cert_sign(client: str, tbs_der: bytes, signature_suite: dict[str, Any]) -> bytes:
    """Sign TBS certificate bytes with the local ephemeral CA key.

    Args:
        client: Plugin client handle returned by `cert_open_client_connection`.
        tbs_der: DER-encoded TBS certificate bytes.
        signature_suite: Signature suite descriptor.

    Returns:
        Raw ECDSA signature bytes.

    Raises:
        ValueError: If requested signature algorithm is unsupported.
        RuntimeError: If local CA private key is not initialized.
    """
    del client

    if signature_suite["algorithm"] != "sha512_ecdsa":
        raise ValueError("Unsupported signature suite")

    if _INT_PRIVATE_KEY is None:
        raise RuntimeError("Local CA private key is not initialized")

    return _INT_PRIVATE_KEY.sign(tbs_der, ec.ECDSA(hashes.SHA512()))


def cert_close_client_connection(client: str) -> None:
    """Close plugin client connection.

    Args:
        client: Plugin client handle.

    Returns:
        None.
    """
    del client
