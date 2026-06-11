#
# TEE Attestation Service - CSR Sanitization Tests
#
# Copyright 2026 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# This file is part of the TEE Attestation Service.
#

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from tas.cert.csr import sanitize_csr


def generate_csr(cn=None, add_extension=False, dns_names=None, return_key=False):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072,
    )
    builder = x509.CertificateSigningRequestBuilder()

    name_attrs = []
    if cn is not None:
        name_attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, cn))
    name_attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, "My Company"))

    builder = builder.subject_name(x509.Name(name_attrs))

    san_entries = []
    if add_extension:
        san_entries.append(x509.DNSName("example.com"))
    if dns_names:
        san_entries.extend(x509.DNSName(name) for name in dns_names)
    if san_entries:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(san_entries),
            critical=False,
        )

    csr = builder.sign(private_key, hashes.SHA256())
    csr_pem = csr.public_bytes(serialization.Encoding.PEM)
    if return_key:
        key_pem = private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        return csr_pem, key_pem
    return csr_pem


def test_csr_sanitization_valid():
    csr_bytes = generate_csr(cn="valid-cn.com")
    pub, spki, cn, dns = sanitize_csr(csr_bytes, ["RSA"], 10000)
    assert cn == "valid-cn.com"
    assert spki is not None
    assert dns == []


def test_csr_sanitization_no_cn():
    csr_bytes = generate_csr()
    pub, spki, cn, dns = sanitize_csr(csr_bytes, ["RSA"], 10000)
    assert cn is None
    assert dns == []


def test_csr_sanitization_invalid_cn_embedded_null():
    csr_bytes = generate_csr(cn="invalid\0cn")
    with pytest.raises(ValueError, match="invalid characters"):
        sanitize_csr(csr_bytes, ["RSA"], 10000)


def test_csr_sanitization_invalid_cn_charset():
    csr_bytes = generate_csr(cn=r"in\/alid@cn")
    with pytest.raises(ValueError, match="forbidden characters"):
        sanitize_csr(csr_bytes, ["RSA"], 10000)


def test_csr_sanitization_ignores_extensions():
    # The example.com DNS SAN is valid and extracted; other extensions ignored.
    csr_bytes = generate_csr(cn="valid", add_extension=True)
    pub, spki, cn, dns = sanitize_csr(csr_bytes, ["RSA"], 10000)
    assert cn == "valid"
    assert dns == ["example.com"]


def test_csr_sanitization_extracts_dns_sans():
    csr_bytes = generate_csr(
        cn="svc.local", dns_names=["svc.example.com", "api.example.com"]
    )
    pub, spki, cn, dns = sanitize_csr(csr_bytes, ["RSA"], 10000)
    assert cn == "svc.local"
    assert dns == ["svc.example.com", "api.example.com"]


def test_csr_sanitization_dedupes_dns_sans():
    csr_bytes = generate_csr(
        cn="svc.local", dns_names=["dup.example.com", "dup.example.com"]
    )
    pub, spki, cn, dns = sanitize_csr(csr_bytes, ["RSA"], 10000)
    assert dns == ["dup.example.com"]


def test_csr_sanitization_drops_unsafe_dns_sans():
    csr_bytes = generate_csr(
        cn="svc.local",
        dns_names=["*.wildcard.example.com", "10.0.0.1", "good.example.com"],
    )
    pub, spki, cn, dns = sanitize_csr(csr_bytes, ["RSA"], 10000)
    assert dns == ["good.example.com"]


def test_csr_bad_size():
    csr_bytes = generate_csr()
    with pytest.raises(ValueError, match="exceeds maximum allowed size"):
        sanitize_csr(csr_bytes, ["RSA"], 100)  # strict 100 byte limit
