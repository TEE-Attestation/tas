#
# TEE Attestation Service - CSR Sanitization Tests
#
# Copyright 2026 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# This file is part of the TEE Attestation Service.
#

import ipaddress
import logging

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from tas.cert.csr import sanitize_csr


def generate_csr(
    cn=None,
    add_extension=False,
    dns_names=None,
    ip_addresses=None,
    email_addresses=None,
    return_key=False,
    key_type="RSA",
):
    if key_type == "RSA":
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=3072,
        )
    elif key_type == "EC":
        private_key = ec.generate_private_key(ec.SECP256R1())
    else:
        raise ValueError(f"Unsupported test key type: {key_type}")
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
    if ip_addresses:
        san_entries.extend(
            x509.IPAddress(ipaddress.ip_address(address)) for address in ip_addresses
        )
    if email_addresses:
        san_entries.extend(x509.RFC822Name(address) for address in email_addresses)
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


@pytest.mark.parametrize(
    ("key_type", "allowed_key_types", "expected_public_key_type"),
    [
        ("RSA", ["RSA"], rsa.RSAPublicKey),
        ("EC", ["EC"], ec.EllipticCurvePublicKey),
    ],
)
def test_csr_sanitization_accepts_supported_public_key_types(
    key_type, allowed_key_types, expected_public_key_type
):
    csr_bytes = generate_csr(cn="valid-cn.com", key_type=key_type)

    public_key, *_ = sanitize_csr(csr_bytes, allowed_key_types, 10000)

    assert isinstance(public_key, expected_public_key_type)


def test_csr_sanitization_valid():
    csr_bytes = generate_csr(cn="valid-cn.com")
    pub, spki, cn, dns, *_ = sanitize_csr(csr_bytes, ["RSA"], 10000)
    assert cn == "valid-cn.com"
    assert spki is not None
    assert dns == []


def test_csr_sanitization_no_cn():
    csr_bytes = generate_csr()
    pub, spki, cn, dns, *_ = sanitize_csr(csr_bytes, ["RSA"], 10000)
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
    pub, spki, cn, dns, *_ = sanitize_csr(csr_bytes, ["RSA"], 10000)
    assert cn == "valid"
    assert dns == ["example.com"]


def test_csr_sanitization_extracts_dns_sans():
    csr_bytes = generate_csr(
        cn="svc.local", dns_names=["svc.example.com", "api.example.com"]
    )
    pub, spki, cn, dns, *_ = sanitize_csr(csr_bytes, ["RSA"], 10000)
    assert cn == "svc.local"
    assert dns == ["svc.example.com", "api.example.com"]


def test_csr_sanitization_dedupes_dns_sans():
    csr_bytes = generate_csr(
        cn="svc.local", dns_names=["dup.example.com", "dup.example.com"]
    )
    pub, spki, cn, dns, *_ = sanitize_csr(csr_bytes, ["RSA"], 10000)
    assert dns == ["dup.example.com"]


def test_csr_sanitization_drops_unsafe_dns_sans():
    csr_bytes = generate_csr(
        cn="svc.local",
        dns_names=["*.wildcard.example.com", "10.0.0.1", "good.example.com"],
    )
    pub, spki, cn, dns, *_ = sanitize_csr(csr_bytes, ["RSA"], 10000)
    assert dns == ["good.example.com"]


@pytest.mark.parametrize(
    "san_kwargs, san_type",
    [
        (
            {"dns_names": [f"service-{index}.example.com" for index in range(17)]},
            "DNS",
        ),
        (
            {"ip_addresses": [f"192.0.2.{index}" for index in range(1, 10)]},
            "IP",
        ),
        (
            {"email_addresses": [f"service-{index}@example.com" for index in range(9)]},
            "email",
        ),
    ],
)
def test_csr_sanitization_rejects_excessive_san_entries(san_kwargs, san_type):
    csr_bytes = generate_csr(cn="svc.local", **san_kwargs)

    with pytest.raises(ValueError, match=rf"too many {san_type} SAN entries"):
        sanitize_csr(csr_bytes, ["RSA"], 10000)


def test_csr_bad_size():
    csr_bytes = generate_csr()
    with pytest.raises(ValueError, match="exceeds maximum allowed size"):
        sanitize_csr(csr_bytes, ["RSA"], 100)  # strict 100 byte limit


def test_csr_sanitization_extracts_ip_and_email_sans():
    csr_bytes = generate_csr(
        cn="svc.local",
        ip_addresses=["192.0.2.10", "2001:db8::1", "192.0.2.10"],
        email_addresses=["service@example.com", "service@example.com"],
    )

    _, _, _, _, ip_addresses, email_addresses = sanitize_csr(csr_bytes, ["RSA"], 10000)

    assert ip_addresses == ["192.0.2.10", "2001:db8::1"]
    assert email_addresses == ["service@example.com"]


@pytest.mark.parametrize(
    "email_address",
    [
        'quoted"local@example.com',
        "bang!local@example.com",
        "percent%local@example.com",
        ".leading-dot@example.com",
        "trailing-dot.@example.com",
        "consecutive..dots@example.com",
        f"{'a' * 65}@example.com",
        f"{'a' * 64}@{'a' * 63}.{'b' * 63}.{'c' * 62}",
    ],
)
def test_csr_sanitization_drops_unsafe_email_local_parts(email_address):
    csr_bytes = generate_csr(cn="svc.local", email_addresses=[email_address])

    _, _, _, _, _, email_addresses = sanitize_csr(csr_bytes, ["RSA"], 10000)

    assert email_addresses == []


def test_csr_sanitization_accepts_safe_email_local_part_at_length_limit():
    email_address = f"{'a' * 64}@{'a' * 63}.{'b' * 63}.{'c' * 61}"
    csr_bytes = generate_csr(cn="svc.local", email_addresses=[email_address])

    _, _, _, _, _, email_addresses = sanitize_csr(csr_bytes, ["RSA"], 10000)

    assert email_addresses == [email_address]


def test_csr_sanitization_logs_invalid_san_counts(caplog):
    csr_bytes = generate_csr(
        cn="svc.local",
        dns_names=["*.wildcard.example.com"],
        email_addresses=["invalid@bad_domain", "valid@example.com"],
    )

    with caplog.at_level(logging.DEBUG, logger="tas.cert.csr"):
        _, _, _, dns_names, _, email_addresses = sanitize_csr(csr_bytes, ["RSA"], 10000)

    assert dns_names == []
    assert email_addresses == ["valid@example.com"]
    warning_messages = [
        record.getMessage()
        for record in caplog.records
        if record.levelno == logging.WARNING
    ]
    debug_messages = [
        record.getMessage()
        for record in caplog.records
        if record.levelno == logging.DEBUG
    ]
    assert warning_messages == [
        "Dropped 1 invalid DNS SAN entries",
        "Dropped 1 invalid email SAN entries",
    ]
    assert all("wildcard" not in message for message in warning_messages)
    assert all("invalid@bad_domain" not in message for message in warning_messages)
    assert "Dropped invalid DNS SAN value: *.wildcard.example.com" in debug_messages
    assert "Dropped invalid email SAN value: invalid@bad_domain" in debug_messages


def test_csr_sanitization_caps_invalid_san_debug_logs(caplog):
    invalid_dns_names = [f"*.invalid-{index}.example.com" for index in range(4)]
    csr_bytes = generate_csr(cn="svc.local", dns_names=invalid_dns_names)

    with caplog.at_level(logging.DEBUG, logger="tas.cert.csr"):
        sanitize_csr(csr_bytes, ["RSA"], 10000)

    warning_messages = [
        record.getMessage()
        for record in caplog.records
        if record.levelno == logging.WARNING
    ]
    debug_messages = [
        record.getMessage()
        for record in caplog.records
        if record.levelno == logging.DEBUG
    ]

    assert warning_messages == ["Dropped 4 invalid DNS SAN entries"]
    assert debug_messages == [
        f"Dropped invalid DNS SAN value: {name}" for name in invalid_dns_names[:3]
    ]
