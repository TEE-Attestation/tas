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
from asn1crypto import csr as asn1_csr
from asn1crypto import keys as asn1_keys
from asn1crypto import x509 as asn1_x509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import NameOID

from tas.certify.csr import sanitize_csr


def generate_csr(
    cn=None,
    add_extension=False,
    dns_names=None,
    ip_addresses=None,
    email_addresses=None,
    uri_sans=None,
    return_key=False,
    duplicate_common_name=False,
    key_type="RSA",
    ec_curve=None,
    rsa_key_size=3072,
):
    if key_type == "RSA":
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=rsa_key_size,
        )
    elif key_type == "EC":
        private_key = ec.generate_private_key(ec_curve or ec.SECP256R1())
    else:
        raise ValueError(f"Unsupported test key type: {key_type}")
    builder = x509.CertificateSigningRequestBuilder()

    name_attrs = []
    if cn is not None:
        name_attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, cn))
        if duplicate_common_name:
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
    if uri_sans:
        san_entries.extend(x509.UniformResourceIdentifier(uri) for uri in uri_sans)
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


def generate_csr_with_overlong_cn(cn):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072,
    )
    request_info = asn1_csr.CertificationRequestInfo(
        {
            "version": "v1",
            "subject": asn1_x509.Name.build(
                {"common_name": cn, "organization_name": "My Company"}
            ),
            "subject_pk_info": asn1_keys.PublicKeyInfo.load(
                private_key.public_key().public_bytes(
                    serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            ),
            "attributes": [],
        }
    )
    signature = private_key.sign(
        request_info.dump(),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    request = asn1_csr.CertificationRequest(
        {
            "certification_request_info": request_info,
            "signature_algorithm": {"algorithm": "sha256_rsa"},
            "signature": signature,
        }
    )
    return request.dump()


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


@pytest.mark.parametrize(
    ("curve", "is_allowed"),
    [
        (ec.SECP256R1(), True),
        (ec.SECP384R1(), True),
        (ec.SECP256K1(), False),
        (ec.BrainpoolP256R1(), False),
        (ec.BrainpoolP384R1(), False),
        (ec.SECP521R1(), False),
    ],
)
def test_csr_sanitization_enforces_allowed_ec_curves(curve, is_allowed):
    csr_bytes = generate_csr(cn="valid-cn.com", key_type="EC", ec_curve=curve)

    if is_allowed:
        public_key, *_ = sanitize_csr(csr_bytes, ["EC"], 10000)
        assert public_key.curve.name == curve.name
    else:
        with pytest.raises(ValueError, match="Public key type or size is not allowed"):
            sanitize_csr(csr_bytes, ["EC"], 10000)


@pytest.mark.parametrize(
    ("rsa_key_size", "is_allowed"),
    [(3072, True), (2048, False)],
)
def test_csr_sanitization_enforces_minimum_rsa_key_size(rsa_key_size, is_allowed):
    csr_bytes = generate_csr(cn="valid-cn.com", rsa_key_size=rsa_key_size)

    if is_allowed:
        public_key, *_ = sanitize_csr(csr_bytes, ["RSA"], 10000)
        assert public_key.key_size == rsa_key_size
    else:
        with pytest.raises(ValueError, match="Public key type or size is not allowed"):
            sanitize_csr(csr_bytes, ["RSA"], 10000)


@pytest.mark.parametrize(
    ("key_type", "allowed_key_types"),
    [("RSA", ["EC"]), ("EC", ["RSA"])],
)
def test_csr_sanitization_respects_allowed_key_families(key_type, allowed_key_types):
    csr_bytes = generate_csr(cn="valid-cn.com", key_type=key_type)

    with pytest.raises(ValueError, match="Public key type or size is not allowed"):
        sanitize_csr(csr_bytes, allowed_key_types, 10000)


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


@pytest.mark.parametrize(
    "cn",
    ["---", "..a..", "-bad.example", "bad-.example", ".example", "example.", "a..b"],
)
def test_csr_sanitization_rejects_malformed_dns_common_names(cn):
    csr_bytes = generate_csr(cn=cn)

    with pytest.raises(ValueError, match="DNS-safe name"):
        sanitize_csr(csr_bytes, ["RSA"], 10000)


@pytest.mark.parametrize(
    ("cn", "is_allowed"),
    [
        ("a" * 63, True),
        ("a" * 64, False),
        (f"{'a' * 62}.b", True),
        (f"{'a' * 63}.b", False),
    ],
)
def test_csr_sanitization_enforces_common_name_length_limits(cn, is_allowed):
    if len(cn) > 64:
        csr_bytes = generate_csr_with_overlong_cn(cn)
    else:
        csr_bytes = generate_csr(cn=cn)

    if is_allowed:
        _, _, subject_cn, *_ = sanitize_csr(csr_bytes, ["RSA"], 10000)
        assert subject_cn == cn
    else:
        if len(cn) > 64:
            with pytest.warns(UserWarning, match="Attribute's length"):
                with pytest.raises(ValueError, match="Common Name"):
                    sanitize_csr(csr_bytes, ["RSA"], 10000)
        else:
            with pytest.raises(ValueError, match="Common Name"):
                sanitize_csr(csr_bytes, ["RSA"], 10000)


def test_csr_sanitization_accepts_pem_and_der_and_returns_matching_spki():
    csr_pem = generate_csr(cn="valid-cn.com", key_type="EC", ec_curve=ec.SECP384R1())
    csr = x509.load_pem_x509_csr(csr_pem)
    csr_der = csr.public_bytes(serialization.Encoding.DER)

    for csr_bytes in (csr_pem, csr_der):
        result = sanitize_csr(csr_bytes, ["EC"], 10000)

        assert len(result) == 6
        public_key, spki_der, subject_cn, dns_names, ip_addresses, email_addresses = (
            result
        )
        assert spki_der == public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        assert subject_cn == "valid-cn.com"
        assert dns_names == []
        assert ip_addresses == []
        assert email_addresses == []


def test_csr_sanitization_rejects_invalid_signature():
    csr = x509.load_pem_x509_csr(generate_csr(cn="valid-cn.com"))
    csr_der = bytearray(csr.public_bytes(serialization.Encoding.DER))
    csr_der[-1] ^= 1

    with pytest.raises(ValueError, match="signature .* invalid"):
        sanitize_csr(bytes(csr_der), ["RSA"], 10000)


def test_csr_sanitization_rejects_malformed_der():
    for csr_bytes in (b"", b"not a CSR"):
        with pytest.raises(ValueError, match="Failed to parse CSR"):
            sanitize_csr(csr_bytes, ["RSA"], 10000)


def test_csr_sanitization_rejects_multiple_common_names():
    csr_bytes = generate_csr(cn="valid-cn.com", duplicate_common_name=True)

    with pytest.raises(ValueError, match="multiple Common Name"):
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


@pytest.mark.parametrize("bad_dns", ["*.wildcard.example.com", "10.0.0.1"])
def test_csr_sanitization_rejects_unsafe_dns_san_alongside_valid_one(bad_dns):
    # One bad entry fails the whole CSR; valid siblings do not rescue it.
    csr_bytes = generate_csr(
        cn="svc.local",
        dns_names=["good.example.com", bad_dns],
    )
    with pytest.raises(ValueError, match="invalid DNS SAN entry"):
        sanitize_csr(csr_bytes, ["RSA"], 10000)


@pytest.mark.parametrize(
    ("dns_name", "is_safe"),
    [
        ("a" * 63, True),
        ("a" * 64, False),
        (f"{'a' * 63}.{'b' * 63}.{'c' * 63}.{'d' * 61}", True),
        (f"{'a' * 63}.{'b' * 63}.{'c' * 63}.{'d' * 62}", False),
        ("example.com\n", False),
        ("-bad.example", False),
        ("bad-.example", False),
        (".example", False),
        ("example.", False),
        ("a..b", False),
        ("10.0.0.1", False),
    ],
)
def test_csr_sanitization_dns_san_boundaries_and_malformed_names(dns_name, is_safe):
    csr_bytes = generate_csr(cn="valid-cn.com", dns_names=[dns_name])

    if is_safe:
        _, _, _, dns_names, *_ = sanitize_csr(csr_bytes, ["RSA"], 10000)
        assert dns_names == [dns_name]
    else:
        with pytest.raises(ValueError, match="invalid DNS SAN entry"):
            sanitize_csr(csr_bytes, ["RSA"], 10000)


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

    sanitize_csr(csr_bytes, ["RSA"], len(csr_bytes))

    with pytest.raises(ValueError, match="exceeds maximum allowed size"):
        sanitize_csr(csr_bytes, ["RSA"], len(csr_bytes) - 1)


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
def test_csr_sanitization_rejects_unsafe_email_sans(email_address):
    csr_bytes = generate_csr(cn="svc.local", email_addresses=[email_address])

    with pytest.raises(ValueError, match="invalid email SAN entry"):
        sanitize_csr(csr_bytes, ["RSA"], 10000)


def test_csr_sanitization_accepts_safe_email_local_part_at_length_limit():
    email_address = f"{'a' * 64}@{'a' * 63}.{'b' * 63}.{'c' * 61}"
    csr_bytes = generate_csr(cn="svc.local", email_addresses=[email_address])

    _, _, _, _, _, email_addresses = sanitize_csr(csr_bytes, ["RSA"], 10000)

    assert email_addresses == [email_address]


def test_csr_sanitization_invalid_san_keeps_value_out_of_error_and_warning(caplog):
    bad_value = "evil.example.com\nFORGED_LOG_ENTRY"
    csr_bytes = generate_csr(
        cn="svc.local",
        dns_names=["good.example.com", bad_value],
    )

    with caplog.at_level(logging.DEBUG, logger="tas.certify.csr"):
        with pytest.raises(ValueError) as exc_info:
            sanitize_csr(csr_bytes, ["RSA"], 10000)

    assert str(exc_info.value) == "CSR contains an invalid DNS SAN entry"
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
    assert warning_messages == ["Rejected CSR with invalid DNS SAN entry"]
    # Debug output carries the value only in repr() form, so the embedded
    # newline cannot start a forged log line.
    assert debug_messages == [f"Invalid DNS SAN value: {bad_value!r}"]
    assert all("\n" not in message for message in debug_messages)
