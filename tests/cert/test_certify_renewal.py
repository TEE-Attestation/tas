#
# TEE Attestation Service - Certificate Renewal Tests
#
# Copyright 2026 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# This file is part of the TEE Attestation Service.
#

import base64
import os
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtensionOID, NameOID

os.environ["TAS_API_KEY"] = "a" * 64
os.environ["TAS_MANAGEMENT_API_KEY"] = "b" * 64
os.environ["TAS_CERT_ENABLED"] = "true"

from app import app as flask_app
from tests.cert.cert_test_utils import API_HEADERS, build_certify_payload, get_nonce


@pytest.fixture
def test_client():
    flask_app.config["TESTING"] = True
    flask_app.config["TAS_API_KEY"] = "a" * 64
    with flask_app.test_client() as client:
        yield client


def _mock_attestation(monkeypatch):
    import tas.cert.routes as cert_routes

    monkeypatch.setattr(
        cert_routes,
        "vm_verify",
        lambda *args, **kwargs: (True, "key_id_123", None),
    )


def _new_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=3072)


def _csr_for_key(private_key, cn="renew.local"):
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, cn),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "My Company"),
                ]
            )
        )
        .sign(private_key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM)


def _csr_b64(private_key):
    return base64.b64encode(_csr_for_key(private_key)).decode("ascii")


def _post_certify(test_client, payload):
    return test_client.post("/alphav1/certify", json=payload, headers=API_HEADERS)


def _spiffe_uri(cert_pem):
    cert = x509.load_pem_x509_certificate(cert_pem.encode("ascii"))
    san_ext = cert.extensions.get_extension_for_oid(
        ExtensionOID.SUBJECT_ALTERNATIVE_NAME
    )
    uri_sans = san_ext.value.get_values_for_type(x509.UniformResourceIdentifier)
    assert len(uri_sans) == 1
    return uri_sans[0]


def _spiffe_uuid(cert_pem):
    return urlsplit(_spiffe_uri(cert_pem)).path.split("/")[-1]


def _issue_cert(test_client, monkeypatch, private_key, **overrides):
    _mock_attestation(monkeypatch)
    payload = build_certify_payload(
        get_nonce(test_client), _csr_b64(private_key), **overrides
    )
    response = _post_certify(test_client, payload)
    assert response.status_code == 200, response.json
    return response.json["certificate"]


def _self_signed_leaf(private_key, uri_sans, *, ca=False, not_after=None):
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "renew.local")])
        )
        .issuer_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "untrusted.local")])
        )
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(not_after or now + timedelta(minutes=5))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    if uri_sans is not None:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(
                [x509.UniformResourceIdentifier(uri) for uri in uri_sans]
            ),
            critical=False,
        )
    cert = builder.sign(private_key, hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


def test_certify_renewal_reuses_spiffe_uuid(test_client, monkeypatch):
    private_key = _new_key()
    prior_cert = _issue_cert(test_client, monkeypatch, private_key)

    payload = build_certify_payload(
        get_nonce(test_client),
        _csr_b64(private_key),
        renew_cert=prior_cert,
    )
    response = _post_certify(test_client, payload)
    assert response.status_code == 200, response.json

    renewed_cert = response.json["certificate"]
    assert _spiffe_uuid(renewed_cert) == _spiffe_uuid(prior_cert)

    prior = x509.load_pem_x509_certificate(prior_cert.encode("ascii"))
    renewed = x509.load_pem_x509_certificate(renewed_cert.encode("ascii"))
    assert renewed.serial_number != prior.serial_number


def test_certify_renewal_rejects_key_mismatch(test_client, monkeypatch):
    prior_cert = _issue_cert(test_client, monkeypatch, _new_key())

    payload = build_certify_payload(
        get_nonce(test_client),
        _csr_b64(_new_key()),
        renew_cert=prior_cert,
    )
    response = _post_certify(test_client, payload)
    assert response.status_code == 400
    assert "public key" in response.json["error"]


def test_certify_renewal_rejects_policy_domain_mismatch(test_client, monkeypatch):
    private_key = _new_key()
    prior_cert = _issue_cert(test_client, monkeypatch, private_key)

    payload = build_certify_payload(
        get_nonce(test_client),
        _csr_b64(private_key),
        renew_cert=prior_cert,
        **{"policy-domain": "prod"},
    )
    response = _post_certify(test_client, payload)
    assert response.status_code == 400
    assert "policy domain" in response.json["error"]


def test_certify_renewal_rejects_untrusted_prior_cert(test_client, monkeypatch):
    _mock_attestation(monkeypatch)
    private_key = _new_key()
    renew_cert = _self_signed_leaf(
        private_key,
        ["spiffe://example.org/staging/11111111-1111-4111-8111-111111111111"],
    )

    payload = build_certify_payload(
        get_nonce(test_client),
        _csr_b64(private_key),
        renew_cert=renew_cert,
    )
    response = _post_certify(test_client, payload)
    assert response.status_code == 400
    assert "active TAS CA" in response.json["error"]


@pytest.mark.parametrize(
    ("renew_cert", "expected"),
    [
        (
            lambda key: _self_signed_leaf(key, None),
            "SPIFFE URI SAN",
        ),
        (
            lambda key: _self_signed_leaf(
                key,
                [
                    "spiffe://example.org/staging/11111111-1111-4111-8111-111111111111",
                    "spiffe://example.org/staging/22222222-2222-4222-8222-222222222222",
                ],
            ),
            "exactly one URI SAN",
        ),
        (
            lambda key: _self_signed_leaf(
                key,
                ["spiffe://example.org/staging/11111111-1111-4111-8111-111111111111"],
                ca=True,
            ),
            "leaf certificate",
        ),
    ],
)
def test_certify_renewal_rejects_bad_prior_cert_profile(
    test_client, monkeypatch, renew_cert, expected
):
    _mock_attestation(monkeypatch)
    private_key = _new_key()
    payload = build_certify_payload(
        get_nonce(test_client),
        _csr_b64(private_key),
        renew_cert=renew_cert(private_key),
    )
    response = _post_certify(test_client, payload)
    assert response.status_code == 400
    assert expected in response.json["error"]
