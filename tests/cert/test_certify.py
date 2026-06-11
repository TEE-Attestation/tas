#
# TEE Attestation Service - Certificate Route Tests
#
# Copyright 2026 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# This file is part of the TEE Attestation Service.
#

import base64
import json
import os
import shutil
import subprocess
import tempfile
from urllib.parse import urlsplit

import pytest
from asn1crypto import core
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import (
    ExtendedKeyUsageOID,
    ExtensionOID,
    NameOID,
    ObjectIdentifier,
)

os.environ["TAS_API_KEY"] = "a" * 64
os.environ["TAS_MANAGEMENT_API_KEY"] = "b" * 64
os.environ["TAS_CERT_ENABLED"] = "true"

from app import app as flask_app
from tests.cert.cert_test_utils import API_HEADERS, build_certify_payload, get_nonce
from tests.cert.test_csr_sanitization import generate_csr

TAS_EVIDENCE_DIGESTS_OID = ObjectIdentifier("1.3.6.1.4.1.65993.5")


@pytest.fixture
def test_client():
    flask_app.config["TESTING"] = True
    flask_app.config["TAS_API_KEY"] = "a" * 64
    with flask_app.test_client() as client:
        yield client


def _post_certify(test_client, payload, headers=API_HEADERS):
    return test_client.post("/alphav1/certify", json=payload, headers=headers)


def test_certify_flow(test_client, monkeypatch):
    import tas.cert.routes as cert_routes

    def mock_vm_verify(*args, **kwargs):
        assert kwargs.get("report_data_binding") is True
        return True, "key_id_123", None

    monkeypatch.setattr(cert_routes, "vm_verify", mock_vm_verify)

    nonce = get_nonce(test_client)
    csr_bytes = generate_csr(cn="test-workload.local")
    csr_b64 = base64.b64encode(csr_bytes).decode("ascii")
    payload = build_certify_payload(nonce, csr_b64)

    response = _post_certify(test_client, payload)
    assert response.status_code == 200, response.json

    data = response.json
    assert "certificate" in data
    assert "ca_chain" in data

    cert = x509.load_pem_x509_certificate(data["certificate"].encode("ascii"))

    # X509-SVID requires exactly one URI SAN (the SPIFFE ID).
    san_ext = cert.extensions.get_extension_for_oid(
        ExtensionOID.SUBJECT_ALTERNATIVE_NAME
    )
    uri_sans = san_ext.value.get_values_for_type(x509.UniformResourceIdentifier)
    assert len(uri_sans) == 1
    assert uri_sans[0].startswith("spiffe://example.org/staging/")

    # SPIFFE leaf constraints: CA=false, critical KU, no cert signing usages.
    bc_ext = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
    assert bc_ext.critical is True
    assert bc_ext.value.ca is False

    ku_ext = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
    assert ku_ext.critical is True
    assert ku_ext.value.digital_signature is True
    assert ku_ext.value.key_cert_sign is False
    assert ku_ext.value.crl_sign is False

    # Leaf EKU should include both client and server auth.
    eku_ext = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
    assert ExtendedKeyUsageOID.CLIENT_AUTH in eku_ext.value
    assert ExtendedKeyUsageOID.SERVER_AUTH in eku_ext.value

    # Subject CN is preserved from CSR when provided.
    cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    assert cn_attrs[0].value == "test-workload.local"


def test_certify_emits_canonical_evidence_digests(test_client, monkeypatch):
    import hashlib

    import tas.cert.routes as cert_routes

    monkeypatch.setattr(
        cert_routes,
        "vm_verify",
        lambda *args, **kwargs: (True, "key_id_123", None),
    )

    nonce = get_nonce(test_client)
    csr_bytes = generate_csr(cn="digest-test.local")
    csr_b64 = base64.b64encode(csr_bytes).decode("ascii")
    cpu_raw = b"cpu evidence"
    gpu0_raw = b"gpu evidence zero"
    gpu1_raw = b"gpu evidence one"
    payload = build_certify_payload(
        nonce,
        csr_b64,
        **{
            "tee-evidence": base64.b64encode(cpu_raw).decode("ascii"),
            "gpu-evidence": [
                {
                    "type": "nvidia-h100",
                    "evidence": base64.b64encode(gpu1_raw).decode("ascii"),
                    "device-index": 1,
                },
                {
                    "type": "nvidia-h100",
                    "evidence": base64.b64encode(gpu0_raw).decode("ascii"),
                    "device-index": 0,
                },
            ],
        },
    )

    response = _post_certify(test_client, payload)
    assert response.status_code == 200, response.json

    cert = x509.load_pem_x509_certificate(response.json["certificate"].encode("ascii"))
    ext = cert.extensions.get_extension_for_oid(TAS_EVIDENCE_DIGESTS_OID)
    evidence_doc = json.loads(core.UTF8String.load(ext.value.value).native)

    assert evidence_doc == {
        "version": 1,
        "entries": [
            {
                "digest": hashlib.sha512(cpu_raw).hexdigest(),
                "digest_alg": "sha-512",
                "evidence_type": "sev-snp-report",
                "platform_id": "amd-sev-snp",
                "role": "cpu",
            },
            {
                "digest": hashlib.sha512(gpu0_raw).hexdigest(),
                "digest_alg": "sha-512",
                "evidence_type": "gpu-attestation-report",
                "platform_id": "nvidia-h100",
                "slot": 0,
            },
            {
                "digest": hashlib.sha512(gpu1_raw).hexdigest(),
                "digest_alg": "sha-512",
                "evidence_type": "gpu-attestation-report",
                "platform_id": "nvidia-h100",
                "slot": 1,
            },
        ],
    }


def test_certify_nonce_replay_rejected(test_client, monkeypatch):
    import tas.cert.routes as cert_routes

    monkeypatch.setattr(
        cert_routes, "vm_verify", lambda *args, **kwargs: (True, "key_id_123", None)
    )

    nonce = get_nonce(test_client)
    csr_b64 = base64.b64encode(generate_csr(cn="replay-test.local")).decode("ascii")
    payload = build_certify_payload(nonce, csr_b64)

    first = _post_certify(test_client, payload)
    assert first.status_code == 200, first.json

    second = _post_certify(test_client, payload)
    assert second.status_code == 403
    assert second.json["error"] == "Invalid or expired nonce"


def test_certify_expired_nonce_rejected(test_client, monkeypatch):
    import tas.cert.routes as cert_routes

    monkeypatch.setattr(
        cert_routes, "vm_verify", lambda *args, **kwargs: (True, "key_id_123", None)
    )

    nonce = get_nonce(test_client)

    # Simulate expiry by deleting the nonce before certify uses it.
    nonce_client = flask_app.extensions.get(
        "redis_ephemeral", flask_app.extensions["redis"]
    )
    nonce_client.delete(nonce)

    csr_b64 = base64.b64encode(generate_csr(cn="expired-test.local")).decode("ascii")
    payload = build_certify_payload(nonce, csr_b64)

    response = _post_certify(test_client, payload)
    assert response.status_code == 403
    assert response.json["error"] == "Invalid or expired nonce"


@pytest.mark.parametrize(
    "headers",
    [{}, {"X-API-Key": "bad-key"}],
)
def test_nonce_requires_valid_api_key(test_client, headers):
    response = test_client.get("/alphav1/nonce", headers=headers)
    assert response.status_code == 401
    assert response.json["error"] == "Unauthorized"


@pytest.mark.parametrize(
    "headers",
    [{}, {"X-API-Key": "bad-key"}],
)
def test_certify_requires_valid_api_key(test_client, headers):
    response = _post_certify(test_client, payload={}, headers=headers)
    assert response.status_code == 401
    assert response.json["error"] == "Unauthorized"


def test_certify_attestation_failure_rejected(test_client, monkeypatch):
    import tas.cert.routes as cert_routes

    monkeypatch.setattr(
        cert_routes,
        "vm_verify",
        lambda *args, **kwargs: (False, None, "Attestation verification failed"),
    )

    nonce = get_nonce(test_client)
    csr_b64 = base64.b64encode(generate_csr(cn="attestation-fail.local")).decode(
        "ascii"
    )
    payload = build_certify_payload(nonce, csr_b64)

    response = _post_certify(test_client, payload)
    assert response.status_code == 403
    assert response.json["error"] == "Attestation verification failed"


def test_certify_cn_fallback_when_missing(test_client, monkeypatch):
    import tas.cert.routes as cert_routes

    monkeypatch.setattr(
        cert_routes, "vm_verify", lambda *args, **kwargs: (True, "key_id_123", None)
    )

    nonce = get_nonce(test_client)
    csr_b64 = base64.b64encode(generate_csr(cn=None)).decode("ascii")
    payload = build_certify_payload(nonce, csr_b64)

    response = _post_certify(test_client, payload)
    assert response.status_code == 200, response.json

    cert = x509.load_pem_x509_certificate(response.json["certificate"].encode("ascii"))
    cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    assert len(cn_attrs) == 1
    assert cn_attrs[0].value.startswith("tas.")


def test_certify_rejects_evidence_digest_limit_overflow(test_client, monkeypatch):
    import tas.cert.routes as cert_routes

    monkeypatch.setattr(
        cert_routes, "vm_verify", lambda *args, **kwargs: (True, "key_id_123", None)
    )

    original_limit = test_client.application.config.get(
        "TAS_CERT_EVIDENCE_DIGEST_MAX_BYTES", 4096
    )
    test_client.application.config["TAS_CERT_EVIDENCE_DIGEST_MAX_BYTES"] = 32
    try:
        nonce = get_nonce(test_client)
        csr_b64 = base64.b64encode(generate_csr(cn="limit-test.local")).decode("ascii")
        payload = build_certify_payload(nonce, csr_b64)

        response = _post_certify(test_client, payload)
        assert response.status_code == 400
        assert (
            response.json["error"]
            == "Evidence digest JSON exceeds configured maximum size"
        )
    finally:
        test_client.application.config["TAS_CERT_EVIDENCE_DIGEST_MAX_BYTES"] = (
            original_limit
        )


@pytest.mark.parametrize("bad_csr", ["%%%not-base64%%%", "not_base64!!", "@@@@"])
def test_certify_rejects_invalid_csr_base64(test_client, bad_csr):
    payload = build_certify_payload(nonce="nonce-placeholder", csr_b64=bad_csr)

    response = _post_certify(test_client, payload)
    assert response.status_code == 400
    assert response.json["error"] == "Invalid base64 encoding for CSR"


@pytest.mark.parametrize(
    "missing_field",
    ["tee-type", "nonce", "tee-evidence", "csr", "policy-domain"],
)
def test_certify_missing_required_field(test_client, missing_field):
    csr_bytes = generate_csr(cn="test-workload.local")
    payload = build_certify_payload(
        nonce="nonce-placeholder",
        csr_b64=base64.b64encode(csr_bytes).decode("ascii"),
    )
    payload.pop(missing_field)

    response = _post_certify(test_client, payload)
    assert response.status_code == 400
    assert response.json["error"] == "Missing required fields"


def test_certify_certificate_renders_with_openssl(test_client, monkeypatch):
    import tas.cert.routes as cert_routes

    if shutil.which("openssl") is None:
        pytest.skip("openssl is not installed in test environment")

    monkeypatch.setattr(
        cert_routes,
        "vm_verify",
        lambda *args, **kwargs: (True, "key_id_123", None),
    )

    nonce = get_nonce(test_client)
    csr_bytes = generate_csr(cn="openssl-render.local")
    csr_b64 = base64.b64encode(csr_bytes).decode("ascii")
    payload = build_certify_payload(nonce, csr_b64)

    response = _post_certify(test_client, payload)
    assert response.status_code == 200, response.json

    cert_pem = response.json["certificate"]

    with tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False) as f:
        f.write(cert_pem)
        cert_path = f.name

    try:
        render = subprocess.run(
            ["openssl", "x509", "-in", cert_path, "-text", "-noout"],
            check=False,
            capture_output=True,
            text=True,
        )
    finally:
        os.unlink(cert_path)

    assert render.returncode == 0, render.stderr
    assert "Certificate:" in render.stdout
    assert "X509v3 extensions:" in render.stdout
    assert "1.3.6.1.4.1.65993.1" in render.stdout
    assert "1.3.6.1.4.1.65993.2" in render.stdout
    assert "1.3.6.1.4.1.65993.3" in render.stdout
    assert "1.3.6.1.4.1.65993.4" in render.stdout
    assert "1.3.6.1.4.1.65993.5" in render.stdout


def test_certify_spiffe_id_x509_svid_compliance(test_client, monkeypatch):
    """Validate issued leaf certificate against X509-SVID SPIFFE ID rules."""
    import tas.cert.routes as cert_routes

    monkeypatch.setattr(
        cert_routes,
        "vm_verify",
        lambda *args, **kwargs: (True, "key_id_123", None),
    )

    nonce = get_nonce(test_client)
    csr_bytes = generate_csr(cn="spiffe-rfc.local")
    csr_b64 = base64.b64encode(csr_bytes).decode("ascii")
    payload = build_certify_payload(nonce, csr_b64)

    response = _post_certify(test_client, payload)
    assert response.status_code == 200, response.json

    cert = x509.load_pem_x509_certificate(response.json["certificate"].encode("ascii"))

    san_ext = cert.extensions.get_extension_for_oid(
        ExtensionOID.SUBJECT_ALTERNATIVE_NAME
    )
    uri_sans = san_ext.value.get_values_for_type(x509.UniformResourceIdentifier)

    # X509-SVID section 2: exactly one URI SAN (exactly one SPIFFE ID).
    assert len(uri_sans) == 1
    spiffe_id = uri_sans[0]

    parsed = urlsplit(spiffe_id)

    # X509-SVID section 5.2: SPIFFE ID scheme must be spiffe and path must be non-root.
    assert parsed.scheme == "spiffe"
    assert parsed.netloc != ""
    assert parsed.path not in ("", "/")

    # Keep SPIFFE ID canonical for workload identity usage.
    assert parsed.query == ""
    assert parsed.fragment == ""

    # X509-SVID section 5.2 leaf validation constraints.
    bc_ext = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
    assert bc_ext.value.ca is False

    ku_ext = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
    assert ku_ext.critical is True
    assert ku_ext.value.key_cert_sign is False
    assert ku_ext.value.crl_sign is False

    # X509-SVID section 3.1 + RFC5280: if subject is omitted, SAN must be critical.
    if len(cert.subject.rdns) == 0:
        assert san_ext.critical is True


def test_ca_chain_spiffe_trust_domain_matches_leaf(test_client, monkeypatch):
    """Validate CA chain trust domain matches leaf certificate trust domain."""
    from urllib.parse import urlsplit

    from cryptography import x509
    from cryptography.x509.oid import ExtensionOID

    import tas.cert.routes as cert_routes

    def mock_vm_verify(*args, **kwargs):
        return True, "key_id_123", None

    monkeypatch.setattr(cert_routes, "vm_verify", mock_vm_verify)

    nonce = get_nonce(test_client)
    csr_bytes = generate_csr(cn="test-workload.local")
    csr_b64 = base64.b64encode(csr_bytes).decode(
        "ascii"
    )  # base64 imported at module level
    payload = build_certify_payload(nonce, csr_b64)

    resp = _post_certify(test_client, payload)
    assert resp.status_code == 200
    result = resp.json
    assert result["ca_chain"]
    assert len(result["ca_chain"]) > 0

    # Parse leaf cert to get trust domain (PEM format)
    leaf_cert = x509.load_pem_x509_certificate(result["certificate"].encode("ascii"))
    leaf_san_ext = leaf_cert.extensions.get_extension_for_oid(
        ExtensionOID.SUBJECT_ALTERNATIVE_NAME
    )
    leaf_uri_sans = leaf_san_ext.value.get_values_for_type(
        x509.UniformResourceIdentifier
    )
    leaf_spiffe_id = leaf_uri_sans[0]
    leaf_parsed = urlsplit(leaf_spiffe_id)
    leaf_trust_domain = leaf_parsed.netloc

    # Parse CA cert (first in chain) to get trust domain
    ca_cert = x509.load_pem_x509_certificate(result["ca_chain"][0].encode("ascii"))
    ca_san_ext = ca_cert.extensions.get_extension_for_oid(
        ExtensionOID.SUBJECT_ALTERNATIVE_NAME
    )
    ca_uri_sans = ca_san_ext.value.get_values_for_type(x509.UniformResourceIdentifier)
    ca_spiffe_id = ca_uri_sans[0]
    ca_parsed = urlsplit(ca_spiffe_id)
    ca_trust_domain = ca_parsed.netloc

    # Assert trust domains match
    assert ca_trust_domain == leaf_trust_domain


def test_certify_ca_chain_renders_with_openssl(test_client, monkeypatch):
    """Validate both leaf and CA chain certs render cleanly with OpenSSL."""
    import subprocess
    import tempfile

    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    import tas.cert.routes as cert_routes

    def mock_vm_verify(*args, **kwargs):
        return True, "key_id_123", None

    monkeypatch.setattr(cert_routes, "vm_verify", mock_vm_verify)

    nonce = get_nonce(test_client)
    csr_bytes = generate_csr(cn="test-workload.local")
    csr_b64 = base64.b64encode(csr_bytes).decode("ascii")
    payload = build_certify_payload(nonce, csr_b64)

    resp = _post_certify(test_client, payload)
    assert resp.status_code == 200
    result = resp.json

    # Certificates are already in PEM format
    leaf_pem = result["certificate"]
    ca_pem = result["ca_chain"][0]

    # Test leaf cert with OpenSSL
    with tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False) as f:
        f.write(leaf_pem)
        leaf_pem_path = f.name

    try:
        result = subprocess.run(
            ["openssl", "x509", "-text", "-noout", "-in", leaf_pem_path],
            capture_output=True,
            text=True,
            timeout=5,
        )
        assert result.returncode == 0, f"OpenSSL failed on leaf: {result.stderr}"
        assert "Subject Alternative Name" in result.stdout
        assert "spiffe://" in result.stdout
    finally:
        import os as os_module

        os_module.unlink(leaf_pem_path)

    # Test CA cert with OpenSSL
    with tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False) as f:
        f.write(ca_pem)
        ca_pem_path = f.name

    try:
        result = subprocess.run(
            ["openssl", "x509", "-text", "-noout", "-in", ca_pem_path],
            capture_output=True,
            text=True,
            timeout=5,
        )
        assert result.returncode == 0, f"OpenSSL failed on CA: {result.stderr}"
        assert "Subject Alternative Name" in result.stdout
        assert "spiffe://" in result.stdout
    finally:
        import os as os_module

        os_module.unlink(ca_pem_path)


def _issue_leaf(test_client, monkeypatch, cn="chain-test.local", dns_names=None):
    """Helper: drive a successful certify call and return the parsed JSON."""
    import tas.cert.routes as cert_routes

    monkeypatch.setattr(
        cert_routes,
        "vm_verify",
        lambda *args, **kwargs: (True, "key_id_123", None),
    )

    nonce = get_nonce(test_client)
    csr_bytes = generate_csr(cn=cn, dns_names=dns_names)
    csr_b64 = base64.b64encode(csr_bytes).decode("ascii")
    payload = build_certify_payload(nonce, csr_b64)

    response = _post_certify(test_client, payload)
    assert response.status_code == 200, response.json
    return response.json


def test_certify_returns_two_element_chain_and_bundle(test_client, monkeypatch):
    """ca_chain has [intermediate, root] and ca_bundle concatenates both PEMs."""
    result = _issue_leaf(test_client, monkeypatch)

    assert "ca_chain" in result
    assert len(result["ca_chain"]) == 2

    intermediate = x509.load_pem_x509_certificate(result["ca_chain"][0].encode("ascii"))
    root = x509.load_pem_x509_certificate(result["ca_chain"][1].encode("ascii"))

    int_cn = intermediate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    root_cn = root.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    assert int_cn == "ca.example.org"
    assert root_cn == "ca-root.example.org"

    # ca_bundle is the concatenation of the chain PEMs.
    assert "ca_bundle" in result
    assert result["ca_bundle"] == "".join(result["ca_chain"])
    assert result["ca_bundle"].count("-----BEGIN CERTIFICATE-----") == 2


def test_certify_full_chain_signature_verification(test_client, monkeypatch):
    """Verify leaf<-intermediate<-root signatures and root self-signature."""
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

    result = _issue_leaf(test_client, monkeypatch)

    leaf = x509.load_pem_x509_certificate(result["certificate"].encode("ascii"))
    intermediate = x509.load_pem_x509_certificate(result["ca_chain"][0].encode("ascii"))
    root = x509.load_pem_x509_certificate(result["ca_chain"][1].encode("ascii"))

    def verify(cert, issuer):
        pub = issuer.public_key()
        if isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                ec.ECDSA(cert.signature_hash_algorithm),
            )
        elif isinstance(pub, rsa.RSAPublicKey):
            pub.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm,
            )
        else:
            raise AssertionError("unexpected issuer key type")

    # leaf signed by intermediate, intermediate signed by root, root self-signed.
    verify(leaf, intermediate)
    verify(intermediate, root)
    verify(root, root)
    assert root.subject == root.issuer


def test_certify_leaf_includes_csr_dns_sans(test_client, monkeypatch):
    """CSR dNSName SANs appear on the leaf alongside the single SPIFFE URI."""
    result = _issue_leaf(
        test_client,
        monkeypatch,
        cn="dns-leaf.local",
        dns_names=["svc.example.com", "api.example.com"],
    )

    leaf = x509.load_pem_x509_certificate(result["certificate"].encode("ascii"))
    san = leaf.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)

    uri_sans = san.value.get_values_for_type(x509.UniformResourceIdentifier)
    assert len(uri_sans) == 1
    assert uri_sans[0].startswith("spiffe://example.org/")

    dns_sans = san.value.get_values_for_type(x509.DNSName)
    assert dns_sans == ["svc.example.com", "api.example.com"]

    eku = leaf.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
    assert ExtendedKeyUsageOID.SERVER_AUTH in eku.value
    assert ExtendedKeyUsageOID.CLIENT_AUTH in eku.value


def test_certify_leaf_without_dns_is_spiffe_only(test_client, monkeypatch):
    """A CSR without dNSName SANs yields a leaf with only the SPIFFE URI."""
    result = _issue_leaf(test_client, monkeypatch, cn="no-dns.local")

    leaf = x509.load_pem_x509_certificate(result["certificate"].encode("ascii"))
    san = leaf.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    assert len(san.value.get_values_for_type(x509.UniformResourceIdentifier)) == 1
    assert san.value.get_values_for_type(x509.DNSName) == []


def test_certify_drops_unsafe_csr_dns_sans(test_client, monkeypatch):
    """Wildcard/IP-literal dNSName SANs in the CSR are dropped from the leaf."""
    result = _issue_leaf(
        test_client,
        monkeypatch,
        cn="filter-dns.local",
        dns_names=["*.bad.example.com", "10.0.0.1", "ok.example.com"],
    )

    leaf = x509.load_pem_x509_certificate(result["certificate"].encode("ascii"))
    san = leaf.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    assert san.value.get_values_for_type(x509.DNSName) == ["ok.example.com"]


def test_certify_chain_verifies_with_openssl(test_client, monkeypatch):
    """openssl verify accepts the leaf using root as CA and intermediate as untrusted."""
    if shutil.which("openssl") is None:
        pytest.skip("openssl is not installed in test environment")

    result = _issue_leaf(
        test_client, monkeypatch, cn="verify.local", dns_names=["verify.example.com"]
    )

    leaf_pem = result["certificate"]
    intermediate_pem = result["ca_chain"][0]
    root_pem = result["ca_chain"][1]

    tmp = tempfile.mkdtemp()
    try:
        leaf_path = os.path.join(tmp, "leaf.pem")
        int_path = os.path.join(tmp, "int.pem")
        root_path = os.path.join(tmp, "root.pem")
        with open(leaf_path, "w") as f:
            f.write(leaf_pem)
        with open(int_path, "w") as f:
            f.write(intermediate_pem)
        with open(root_path, "w") as f:
            f.write(root_pem)

        verify = subprocess.run(
            [
                "openssl",
                "verify",
                "-CAfile",
                root_path,
                "-untrusted",
                int_path,
                leaf_path,
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        assert verify.returncode == 0, verify.stderr + verify.stdout
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_certify_intermediate_pathlen_blocks_subca(test_client, monkeypatch):
    """Path-length negative test: a sub-CA under the intermediate is rejected.

    The intermediate has pathlen=0, so it may issue only leaves. We craft a
    bogus sub-CA "signed" reference and confirm openssl path validation fails
    when a second CA is inserted below the intermediate.
    """
    if shutil.which("openssl") is None:
        pytest.skip("openssl is not installed in test environment")

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    result = _issue_leaf(test_client, monkeypatch, cn="pathlen.local")
    intermediate = x509.load_pem_x509_certificate(result["ca_chain"][0].encode("ascii"))
    root_pem = result["ca_chain"][1]

    # Build a self-consistent sub-CA whose issuer claims to be the intermediate.
    # Even though it is not validly chained, the point is that pathlen=0 on the
    # intermediate forbids any CA beneath it, so verification must fail.
    subca_key = ec.generate_private_key(ec.SECP384R1())
    subca_name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "sub-ca.example.org")]
    )
    now = __import__("datetime").datetime.now(__import__("datetime").timezone.utc)
    subca = (
        x509.CertificateBuilder()
        .subject_name(subca_name)
        .issuer_name(intermediate.subject)
        .public_key(subca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + __import__("datetime").timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(subca_key, hashes.SHA512())
    )

    # Issue a leaf under the bogus sub-CA.
    leaf_key = ec.generate_private_key(ec.SECP384R1())
    leaf = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "deep-leaf.local")])
        )
        .issuer_name(subca.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + __import__("datetime").timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(subca_key, hashes.SHA512())
    )

    tmp = tempfile.mkdtemp()
    try:
        root_path = os.path.join(tmp, "root.pem")
        chain_path = os.path.join(tmp, "untrusted.pem")
        leaf_path = os.path.join(tmp, "deep_leaf.pem")
        with open(root_path, "w") as f:
            f.write(root_pem)
        with open(chain_path, "w") as f:
            f.write(result["ca_chain"][0])
            f.write(subca.public_bytes(serialization.Encoding.PEM).decode("ascii"))
        with open(leaf_path, "w") as f:
            f.write(leaf.public_bytes(serialization.Encoding.PEM).decode("ascii"))

        verify = subprocess.run(
            [
                "openssl",
                "verify",
                "-CAfile",
                root_path,
                "-untrusted",
                chain_path,
                leaf_path,
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        # pathlen=0 on the intermediate must cause path validation to fail.
        assert verify.returncode != 0
        assert "path length" in (verify.stdout + verify.stderr).lower()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ---------------------------------------------------------------------------
# SPIFFE X509-SVID validation, using the official py-spiffe library (PyPI
# package "spiffe") purely as an independent test oracle. These tests are
# skipped when the dev-only dependency is not installed.
#   pip install -r requirements-dev.txt   (or)   pip install -e ".[dev]"
# ---------------------------------------------------------------------------


def _issue_leaf_with_key(
    test_client,
    monkeypatch,
    cn="svid.local",
    dns_names=None,
    policy_domain="production",
):
    """Like _issue_leaf, but also returns the matching PKCS#8 private key PEM.

    py-spiffe's ``X509Svid.parse`` requires the leaf certificate together with
    its private key, so we generate the CSR with ``return_key=True``.
    """
    import tas.cert.routes as cert_routes

    monkeypatch.setattr(
        cert_routes,
        "vm_verify",
        lambda *args, **kwargs: (True, "key_id_123", None),
    )

    nonce = get_nonce(test_client)
    csr_bytes, key_pem = generate_csr(cn=cn, dns_names=dns_names, return_key=True)
    csr_b64 = base64.b64encode(csr_bytes).decode("ascii")
    payload = build_certify_payload(nonce, csr_b64, **{"policy-domain": policy_domain})

    response = _post_certify(test_client, payload)
    assert response.status_code == 200, response.json
    return response.json, key_pem


def _self_signed_leaf(sans, ca=False):
    """Build a throwaway self-signed EC leaf and return (cert_pem, pkcs8_key_pem)."""
    import datetime

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.generate_private_key(ec.SECP384R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "crafted.local")])
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    if sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(sans), critical=False
        )
    cert = builder.sign(key, hashes.SHA512())
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return cert_pem, key_pem


def test_spiffe_leaf_parses_as_x509_svid(test_client, monkeypatch):
    """py-spiffe accepts the issued leaf as a valid X509-SVID with the right ID."""
    pytest.importorskip("spiffe")
    from spiffe import X509Svid

    result, key_pem = _issue_leaf_with_key(
        test_client, monkeypatch, cn="svid.local", policy_domain="production"
    )

    svid = X509Svid.parse(result["certificate"].encode("ascii"), key_pem)
    spiffe_id = svid.spiffe_id

    assert spiffe_id.trust_domain.name == "example.org"
    assert spiffe_id.path.startswith("/production/")
    assert str(spiffe_id).startswith("spiffe://example.org/production/")


def test_spiffe_leaf_uri_san_obeys_spiffe_grammar(test_client, monkeypatch):
    """The leaf's URI SAN is a syntactically valid SPIFFE ID per py-spiffe."""
    pytest.importorskip("spiffe")
    from spiffe import SpiffeId

    result, _ = _issue_leaf_with_key(
        test_client, monkeypatch, cn="grammar.local", policy_domain="production"
    )

    leaf = x509.load_pem_x509_certificate(result["certificate"].encode("ascii"))
    san = leaf.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    uri_sans = san.value.get_values_for_type(x509.UniformResourceIdentifier)
    assert len(uri_sans) == 1

    spiffe_id = SpiffeId(uri_sans[0])
    assert spiffe_id.trust_domain.name == "example.org"
    assert spiffe_id.path.startswith("/production/")


def test_spiffe_ca_chain_parses_as_x509_bundle(test_client, monkeypatch):
    """The returned CA chain forms a valid SPIFFE trust bundle (root+intermediate)."""
    pytest.importorskip("spiffe")
    from spiffe import TrustDomain, X509Bundle

    result, _ = _issue_leaf_with_key(test_client, monkeypatch, cn="bundle.local")

    # X509Bundle expects PEM blocks; order is not significant.
    bundle_pem = (result["ca_chain"][1] + result["ca_chain"][0]).encode("ascii")
    bundle = X509Bundle.parse(TrustDomain("example.org"), bundle_pem)

    assert len(bundle.x509_authorities) == 2


def test_spiffe_rejects_invalid_leaves(test_client, monkeypatch):
    """py-spiffe rejects certs that are not valid X509-SVID leaves."""
    pytest.importorskip("spiffe")
    from spiffe import X509Svid
    from spiffe.svid.errors import InvalidLeafCertificateError

    result, _ = _issue_leaf_with_key(test_client, monkeypatch, cn="neg.local")

    # (a) A CA certificate (the intermediate, CA:TRUE) is not a valid leaf SVID.
    int_pem = result["ca_chain"][0].encode("ascii")
    _, int_dummy_key = _self_signed_leaf(
        [x509.UniformResourceIdentifier("spiffe://example.org/x")]
    )
    with pytest.raises(InvalidLeafCertificateError):
        X509Svid.parse(int_pem, int_dummy_key)

    # (b) A leaf carrying two URI SANs violates the single-ID SVID rule.
    two_uri_pem, two_uri_key = _self_signed_leaf(
        [
            x509.UniformResourceIdentifier("spiffe://example.org/a"),
            x509.UniformResourceIdentifier("spiffe://example.org/b"),
        ]
    )
    with pytest.raises(InvalidLeafCertificateError):
        X509Svid.parse(two_uri_pem, two_uri_key)

    # (c) A leaf with no SPIFFE URI SAN at all is not an SVID.
    no_uri_pem, no_uri_key = _self_signed_leaf([x509.DNSName("plain.local")])
    with pytest.raises(InvalidLeafCertificateError):
        X509Svid.parse(no_uri_pem, no_uri_key)
