#
# TEE Attestation Service - TAS-attestation route tests
#
# Copyright 2026 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#

import base64
import hashlib
import os
import threading
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from flask import Flask

from tas import attest_routes
from tas.attest_routes import attest_bp
from tas.auth import init_client_auth, init_management_auth
from tas.rate_limiter import setup_attest_budget

CLIENT_API_KEY = "k" * 64
MANAGEMENT_API_KEY = "m" * 64
FAKE_REPORT = os.urandom(1184)
NONCE = os.urandom(32).hex()
URL = "/attest/v0/report"


@pytest.fixture()
def slot(tmp_path):
    """A directory that looks like a configfs-tsm report slot (static outblob)."""
    d = tmp_path / "slot"
    d.mkdir()
    (d / "outblob").write_bytes(FAKE_REPORT)
    (d / "auxblob").write_bytes(b"")
    (d / "provider").write_text("sev_guest\n")
    (d / "inblob").write_bytes(b"")
    return d


@pytest.fixture(scope="module")
def tls_cert():
    """(PEM chain file contents, leaf DER) for a self-signed EC certificate."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "tas-test")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    pem = cert.public_bytes(serialization.Encoding.PEM)
    # Fullchain layout as nginx uses it: leaf first, then the issuer
    return pem + pem, cert.public_bytes(serialization.Encoding.DER)


@pytest.fixture()
def app(slot, tls_cert, tmp_path):
    cert_file = tmp_path / "server.crt"
    cert_file.write_bytes(tls_cert[0])
    return _make_app(slot, cert_file, tmp_path)


def _make_app(slot, cert_file, tmp_path, rate="2 per minute", **config):
    test_app = Flask(__name__)
    test_app.config.update(
        TESTING=True,
        TAS_API_KEY=CLIENT_API_KEY,
        TAS_MANAGEMENT_API_KEY=MANAGEMENT_API_KEY,
        TAS_ATTEST_TSM_SLOT=str(slot),
        TAS_ATTEST_TLS_CERT_FILE=str(cert_file),
        TAS_ATTEST_LOCK_FILE=str(tmp_path / "attest.lock"),
        TAS_ATTEST_RATE_LIMIT=rate,
    )
    test_app.config.update(config)
    test_app.register_blueprint(attest_bp)
    init_client_auth(test_app)
    init_management_auth(test_app)
    setup_attest_budget(test_app, "memory://", {})
    return test_app


def _post(client, nonce=NONCE, **kwargs):
    return client.post(URL, json={"nonce": nonce}, **kwargs)


def expected_report_data(nonce_hex, leaf_der):
    return hashlib.sha512(
        b"TAS-attest/v1" + bytes.fromhex(nonce_hex) + hashlib.sha256(leaf_der).digest()
    ).digest()


# --------------------------------------------------------------------------- #
# Happy path and binding
# --------------------------------------------------------------------------- #
def test_report_is_bound_to_tls_certificate(app, slot, tls_cert):
    response = _post(app.test_client())
    assert response.status_code == 200
    body = response.get_json()
    assert body["provider"] == "sev_guest"
    assert body["nonce"] == NONCE
    assert body["tls_cert_sha256"] == hashlib.sha256(tls_cert[1]).hexdigest()
    assert base64.b64decode(body["report"]) == FAKE_REPORT
    assert body["auxblob"] is None
    assert "report_data_scheme" not in body
    # The firmware was asked for REPORT_DATA = sha512("TAS-attest/v1" || nonce || sha256(leaf DER))
    assert (slot / "inblob").read_bytes() == expected_report_data(NONCE, tls_cert[1])
    assert response.headers["Cache-Control"] == "no-store"


def test_auxblob_passthrough_and_tdx_provider(app, slot):
    (slot / "auxblob").write_bytes(b"\x01\x02\x03")
    assert (
        base64.b64decode(_post(app.test_client()).get_json()["auxblob"])
        == b"\x01\x02\x03"
    )
    (slot / "auxblob").unlink()  # TDX exposes no auxblob attribute at all
    (slot / "provider").write_text("tdx_guest\n")
    body = _post(app.test_client()).get_json()
    assert body["provider"] == "tdx_guest" and body["auxblob"] is None


def test_get_is_not_allowed(app):
    assert app.test_client().get(f"{URL}?nonce={NONCE}").status_code == 405


# --------------------------------------------------------------------------- #
# Fail closed
# --------------------------------------------------------------------------- #
def test_unreadable_tls_certificate_fails_closed(slot, tmp_path):
    app = _make_app(slot, tmp_path / "missing.crt", tmp_path)
    response = _post(app.test_client())
    assert response.status_code == 503
    assert (slot / "inblob").read_bytes() == b""  # no report was generated


def test_malformed_tls_certificate_fails_closed(slot, tmp_path):
    bad = tmp_path / "bad.crt"
    bad.write_text(
        "-----BEGIN CERTIFICATE-----\nnot base64!\n-----END CERTIFICATE-----\n"
    )
    assert _post(_make_app(slot, bad, tmp_path).test_client()).status_code == 503


def test_not_a_cvm_without_slot(app):
    app.config["TAS_ATTEST_TSM_SLOT"] = app.config["TAS_ATTEST_TSM_SLOT"] + "-missing"
    assert _post(app.test_client()).status_code == 501


def test_empty_report_is_an_error(app, slot):
    (slot / "outblob").write_bytes(b"")
    response = _post(app.test_client())
    assert response.status_code == 500
    assert "empty report" in response.get_json()["error"]


def test_lock_file_symlink_is_refused(app, tmp_path):
    target = tmp_path / "victim"
    target.write_text("keep")
    link = tmp_path / "planted.lock"
    link.symlink_to(target)
    app.config["TAS_ATTEST_LOCK_FILE"] = str(link)
    assert _post(app.test_client()).status_code == 500
    assert target.read_text() == "keep"


def test_lock_directory_is_created_private(app, tmp_path):
    app.config["TAS_ATTEST_LOCK_FILE"] = str(tmp_path / "newdir" / "attest.lock")
    assert _post(app.test_client()).status_code == 200
    assert (tmp_path / "newdir").stat().st_mode & 0o777 == 0o700
    assert (tmp_path / "newdir" / "attest.lock").stat().st_mode & 0o777 == 0o600


# --------------------------------------------------------------------------- #
# Input validation and authentication
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "body",
    [
        None,
        {},
        {"nonce": ""},
        {"nonce": "zz"},
        {"nonce": "00"},
        {"nonce": "00" * 65},
        {"nonce": 5},
    ],
)
def test_nonce_validation(app, body):
    client = app.test_client()
    response = (
        client.post(URL, json=body) if body is not None else client.post(URL, data="x")
    )
    assert response.status_code == 400


def test_require_management_key_rejects_anonymous_and_client_key(
    slot, tmp_path, tls_cert
):
    cert_file = tmp_path / "server.crt"
    cert_file.write_bytes(tls_cert[0])
    client = _make_app(
        slot, cert_file, tmp_path, TAS_ATTEST_REQUIRE_MANAGEMENT_API_KEY=True
    ).test_client()
    assert _post(client).status_code == 401
    assert _post(client, headers={"X-MANAGEMENT-API-KEY": "wrong"}).status_code == 401
    # The client (agent) key is not sufficient: this is an operator endpoint
    assert _post(client, headers={"X-API-KEY": CLIENT_API_KEY}).status_code == 401
    assert (
        _post(client, headers={"X-MANAGEMENT-API-KEY": CLIENT_API_KEY}).status_code
        == 401
    )
    assert (slot / "inblob").read_bytes() == b""
    assert (
        _post(client, headers={"X-MANAGEMENT-API-KEY": MANAGEMENT_API_KEY}).status_code
        == 200
    )


def test_require_management_key_false_keeps_endpoint_open(app):
    app.config["TAS_ATTEST_REQUIRE_MANAGEMENT_API_KEY"] = False
    assert _post(app.test_client()).status_code == 200


# --------------------------------------------------------------------------- #
# Concurrency: slot lock and global budget
# --------------------------------------------------------------------------- #
def test_busy_slot_returns_503_instead_of_queueing(app, slot, monkeypatch):
    monkeypatch.setattr(attest_routes, "SLOT_WAIT_SECONDS", 0.1)
    held = open(app.config["TAS_ATTEST_LOCK_FILE"], "w")
    import fcntl

    fcntl.flock(held, fcntl.LOCK_EX)  # another process is generating a report
    try:
        response = _post(app.test_client())
    finally:
        held.close()
    assert response.status_code == 503
    assert response.headers["Retry-After"] == "1"  # whole seconds (RFC 9110)
    assert (slot / "inblob").read_bytes() == b""
    assert _post(app.test_client()).status_code == 200  # recovers once the slot is free


def test_budget_is_global_and_counts_only_served_reports(app):
    client = app.test_client()
    a, b, c = ({"REMOTE_ADDR": ip} for ip in ("10.0.0.1", "10.0.0.2", "10.0.0.3"))
    assert client.post(URL, json={"nonce": "zz"}, environ_base=a).status_code == 400
    assert _post(client, environ_base=a).status_code == 200
    assert _post(client, environ_base=b).status_code == 200
    response = _post(client, environ_base=c)  # third caller: shared bucket is empty
    assert response.status_code == 429
    assert response.get_json()["error"] == "rate_limit_exceeded"
    assert 1 <= int(response.headers["Retry-After"]) <= 60
    assert response.headers["Cache-Control"] == "no-store"


def test_budget_is_configurable_and_can_be_disabled(slot, tmp_path, tls_cert):
    cert_file = tmp_path / "server.crt"
    cert_file.write_bytes(tls_cert[0])
    client = _make_app(slot, cert_file, tmp_path, rate="1 per minute").test_client()
    assert _post(client).status_code == 200
    assert _post(client).status_code == 429
    client = _make_app(slot, cert_file, tmp_path, RATELIMIT_ENABLED=False).test_client()
    assert all(_post(client).status_code == 200 for _ in range(5))


def test_burst_cannot_overshoot_budget(app):
    """Concurrent requests at the start of a window must yield exactly N reports."""
    results = []

    def worker():
        results.append(_post(app.test_client()).status_code)

    threads = [threading.Thread(target=worker) for _ in range(12)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results.count(200) == 2
    assert set(results) <= {200, 429, 503}
