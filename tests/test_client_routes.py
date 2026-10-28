#
# TEE Attestation Service - Client route KBM error handling tests
#
# Copyright 2026 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#

import base64
import hashlib
import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from flask import Flask

from tas.client_routes import client_bp
from tas.error_handlers import register_error_handlers
from tas.exceptions import KBMResponseError, KBMUnavailableError


@pytest.fixture()
def app():
    test_app = Flask(__name__)
    test_app.config["TESTING"] = True
    test_app.extensions["redis"] = MagicMock(name="redis")
    test_app.extensions["kbm_client"] = MagicMock(name="kbm_client")
    test_app.extensions["kbm_get_secret"] = MagicMock(name="kbm_get_secret")
    test_app.register_blueprint(client_bp)
    register_error_handlers(test_app)
    return test_app


def _request_body():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return {
        "tee-type": "amd-sev-snp",
        "nonce": "nonce-value",
        "tee-evidence": "evidence",
        "policy-id": "policy:test",
        "report-data-binding": True,
        "wrapping-key": base64.b64encode(public_key).decode("ascii"),
    }


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def patched_route_dependencies():
    with (
        patch("tas.client_routes.authenticate_request", return_value=None),
        patch("tas.client_routes.validate_nonce", return_value=(True, None)),
        patch(
            "tas.client_routes.vm_verify", return_value=(True, "key-id", None)
        ) as verifier,
    ):
        yield verifier


def _post_secret(client):
    return client.post("/kb/v0/get_secret", json=_request_body())


def _assert_no_internal_details(response, details):
    response_text = response.get_data(as_text=True)
    for detail in details:
        assert detail not in response_text


def test_unavailable_exception_returns_503(app, client, patched_route_dependencies):
    app.extensions["kbm_get_secret"].side_effect = KBMUnavailableError(retry_after=17)

    response = _post_secret(client)

    assert response.status_code == 503
    assert response.headers["Retry-After"] == "17"
    assert response.get_json() == {"error": "Secret service is temporarily unavailable"}
    _assert_no_internal_details(
        response, ["http://", "key-id", "KBMUnavailableError", "connection"]
    )


def test_response_exception_returns_502(app, client, patched_route_dependencies):
    app.extensions["kbm_get_secret"].side_effect = KBMResponseError()

    response = _post_secret(client)

    assert response.status_code == 502
    assert response.get_json() == {
        "error": "Secret service returned an invalid response"
    }
    assert "Retry-After" not in response.headers
    _assert_no_internal_details(
        response,
        [
            "http://",
            "key-id",
            "KBMResponseError",
            "response body",
            "parser",
            "protocol",
        ],
    )


@pytest.mark.parametrize(
    "exception",
    [
        RuntimeError("internal implementation detail"),
        RuntimeError("legacy plugin failure"),
    ],
)
def test_unrelated_exceptions_return_generic_500(
    app, client, patched_route_dependencies, exception
):
    app.extensions["kbm_get_secret"].side_effect = exception

    response = _post_secret(client)

    assert response.status_code == 500
    assert response.get_json() == {"error": "Internal server error"}
    _assert_no_internal_details(
        response, [str(exception), exception.__class__.__name__]
    )


def test_value_error_remains_404(app, client, patched_route_dependencies):
    app.extensions["kbm_get_secret"].side_effect = ValueError("Secret not found")

    response = _post_secret(client)

    assert response.status_code == 404
    assert response.get_json() == {"error": "Secret retrieval failed"}
    _assert_no_internal_details(response, ["Secret not found"])


@pytest.mark.parametrize("tee_type", ["amd-sev-snp", "intel-tdx"])
@pytest.mark.parametrize("include_gpu", [False, True])
def test_secret_fetch_always_enables_verifier_binding(
    app, client, patched_route_dependencies, tee_type, include_gpu
):
    """Guard against accidental removal of report_data_binding=True in get_secret."""
    app.extensions["kbm_get_secret"].return_value = "wrapped-secret"
    body = _request_body()
    body["tee-type"] = tee_type
    if include_gpu:
        body["component-evidence"] = {
            "gpu": [{"type": "gpu-nvidia", "device-index": 0, "evidence": "evidence"}]
        }

    response = client.post("/kb/v0/get_secret", json=body)

    assert response.status_code == 200
    assert response.get_json() == {"secret_key": "wrapped-secret"}
    patched_route_dependencies.assert_called_once()
    assert patched_route_dependencies.call_args.kwargs["report_data_binding"] is True
    app.extensions["kbm_get_secret"].assert_called_once_with(
        app.extensions["kbm_client"],
        "key-id",
        base64.b64decode(body["wrapping-key"]),
    )


@pytest.mark.parametrize("binding", [True, False])
def test_secret_binding_is_mandatory(app, client, patched_route_dependencies, binding):
    """Reject requests that set report-data-binding to false before verification."""
    app.extensions["kbm_get_secret"].return_value = "wrapped-secret"
    body = _request_body()
    body["report-data-binding"] = binding

    response = client.post("/kb/v0/get_secret", json=body)

    if not binding:
        assert response.status_code == 400
        assert response.get_json() == {"error": "Report data binding must be enabled"}
        patched_route_dependencies.assert_not_called()
        app.extensions["kbm_get_secret"].assert_not_called()
    else:
        assert response.status_code == 200
        assert response.get_json() == {"secret_key": "wrapped-secret"}
        assert (
            patched_route_dependencies.call_args.kwargs["report_data_binding"] is True
        )
        app.extensions["kbm_get_secret"].assert_called_once_with(
            app.extensions["kbm_client"],
            "key-id",
            base64.b64decode(body["wrapping-key"]),
        )


@pytest.mark.parametrize("binding", [None, 0, 1, "", "false", "true", [], {}])
def test_secret_binding_rejects_non_boolean(
    app, client, patched_route_dependencies, binding
):
    """Require a strict JSON boolean for report-data-binding, not truthy/falsy values."""
    body = _request_body()
    body["report-data-binding"] = binding
    response = client.post("/kb/v0/get_secret", json=body)
    assert response.status_code == 400
    error = (
        "Report data binding is required"
        if binding is None
        else "Report data binding must be a Boolean"
    )
    assert response.get_json() == {"error": error}
    patched_route_dependencies.assert_not_called()
    app.extensions["kbm_get_secret"].assert_not_called()


def test_secret_binding_field_still_required(app, client, patched_route_dependencies):
    """Reject secret requests that omit the report-data-binding field."""
    body = _request_body()
    del body["report-data-binding"]
    response = client.post("/kb/v0/get_secret", json=body)
    assert response.status_code == 400
    assert response.get_json() == {"error": "Report data binding is required"}
    patched_route_dependencies.assert_not_called()
    app.extensions["kbm_get_secret"].assert_not_called()


@pytest.mark.parametrize("wrapping_key", [" ", "!!!", "\n\t"])
def test_secret_rejects_empty_decoded_key(
    app, client, patched_route_dependencies, wrapping_key
):
    """Reject base64 strings that decode to empty bytes before calling vm_verify."""
    body = _request_body()
    body["wrapping-key"] = wrapping_key
    response = client.post("/kb/v0/get_secret", json=body)
    assert response.status_code == 400
    assert response.get_json() == {"error": "Invalid wrapping key format"}
    patched_route_dependencies.assert_not_called()
    app.extensions["kbm_get_secret"].assert_not_called()


@pytest.mark.parametrize(
    "encoding", [serialization.Encoding.PEM, serialization.Encoding.DER]
)
@pytest.mark.parametrize(
    "key_format",
    [serialization.PublicFormat.SubjectPublicKeyInfo, serialization.PublicFormat.PKCS1],
)
@pytest.mark.parametrize("key_size", [2048, 3072])
def test_secret_accepts_rsa_key_without_changing_bound_bytes(
    app, client, patched_route_dependencies, encoding, key_format, key_size
):
    """Accept valid PEM/DER RSA keys while forwarding the exact decoded bytes."""
    app.extensions["kbm_get_secret"].return_value = "wrapped-secret"
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    raw_key = key.public_key().public_bytes(encoding, key_format)
    body = _request_body()
    body["wrapping-key"] = base64.b64encode(raw_key).decode("ascii")
    response = client.post("/kb/v0/get_secret", json=body)
    assert response.status_code == 200
    assert patched_route_dependencies.call_args.kwargs["wrapping_key"] == raw_key
    app.extensions["kbm_get_secret"].assert_called_once_with(
        app.extensions["kbm_client"], "key-id", raw_key
    )


@pytest.mark.parametrize(
    "encoding", [serialization.Encoding.PEM, serialization.Encoding.DER]
)
@pytest.mark.parametrize("key_kind", ["weak-rsa", "ec", "ed25519", "private-rsa"])
def test_secret_rejects_unacceptable_key_before_verification(
    app, client, patched_route_dependencies, encoding, key_kind, caplog
):
    """Reject non-RSA, private, and <2048-bit RSA keys before attestation verification."""
    if key_kind == "ec":
        key = ec.generate_private_key(ec.SECP256R1())
    elif key_kind == "ed25519":
        key = ed25519.Ed25519PrivateKey.generate()
    else:
        key = rsa.generate_private_key(
            public_exponent=65537, key_size=1024 if key_kind == "weak-rsa" else 2048
        )
    if key_kind == "private-rsa":
        raw_key = key.private_bytes(
            encoding, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    else:
        raw_key = key.public_key().public_bytes(
            encoding, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    body = _request_body()
    body["wrapping-key"] = base64.b64encode(raw_key).decode("ascii")
    response = client.post("/kb/v0/get_secret", json=body)
    assert response.status_code == 400
    assert response.get_json() == {
        "error": "Wrapping key must be an RSA public key of at least 2048 bits"
    }
    assert "Invalid wrapping key:" in caplog.text
    patched_route_dependencies.assert_not_called()
    app.extensions["kbm_get_secret"].assert_not_called()


@pytest.mark.parametrize(
    "raw_key",
    [
        b"not a key",
        b"$$$",
        b"-----BEGIN PUBLIC KEY-----\ninvalid\n-----END PUBLIC KEY-----",
    ],
)
def test_secret_rejects_malformed_public_key(
    app, client, patched_route_dependencies, raw_key
):
    """Reject byte payloads that cannot be parsed as PEM or DER public keys."""
    body = _request_body()
    body["wrapping-key"] = base64.b64encode(raw_key).decode("ascii")
    response = client.post("/kb/v0/get_secret", json=body)
    assert response.status_code == 400
    assert response.get_json() == {
        "error": "Wrapping key must be an RSA public key of at least 2048 bits"
    }
    patched_route_dependencies.assert_not_called()
    app.extensions["kbm_get_secret"].assert_not_called()


@pytest.mark.parametrize("loader", ["load_pem_public_key", "load_der_public_key"])
def test_secret_rejects_unsupported_key_algorithm(
    app, client, patched_route_dependencies, loader
):
    """Convert cryptography UnsupportedAlgorithm errors into a 400 client error."""
    body = _request_body()
    if loader == "load_der_public_key":
        # Non-PEM bytes force load_pem_public_key to raise ValueError and fall back to DER.
        body["wrapping-key"] = base64.b64encode(b"der-input").decode("ascii")
    with patch(
        f"tas.wrapping_key.{loader}", side_effect=UnsupportedAlgorithm("unsupported")
    ):
        response = client.post("/kb/v0/get_secret", json=body)
    assert response.status_code == 400
    assert response.get_json() == {
        "error": "Wrapping key must be an RSA public key of at least 2048 bits"
    }
    patched_route_dependencies.assert_not_called()
    app.extensions["kbm_get_secret"].assert_not_called()


@pytest.mark.parametrize("failure", [None, "gpu-evidence", "gpu-claims", "cpu"])
def test_combined_policy_controls_secret_release(app, client, failure):
    """Require both CPU and GPU policy checks to pass before releasing a combined-policy secret."""
    nvidia = pytest.importorskip("nvidia_pytools")
    app.config["TAS_ENFORCE_SIGNED_POLICIES"] = False
    gpu_policy = {
        "version": "4.0",
        "authorization-rules": {
            "type": "JWT",
            "overall-claims": {"x-nvidia-overall-att-result": True},
        },
    }
    policy = {
        "metadata": {"key_id": "combined-policy-secret"},
        "validation_rules": {},
        "components": {"gpu": {"gpu-nvidia": gpu_policy}},
    }
    app.extensions["redis"].get.return_value = json.dumps(policy)
    app.extensions["kbm_get_secret"].return_value = "wrapped-combined-secret"
    body = _request_body()
    body["policy-id"] = "combined-policy"
    body["tee-evidence"] = base64.b64encode(b"cpu-report").decode("ascii")
    raw_gpu = b"gpu-report"
    envelope = json.dumps({"evidence": base64.b64encode(raw_gpu).decode("ascii")})
    body["component-evidence"] = {
        "gpu": [
            {
                "type": "gpu-nvidia",
                "device-index": 0,
                "evidence": base64.b64encode(envelope.encode()).decode("ascii"),
            }
        ]
    }
    claims = nvidia.GpuClaims(
        raw_overall_claims={"x-nvidia-overall-att-result": failure != "gpu-claims"},
    )
    gpu_result = (
        (False, None, "GPU evidence rejected")
        if failure == "gpu-evidence"
        else (True, claims, None)
    )
    cpu_result = (False, "CPU policy rejected") if failure == "cpu" else (True, None)
    with (
        patch("tas.client_routes.authenticate_request", return_value=None),
        patch("tas.client_routes.validate_nonce", return_value=(True, None)),
        patch("tas.tas_vm.gpu_vm_verify", return_value=gpu_result) as gpu,
        patch("tas.tas_vm.sev_vm_verify", return_value=cpu_result) as cpu,
    ):
        response = client.post("/kb/v0/get_secret", json=body)

    app.extensions["redis"].get.assert_called_once_with("policy:combined-policy")
    gpu.assert_called_once()
    if failure:
        assert response.status_code == 400
        assert response.get_json() == {"error": "TEE verification failed"}
        app.extensions["kbm_get_secret"].assert_not_called()
        if failure != "cpu":
            # GPU evidence or claim failures short-circuit before CPU verification.
            cpu.assert_not_called()
    else:
        assert response.status_code == 200
        assert response.get_json() == {"secret_key": "wrapped-combined-secret"}
        key = base64.b64decode(body["wrapping-key"])
        app.extensions["kbm_get_secret"].assert_called_once_with(
            app.extensions["kbm_client"], "combined-policy-secret", key
        )
        expected = hashlib.sha512(
            body["nonce"].encode() + key + hashlib.sha512(raw_gpu).digest()
        ).digest()
        assert cpu.call_args.kwargs["expected_report_data"] == expected


@pytest.mark.parametrize("report_binding", ["raw-nonce", "other-key", "matching-key"])
def test_secret_checks_report_data_binding(app, client, report_binding):
    """Verify end-to-end that only evidence bound to SHA-512(nonce || wrapping_key) succeeds."""
    from sev_pytools import AttestationPolicy
    from sev_pytools.policy import PolicyValidationError

    body = _request_body()
    nonce = body["nonce"].encode()
    wrapping_key = base64.b64decode(body["wrapping-key"])
    report_data = nonce
    if report_binding == "matching-key":
        report_data = hashlib.sha512(nonce + wrapping_key).digest()
    elif report_binding == "other-key":
        report_data = hashlib.sha512(nonce + b"other-wrapping-key").digest()
    body["tee-evidence"] = base64.b64encode(report_data).decode()
    app.config["TAS_ENFORCE_SIGNED_POLICIES"] = False
    app.extensions["redis"].get.return_value = json.dumps(
        {"metadata": {"key_id": "bound-secret"}, "validation_rules": {}}
    )
    app.extensions["kbm_get_secret"].return_value = "wrapped-bound-secret"

    def compare_cpu_report_data(
        redis_client, nonce, evidence, policy, *, expected_report_data
    ):
        # Hardware authenticity is stubbed; the SEV report-data comparison is real.
        report = SimpleNamespace(report_data=evidence)
        try:
            AttestationPolicy(policy).validate_report(
                report, report_data=expected_report_data
            )
        except PolicyValidationError as error:
            return False, str(error)
        return True, None

    with (
        patch("tas.client_routes.authenticate_request", return_value=None),
        patch("tas.client_routes.validate_nonce", return_value=(True, None)),
        patch("tas.tas_vm.sev_vm_verify", side_effect=compare_cpu_report_data),
    ):
        response = client.post("/kb/v0/get_secret", json=body)

    if report_binding == "matching-key":
        assert response.status_code == 200
        app.extensions["kbm_get_secret"].assert_called_once_with(
            app.extensions["kbm_client"], "bound-secret", wrapping_key
        )
    else:
        assert response.status_code == 400
        assert response.get_json() == {"error": "TEE verification failed"}
        app.extensions["kbm_get_secret"].assert_not_called()


def test_secret_accepts_quoted_agent_nonce_and_binds_unquoted(app, client):
    """Mirror tas_agent: it posts the JSON-quoted nonce but binds report_data to the bare nonce."""
    from sev_pytools import AttestationPolicy
    from sev_pytools.policy import PolicyValidationError

    nonce = "ab" * 32
    body = _request_body()
    body["nonce"] = f'"{nonce}"'
    wrapping_key = base64.b64decode(body["wrapping-key"])
    report_data = hashlib.sha512(nonce.encode() + wrapping_key).digest()
    body["tee-evidence"] = base64.b64encode(report_data).decode()
    app.config["TAS_ENFORCE_SIGNED_POLICIES"] = False
    redis_client = app.extensions["redis"]
    redis_client.getdel.return_value = "1"
    redis_client.get.return_value = json.dumps(
        {"metadata": {"key_id": "bound-secret"}, "validation_rules": {}}
    )
    app.extensions["kbm_get_secret"].return_value = "wrapped-bound-secret"

    def compare_cpu_report_data(
        redis_client, nonce, evidence, policy, *, expected_report_data
    ):
        report = SimpleNamespace(report_data=evidence)
        try:
            AttestationPolicy(policy).validate_report(
                report, report_data=expected_report_data
            )
        except PolicyValidationError as error:
            return False, str(error)
        return True, None

    with (
        patch("tas.client_routes.authenticate_request", return_value=None),
        patch(
            "tas.tas_vm.sev_vm_verify", side_effect=compare_cpu_report_data
        ) as cpu_verify,
    ):
        response = client.post("/kb/v0/get_secret", json=body)

    assert response.status_code == 200
    redis_client.getdel.assert_called_once_with(f"nonce:{nonce}")
    assert cpu_verify.call_args.args[1] == nonce
    app.extensions["kbm_get_secret"].assert_called_once_with(
        app.extensions["kbm_client"], "bound-secret", wrapping_key
    )
