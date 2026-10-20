#
# TEE Attestation Service - Policy Store Consumer & Multi-Worker Reliability Tests
#
# Copyright 2026 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# This file is part of the TEE Attestation Service.
#
# Tests covering all functions provided by PolicyStore to the rest of the
# codebase (`tas_vm` policy loaders, `vm_verify`, `domain_verify`,
# `/kb/v0/get_secret`, `/alphav1/certify`, management CRUD/status/outage) and
# single-worker / multi-worker reliability across Flask and Gunicorn launch
# modes.
#

import base64
import json
import re
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import MagicMock, patch

import psycopg
import pytest
import redis as redis_lib
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import Flask

from plugins import tas_cert_local
from tas import tas_vm
from tas.policy_store import (
    CERTIFY_POLICY_NAMESPACE,
    DOMAIN_POLICY_NAMESPACE,
    POLICY_NAMESPACE,
    PolicyAlreadyExists,
    PolicyStoreUnavailable,
    RedisPolicyStore,
    init_policy_store,
)
from tas.postgres_policy_store import PostgresPolicyStore, _safe_driver_error
from tests.certify.test_csr_sanitization import generate_csr
from tests.test_policy_store_backends import (
    CLIENT_API_KEY,
    MGMT_API_KEY,
    REPO_ROOT,
    FailingPolicyStore,
    RecordingFakeRedis,
    _free_tcp_port,
    _make_full_test_app,
    _sample_certify_policy,
    _sample_domain_policy,
    _sample_secret_policy,
    _sign_policy_doc,
    _smoke_env,
    _stop_process_and_collect,
    backend_env,
    client_headers,
    isolated_redis,
    mgmt_headers,
    pg_cluster,
    pg_dsn,
)

__all__ = [
    "backend_env",
    "client_headers",
    "isolated_redis",
    "mgmt_headers",
    "pg_cluster",
    "pg_dsn",
]


# --------------------------------------------------------------------------- #
# 1. Direct PolicyStore Functions & Initialization
# --------------------------------------------------------------------------- #


class TestPolicyStoreProvidedFunctions:
    def test_init_policy_store_registers_selected_backend_and_validates_config(
        self, pg_dsn
    ):
        fake_redis = RecordingFakeRedis()

        redis_app = Flask(__name__)
        redis_app.config["TAS_POLICY_BACKEND"] = "redis"
        redis_store = init_policy_store(redis_app, fake_redis)
        assert isinstance(redis_store, RedisPolicyStore)
        assert redis_app.extensions["policy_store"] is redis_store

        pg_app = Flask(__name__)
        pg_app.config["TAS_POLICY_BACKEND"] = "postgresql"
        pg_app.config["TAS_POSTGRES_DSN"] = pg_dsn
        pg_app.config["TAS_POSTGRES_CONNECT_TIMEOUT_SECONDS"] = 17
        pg_app.config["TAS_POSTGRES_STATEMENT_TIMEOUT_SECONDS"] = 3
        pg_store = init_policy_store(pg_app, fake_redis)
        assert isinstance(pg_store, PostgresPolicyStore)
        assert pg_app.extensions["policy_store"] is pg_store
        assert pg_store._connect_timeout == 17
        assert pg_store._statement_timeout_ms == 3000

        missing_dsn_app = Flask(__name__)
        missing_dsn_app.config["TAS_POLICY_BACKEND"] = "postgresql"
        missing_dsn_app.config["TAS_POSTGRES_DSN"] = "   "
        with pytest.raises(RuntimeError, match="TAS_POSTGRES_DSN is required"):
            init_policy_store(missing_dsn_app, fake_redis)

        invalid_backend_app = Flask(__name__)
        invalid_backend_app.config["TAS_POLICY_BACKEND"] = "sqlite"
        with pytest.raises(RuntimeError, match="Unsupported TAS_POLICY_BACKEND"):
            init_policy_store(invalid_backend_app, fake_redis)

    def test_adapter_ordering_bytes_fallback_and_error_translation(self, pg_dsn):
        fake_redis = RecordingFakeRedis()
        redis_store = RedisPolicyStore(fake_redis)
        pg_store = PostgresPolicyStore(pg_dsn)

        for pid in ("pol-c", "pol-a", "pol-b"):
            pg_store.create(
                POLICY_NAMESPACE,
                pid,
                json.dumps(_sample_secret_policy(pid)),
            )

        with pytest.raises(PolicyAlreadyExists) as exc_info:
            pg_store.create(
                POLICY_NAMESPACE,
                "pol-a",
                json.dumps(_sample_secret_policy("pol-a")),
            )
        assert exc_info.value.namespace == POLICY_NAMESPACE
        assert exc_info.value.policy_id == "pol-a"

        listed_ids = [
            json.loads(raw)["metadata"]["policy_id"]
            for raw in pg_store.list(POLICY_NAMESPACE)
        ]
        assert listed_ids == ["pol-a", "pol-b", "pol-c"]

        # Verify RedisPolicyStore bytes decoding, duplicate-key deduplication, keys() fallback, and vanished key handling
        class KeysOnlyBytesRedis:
            def get(self, key):
                if key in ("policy:b1", b"policy:b1"):
                    return b'{"metadata":{"policy_id":"b1"}}'
                return None

            def keys(self, pattern="*"):
                return [b"policy:b1", b"policy:b1", b"policy:vanished"]

            def ping(self):
                return False

        bytes_store = RedisPolicyStore(KeysOnlyBytesRedis())
        assert (
            bytes_store.get(POLICY_NAMESPACE, "b1") == '{"metadata":{"policy_id":"b1"}}'
        )
        assert list(bytes_store.list(POLICY_NAMESPACE)) == [
            '{"metadata":{"policy_id":"b1"}}'
        ]
        assert bytes_store.is_reachable() is False

        fake_redis.reachable = False
        assert redis_store.is_reachable() is False

        # Verify RedisPolicyStore and PostgresPolicyStore translate backend errors to PolicyStoreUnavailable
        broken_redis = MagicMock()
        broken_redis.set.side_effect = RuntimeError("redis set down")
        broken_redis.get.side_effect = RuntimeError("redis get down")
        broken_redis.scan_iter.side_effect = RuntimeError("redis scan down")
        broken_redis.delete.side_effect = RuntimeError("redis delete down")
        broken_redis_store = RedisPolicyStore(broken_redis)

        with pytest.raises(PolicyStoreUnavailable):
            broken_redis_store.create(POLICY_NAMESPACE, "p1", "{}")
        with pytest.raises(PolicyStoreUnavailable):
            broken_redis_store.get(POLICY_NAMESPACE, "p1")
        with pytest.raises(PolicyStoreUnavailable):
            list(broken_redis_store.list(POLICY_NAMESPACE))
        with pytest.raises(PolicyStoreUnavailable):
            broken_redis_store.delete(POLICY_NAMESPACE, "p1")

        with pytest.raises(ValueError, match="TAS_POSTGRES_DSN is required"):
            PostgresPolicyStore("   ")

        sqlstate_exc = psycopg.OperationalError("db error")
        sqlstate_exc.sqlstate = "08006"
        assert _safe_driver_error(sqlstate_exc) == "OperationalError (SQLSTATE 08006)"

        class NonPkUniqueViolation(psycopg.errors.UniqueViolation):
            diag = MagicMock(constraint_name="other_unique_idx")

        with patch.object(
            pg_store, "_connect", side_effect=NonPkUniqueViolation("other constraint")
        ):
            with pytest.raises(PolicyStoreUnavailable):
                pg_store.create(POLICY_NAMESPACE, "p1", "{}")

        with patch.object(
            pg_store, "_connect", side_effect=psycopg.OperationalError("down")
        ):
            with pytest.raises(PolicyStoreUnavailable):
                list(pg_store.list(POLICY_NAMESPACE))
            with pytest.raises(PolicyStoreUnavailable):
                pg_store.delete(POLICY_NAMESPACE, "p1")


# --------------------------------------------------------------------------- #
# 2. Codebase Consumers of PolicyStore (`tas_vm`, `client_routes`, certify,
#    and management routes)
# --------------------------------------------------------------------------- #


class TestPolicyStoreCodebaseConsumers:
    def test_tas_vm_policy_loaders_and_enforcement_modes(self, backend_env):
        _, store, fake_redis = backend_env
        priv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        trusted_keys = [("public_key", "trusted-mem", priv_key.public_key())]

        assert tas_vm.get_policy_from_redis is tas_vm.get_policy
        assert tas_vm.get_certify_policy_from_redis is tas_vm.get_certify_policy
        assert tas_vm.get_domain_policy_from_redis is tas_vm.get_domain_policy

        store.create(POLICY_NAMESPACE, "corrupt-sec", "{not-valid-json")
        store.create(
            POLICY_NAMESPACE,
            "unsigned-sec",
            json.dumps(_sample_secret_policy("unsigned-sec", key_id="unsigned-k")),
        )
        store.create(
            POLICY_NAMESPACE,
            "untrusted-sec",
            json.dumps(
                _sign_policy_doc(
                    _sample_secret_policy("untrusted-sec", key_id="untrusted-k"),
                    other_key,
                )
            ),
        )
        store.create(
            CERTIFY_POLICY_NAMESPACE,
            "unsigned-cert",
            json.dumps(_sample_certify_policy("unsigned-cert")),
        )
        store.create(
            DOMAIN_POLICY_NAMESPACE,
            "unsigned-dom",
            json.dumps(_sample_domain_policy("unsigned-dom", ["unsigned-cert"])),
        )

        enforced_app = _make_full_test_app(
            store, fake_redis, enforce_signed=True, trusted_keys=trusted_keys
        )
        with enforced_app.app_context():
            with pytest.raises(ValueError, match="Policy not found"):
                tas_vm.get_policy(store, "missing-sec")
            with pytest.raises(ValueError, match="Certify policy not found"):
                tas_vm.get_certify_policy(store, "missing-cert")
            with pytest.raises(ValueError, match="Domain policy not found"):
                tas_vm.get_domain_policy(store, "missing-dom")

            with pytest.raises(ValueError, match="Invalid policy format"):
                tas_vm.get_policy(store, "corrupt-sec")
            with pytest.raises(ValueError, match="Policy not signed"):
                tas_vm.get_policy(store, "unsigned-sec")
            with pytest.raises(ValueError, match="Certify policy not signed"):
                tas_vm.get_certify_policy(store, "unsigned-cert")
            with pytest.raises(ValueError, match="Domain policy not signed"):
                tas_vm.get_domain_policy(store, "unsigned-dom")
            with pytest.raises(
                ValueError, match="Policy signature verification failed"
            ):
                tas_vm.get_policy(store, "untrusted-sec")

        permissive_app = _make_full_test_app(
            store, fake_redis, enforce_signed=False, trusted_keys=trusted_keys
        )
        with permissive_app.app_context():
            sec_obj, sec_key = tas_vm.get_policy_from_redis(store, "unsigned-sec")
            assert sec_obj["metadata"]["policy_id"] == "unsigned-sec"
            assert sec_key == "unsigned-k"

            untrusted_obj, untrusted_key = tas_vm.get_policy(store, "untrusted-sec")
            assert untrusted_obj["metadata"]["policy_id"] == "untrusted-sec"
            assert untrusted_key == "untrusted-k"

            cert_obj, cert_key = tas_vm.get_certify_policy_from_redis(
                store, "unsigned-cert"
            )
            assert cert_obj["metadata"]["policy_id"] == "unsigned-cert"
            assert cert_key == "key-unsigned-cert"

            dom_obj = tas_vm.get_domain_policy_from_redis(store, "unsigned-dom")
            assert dom_obj["metadata"]["policy_id"] == "unsigned-dom"

    def test_vm_verify_and_domain_verify_integration_with_policy_store(
        self, backend_env, monkeypatch
    ):
        _, store, fake_redis = backend_env
        app = _make_full_test_app(store, fake_redis, enforce_signed=False)
        evidence_b64 = base64.b64encode(b"valid-evidence").decode("ascii")

        store.create(
            POLICY_NAMESPACE,
            "sec-pass",
            json.dumps(_sample_secret_policy("sec-pass", key_id="kbm-secret-42")),
        )
        store.create(CERTIFY_POLICY_NAMESPACE, "cert-corrupt", "{bad-json")
        store.create(
            CERTIFY_POLICY_NAMESPACE,
            "cert-wrong-tee",
            json.dumps(_sample_certify_policy("cert-wrong-tee", policy_type="TDX")),
        )
        store.create(
            CERTIFY_POLICY_NAMESPACE,
            "cert-fail",
            json.dumps(_sample_certify_policy("cert-fail", policy_type="SEV")),
        )
        store.create(
            CERTIFY_POLICY_NAMESPACE,
            "cert-pass",
            json.dumps(_sample_certify_policy("cert-pass", policy_type="SEV")),
        )
        store.create(
            DOMAIN_POLICY_NAMESPACE,
            "dom-or",
            json.dumps(
                _sample_domain_policy(
                    "dom-or",
                    [
                        "cert-missing",
                        "cert-corrupt",
                        "cert-wrong-tee",
                        "cert-fail",
                        "cert-pass",
                    ],
                )
            ),
        )

        def _fake_verify(
            redis_client,
            nonce,
            tee_type,
            tee_evidence,
            policy_json,
            **kwargs,
        ):
            pid = policy_json.get("metadata", {}).get("policy_id")
            if pid in ("sec-pass", "cert-pass"):
                return True, None
            return False, f"{pid} rejected"

        monkeypatch.setattr(tas_vm, "verify", _fake_verify)

        with app.app_context():
            ok, key_id, err = tas_vm.vm_verify(
                store,
                fake_redis,
                "nonce-1",
                "amd-sev-snp",
                evidence_b64,
                "sec-pass",
            )
            assert (ok, key_id, err) == (True, "kbm-secret-42", None)

            ok_dom, dom_key, dom_err = tas_vm.domain_verify(
                store,
                fake_redis,
                "nonce-1",
                "amd-sev-snp",
                evidence_b64,
                "dom-or",
            )
            assert (ok_dom, dom_key, dom_err) == (True, "key-cert-pass", None)

            ok_req, req_key, req_err = tas_vm.domain_verify(
                store,
                fake_redis,
                "nonce-1",
                "amd-sev-snp",
                evidence_b64,
                "dom-or",
                requested_policy_id="cert-pass",
            )
            assert (ok_req, req_key, req_err) == (True, "key-cert-pass", None)

            ok_bad_req, bad_key, bad_err = tas_vm.domain_verify(
                store,
                fake_redis,
                "nonce-1",
                "amd-sev-snp",
                evidence_b64,
                "dom-or",
                requested_policy_id="not-in-domain",
            )
            assert ok_bad_req is False
            assert bad_key is None
            assert "not permitted" in bad_err

            assert store.delete(POLICY_NAMESPACE, "sec-pass") is True
            ok_after_del, key_after_del, err_after_del = tas_vm.vm_verify(
                store,
                fake_redis,
                "nonce-1",
                "amd-sev-snp",
                evidence_b64,
                "sec-pass",
            )
            assert (ok_after_del, key_after_del, err_after_del) == (
                False,
                None,
                "Policy not found",
            )

            assert store.delete(CERTIFY_POLICY_NAMESPACE, "cert-pass") is True
            ok_dom_del, dom_key_del, dom_err_del = tas_vm.domain_verify(
                store,
                fake_redis,
                "nonce-1",
                "amd-sev-snp",
                evidence_b64,
                "dom-or",
            )
            assert ok_dom_del is False
            assert dom_key_del is None
            assert dom_err_del == "Certify policy not found"

            ok_fail_req, fail_key_req, fail_err_req = tas_vm.domain_verify(
                store,
                fake_redis,
                "nonce-1",
                "amd-sev-snp",
                evidence_b64,
                "dom-or",
                requested_policy_id="cert-fail",
            )
            assert ok_fail_req is False
            assert fail_key_req is None
            assert fail_err_req == "cert-fail rejected"

    def test_client_get_secret_and_certify_routes_consume_policy_store(
        self, backend_env, mgmt_headers, client_headers, monkeypatch
    ):
        _, store, fake_redis = backend_env
        app = _make_full_test_app(store, fake_redis, enforce_signed=False)

        cert_handle = tas_cert_local.cert_open_client_connection(
            config_file=None, trust_domain="example.org"
        )
        app.extensions["cert_client"] = cert_handle
        app.extensions["cert_get_ca_info"] = tas_cert_local.cert_get_ca_info
        app.extensions["cert_sign"] = tas_cert_local.cert_sign

        monkeypatch.setattr(tas_vm, "verify", lambda *a, **k: (True, None))
        client = app.test_client()

        assert (
            client.post(
                "/management/policy/v0/store",
                headers=mgmt_headers,
                json=_sample_secret_policy("route-sec-1", key_id="kbm-route-key"),
            ).status_code
            == 201
        )
        assert (
            client.post(
                "/management/certify-policy/v0/store",
                headers=mgmt_headers,
                json=_sample_certify_policy("route-cert-1", "SEV"),
            ).status_code
            == 201
        )
        assert (
            client.post(
                "/management/domain-policy/v0/store",
                headers=mgmt_headers,
                json=_sample_domain_policy("route-dom-1", ["route-cert-1"]),
            ).status_code
            == 201
        )

        wrapping_pub = (
            rsa.generate_private_key(public_exponent=65537, key_size=2048)
            .public_key()
            .public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        kb_nonce = client.get("/kb/v0/get_nonce", headers=client_headers).get_json()[
            "nonce"
        ]
        secret_resp = client.post(
            "/kb/v0/get_secret",
            headers=client_headers,
            json={
                "tee-type": "amd-sev-snp",
                "nonce": kb_nonce,
                "tee-evidence": base64.b64encode(b"evidence").decode("ascii"),
                "policy-id": "route-sec-1",
                "report-data-binding": True,
                "wrapping-key": base64.b64encode(wrapping_pub).decode("ascii"),
            },
        )
        assert secret_resp.status_code == 200
        assert secret_resp.get_json() == {"secret_key": "wrapped-secret-value"}
        app.extensions["kbm_get_secret"].assert_called_once_with(
            app.extensions["kbm_client"], "kbm-route-key", wrapping_pub
        )

        app.extensions["kbm_get_secret"].reset_mock()
        assert (
            client.delete(
                "/management/policy/v0/delete/route-sec-1", headers=mgmt_headers
            ).status_code
            == 200
        )
        kb_nonce_2 = client.get("/kb/v0/get_nonce", headers=client_headers).get_json()[
            "nonce"
        ]
        secret_resp_after_del = client.post(
            "/kb/v0/get_secret",
            headers=client_headers,
            json={
                "tee-type": "amd-sev-snp",
                "nonce": kb_nonce_2,
                "tee-evidence": base64.b64encode(b"evidence").decode("ascii"),
                "policy-id": "route-sec-1",
                "report-data-binding": True,
                "wrapping-key": base64.b64encode(wrapping_pub).decode("ascii"),
            },
        )
        assert secret_resp_after_del.status_code == 400
        app.extensions["kbm_get_secret"].assert_not_called()

        csr_b64 = base64.b64encode(generate_csr(cn="workload.example.org")).decode(
            "ascii"
        )
        cert_nonce = client.get("/alphav1/nonce", headers=client_headers).get_json()[
            "nonce"
        ]
        cert_resp = client.post(
            "/alphav1/certify",
            headers=client_headers,
            json={
                "tee-type": "amd-sev-snp",
                "nonce": cert_nonce,
                "tee-evidence": base64.b64encode(b"evidence").decode("ascii"),
                "csr": csr_b64,
                "domain-policy": "route-dom-1",
                "policy-id": "route-cert-1",
            },
        )
        assert cert_resp.status_code == 200
        cert_data = cert_resp.get_json()
        assert "BEGIN CERTIFICATE" in cert_data["certificate"]
        assert len(cert_data["ca_chain"]) == 2

        assert (
            client.delete(
                "/management/domain-policy/v0/delete/route-dom-1",
                headers=mgmt_headers,
            ).status_code
            == 200
        )
        cert_nonce_2 = client.get("/alphav1/nonce", headers=client_headers).get_json()[
            "nonce"
        ]
        cert_resp_after_del = client.post(
            "/alphav1/certify",
            headers=client_headers,
            json={
                "tee-type": "amd-sev-snp",
                "nonce": cert_nonce_2,
                "tee-evidence": base64.b64encode(b"evidence").decode("ascii"),
                "csr": csr_b64,
                "domain-policy": "route-dom-1",
            },
        )
        assert cert_resp_after_del.status_code == 403
        assert "Domain policy not found" in cert_resp_after_del.get_json()["error"]

    def test_management_routes_type_mismatch_corrupted_json_and_outage(
        self, backend_env, mgmt_headers, monkeypatch
    ):
        backend_name, store, fake_redis = backend_env
        app = _make_full_test_app(store, fake_redis, enforce_signed=False)
        client = app.test_client()

        assert (
            client.post(
                "/management/certify-policy/v0/store",
                headers=mgmt_headers,
                json=_sample_certify_policy("tdx-member", policy_type="TDX"),
            ).status_code
            == 201
        )
        mismatch_resp = client.post(
            "/management/domain-policy/v0/store",
            headers=mgmt_headers,
            json=_sample_domain_policy(
                "dom-mismatch", ["tdx-member"], tee_type="amd-sev-snp"
            ),
        )
        assert mismatch_resp.status_code == 201
        assert (
            "type does not match their TEE group" in mismatch_resp.get_json()["warning"]
        )

        store.create(POLICY_NAMESPACE, "bad-sec", "{broken")
        store.create(CERTIFY_POLICY_NAMESPACE, "bad-cert", "{broken")
        store.create(DOMAIN_POLICY_NAMESPACE, "bad-dom", "{broken")

        assert (
            client.get(
                "/management/policy/v0/get/bad-sec", headers=mgmt_headers
            ).status_code
            == 500
        )
        assert (
            client.get(
                "/management/certify-policy/v0/get/bad-cert", headers=mgmt_headers
            ).status_code
            == 500
        )
        assert (
            client.get(
                "/management/domain-policy/v0/get/bad-dom", headers=mgmt_headers
            ).status_code
            == 500
        )
        assert (
            client.get("/management/policy/v0/list", headers=mgmt_headers).get_json()[
                "count"
            ]
            == 0
        )
        assert (
            client.get(
                "/management/certify-policy/v0/list", headers=mgmt_headers
            ).get_json()["count"]
            == 1
        )
        assert (
            client.get(
                "/management/domain-policy/v0/list", headers=mgmt_headers
            ).get_json()["count"]
            == 1
        )

        monkeypatch.setattr(store, "is_reachable", lambda: False)
        status_resp = client.get("/management/status", headers=mgmt_headers)
        assert status_resp.status_code == 200
        assert status_resp.get_json()["policy_storage"] == {
            "backend": backend_name,
            "reachable": False,
        }

        failing_app = _make_full_test_app(FailingPolicyStore(fake_redis), fake_redis)
        failing_client = failing_app.test_client()
        for path, method, payload in [
            (
                "/management/certify-policy/v0/store",
                "post",
                _sample_certify_policy("cp1"),
            ),
            ("/management/certify-policy/v0/get/cp1", "get", None),
            ("/management/certify-policy/v0/list", "get", None),
            ("/management/certify-policy/v0/delete/cp1", "delete", None),
            (
                "/management/domain-policy/v0/store",
                "post",
                _sample_domain_policy("dp1", ["cp1"]),
            ),
            ("/management/domain-policy/v0/get/dp1", "get", None),
            ("/management/domain-policy/v0/list", "get", None),
            ("/management/domain-policy/v0/delete/dp1", "delete", None),
        ]:
            resp = getattr(failing_client, method)(
                path, headers=mgmt_headers, json=payload
            )
            assert resp.status_code == 500


# --------------------------------------------------------------------------- #
# 3. Single-Worker & Multi-Worker Server Launch Matrix (8 Configurations)
# --------------------------------------------------------------------------- #


WORKER_MATRIX = [
    ("flask-single-worker-pg", "postgresql", "flask", 1, []),
    ("gunicorn-1w-pg", "postgresql", "gunicorn", 1, []),
    ("gunicorn-4w-pg", "postgresql", "gunicorn", 4, []),
    ("gunicorn-4w-preload-pg", "postgresql", "gunicorn", 4, ["--preload"]),
    ("gunicorn-4w-4t-pg", "postgresql", "gunicorn", 4, ["--threads", "4"]),
    ("gunicorn-1w-redis", "redis", "gunicorn", 1, []),
    ("gunicorn-4w-redis", "redis", "gunicorn", 4, []),
    ("gunicorn-4w-preload-redis", "redis", "gunicorn", 4, ["--preload"]),
]


class TestServerWorkerReliabilityMatrix:
    @pytest.mark.parametrize(
        "label,backend,server_kind,workers,extra_args",
        WORKER_MATRIX,
        ids=[item[0] for item in WORKER_MATRIX],
    )
    def test_server_launch_and_concurrent_worker_reliability(
        self,
        pg_dsn,
        isolated_redis,
        tmp_path,
        label,
        backend,
        server_kind,
        workers,
        extra_args,
    ):
        redis_lib.StrictRedis(host="127.0.0.1", port=isolated_redis).flushall()

        http_port = _free_tcp_port()
        access_log = tmp_path / f"{label}.access.log"
        server_log = tmp_path / f"{label}.server.log"

        env = _smoke_env(pg_dsn, isolated_redis, certify_enabled=True)
        env["TAS_POLICY_BACKEND"] = backend
        env["TAS_OVERRIDE__LOGGING__FILE"] = str(tmp_path / f"{label}.tas.log")

        if server_kind == "flask":
            env["FLASK_APP"] = "app:app"
            cmd = [
                sys.executable,
                "-m",
                "flask",
                "run",
                "--no-reload",
                "-h",
                "127.0.0.1",
                "-p",
                str(http_port),
            ]
        else:
            cmd = [
                sys.executable,
                "-m",
                "gunicorn",
                *extra_args,
                "-w",
                str(workers),
                "--access-logfile",
                str(access_log),
                "--access-logformat",
                "WORKER=%(p)s %(m)s %(U)s %(s)s",
                "-b",
                f"127.0.0.1:{http_port}",
                "app:app",
            ]

        base_url = f"http://127.0.0.1:{http_port}"

        def _http_json(method: str, path: str, payload=None):
            data = None
            headers = {"X-MANAGEMENT-API-KEY": MGMT_API_KEY}
            if payload is not None:
                data = json.dumps(payload).encode("utf-8")
                headers["Content-Type"] = "application/json"
            req = urllib.request.Request(
                f"{base_url}{path}",
                data=data,
                headers=headers,
                method=method,
            )
            try:
                with urllib.request.urlopen(req, timeout=5) as resp:
                    body = resp.read().decode("utf-8")
                    return resp.status, json.loads(body) if body else None
            except urllib.error.HTTPError as exc:
                body = exc.read().decode("utf-8")
                return exc.code, json.loads(body) if body else None

        with server_log.open("w") as log_fp:
            proc = subprocess.Popen(
                cmd,
                cwd=str(REPO_ROOT),
                env=env,
                stdout=log_fp,
                stderr=subprocess.STDOUT,
                text=True,
            )
            try:
                ready = False
                for _ in range(40):
                    if proc.poll() is not None:
                        break
                    try:
                        req = urllib.request.Request(
                            f"{base_url}/version",
                            headers={"X-API-KEY": CLIENT_API_KEY},
                        )
                        with urllib.request.urlopen(req, timeout=1) as resp:
                            if resp.status == 200 and (
                                server_kind == "flask"
                                or server_log.read_text().count(
                                    "Booting worker with pid:"
                                )
                                >= workers
                            ):
                                ready = True
                                break
                    except Exception:
                        pass
                    time.sleep(0.25)

                if not ready:
                    _stop_process_and_collect(proc)
                    pytest.fail(f"{label} failed to start:\n{server_log.read_text()}")

                # 1. Status reports active backend and reachability
                status_code, status_body = _http_json("GET", "/management/status")
                assert status_code == 200
                assert status_body["policy_storage"] == {
                    "backend": backend,
                    "reachable": True,
                }

                # 2. Concurrent duplicate creation race across all 3 namespaces
                assert (
                    _http_json(
                        "POST",
                        "/management/certify-policy/v0/store",
                        _sample_certify_policy("seed-cert"),
                    )[0]
                    == 201
                )
                for route_prefix, doc in [
                    (
                        "/management/policy/v0",
                        _sample_secret_policy("race-sec"),
                    ),
                    (
                        "/management/certify-policy/v0",
                        _sample_certify_policy("race-cert"),
                    ),
                    (
                        "/management/domain-policy/v0",
                        _sample_domain_policy("race-dom", ["seed-cert"]),
                    ),
                ]:
                    barrier = threading.Barrier(12)

                    def _store_attempt(prefix=route_prefix, body_doc=doc):
                        barrier.wait(timeout=5)
                        return _http_json("POST", f"{prefix}/store", body_doc)[0]

                    with ThreadPoolExecutor(max_workers=12) as pool:
                        codes = list(pool.map(lambda _: _store_attempt(), range(12)))
                    assert codes.count(201) == 1
                    assert codes.count(409) == 11

                # 3. Delete and recreate under the same ID, verifying no stale reads
                assert (
                    _http_json("DELETE", "/management/policy/v0/delete/race-sec")[0]
                    == 200
                )
                for _ in range(6):
                    assert (
                        _http_json("GET", "/management/policy/v0/get/race-sec")[0]
                        == 404
                    )

                assert (
                    _http_json(
                        "POST",
                        "/management/policy/v0/store",
                        _sample_secret_policy("race-sec", key_id="updated-key-2"),
                    )[0]
                    == 201
                )
                for _ in range(8):
                    st, body = _http_json("GET", "/management/policy/v0/get/race-sec")
                    assert st == 200
                    assert body["policy"]["metadata"]["key_id"] == "updated-key-2"

                # 4. Concurrent batch creates, list, and concurrent deletes
                batch_ids = [f"batch-{i}" for i in range(12)]
                with ThreadPoolExecutor(max_workers=8) as pool:
                    create_codes = list(
                        pool.map(
                            lambda pid: _http_json(
                                "POST",
                                "/management/policy/v0/store",
                                _sample_secret_policy(pid),
                            )[0],
                            batch_ids,
                        )
                    )
                assert create_codes == [201] * len(batch_ids)

                st, list_body = _http_json("GET", "/management/policy/v0/list")
                assert st == 200
                assert list_body["count"] == len(batch_ids) + 1

                with ThreadPoolExecutor(max_workers=8) as pool:
                    del_codes = list(
                        pool.map(
                            lambda pid: _http_json(
                                "DELETE", f"/management/policy/v0/delete/{pid}"
                            )[0],
                            batch_ids * 2,
                        )
                    )
                assert del_codes.count(200) == len(batch_ids)
                assert del_codes.count(404) == len(batch_ids)

                if server_kind == "gunicorn" and workers > 1:
                    for _ in range(10):
                        current_served = set(
                            re.findall(r"WORKER=(<\d+>|[^\s]+)", access_log.read_text())
                        )
                        if len(current_served) >= workers:
                            break
                        fanout = workers * 4
                        fanout_barrier = threading.Barrier(fanout)

                        def _status_probe(b=fanout_barrier):
                            b.wait(timeout=5)
                            return _http_json("GET", "/management/status")[0]

                        with ThreadPoolExecutor(max_workers=fanout) as pool:
                            probe_codes = list(
                                pool.map(lambda _: _status_probe(), range(fanout))
                            )
                        assert probe_codes == [200] * fanout
            finally:
                _stop_process_and_collect(proc)

        if server_kind == "gunicorn":
            booted_pids = set(
                re.findall(r"Booting worker with pid: (\d+)", server_log.read_text())
            )
            served_pids = set(
                re.findall(r"WORKER=(<\d+>|[^\s]+)", access_log.read_text())
            )
            assert len(booted_pids) == workers
            assert len(served_pids) == workers
