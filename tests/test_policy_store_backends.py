#
# TEE Attestation Service - Policy Store Backend Contract and PostgreSQL Tests
#
# Copyright 2026 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# This file is part of the TEE Attestation Service.
#
# Tests covering the PolicyStore abstraction, RedisPolicyStore and
# PostgresPolicyStore contract parity, strict single-store isolation
# (no dual-write, no cross-read), atomic concurrent policy creation,
# fail-closed store outage handling, PostgreSQL schema verification, DSN
# redaction, backup/restore, and startup failure handling.
#

import base64
import fnmatch
import glob
import json
import logging
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
import traceback
import tracemalloc
from collections.abc import Generator
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
from unittest.mock import MagicMock, patch

import psycopg
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from flask import Flask

from tas import tas_vm
from tas.auth import init_client_auth, init_management_auth
from tas.certify.policy_routes import certify_policy_bp
from tas.certify.routes import certify_bp
from tas.client_routes import client_bp
from tas.error_handlers import register_error_handlers
from tas.management_routes import management_bp
from tas.policy_helper import canonicalize_policy, verify_policy_signature
from tas.policy_store import (
    CERTIFY_POLICY_NAMESPACE,
    DOMAIN_POLICY_NAMESPACE,
    POLICY_NAMESPACE,
    PolicyAlreadyExists,
    PolicyStoreError,
    PolicyStoreUnavailable,
    RedisPolicyStore,
    init_policy_store,
)
from tas.postgres_policy_store import PostgresPolicyStore, _safe_driver_error

REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_SQL_PATH = REPO_ROOT / "db" / "postgresql" / "schema_v1.sql"

CLIENT_API_KEY = "a" * 64
MGMT_API_KEY = "b" * 64


# --------------------------------------------------------------------------- #
# Helpers and thread-safe / recording Redis test doubles
# --------------------------------------------------------------------------- #


class RecordingFakeRedis:
    """Thread-safe in-memory Redis double that records every command and key."""

    def __init__(self):
        self._store: dict[str, str] = {}
        self._lock = threading.Lock()
        self.calls: list[tuple[str, str]] = []
        self.reachable = True

    def set(self, key: str, value: str, nx: bool = False, ex: int | None = None):
        with self._lock:
            self.calls.append(("SET", key))
            if nx and key in self._store:
                return None
            self._store[key] = value
            return True

    def setex(self, key: str, ttl: int, value: str):
        with self._lock:
            self.calls.append(("SETEX", key))
            self._store[key] = value
            return True

    def get(self, key: str):
        with self._lock:
            self.calls.append(("GET", key))
            return self._store.get(key)

    def getdel(self, key: str):
        with self._lock:
            self.calls.append(("GETDEL", key))
            return self._store.pop(key, None)

    def delete(self, *keys: str) -> int:
        with self._lock:
            deleted = 0
            for key in keys:
                self.calls.append(("DEL", key))
                if key in self._store:
                    del self._store[key]
                    deleted += 1
            return deleted

    def keys(self, pattern: str = "*") -> list[str]:
        with self._lock:
            self.calls.append(("KEYS", pattern))
            return [k for k in self._store if fnmatch.fnmatch(k, pattern)]

    def scan_iter(self, match: str = "*", count: int | None = None):
        with self._lock:
            self.calls.append(("SCAN", match))
            matched = [k for k in self._store if fnmatch.fnmatch(k, match)]
        return iter(matched)

    def ping(self) -> bool:
        if not self.reachable:
            raise RuntimeError("Redis connection refused")
        return True

    def config_get(self, key: str) -> dict[str, str]:
        return {key: "yes"}

    def policy_calls(self) -> list[tuple[str, str]]:
        prefixes = ("policy:", "certify-policy:", "domain-policy:")
        return [
            (op, target)
            for op, target in self.calls
            if any(target.startswith(p) for p in prefixes)
        ]


def _sign_policy_doc(doc: dict, private_key) -> dict:
    signed = json.loads(json.dumps(doc))
    canonical = canonicalize_policy(signed)
    sig = private_key.sign(
        canonical,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA384()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA384(),
    )
    signed["signature"] = {
        "algorithm": "SHA384",
        "padding": "PSS",
        "value": base64.b64encode(sig).decode("ascii"),
    }
    return signed


def _sample_secret_policy(policy_id: str = "sev-pol-1", key_id: str = "key-1") -> dict:
    return {
        "metadata": {
            "name": f"Policy {policy_id}",
            "version": "1.0",
            "description": "Test secret-release policy",
            "policy_type": "SEV",
            "policy_id": policy_id,
            "key_id": key_id,
        },
        "validation_rules": {
            "policy": {"debug_allowed": False},
        },
    }


def _sample_certify_policy(
    policy_id: str = "cert-pol-1", policy_type: str = "SEV"
) -> dict:
    return {
        "metadata": {
            "name": f"Certify Policy {policy_id}",
            "version": "1.0",
            "description": "Test certify policy",
            "policy_type": policy_type,
            "policy_id": policy_id,
            "key_id": f"key-{policy_id}",
        },
        "validation_rules": {
            "policy": {"debug_allowed": False},
        },
    }


def _sample_domain_policy(
    policy_id: str = "dom-prod",
    members: list[str] | None = None,
    tee_type: str = "amd-sev-snp",
) -> dict:
    return {
        "metadata": {
            "policy_id": policy_id,
            "description": "Test domain policy",
        },
        "certify_policies": {
            tee_type: list(members or ["cert-pol-1"]),
        },
    }


def _find_pg_bin(tool_name: str) -> str:
    path = shutil.which(tool_name)
    if path:
        return path
    candidates = sorted(glob.glob(f"/usr/lib/postgresql/*/bin/{tool_name}"))
    if candidates:
        return candidates[-1]
    pytest.skip(f"PostgreSQL binary '{tool_name}' is not installed")


def _free_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# --------------------------------------------------------------------------- #
# Ephemeral local PostgreSQL cluster fixture for real database integration tests
# --------------------------------------------------------------------------- #


def _pg_server_cmd(*args: str) -> list[str]:
    """Prefix PostgreSQL server commands with `runuser -u postgres` when running as root."""
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return ["runuser", "-u", "postgres", "--", *args]
    return list(args)


@pytest.fixture(scope="module")
def pg_cluster(tmp_path_factory):
    """Start an isolated temporary PostgreSQL cluster for real SQL tests."""
    initdb_bin = _find_pg_bin("initdb")
    pg_ctl_bin = _find_pg_bin("pg_ctl")
    psql_bin = _find_pg_bin("psql")
    pg_dump_bin = _find_pg_bin("pg_dump")

    base_dir = tmp_path_factory.mktemp("tas_pg_cluster")
    data_dir = base_dir / "data"
    sock_dir = base_dir / "sock"
    log_file = base_dir / "postgres.log"
    sock_dir.mkdir(parents=True, exist_ok=True)
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        cur = base_dir
        while str(cur) not in ("/", "/tmp"):
            cur.chmod(0o755)
            cur = cur.parent
        shutil.chown(base_dir, user="postgres", group="postgres")
        shutil.chown(sock_dir, user="postgres", group="postgres")
    port = _free_tcp_port()

    subprocess.run(
        _pg_server_cmd(
            initdb_bin,
            "-D",
            str(data_dir),
            "-U",
            "postgres",
            "-A",
            "trust",
            "--encoding=UTF8",
            "--no-instructions",
        ),
        check=True,
        capture_output=True,
        text=True,
    )

    pg_opts = (
        f"-p {port} -h 127.0.0.1 -k {sock_dir} "
        "-c fsync=on -c synchronous_commit=on -c full_page_writes=on"
    )
    subprocess.run(
        _pg_server_cmd(
            pg_ctl_bin,
            "-D",
            str(data_dir),
            "-l",
            str(log_file),
            "-o",
            pg_opts,
            "-w",
            "start",
        ),
        check=True,
        capture_output=True,
        text=True,
    )

    admin_dsn = f"postgresql://postgres@127.0.0.1:{port}/postgres"
    try:
        yield {
            "port": port,
            "data_dir": data_dir,
            "sock_dir": sock_dir,
            "log_file": log_file,
            "pg_opts": pg_opts,
            "pg_ctl_bin": pg_ctl_bin,
            "psql_bin": psql_bin,
            "pg_dump_bin": pg_dump_bin,
            "admin_dsn": admin_dsn,
        }
    finally:
        subprocess.run(
            _pg_server_cmd(pg_ctl_bin, "-D", str(data_dir), "-m", "immediate", "stop"),
            check=False,
            capture_output=True,
        )


@pytest.fixture()
def pg_dsn(pg_cluster):
    """Create a fresh database with schema_v1.sql applied via `psql` -f."""
    db_name = f"tas_test_{int(time.time() * 1_000_000) % 1_000_000_000}"
    admin_dsn = pg_cluster["admin_dsn"]
    with psycopg.connect(admin_dsn, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute(f"DROP DATABASE IF EXISTS {db_name}")
            cur.execute(f"CREATE DATABASE {db_name}")

    dsn = f"postgresql://postgres@127.0.0.1:{pg_cluster['port']}/{db_name}"
    subprocess.run(
        [
            pg_cluster["psql_bin"],
            dsn,
            "-v",
            "ON_ERROR_STOP=1",
            "-f",
            str(SCHEMA_SQL_PATH),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    yield dsn

    with psycopg.connect(admin_dsn, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute(f"DROP DATABASE IF EXISTS {db_name} WITH (FORCE)")


def _stop_process_and_collect(proc: subprocess.Popen) -> str:
    """Stop a test-owned process and collect output without blocking."""
    if proc.poll() is None:
        proc.terminate()
    try:
        stdout, _ = proc.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        stdout, _ = proc.communicate(timeout=5)
    return stdout or ""


@pytest.fixture()
def isolated_redis(tmp_path):
    """Run a test-owned Redis instance on a random local port."""
    redis_bin = shutil.which("redis-server")
    if not redis_bin:
        pytest.skip("redis-server is not installed")

    port = _free_tcp_port()
    proc = subprocess.Popen(
        [
            redis_bin,
            "--bind",
            "127.0.0.1",
            "--port",
            str(port),
            "--save",
            "",
            "--appendonly",
            "no",
            "--dir",
            str(tmp_path),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        for _ in range(40):
            if proc.poll() is not None:
                pytest.fail(
                    f"Owned Redis failed to start:\n{_stop_process_and_collect(proc)}"
                )
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.25):
                    break
            except OSError:
                time.sleep(0.1)
        else:
            pytest.fail(
                f"Owned Redis did not become ready:\n"
                f"{_stop_process_and_collect(proc)}"
            )
        yield port
    finally:
        _stop_process_and_collect(proc)


def _smoke_env(pg_dsn: str, redis_port: int, *, certify_enabled: bool = False):
    """Return an environment isolated from inherited TAS and Flask settings."""
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("TAS_", "FLASK_"))
    }
    env.update(
        {
            "TAS_API_KEY": CLIENT_API_KEY,
            "TAS_MANAGEMENT_API_KEY": MGMT_API_KEY,
            "TAS_REDIS_HOST": "127.0.0.1",
            "TAS_REDIS_PORT": str(redis_port),
            "TAS_REDIS_PERSISTENCE": "false",
            "TAS_EPHEMERAL_REDIS_URI": "",
            "TAS_POLICY_BACKEND": "postgresql",
            "TAS_POSTGRES_DSN": pg_dsn,
            "TAS_ENFORCE_SIGNED_POLICIES": "false",
            "TAS_CERTIFY_ENABLED": str(certify_enabled).lower(),
            "TAS_OVERRIDE__LOGGING__FILE": "/tmp/tas-smoke.log",
        }
    )
    return env


@pytest.fixture(params=["redis", "postgresql"])
def backend_env(request):
    """Yield (`backend_name`, `policy_store`, `recording_redis`) for contract tests."""
    recording_redis = RecordingFakeRedis()
    if request.param == "redis":
        store = RedisPolicyStore(recording_redis)
    else:
        pg_dsn = request.getfixturevalue("pg_dsn")
        store = PostgresPolicyStore(pg_dsn)
        store.verify_schema()
    return request.param, store, recording_redis


def _make_full_test_app(
    policy_store,
    redis_client,
    enforce_signed: bool = False,
    trusted_keys: list | None = None,
) -> Flask:
    app = Flask(__name__)
    app.config.update(
        TESTING=True,
        TAS_API_KEY=CLIENT_API_KEY,
        TAS_MANAGEMENT_API_KEY=MGMT_API_KEY,
        TAS_ENFORCE_SIGNED_POLICIES=enforce_signed,
        TAS_TRUSTED_KEYS=trusted_keys or [],
        TAS_POLICY_BACKEND=policy_store.backend_name,
        TAS_CERTIFY_MAX_POLICIES=32,
        TAS_NONCE_EXPIRATION_SECONDS=120,
    )
    app.extensions["redis"] = redis_client
    app.extensions["policy_store"] = policy_store
    app.extensions["redis_config_rewrite_ok"] = True
    app.extensions["kbm_client"] = MagicMock(name="kbm_client")
    app.extensions["kbm_get_secret"] = MagicMock(return_value="wrapped-secret-value")

    init_client_auth(app)
    init_management_auth(app)
    register_error_handlers(app)

    app.register_blueprint(management_bp)
    app.register_blueprint(certify_policy_bp)
    app.register_blueprint(client_bp)
    app.register_blueprint(certify_bp)
    return app


@pytest.fixture()
def mgmt_headers():
    return {"X-MANAGEMENT-API-KEY": MGMT_API_KEY, "Content-Type": "application/json"}


@pytest.fixture()
def client_headers():
    return {"X-API-KEY": CLIENT_API_KEY, "Content-Type": "application/json"}


# --------------------------------------------------------------------------- #
# 1. Error Hierarchy & Scope Validation
# --------------------------------------------------------------------------- #


class TestStartupProcessCleanup:
    def test_stops_running_child_with_bounded_output_collection(self):
        proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        try:
            assert proc.poll() is None
            started = time.monotonic()
            with patch.object(proc, "communicate", wraps=proc.communicate) as collect:
                assert _stop_process_and_collect(proc) == ""
                collect.assert_called_once_with(timeout=5)
            assert proc.poll() is not None
            assert time.monotonic() - started < 12
        finally:
            _stop_process_and_collect(proc)

    def test_kills_child_when_graceful_shutdown_times_out(self):
        proc = MagicMock(spec=subprocess.Popen)
        proc.poll.return_value = None
        proc.communicate.side_effect = [
            subprocess.TimeoutExpired("test-child", 5),
            ("child output", None),
        ]

        assert _stop_process_and_collect(proc) == "child output"
        proc.terminate.assert_called_once_with()
        proc.kill.assert_called_once_with()
        assert proc.communicate.call_count == 2
        for call in proc.communicate.call_args_list:
            assert call.kwargs == {"timeout": 5}


class TestPolicyStoreErrorContract:
    def test_policy_store_unavailable_is_not_value_error(self):
        err = PolicyStoreUnavailable()
        assert isinstance(err, PolicyStoreError)
        assert isinstance(err, RuntimeError)
        assert not isinstance(err, ValueError)
        assert not issubclass(PolicyStoreUnavailable, ValueError)

    def test_policy_already_exists_is_not_value_error(self):
        err = PolicyAlreadyExists("policy", "pol-1")
        assert isinstance(err, PolicyStoreError)
        assert not isinstance(err, ValueError)

    def test_invalid_namespace_rejected_by_both_adapters(self, pg_dsn):
        redis_store = RedisPolicyStore(RecordingFakeRedis())
        pg_store = PostgresPolicyStore(pg_dsn)
        for store in (redis_store, pg_store):
            with pytest.raises(ValueError, match="Unsupported policy namespace"):
                store.create("invalid-ns", "id1", "{}")
            with pytest.raises(ValueError, match="Unsupported policy namespace"):
                store.get("invalid-ns", "id1")
            with pytest.raises(ValueError, match="Unsupported policy namespace"):
                list(store.list("invalid-ns"))
            with pytest.raises(ValueError, match="Unsupported policy namespace"):
                store.delete("invalid-ns", "id1")


# --------------------------------------------------------------------------- #
# 2. Shared Contract Tests Across Redis and PostgreSQL Backends
# --------------------------------------------------------------------------- #


class TestSharedPolicyStoreContract:
    def test_redis_list_fetches_documents_only_as_consumed(self):
        redis = RecordingFakeRedis()
        store = RedisPolicyStore(redis)
        store.create(POLICY_NAMESPACE, "p1", '{"value": 1}')
        store.create(POLICY_NAMESPACE, "p2", '{"value": 2}')
        redis.calls.clear()

        with closing(store.list(POLICY_NAMESPACE)) as documents:
            assert redis.calls == []
            assert next(documents) == '{"value": 1}'
            assert redis.calls == [("SCAN", "policy:*"), ("GET", "policy:p1")]

        assert ("GET", "policy:p2") not in redis.calls

    @pytest.mark.parametrize(
        "namespace,make_document,response_key,summary_fields",
        [
            (
                POLICY_NAMESPACE,
                _sample_secret_policy,
                "policies",
                ("name", "policy_type", "key_id", "version", "description"),
            ),
            (
                CERTIFY_POLICY_NAMESPACE,
                _sample_certify_policy,
                "certify_policies",
                ("name", "policy_type", "key_id"),
            ),
            (
                DOMAIN_POLICY_NAMESPACE,
                _sample_domain_policy,
                "domain_policies",
                ("description", "certify_policies"),
            ),
        ],
    )
    def test_list_routes_bound_document_memory_and_preserve_summaries(
        self,
        backend_env,
        mgmt_headers,
        monkeypatch,
        namespace,
        make_document,
        response_key,
        summary_fields,
    ):
        _, store, redis = backend_env
        count = 64
        expected = []
        for index in range(count):
            policy_id = f"memory-{index:03d}"
            document = make_document(policy_id)
            document.setdefault("validation_rules", {})["large_rule"] = "x" * (
                512 * 1024
            )
            store.create(namespace, policy_id, json.dumps(document))
            summary = {"policy_id": policy_id, "signed": False}
            for field in summary_fields:
                summary[field] = (
                    document[field]
                    if field == "certify_policies"
                    else document["metadata"][field]
                )
            expected.append(summary)

        original_get = redis.get

        def fresh_get(key):
            # Real Redis reads allocate a newly decoded document, not a shared string.
            raw = original_get(key)
            return raw.encode("utf-8").decode("utf-8") if raw is not None else None

        monkeypatch.setattr(redis, "get", fresh_get)
        client = _make_full_test_app(store, redis).test_client()
        tracemalloc.start()
        try:
            response = client.get(
                f"/management/{namespace}/v0/list", headers=mgmt_headers
            )
            _, peak_bytes = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()

        assert response.status_code == 200
        body = response.get_json()
        assert set(body) == {response_key, "count"}
        assert body["count"] == count
        assert (
            sorted(body[response_key], key=lambda item: item["policy_id"]) == expected
        )
        assert peak_bytes < 8 * 1024 * 1024

    def test_crud_and_namespace_isolation(self, backend_env):
        _, store, _ = backend_env

        sec_doc = json.dumps(_sample_secret_policy("shared-id"))
        cert_doc = json.dumps(_sample_certify_policy("shared-id"))
        dom_doc = json.dumps(_sample_domain_policy("shared-id", ["shared-id"]))

        store.create(POLICY_NAMESPACE, "shared-id", sec_doc)
        store.create(CERTIFY_POLICY_NAMESPACE, "shared-id", cert_doc)
        store.create(DOMAIN_POLICY_NAMESPACE, "shared-id", dom_doc)

        assert store.get(POLICY_NAMESPACE, "shared-id") == sec_doc
        assert store.get(CERTIFY_POLICY_NAMESPACE, "shared-id") == cert_doc
        assert store.get(DOMAIN_POLICY_NAMESPACE, "shared-id") == dom_doc

        assert list(store.list(POLICY_NAMESPACE)) == [sec_doc]
        assert list(store.list(CERTIFY_POLICY_NAMESPACE)) == [cert_doc]
        assert list(store.list(DOMAIN_POLICY_NAMESPACE)) == [dom_doc]

        # Deleting from one scope leaves the other two untouched
        assert store.delete(POLICY_NAMESPACE, "shared-id") is True
        assert store.delete(POLICY_NAMESPACE, "shared-id") is False
        assert store.get(POLICY_NAMESPACE, "shared-id") is None
        assert store.get(CERTIFY_POLICY_NAMESPACE, "shared-id") == cert_doc
        assert store.get(DOMAIN_POLICY_NAMESPACE, "shared-id") == dom_doc

    def test_http_routes_all_three_namespaces(self, backend_env, mgmt_headers):
        backend_name, store, fake_redis = backend_env
        app = _make_full_test_app(store, fake_redis)
        client = app.test_client()

        # 1. Domain policy can be uploaded before referenced certify policy exists
        dom = _sample_domain_policy("prod", ["cert-1"])
        r_dom = client.post(
            "/management/domain-policy/v0/store",
            headers=mgmt_headers,
            json=dom,
        )
        assert r_dom.status_code == 201
        assert "Referenced certify-policies not found" in r_dom.get_json()["warning"]

        # 2. Upload certify policy
        cert = _sample_certify_policy("cert-1", "SEV")
        r_cert = client.post(
            "/management/certify-policy/v0/store",
            headers=mgmt_headers,
            json=cert,
        )
        assert r_cert.status_code == 201

        # 3. Uploading a second domain policy referencing cert-1 resolves cert-1
        # from the same PolicyStore and emits no missing-member warning
        dom2 = _sample_domain_policy("staging", ["cert-1"])
        r_dom2 = client.post(
            "/management/domain-policy/v0/store",
            headers=mgmt_headers,
            json=dom2,
        )
        assert r_dom2.status_code == 201
        assert "not found" not in r_dom2.get_json().get("warning", "")

        # 4. Upload secret-release policy
        sec = _sample_secret_policy("sec-1", "kbm-key-1")
        r_sec = client.post(
            "/management/policy/v0/store",
            headers=mgmt_headers,
            json=sec,
        )
        assert r_sec.status_code == 201

        # 5. Verify status endpoint reports the active backend
        status_resp = client.get("/management/status", headers=mgmt_headers)
        assert status_resp.status_code == 200
        status_json = status_resp.get_json()
        assert status_json["policy_storage"] == {
            "backend": backend_name,
            "reachable": True,
        }

    def test_concurrent_policy_creation_yields_single_201_and_rest_409(
        self, backend_env, mgmt_headers
    ):
        _, store, fake_redis = backend_env
        app = _make_full_test_app(store, fake_redis)
        payload = json.dumps(_sample_secret_policy("race-policy-001"))

        barrier = threading.Barrier(12)

        def _worker():
            with app.test_client() as c:
                barrier.wait(timeout=5)
                resp = c.post(
                    "/management/policy/v0/store",
                    headers=mgmt_headers,
                    data=payload,
                )
                return resp.status_code

        with ThreadPoolExecutor(max_workers=12) as pool:
            statuses = list(pool.map(lambda _: _worker(), range(12)))

        assert statuses.count(201) == 1
        assert statuses.count(409) == 11

    def test_signed_policy_round_trip_preserves_signature(
        self, backend_env, mgmt_headers
    ):
        _, store, fake_redis = backend_env
        priv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        trusted_keys = [("public_key", "test-mem", priv_key.public_key())]

        app = _make_full_test_app(
            store, fake_redis, enforce_signed=True, trusted_keys=trusted_keys
        )
        client = app.test_client()

        signed_sec = _sign_policy_doc(_sample_secret_policy("signed-sec"), priv_key)
        signed_cert = _sign_policy_doc(_sample_certify_policy("signed-cert"), priv_key)
        signed_dom = _sign_policy_doc(
            _sample_domain_policy("signed-dom", ["signed-cert"]), priv_key
        )

        assert (
            client.post(
                "/management/policy/v0/store", headers=mgmt_headers, json=signed_sec
            ).status_code
            == 201
        )
        assert (
            client.post(
                "/management/certify-policy/v0/store",
                headers=mgmt_headers,
                json=signed_cert,
            ).status_code
            == 201
        )
        assert (
            client.post(
                "/management/domain-policy/v0/store",
                headers=mgmt_headers,
                json=signed_dom,
            ).status_code
            == 201
        )

        # Verify attestation loaders accept the stored signed documents
        with app.app_context():
            loaded_sec, key_id = tas_vm.get_policy(store, "signed-sec")
            assert key_id == "key-1"
            assert verify_policy_signature(loaded_sec, trusted_keys)

            loaded_dom = tas_vm.get_domain_policy(store, "signed-dom")
            assert verify_policy_signature(loaded_dom, trusted_keys)

            loaded_cert, cert_key_id = tas_vm.get_certify_policy(store, "signed-cert")
            assert cert_key_id == "key-signed-cert"
            assert verify_policy_signature(loaded_cert, trusted_keys)


# --------------------------------------------------------------------------- #
# 3. Single Authoritative Store — No Dual-Write & No Cross-Read
# --------------------------------------------------------------------------- #


class TestSingleAuthoritativeStoreIsolation:
    def test_no_dual_write_in_postgresql_mode(self, pg_dsn, mgmt_headers):
        recording_redis = RecordingFakeRedis()
        pg_store = PostgresPolicyStore(pg_dsn)
        app = _make_full_test_app(pg_store, recording_redis)
        client = app.test_client()

        # Store and delete across all three scopes in PostgreSQL mode
        assert (
            client.post(
                "/management/policy/v0/store",
                headers=mgmt_headers,
                json=_sample_secret_policy("pg-only-sec"),
            ).status_code
            == 201
        )
        assert (
            client.post(
                "/management/certify-policy/v0/store",
                headers=mgmt_headers,
                json=_sample_certify_policy("pg-only-cert"),
            ).status_code
            == 201
        )
        assert (
            client.post(
                "/management/domain-policy/v0/store",
                headers=mgmt_headers,
                json=_sample_domain_policy("pg-only-dom", ["pg-only-cert"]),
            ).status_code
            == 201
        )
        assert (
            client.delete(
                "/management/policy/v0/delete/pg-only-sec", headers=mgmt_headers
            ).status_code
            == 200
        )
        assert (
            client.delete(
                "/management/certify-policy/v0/delete/pg-only-cert",
                headers=mgmt_headers,
            ).status_code
            == 200
        )
        assert (
            client.delete(
                "/management/domain-policy/v0/delete/pg-only-dom",
                headers=mgmt_headers,
            ).status_code
            == 200
        )

        # Redis must have zero calls touching policy:*, certify-policy:*, or domain-policy:*
        assert recording_redis.policy_calls() == []
        assert recording_redis._store == {}

    def test_no_cross_read_in_postgresql_mode(self, pg_dsn, mgmt_headers):
        recording_redis = RecordingFakeRedis()
        # Seed policies directly in Redis (simulating data in the non-selected store)
        recording_redis._store["policy:redis-only-sec"] = json.dumps(
            _sample_secret_policy("redis-only-sec")
        )
        recording_redis._store["certify-policy:redis-only-cert"] = json.dumps(
            _sample_certify_policy("redis-only-cert")
        )
        recording_redis._store["domain-policy:redis-only-dom"] = json.dumps(
            _sample_domain_policy("redis-only-dom", ["redis-only-cert"])
        )
        recording_redis.calls.clear()

        pg_store = PostgresPolicyStore(pg_dsn)
        app = _make_full_test_app(pg_store, recording_redis)
        client = app.test_client()

        # Management get and list must report missing/empty without touching Redis
        assert (
            client.get(
                "/management/policy/v0/get/redis-only-sec", headers=mgmt_headers
            ).status_code
            == 404
        )
        assert (
            client.get(
                "/management/certify-policy/v0/get/redis-only-cert",
                headers=mgmt_headers,
            ).status_code
            == 404
        )
        assert (
            client.get(
                "/management/domain-policy/v0/get/redis-only-dom",
                headers=mgmt_headers,
            ).status_code
            == 404
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
            == 0
        )
        assert (
            client.get(
                "/management/domain-policy/v0/list", headers=mgmt_headers
            ).get_json()["count"]
            == 0
        )

        # Attestation `vm_verify` and `domain_verify` must also report missing and never read Redis
        evidence_b64 = base64.b64encode(b"\x01\x02\x03").decode("ascii")
        with app.app_context():
            ok, key_id, err = tas_vm.vm_verify(
                pg_store,
                recording_redis,
                "nonce-1",
                "amd-sev-snp",
                evidence_b64,
                "redis-only-sec",
            )
            assert ok is False
            assert key_id is None
            assert err == "Policy not found"

            ok_dom, dom_key, dom_err = tas_vm.domain_verify(
                pg_store,
                recording_redis,
                "nonce-1",
                "amd-sev-snp",
                evidence_b64,
                "redis-only-dom",
            )
            assert ok_dom is False
            assert dom_key is None
            assert dom_err == "Domain policy not found"

        assert recording_redis.policy_calls() == []

    def test_no_cross_read_in_redis_mode_and_no_postgres_import_or_connect(
        self, pg_dsn, mgmt_headers, monkeypatch
    ):
        # Seed policies only in PostgreSQL
        pg_store = PostgresPolicyStore(pg_dsn)
        pg_store.create(
            POLICY_NAMESPACE,
            "pg-seeded-sec",
            json.dumps(_sample_secret_policy("pg-seeded-sec")),
        )
        pg_store.create(
            CERTIFY_POLICY_NAMESPACE,
            "pg-seeded-cert",
            json.dumps(_sample_certify_policy("pg-seeded-cert")),
        )
        pg_store.create(
            DOMAIN_POLICY_NAMESPACE,
            "pg-seeded-dom",
            json.dumps(_sample_domain_policy("pg-seeded-dom", ["pg-seeded-cert"])),
        )

        # Redis mode must not call psycopg.connect for policy operations.
        connect_mock = MagicMock(
            side_effect=AssertionError("psycopg.connect called in Redis mode")
        )
        monkeypatch.setattr(psycopg, "connect", connect_mock)

        recording_redis = RecordingFakeRedis()
        app = Flask(__name__)
        app.config["TAS_POLICY_BACKEND"] = "redis"
        redis_store = init_policy_store(app, recording_redis)
        connect_mock.assert_not_called()

        full_app = _make_full_test_app(redis_store, recording_redis)
        client = full_app.test_client()

        assert (
            client.get(
                "/management/policy/v0/get/pg-seeded-sec", headers=mgmt_headers
            ).status_code
            == 404
        )
        assert (
            client.get("/management/policy/v0/list", headers=mgmt_headers).get_json()[
                "count"
            ]
            == 0
        )

        evidence_b64 = base64.b64encode(b"\x01\x02\x03").decode("ascii")
        with full_app.app_context():
            ok, _, err = tas_vm.vm_verify(
                redis_store,
                recording_redis,
                "nonce-1",
                "amd-sev-snp",
                evidence_b64,
                "pg-seeded-sec",
            )
            assert ok is False
            assert err == "Policy not found"

            ok_dom, _, dom_err = tas_vm.domain_verify(
                redis_store,
                recording_redis,
                "nonce-1",
                "amd-sev-snp",
                evidence_b64,
                "pg-seeded-dom",
            )
            assert ok_dom is False
            assert dom_err == "Domain policy not found"

        connect_mock.assert_not_called()


# --------------------------------------------------------------------------- #
# 4. Outage Handling (Fail-Closed 500, Never Skips Domain Members)
# --------------------------------------------------------------------------- #


class FailingPolicyStore(RedisPolicyStore):
    """PolicyStore test double that raises PolicyStoreUnavailable on demand."""

    def __init__(self, redis_client, fail_on_id: str | None = None):
        super().__init__(redis_client)
        self.fail_on_id = fail_on_id
        self.always_fail = fail_on_id is None

    def get(self, namespace: str, policy_id: str):
        if self.always_fail or policy_id == self.fail_on_id:
            raise PolicyStoreUnavailable()
        return super().get(namespace, policy_id)

    def create(self, namespace: str, policy_id: str, document: str) -> None:
        if self.always_fail or policy_id == self.fail_on_id:
            raise PolicyStoreUnavailable()
        super().create(namespace, policy_id, document)

    def list(self, namespace: str) -> Generator[str, None, None]:
        if self.always_fail:
            raise PolicyStoreUnavailable()
        return super().list(namespace)

    def delete(self, namespace: str, policy_id: str) -> bool:
        if self.always_fail or policy_id == self.fail_on_id:
            raise PolicyStoreUnavailable()
        return super().delete(namespace, policy_id)


class TestPolicyStoreOutageFailClosed:
    @pytest.mark.parametrize(
        "namespace,error",
        [
            (POLICY_NAMESPACE, "Failed to list policies"),
            (CERTIFY_POLICY_NAMESPACE, "Failed to list certify-policies"),
            (DOMAIN_POLICY_NAMESPACE, "Failed to list domain policies"),
        ],
    )
    @pytest.mark.parametrize("failure", ["iteration", "summary"])
    def test_list_failure_closes_iterator_without_partial_success(
        self, mgmt_headers, monkeypatch, namespace, error, failure
    ):
        redis = RecordingFakeRedis()
        store = RedisPolicyStore(redis)
        closed = []

        def documents():
            try:
                yield json.dumps(_sample_secret_policy("first"))
                if failure == "summary":
                    yield "[]"
                raise PolicyStoreUnavailable()
            finally:
                closed.append(True)

        iterator = documents()
        monkeypatch.setattr(store, "list", lambda _: iterator)
        client = _make_full_test_app(store, redis).test_client()
        response = client.get(f"/management/{namespace}/v0/list", headers=mgmt_headers)

        assert response.status_code == 500
        assert response.get_json() == {"error": error}
        assert closed == [True]

    def test_management_routes_return_500_with_backend_neutral_messages(
        self, mgmt_headers
    ):
        fake_redis = RecordingFakeRedis()
        failing_store = FailingPolicyStore(fake_redis)
        app = _make_full_test_app(failing_store, fake_redis)
        client = app.test_client()

        r_store = client.post(
            "/management/policy/v0/store",
            headers=mgmt_headers,
            json=_sample_secret_policy("p1"),
        )
        assert r_store.status_code == 500
        assert r_store.get_json() == {"error": "Failed to store policy"}
        assert "Redis" not in r_store.get_data(as_text=True)

        r_get = client.get("/management/policy/v0/get/p1", headers=mgmt_headers)
        assert r_get.status_code == 500
        assert r_get.get_json() == {"error": "Failed to retrieve policy"}

        r_list = client.get("/management/policy/v0/list", headers=mgmt_headers)
        assert r_list.status_code == 500
        assert r_list.get_json() == {"error": "Failed to list policies"}

        r_del = client.delete("/management/policy/v0/delete/p1", headers=mgmt_headers)
        assert r_del.status_code == 500
        assert r_del.get_json() == {"error": "Failed to delete policy"}

    def test_get_secret_outage_surfaces_as_500_and_never_releases_secret(
        self, client_headers
    ):
        fake_redis = RecordingFakeRedis()
        failing_store = FailingPolicyStore(fake_redis)
        app = _make_full_test_app(failing_store, fake_redis)
        client = app.test_client()

        nonce = client.get("/kb/v0/get_nonce", headers=client_headers).get_json()[
            "nonce"
        ]
        wrapping_key = (
            rsa.generate_private_key(public_exponent=65537, key_size=2048)
            .public_key()
            .public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        resp = client.post(
            "/kb/v0/get_secret",
            headers=client_headers,
            json={
                "tee-type": "amd-sev-snp",
                "nonce": nonce,
                "tee-evidence": base64.b64encode(b"evidence").decode("ascii"),
                "policy-id": "sec-1",
                "report-data-binding": True,
                "wrapping-key": base64.b64encode(wrapping_key).decode("ascii"),
            },
        )
        assert resp.status_code == 500
        assert resp.get_json() == {"error": "Internal server error"}
        app.extensions["kbm_get_secret"].assert_not_called()

    def test_domain_verify_member_outage_is_not_skipped_and_surfaces_as_500(
        self, monkeypatch
    ):
        fake_redis = RecordingFakeRedis()
        # Seed domain-policy referencing pol-a and pol-b, and seed pol-b (which would pass!)
        # If pol-a raises PolicyStoreUnavailable, `domain_verify` MUST abort and raise
        # PolicyStoreUnavailable rather than skipping pol-a and passing on pol-b.
        store = FailingPolicyStore(fake_redis, fail_on_id="pol-a")
        RedisPolicyStore(fake_redis).create(
            DOMAIN_POLICY_NAMESPACE,
            "prod",
            json.dumps(_sample_domain_policy("prod", ["pol-a", "pol-b"])),
        )
        RedisPolicyStore(fake_redis).create(
            CERTIFY_POLICY_NAMESPACE,
            "pol-b",
            json.dumps(_sample_certify_policy("pol-b", "SEV")),
        )

        app = _make_full_test_app(store, fake_redis)
        monkeypatch.setattr(tas_vm, "verify", lambda *a, **k: (True, None))

        with app.app_context():
            with pytest.raises(PolicyStoreUnavailable):
                tas_vm.domain_verify(
                    store,
                    fake_redis,
                    "nonce-1",
                    "amd-sev-snp",
                    base64.b64encode(b"ev").decode("ascii"),
                    "prod",
                )


# --------------------------------------------------------------------------- #
# 5. PostgreSQL Schema Verification, DSN handling, Restart, Backup/Restore,
#    and Startup Failure Handling
# --------------------------------------------------------------------------- #


class TestPostgresSchemaAndOperations:
    @pytest.mark.parametrize("exit_mode", ["complete", "close", "outage"])
    def test_list_uses_server_cursor_and_releases_connection(
        self, pg_dsn, monkeypatch, exit_mode
    ):
        store = PostgresPolicyStore(pg_dsn)
        store.create(POLICY_NAMESPACE, "p1", '{"value": 1}')
        store.create(POLICY_NAMESPACE, "p2", '{"value": 2}')
        connections = []
        original_connect = store._connect

        def connect():
            conn = original_connect()
            connections.append(conn)
            return conn

        monkeypatch.setattr(store, "_connect", connect)
        with closing(store.list(POLICY_NAMESPACE)) as documents:
            assert connections == []
            assert next(documents) == '{"value": 1}'
            conn = connections[0]
            assert not conn.closed
            with conn.cursor() as cur:
                cur.execute("SELECT count(*) FROM pg_cursors")
                assert cur.fetchone() == (1,)
            if exit_mode == "complete":
                assert list(documents) == ['{"value": 2}']
            elif exit_mode == "outage":
                conn.close()
                with pytest.raises(PolicyStoreUnavailable):
                    next(documents)

        assert len(connections) == 1
        assert connections[0].closed

    def test_schema_verification_fails_when_tables_missing(self, pg_cluster):
        db_name = "tas_empty_db"
        with psycopg.connect(pg_cluster["admin_dsn"], autocommit=True) as conn:
            with conn.cursor() as cur:
                cur.execute(f"DROP DATABASE IF EXISTS {db_name} WITH (FORCE)")
                cur.execute(f"CREATE DATABASE {db_name}")
        try:
            empty_dsn = (
                f"postgresql://postgres@127.0.0.1:{pg_cluster['port']}/{db_name}"
            )
            store = PostgresPolicyStore(empty_dsn)
            with pytest.raises(
                RuntimeError, match="PostgreSQL policy schema is not initialized"
            ):
                store.verify_schema()
        finally:
            with psycopg.connect(pg_cluster["admin_dsn"], autocommit=True) as conn:
                with conn.cursor() as cur:
                    cur.execute(f"DROP DATABASE IF EXISTS {db_name} WITH (FORCE)")

    def test_schema_verification_fails_on_wrong_schema_version(self, pg_dsn):
        with psycopg.connect(pg_dsn, autocommit=True) as conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE tas_schema_version SET version = 99")

        store = PostgresPolicyStore(pg_dsn)
        with pytest.raises(
            RuntimeError, match="Unsupported PostgreSQL policy schema version"
        ):
            store.verify_schema()

    def test_dsn_and_credentials_redacted_in_errors_and_logs(self, caplog):
        secret_dsn = "postgresql://tas:review%zzcanary@127.0.0.1:1/tas_missing"
        keyword_dsn = (
            "host=127.0.0.1 port=1 dbname=tas user=tas "
            "password=review%zzcanary connect_timeout=1"
        )
        redacted = _safe_driver_error(
            psycopg.OperationalError(
                f"connection to {secret_dsn} failed with password=review%zzcanary",
                secret_dsn,
            )
        )
        assert redacted == "OperationalError"
        assert "review%zzcanary" not in redacted
        assert secret_dsn not in redacted

        store = PostgresPolicyStore(secret_dsn, connect_timeout=1)
        with caplog.at_level(logging.WARNING):
            assert store.is_reachable() is False
            with pytest.raises(RuntimeError) as exc_info:
                store.verify_schema()

        formatted = "".join(
            traceback.format_exception(exc_info.type, exc_info.value, exc_info.tb)
        )
        assert "review%zzcanary" not in formatted
        assert "review%zzcanary" not in str(exc_info.value)
        assert secret_dsn not in str(exc_info.value)
        assert "review%zzcanary" not in caplog.text
        assert secret_dsn not in caplog.text

        keyword_store = PostgresPolicyStore(keyword_dsn, connect_timeout=1)
        with pytest.raises(RuntimeError) as keyword_error:
            keyword_store.verify_schema()
        keyword_traceback = "".join(
            traceback.format_exception(
                keyword_error.type, keyword_error.value, keyword_error.tb
            )
        )
        assert "review%zzcanary" not in keyword_traceback

    @pytest.mark.parametrize(
        "dsn",
        [
            "host=127.0.0.1 dbname=tas connect_timeout=30",
            "postgresql://tas@127.0.0.1/tas?connect_timeout=30",
        ],
    )
    def test_dsn_connect_timeout_overrides_configured_timeout(self, dsn):
        store = PostgresPolicyStore(dsn, connect_timeout=7)
        with patch("tas.postgres_policy_store.psycopg.connect") as connect:
            store._connect()
        connect.assert_called_once_with(dsn)

    @pytest.mark.parametrize(
        "options",
        [
            "-c statement_timeout=111",
            "-cstatement_timeout=111",
            "--statement_timeout=111",
            "-c application_name=it's -c statement_timeout=111",
            r"-c application_name=a\ b -c statement_timeout=111",
        ],
    )
    def test_dsn_statement_timeout_overrides_configured_timeout(self, options):
        from psycopg.conninfo import make_conninfo

        dsn = make_conninfo(
            "postgresql://tas@127.0.0.1/tas",
            options=options,
        )
        store = PostgresPolicyStore(dsn, statement_timeout_seconds=5)
        cursor = MagicMock()
        store._apply_statement_timeout(cursor)
        cursor.execute.assert_not_called()

    def test_configured_timeouts_are_used_when_dsn_does_not_set_them(self):
        dsn = "host=127.0.0.1 dbname=tas"
        store = PostgresPolicyStore(
            dsn,
            connect_timeout=7,
            statement_timeout_seconds=2,
        )
        with patch("tas.postgres_policy_store.psycopg.connect") as connect:
            store._connect()
        connect.assert_called_once_with(dsn, connect_timeout=7)

        cursor = MagicMock()
        store._apply_statement_timeout(cursor)
        cursor.execute.assert_called_once_with("SET LOCAL statement_timeout = 2000")

    @pytest.mark.parametrize(
        "options",
        [
            "-c statement_timeout=111",
            "-c application_name=it's -c statement_timeout=111",
            r"-c application_name=a\ b -c statement_timeout=111",
        ],
    )
    def test_dsn_statement_timeout_is_preserved_in_policy_transaction(
        self, pg_dsn, options
    ):
        from psycopg.conninfo import make_conninfo

        dsn = make_conninfo(pg_dsn, options=options)
        store = PostgresPolicyStore(dsn, statement_timeout_seconds=5)
        with store._connect() as conn, conn.transaction():
            with conn.cursor() as cursor:
                cursor.execute("SHOW statement_timeout")
                assert cursor.fetchone()[0] == "111ms"
                store._apply_statement_timeout(cursor)
                cursor.execute("SHOW statement_timeout")
                assert cursor.fetchone()[0] == "111ms"

    def test_commit_failure_surfaces_unavailable_without_false_success(self):
        commit_error = psycopg.OperationalError("commit failed for review%zzcanary")
        cursor = MagicMock()
        cursor.__enter__.return_value = cursor

        class CommitFailureTransaction:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc_value, traceback):
                raise commit_error

        class Connection:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc_value, traceback):
                return False

            def transaction(self):
                return CommitFailureTransaction()

            def cursor(self):
                return cursor

        store = PostgresPolicyStore("postgresql://tas@127.0.0.1:1/tas")
        with patch.object(store, "_connect", return_value=Connection()):
            with pytest.raises(PolicyStoreUnavailable):
                store.create(POLICY_NAMESPACE, "commit-failure", "{}")

        assert cursor.execute.call_count == 2

    def test_request_error_handler_logs_no_driver_dsn_or_password(self, caplog):
        secret = "review%zzcanary"
        store = PostgresPolicyStore(
            f"postgresql://tas:{secret}@127.0.0.1:1/tas",
            connect_timeout=1,
        )
        app = _make_full_test_app(store, RecordingFakeRedis())

        @app.get("/trigger-policy-store-error")
        def trigger_policy_store_error():
            store.get(POLICY_NAMESPACE, "request-failure")
            return "unreachable"

        with caplog.at_level(logging.ERROR, logger="tas"):
            response = app.test_client().get("/trigger-policy-store-error")

        assert response.status_code == 500
        assert secret not in caplog.text
        for record in caplog.records:
            if record.exc_info:
                formatted = "".join(traceback.format_exception(*record.exc_info))
                assert secret not in formatted

    def test_persistence_across_postgres_restart_and_pg_dump_restore(
        self, pg_cluster, pg_dsn, tmp_path
    ):
        priv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        trusted_keys = [("public_key", "test-mem", priv_key.public_key())]
        signed_doc = _sign_policy_doc(
            _sample_secret_policy("durable-pol-1", "durable-key-1"), priv_key
        )

        store = PostgresPolicyStore(pg_dsn)
        store.create(POLICY_NAMESPACE, "durable-pol-1", json.dumps(signed_doc))

        # 1. Simulate an unclean stop, restart, and confirm WAL recovery survives.
        subprocess.run(
            _pg_server_cmd(
                pg_cluster["pg_ctl_bin"],
                "-D",
                str(pg_cluster["data_dir"]),
                "-l",
                str(pg_cluster["log_file"]),
                "-w",
                "-m",
                "immediate",
                "stop",
            ),
            check=True,
            capture_output=True,
            text=True,
        )
        subprocess.run(
            _pg_server_cmd(
                pg_cluster["pg_ctl_bin"],
                "-D",
                str(pg_cluster["data_dir"]),
                "-l",
                str(pg_cluster["log_file"]),
                "-o",
                pg_cluster["pg_opts"],
                "-w",
                "start",
            ),
            check=True,
            capture_output=True,
            text=True,
        )

        after_restart = store.get(POLICY_NAMESPACE, "durable-pol-1")
        assert after_restart is not None
        assert verify_policy_signature(json.loads(after_restart), trusted_keys)

        # 2. Back up with `pg_dump` and restore into a brand-new database
        dump_file = tmp_path / "tas_backup.sql"
        subprocess.run(
            [pg_cluster["pg_dump_bin"], pg_dsn, "-f", str(dump_file)],
            check=True,
            capture_output=True,
            text=True,
        )

        restore_db = "tas_restored_db"
        with psycopg.connect(pg_cluster["admin_dsn"], autocommit=True) as conn:
            with conn.cursor() as cur:
                cur.execute(f"DROP DATABASE IF EXISTS {restore_db} WITH (FORCE)")
                cur.execute(f"CREATE DATABASE {restore_db}")

        try:
            restore_dsn = (
                f"postgresql://postgres@127.0.0.1:{pg_cluster['port']}/{restore_db}"
            )
            subprocess.run(
                [
                    pg_cluster["psql_bin"],
                    restore_dsn,
                    "-v",
                    "ON_ERROR_STOP=1",
                    "-f",
                    str(dump_file),
                ],
                check=True,
                capture_output=True,
                text=True,
            )

            restored_store = PostgresPolicyStore(restore_dsn)
            restored_store.verify_schema()
            restored_raw = restored_store.get(POLICY_NAMESPACE, "durable-pol-1")
            assert restored_raw is not None
            restored_doc = json.loads(restored_raw)
            assert verify_policy_signature(restored_doc, trusted_keys)
            assert canonicalize_policy(restored_doc) == canonicalize_policy(signed_doc)
        finally:
            with psycopg.connect(pg_cluster["admin_dsn"], autocommit=True) as conn:
                with conn.cursor() as cur:
                    cur.execute(f"DROP DATABASE IF EXISTS {restore_db} WITH (FORCE)")

    def test_flask_startup_failure_is_bounded_and_redacts_dsn(self, isolated_redis):
        secret = "review%zzcanary"
        env = _smoke_env(
            f"postgresql://tas:{secret}@127.0.0.1:1/tas",
            isolated_redis,
        )
        env["FLASK_APP"] = "app:app"
        proc = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "flask",
                "run",
                "--no-reload",
                "-h",
                "127.0.0.1",
                "-p",
                str(_free_tcp_port()),
            ],
            cwd=str(REPO_ROOT),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        try:
            output, _ = proc.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            output = _stop_process_and_collect(proc)
            pytest.fail(f"Flask startup failure hung:\n{output}")

        assert proc.returncode != 0
        assert secret not in output
        assert "Failed to verify PostgreSQL policy schema at startup" in output
