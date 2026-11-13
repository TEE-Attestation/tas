#
# TEE Attestation Service - Real-Service Policy Rollback Tests
#
# Copyright 2026 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# This file is part of the TEE Attestation Service.
#
# End-to-end rollback tests against etcd, PostgreSQL, Redis and gunicorn
# TAS processes started by the tests. They run only in the GitHub Actions
# workflow, which sets GITHUB_ACTIONS=true and TAS_RUN_ETCD_INTEGRATION=1.
#

import ipaddress
import json
import os
import secrets
import shutil
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import redis
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from flask import Flask

from tas.auth import init_management_auth
from tas.certify.policy_routes import certify_policy_bp
from tas.error_handlers import register_error_handlers
from tas.etcd_client import EtcdClient
from tas.etcd_protected_policy_store import (
    POLICY_AUTH_FORMAT,
    POLICY_AUTH_FORMAT_KEY,
    EtcdProtectedPolicyStore,
)
from tas.management_routes import management_bp
from tas.policy_helper import verify_policy_signature
from tas.policy_store import (
    PolicyAlreadyExists,
    PolicyAuthorizationDenied,
    PolicyStore,
    PolicyStoreUnavailable,
    RedisPolicyStore,
)
from tas.postgres_policy_store import PostgresPolicyStore
from tas.postgres_publication_store import PostgresPublicationStore
from tas.publication_store import PublicationStore
from tas.redis_publication_store import RedisPublicationStore
from tests.test_policy_store_backends import (
    MGMT_API_KEY,
    _find_pg_bin,
    _free_tcp_port,
    _sample_certify_policy,
    _sample_domain_policy,
    _sample_secret_policy,
    _sign_policy_doc,
    _stop_process_and_collect,
    pg_cluster,
    pg_dsn,
)

__all__ = ["pg_cluster", "pg_dsn"]

# Designed to be run only by the CI hence the skip when when GITHUB_ACTIONS != "true"
# To run locally install etcd, redis and psostgres and set GITHUB_ACTIONS = true
pytestmark = pytest.mark.skipif(
    os.environ.get("GITHUB_ACTIONS") != "true"
    or os.environ.get("TAS_RUN_ETCD_INTEGRATION") != "1",
    reason="Real-service rollback tests run only in the GitHub Actions workflow",
)


def _binary(name: str) -> str:
    setting = f"{name.upper().replace('-', '_')}_BIN"
    override = os.environ.get(setting, name)
    path = shutil.which(override)
    if path is None:
        pytest.fail(f"{name} is required; set {setting} or add it to PATH")
    return path


@pytest.fixture(scope="module", autouse=True)
def require_backend_tools():
    for name in ("etcd", "etcdctl", "etcdutl", "redis-server"):
        _binary(name)
    for name in ("initdb", "pg_ctl", "psql", "pg_dump", "pg_restore"):
        if not shutil.which(name) and not list(
            Path("/usr/lib/postgresql").glob(f"*/bin/{name}")
        ):
            pytest.fail(f"PostgreSQL binary {name} is required for integration tests")


def _run(*command: str):
    return subprocess.run(
        command,
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
        env=_service_environment(),
    )


def _service_environment():
    return {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("ETCD_", "ETCDCTL_"))
    }


def _tls_files(directory: Path) -> tuple[Path, Path, Path]:
    now = datetime.now(timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "TAS test CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
        .issuer_name(ca_name)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(server_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    ca_path, cert_path, key_path = (
        directory / "ca.pem",
        directory / "server.pem",
        directory / "server.key",
    )
    ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        server_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    key_path.chmod(0o600)
    return ca_path, cert_path, key_path


class RealEtcd:
    def __init__(self, directory: Path):
        self.etcd = _binary("etcd")
        self.etcdctl = _binary("etcdctl")
        self.etcdutl = _binary("etcdutl")
        self.directory = directory
        self.data = directory / "data"
        self.ca, self.cert, self.key = _tls_files(directory)
        port, peer_port = _free_tcp_port(), _free_tcp_port()
        while peer_port == port:
            peer_port = _free_tcp_port()
        self.endpoint = f"https://127.0.0.1:{port}"
        self.peer = f"http://127.0.0.1:{peer_port}"
        self.password = secrets.token_urlsafe(24)
        self.root_password = secrets.token_urlsafe(24)
        self.process: subprocess.Popen | None = None

    def start(self):
        import requests

        with (self.directory / "etcd.log").open("ab") as log:
            self.process = subprocess.Popen(
                [
                    self.etcd,
                    "--name=rollback-test",
                    f"--data-dir={self.data}",
                    f"--listen-client-urls={self.endpoint}",
                    f"--advertise-client-urls={self.endpoint}",
                    f"--listen-peer-urls={self.peer}",
                    f"--initial-advertise-peer-urls={self.peer}",
                    f"--initial-cluster=rollback-test={self.peer}",
                    f"--cert-file={self.cert}",
                    f"--key-file={self.key}",
                    "--log-level=error",
                ],
                stdout=log,
                stderr=subprocess.STDOUT,
                env=_service_environment(),
            )
        last_error = "No response"
        for _ in range(100):
            if self.process.poll() is not None:
                pytest.fail((self.directory / "etcd.log").read_text())
            try:
                response = requests.get(
                    self.endpoint + "/health", verify=str(self.ca), timeout=0.5
                )
                if response.status_code == 200 and response.json().get("health") in (
                    "true",
                    True,
                ):
                    return
                last_error = f"HTTP {response.status_code}: {response.text[:200]}"
            except requests.RequestException as exc:
                last_error = str(exc)
            time.sleep(0.1)
        pytest.fail(f"Owned etcd did not become ready: {last_error}")

    def stop(self):
        if self.process is not None:
            _stop_process_and_collect(self.process)
            self.process = None

    def ctl(self, *args: str, authenticated: bool = True):
        command = [
            self.etcdctl,
            f"--endpoints={self.endpoint}",
            f"--cacert={self.ca}",
            "--dial-timeout=2s",
            "--command-timeout=10s",
        ]
        if authenticated:
            command.append(f"--user=root:{self.root_password}")
        return _run(*command, *args)

    def provision(self):
        self.ctl(
            "user",
            "add",
            "root",
            f"--new-user-password={self.root_password}",
            authenticated=False,
        )
        self.ctl("user", "grant-role", "root", "root", authenticated=False)
        self.ctl(
            "user",
            "add",
            "tas",
            f"--new-user-password={self.password}",
            authenticated=False,
        )
        self.ctl("role", "add", "tas-policy", authenticated=False)
        self.ctl(
            "role",
            "grant-permission",
            "tas-policy",
            "readwrite",
            "/tas/policy-auth/",
            "--prefix",
            authenticated=False,
        )
        self.ctl(
            "role",
            "grant-permission",
            "tas-policy",
            "read",
            POLICY_AUTH_FORMAT_KEY.decode(),
            authenticated=False,
        )
        self.ctl("user", "grant-role", "tas", "tas-policy", authenticated=False)
        self.ctl(
            "put",
            POLICY_AUTH_FORMAT_KEY.decode(),
            POLICY_AUTH_FORMAT.decode(),
            authenticated=False,
        )
        self.ctl("auth", "enable", authenticated=False)

    def client(self) -> EtcdClient:
        return EtcdClient(
            [self.endpoint], str(self.ca), "tas", self.password, timeout_seconds=2
        )

    def snapshot(self, path: Path):
        self.ctl("snapshot", "save", str(path))

    def restore(self, path: Path):
        self.stop()
        self.data = self.directory / "restored-data"
        _run(
            self.etcdutl,
            "snapshot",
            "restore",
            str(path),
            f"--data-dir={self.data}",
            "--name=rollback-test",
            f"--initial-cluster=rollback-test={self.peer}",
            f"--initial-advertise-peer-urls={self.peer}",
            "--bump-revision=10000",
            "--mark-compacted",
        )
        self.start()


@pytest.fixture
def authority(tmp_path):
    directory = tmp_path / "etcd"
    directory.mkdir()
    server = RealEtcd(directory)
    try:
        server.start()
        server.provision()
        marker = server.client().get(POLICY_AUTH_FORMAT_KEY)
        assert marker is not None and marker.value == POLICY_AUTH_FORMAT
        yield server
    finally:
        server.stop()


class RealRedis:
    def __init__(self, directory: Path):
        self.directory = directory
        self.port = _free_tcp_port()
        self.client = redis.Redis(
            host="127.0.0.1",
            port=self.port,
            decode_responses=True,
            socket_timeout=2,
            socket_connect_timeout=2,
        )
        self.process: subprocess.Popen | None = None

    def start(self):
        with (self.directory / "redis.log").open("ab") as log:
            self.process = subprocess.Popen(
                [
                    _binary("redis-server"),
                    "--bind",
                    "127.0.0.1",
                    "--port",
                    str(self.port),
                    "--save",
                    "",
                    "--appendonly",
                    "no",
                    "--dir",
                    str(self.directory),
                    "--dbfilename",
                    "dump.rdb",
                ],
                stdout=log,
                stderr=subprocess.STDOUT,
            )
        last_error = "No response"
        for _ in range(100):
            if self.process.poll() is not None:
                pytest.fail((self.directory / "redis.log").read_text())
            try:
                if self.client.ping():
                    return
            except redis.RedisError as exc:
                last_error = str(exc)
            time.sleep(0.05)
        pytest.fail(f"Owned Redis did not become ready: {last_error}")

    def stop(self):
        if self.process is not None:
            _stop_process_and_collect(self.process)
            self.process = None

    def snapshot(self, path: Path):
        assert self.client.save()
        shutil.copyfile(self.directory / "dump.rdb", path)

    def restore(self, path: Path):
        self.stop()
        shutil.copyfile(path, self.directory / "dump.rdb")
        self.start()


@dataclass
class PolicyDatabase:
    unprotected_policy_store: PolicyStore
    publications: PublicationStore
    snapshot: Callable[[Path], None]
    restore: Callable[[Path], None]
    tas_settings: dict[str, str]
    redis_port: int | None = None


@pytest.fixture(params=["postgresql", "redis"])
def database(request, tmp_path):
    if request.param == "postgresql":
        dsn = request.getfixturevalue("pg_dsn")
        cluster = request.getfixturevalue("pg_cluster")
        pg_restore = _find_pg_bin("pg_restore")

        def snapshot(path):
            _run(cluster["pg_dump_bin"], dsn, "-Fc", "-f", str(path))

        def restore(path):
            _run(
                pg_restore,
                "--dbname",
                dsn,
                "--clean",
                "--if-exists",
                "--no-owner",
                "--no-acl",
                str(path),
            )

        yield PolicyDatabase(
            PostgresPolicyStore(dsn),
            PostgresPublicationStore(dsn),
            snapshot,
            restore,
            {"TAS_POLICY_BACKEND": "postgresql", "TAS_POSTGRES_DSN": dsn},
        )
    else:
        directory = tmp_path / "redis"
        directory.mkdir()
        server = RealRedis(directory)
        try:
            server.start()
            yield PolicyDatabase(
                RedisPolicyStore(server.client),
                RedisPublicationStore(server.client),
                server.snapshot,
                server.restore,
                {"TAS_POLICY_BACKEND": "redis"},
                server.port,
            )
        finally:
            server.stop()
            server.client.close()


@pytest.fixture(scope="module")
def signing_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _document(namespace, policy_id, key, revision=1):
    factory = {
        "policy": _sample_secret_policy,
        "certify-policy": _sample_certify_policy,
        "domain-policy": _sample_domain_policy,
    }[namespace]
    policy = factory(policy_id)
    policy["metadata"]["revision"] = revision
    return json.dumps(_sign_policy_doc(policy, key))


def _store(authority, database):
    return EtcdProtectedPolicyStore(
        authority.client(), database.publications, database.unprotected_policy_store
    )


def _management_client(store, key, authorization="etcd"):
    app = Flask(__name__)
    app.config.update(
        TESTING=True,
        TAS_MANAGEMENT_API_KEY=MGMT_API_KEY,
        TAS_POLICY_AUTHORIZATION=authorization,
        TAS_ENFORCE_SIGNED_POLICIES=True,
        TAS_TRUSTED_KEYS=[("public_key", "test", key.public_key())],
    )
    app.extensions["policy_store"] = store
    init_management_auth(app)
    register_error_handlers(app)
    app.register_blueprint(management_bp)
    app.register_blueprint(certify_policy_bp)
    return app.test_client()


HEADERS = {"X-MANAGEMENT-API-KEY": MGMT_API_KEY}


@pytest.mark.parametrize("namespace", ["policy", "certify-policy", "domain-policy"])
def test_restored_signed_policy_stays_revoked(
    authority, database, signing_key, tmp_path, namespace
):
    document = _document(namespace, "retired-policy", signing_key)
    database.unprotected_policy_store.create(namespace, "retired-policy", document)
    store = _store(authority, database)
    client = _management_client(store, signing_key)
    base = f"/management/{namespace}/v0"
    assert (
        client.post(
            base + "/store", json=json.loads(document), headers=HEADERS
        ).status_code
        == 201
    )
    approved = store.load_approved(namespace, "retired-policy")
    assert approved is not None and approved.approval is not None
    snapshot = tmp_path / "database.snapshot"
    database.snapshot(snapshot)
    assert (
        client.delete(base + "/delete/retired-policy", headers=HEADERS).status_code
        == 200
    )

    database.restore(snapshot)
    restored = database.unprotected_policy_store.get(namespace, "retired-policy")
    assert restored == document
    assert verify_policy_signature(
        json.loads(restored), [("public_key", "test", signing_key.public_key())]
    )
    assert database.publications.list_ids(namespace, "retired-policy")
    store = _store(authority, database)
    client = _management_client(store, signing_key)
    assert client.get(base + "/get/retired-policy", headers=HEADERS).status_code == 404
    assert client.get(base + "/list", headers=HEADERS).json["count"] == 0
    with pytest.raises(PolicyAuthorizationDenied):
        store.check_approvals([approved.approval])

    unprotected = _management_client(
        database.unprotected_policy_store, signing_key, "none"
    )
    assert (
        unprotected.get(base + "/get/retired-policy", headers=HEADERS).status_code
        == 200
    )


@pytest.mark.parametrize("same_bytes", [False, True])
def test_database_rollback_cannot_replace_a_new_publication(
    authority, database, signing_key, tmp_path, same_bytes
):
    store = _store(authority, database)
    old_document = _document("policy", "recreated", signing_key)
    store.create("policy", "recreated", old_document)
    old_policy = store.load_approved("policy", "recreated")
    assert old_policy is not None and old_policy.approval is not None
    old_approval = old_policy.approval
    snapshot = tmp_path / "database.snapshot"
    database.snapshot(snapshot)
    assert store.delete("policy", "recreated")
    new_document = (
        old_document
        if same_bytes
        else _document("policy", "recreated", signing_key, revision=2)
    )
    store.create("policy", "recreated", new_document)
    assert store.get("policy", "recreated") == new_document

    database.restore(snapshot)
    store = _store(authority, database)
    client = _management_client(store, signing_key)
    for path in ("/get/recreated", "/list"):
        response = client.get("/management/policy/v0" + path, headers=HEADERS)
        assert response.status_code == 503
        assert response.json["reason"] == "policy_integrity_error"
    with pytest.raises(PolicyAuthorizationDenied):
        store.check_approvals([old_approval])


def test_changed_publication_fails_digest_check(authority, database, signing_key):
    store = _store(authority, database)
    store.create("policy", "changed", _document("policy", "changed", signing_key))
    (publication_id,) = database.publications.list_ids("policy", "changed")
    assert database.publications.delete("policy", "changed", publication_id)
    assert database.publications.insert(
        "policy",
        "changed",
        publication_id,
        _document("policy", "changed", signing_key, revision=2),
    )
    with pytest.raises(PolicyStoreUnavailable, match="digest"):
        store.get("policy", "changed")


def test_authority_outage_never_uses_cached_approval(authority, database, signing_key):
    store = _store(authority, database)
    store.create("policy", "outage", _document("policy", "outage", signing_key))
    approved = store.load_approved("policy", "outage")
    assert approved is not None and approved.approval is not None
    authority.stop()
    with pytest.raises(PolicyStoreUnavailable):
        store.get("policy", "outage")
    with pytest.raises(PolicyStoreUnavailable):
        store.check_approvals([approved.approval])


def test_delete_fences_delayed_real_database_insert(
    authority, database, signing_key, monkeypatch
):
    store = _store(authority, database)
    entered, resume = threading.Event(), threading.Event()
    original_insert = database.publications.insert

    def delayed_insert(*args):
        entered.set()
        assert resume.wait(timeout=10)
        return original_insert(*args)

    monkeypatch.setattr(database.publications, "insert", delayed_insert)
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(
            store.create,
            "policy",
            "delayed",
            _document("policy", "delayed", signing_key),
        )
        try:
            assert entered.wait(timeout=5)
            assert _store(authority, database).delete("policy", "delayed")
        finally:
            resume.set()
        with pytest.raises(PolicyAlreadyExists):
            future.result(timeout=10)
    assert store.get("policy", "delayed") is None
    assert database.publications.list_ids("policy", "delayed") == []


def test_delayed_delete_preserves_real_recreated_publication(
    authority, database, signing_key, monkeypatch
):
    client = authority.client()
    store = EtcdProtectedPolicyStore(
        client, database.publications, database.unprotected_policy_store
    )
    document = _document("policy", "stale-delete", signing_key)
    store.create("policy", "stale-delete", document)
    entered, resume = threading.Event(), threading.Event()
    original_delete = client.delete_if_revision

    def delayed_delete(*args):
        entered.set()
        assert resume.wait(timeout=10)
        return original_delete(*args)

    monkeypatch.setattr(client, "delete_if_revision", delayed_delete)
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(store.delete, "policy", "stale-delete")
        try:
            assert entered.wait(timeout=5)
            other = _store(authority, database)
            assert other.delete("policy", "stale-delete")
            other.create("policy", "stale-delete", document)
        finally:
            resume.set()
        future.result(timeout=10)
    assert store.get("policy", "stale-delete") == document


def test_joint_authority_and_database_rollback_is_not_protected(
    authority, database, signing_key, tmp_path
):
    store = _store(authority, database)
    document = _document("policy", "joint-rollback", signing_key)
    store.create("policy", "joint-rollback", document)
    database_snapshot = tmp_path / "database.snapshot"
    authority_snapshot = tmp_path / "authority.snapshot"
    database.snapshot(database_snapshot)
    authority.snapshot(authority_snapshot)
    assert store.delete("policy", "joint-rollback")
    assert store.get("policy", "joint-rollback") is None

    database.restore(database_snapshot)
    assert _store(authority, database).get("policy", "joint-rollback") is None
    authority.restore(authority_snapshot)
    restored_store = _store(authority, database)
    assert restored_store.get("policy", "joint-rollback") == document
    approved = restored_store.load_approved("policy", "joint-rollback")
    assert approved is not None and approved.approval is not None
    restored_store.check_approvals([approved.approval])


REPO_ROOT = Path(__file__).resolve().parents[1]
CLIENT_API_KEY = "a" * 64


class RealTas:
    """A TAS server process started with gunicorn, as in production."""

    def __init__(self, directory: Path, environment: dict[str, str], name: str):
        self.environment = environment
        self.log = directory / f"tas-{name}.log"
        self.port = _free_tcp_port()
        self.url = f"http://127.0.0.1:{self.port}"
        self.process: subprocess.Popen | None = None

    def _launch(self):
        with self.log.open("ab") as log:
            self.process = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "gunicorn",
                    "--workers=2",
                    f"--bind=127.0.0.1:{self.port}",
                    "app:app",
                ],
                cwd=REPO_ROOT,
                env=self.environment,
                stdout=log,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )

    def start(self):
        import requests

        self._launch()
        for _ in range(300):
            if self.process.poll() is not None:
                pytest.fail(f"TAS exited during startup:\n{self.log.read_text()}")
            try:
                response = requests.get(
                    self.url + "/version",
                    headers={"X-API-KEY": CLIENT_API_KEY},
                    timeout=1,
                )
                if response.status_code == 200:
                    return
            except requests.RequestException:
                pass
            time.sleep(0.1)
        pytest.fail(f"TAS did not become ready:\n{self.log.read_text()}")

    def start_expecting_failure(self) -> str:
        self._launch()
        try:
            self.process.wait(timeout=60)
        except subprocess.TimeoutExpired:
            pytest.fail(f"TAS started unexpectedly:\n{self.log.read_text()}")
        assert self.process.returncode != 0
        self.process = None
        return self.log.read_text()

    def stop(self):
        if self.process is None:
            return
        self.process.terminate()
        try:
            self.process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            os.killpg(self.process.pid, signal.SIGKILL)
            self.process.wait(timeout=5)
        self.process = None

    def management(self, method: str, path: str, **kwargs):
        import requests

        return requests.request(
            method,
            self.url + "/management" + path,
            headers=HEADERS,
            timeout=30,
            **kwargs,
        )


@pytest.fixture
def tas_servers(authority, database, signing_key, tmp_path):
    """Start real TAS processes in mode etcd against the shared services."""
    trust = tmp_path / "policy-signer.pem"
    trust.write_bytes(
        signing_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    core_redis = None
    config_file = tmp_path / "tas_config.yaml"
    config_file.write_text(
        f"TAS_POLICY_TRUST: {json.dumps(str(trust))}\n"
        "TAS_ENFORCE_SIGNED_POLICIES: true\n"
    )
    redis_port = database.redis_port
    if redis_port is None:
        directory = tmp_path / "core-redis"
        directory.mkdir()
        core_redis = RealRedis(directory)
        core_redis.start()
        redis_port = core_redis.port

    environment = {
        key: value
        for key, value in _service_environment().items()
        if not key.startswith(("TAS_", "FLASK_"))
    }
    environment.update(
        database.tas_settings,
        TAS_API_KEY=CLIENT_API_KEY,
        TAS_MANAGEMENT_API_KEY=MGMT_API_KEY,
        TAS_REDIS_HOST="127.0.0.1",
        TAS_REDIS_PORT=str(redis_port),
        TAS_REDIS_PERSISTENCE="false",
        TAS_CONFIG_FILE=str(config_file),
        TAS_POLICY_AUTHORIZATION="etcd",
        TAS_ETCD_ENDPOINTS=authority.endpoint,
        TAS_ETCD_CA_FILE=str(authority.ca),
        TAS_ETCD_USERNAME="tas",
        TAS_ETCD_PASSWORD=authority.password,
    )
    servers: list[RealTas] = []

    def create(name: str) -> RealTas:
        server = RealTas(tmp_path, dict(environment), name)
        servers.append(server)
        return server

    try:
        yield create
    finally:
        for server in servers:
            server.stop()
        if core_redis is not None:
            core_redis.stop()
            core_redis.client.close()


def _assert_protected_status(server: RealTas):
    response = server.management("GET", "/status")
    assert response.status_code == 200
    assert response.json()["policy_authorization"] == "etcd"
    assert response.json()["policy_storage"]["reachable"] is True


def test_real_tas_refuses_restored_policies_after_restart(
    tas_servers, database, signing_key, tmp_path
):
    tas = tas_servers("primary")
    tas.start()
    _assert_protected_status(tas)
    retired = _document("policy", "e2e-retired", signing_key)
    replaced_v1 = _document("policy", "e2e-replaced", signing_key)
    replaced_v2 = _document("policy", "e2e-replaced", signing_key, revision=2)
    for document in (retired, replaced_v1):
        response = tas.management("POST", "/policy/v0/store", json=json.loads(document))
        assert response.status_code == 201, response.text

    snapshot = tmp_path / "e2e-database.snapshot"
    database.snapshot(snapshot)
    assert tas.management("DELETE", "/policy/v0/delete/e2e-retired").status_code == 200
    assert tas.management("DELETE", "/policy/v0/delete/e2e-replaced").status_code == 200
    response = tas.management("POST", "/policy/v0/store", json=json.loads(replaced_v2))
    assert response.status_code == 201, response.text

    tas.stop()
    database.restore(snapshot)
    assert database.unprotected_policy_store.get("policy", "e2e-retired") is None
    assert database.publications.list_ids("policy", "e2e-retired")
    tas.start()

    _assert_protected_status(tas)
    assert tas.management("GET", "/policy/v0/get/e2e-retired").status_code == 404
    for path in ("/policy/v0/get/e2e-replaced", "/policy/v0/list"):
        response = tas.management("GET", path)
        assert response.status_code == 503, response.text
        assert response.json()["reason"] == "policy_integrity_error"

    assert tas.management("DELETE", "/policy/v0/delete/e2e-replaced").status_code == 200
    response = tas.management("POST", "/policy/v0/store", json=json.loads(replaced_v2))
    assert response.status_code == 201, response.text
    response = tas.management("GET", "/policy/v0/get/e2e-replaced")
    assert response.json()["policy"] == json.loads(replaced_v2)


def test_real_tas_instances_share_etcd_approvals(tas_servers, signing_key):
    first, second = tas_servers("first"), tas_servers("second")
    first.start()
    second.start()
    document = _document("policy", "e2e-shared", signing_key)

    response = first.management("POST", "/policy/v0/store", json=json.loads(document))
    assert response.status_code == 201, response.text
    response = second.management("GET", "/policy/v0/get/e2e-shared")
    assert response.json()["policy"] == json.loads(document)
    response = second.management("POST", "/policy/v0/store", json=json.loads(document))
    assert response.status_code == 409

    assert (
        second.management("DELETE", "/policy/v0/delete/e2e-shared").status_code == 200
    )
    assert first.management("GET", "/policy/v0/get/e2e-shared").status_code == 404


@pytest.mark.parametrize("marker", [None, b"2"])
def test_real_tas_refuses_to_start_without_valid_format_marker(
    tas_servers, authority, marker
):
    key = POLICY_AUTH_FORMAT_KEY.decode()
    if marker is None:
        authority.ctl("del", key)
    else:
        authority.ctl("put", key, marker.decode())

    log = tas_servers("bad-marker").start_expecting_failure()
    assert "policy authorization format marker is missing or invalid" in log
