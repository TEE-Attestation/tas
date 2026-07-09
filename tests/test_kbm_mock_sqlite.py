#
# TEE Attestation Service - Mock KBM SQLite backend tests.
#
# Copyright 2026 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# This file is part of the TEE Attestation Service.
#

"""Tests for the Mock KBM optional SQLite backend and create-only writes."""

import base64
import multiprocessing
import os
import subprocess
import sys
import threading

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as ap
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from plugins import tas_kbm_mock as kbm


def _sqlite_client(tmp_path, secrets=None, strict=True):
    cfg = {"backend": "sqlite", "db_path": "kbm_db/secrets.db", "strict": strict}
    if secrets:
        cfg["secrets"] = secrets
    return kbm._client_from_config(cfg, base_dir=str(tmp_path))


def _seed(client, key_id, value):
    """White-box helper: store a known secret straight through the backend store.

    kbm_put_secret was removed from the plugin's public surface (it was never
    part of the KBM contract). The only write paths are kbm_get_secret's
    get-or-create side effect and the standalone CLI, so tests that need a
    specific stored value write directly to client.store.
    """
    return client.store.put(key_id, kbm._secret_to_bytes(value))


# --------------------------------------------------------------------------
# Backend selection / precedence
# --------------------------------------------------------------------------


def test_default_backend_is_file_readonly(tmp_path):
    client = kbm._client_from_config({"secrets": {"k": "v"}}, base_dir=str(tmp_path))
    assert type(client.store).__name__ == "_InMemoryStore"
    assert client.store.supports_write is False
    assert client.get_secret("k") == b"v"


def test_explicit_file_backend_wins_over_db_path(tmp_path):
    client = kbm._client_from_config(
        {"backend": "file", "db_path": "kbm_db/x.db"}, base_dir=str(tmp_path)
    )
    assert type(client.store).__name__ == "_InMemoryStore"


def test_db_path_alone_does_not_select_sqlite(tmp_path):
    # db_path without an explicit `backend: sqlite` must NOT select SQLite; it
    # falls back to the default read-only file/in-memory backend.
    client = kbm._client_from_config({"db_path": "kbm_db/x.db"}, base_dir=str(tmp_path))
    assert type(client.store).__name__ == "_InMemoryStore"


def test_explicit_sqlite_backend(tmp_path):
    client = _sqlite_client(tmp_path)
    assert type(client.store).__name__ == "_SQLiteStore"
    assert client.store.supports_write is True
    assert (tmp_path / "kbm_db" / "secrets.db").is_file()


def test_invalid_backend_raises(tmp_path):
    with pytest.raises(ValueError, match="Invalid mock KBM backend"):
        kbm._client_from_config({"backend": "postgres"}, base_dir=str(tmp_path))


def test_db_path_override_conflicts_with_explicit_file_backend(tmp_path):
    # A db_path override selects SQLite; an explicit `backend: file` contradicts
    # it and must fail fast rather than being silently overridden.
    with pytest.raises(ValueError, match="conflicting mock KBM configuration"):
        kbm._client_from_config(
            {"backend": "file"},
            base_dir=str(tmp_path),
            db_path_override=str(tmp_path / "kbm_db" / "x.db"),
        )


def test_db_path_override_ignores_unset_backend(tmp_path):
    # Without an explicit `backend`, the override just selects SQLite.
    client = kbm._client_from_config({}, db_path_override=str(tmp_path / "x.db"))
    assert type(client.store).__name__ == "_SQLiteStore"


# --------------------------------------------------------------------------
# Write path (SQLite only)
# --------------------------------------------------------------------------


def test_file_backend_rejects_write(tmp_path):
    client = kbm._client_from_config({"secrets": {"k": "v"}}, base_dir=str(tmp_path))
    with pytest.raises(ValueError, match="write not supported"):
        client.store.put("k2", b"x")


def test_sqlite_write_then_read(tmp_path):
    client = _sqlite_client(tmp_path)
    assert _seed(client, "w1", "hello") is True
    assert client.get_secret("w1") == b"hello"


def test_sqlite_create_only_rejects_duplicate(tmp_path):
    client = _sqlite_client(tmp_path)
    _seed(client, "dup", "first")
    with pytest.raises(ValueError, match="already exists"):
        _seed(client, "dup", "second")
    # original value preserved
    assert client.get_secret("dup") == b"first"


# --------------------------------------------------------------------------
# The sqlite backend does not seed from the config `secrets:` map
# --------------------------------------------------------------------------


def test_sqlite_ignores_config_secrets(tmp_path):
    # `secrets:` are only served by the file backend; sqlite must ignore them.
    client = _sqlite_client(tmp_path, secrets={"seed": "abc"}, strict=True)
    with pytest.raises(ValueError, match="Secret not found"):
        client.get_secret("seed")


def test_sqlite_persists_only_explicit_writes(tmp_path):
    # A value written explicitly survives a reopen; config secrets never appear.
    c1 = _sqlite_client(tmp_path, secrets={"cfg-only": "x"})
    _seed(c1, "written", "value")
    c2 = _sqlite_client(tmp_path, secrets={"cfg-only": "x"}, strict=False)
    assert c2.get_secret("written") == b"value"
    # config-only key was never seeded -> non-strict derivation yields random bytes
    derived = c2.get_secret("cfg-only")
    assert isinstance(derived, bytes) and len(derived) == kbm.SECRET_LEN


# --------------------------------------------------------------------------
# strict behavior
# --------------------------------------------------------------------------


def test_sqlite_strict_missing_raises(tmp_path):
    client = _sqlite_client(tmp_path, strict=True)
    with pytest.raises(ValueError, match="Secret not found"):
        client.get_secret("nope")


def test_sqlite_non_strict_derives(tmp_path):
    client = _sqlite_client(tmp_path, strict=False)
    val = client.get_secret("nope")
    assert isinstance(val, bytes) and len(val) == kbm.SECRET_LEN


def test_sqlite_non_strict_persists_generated_secret(tmp_path):
    import sqlite3

    client = _sqlite_client(tmp_path, strict=False)
    first = client.get_secret("auto")
    assert isinstance(first, bytes) and len(first) == kbm.SECRET_LEN
    # Stable across calls (get-or-create).
    assert client.get_secret("auto") == first
    # Actually persisted in the DB.
    db = tmp_path / "kbm_db" / "secrets.db"
    row = (
        sqlite3.connect(str(db))
        .execute("SELECT secret FROM secrets WHERE key_id = ?", ("auto",))
        .fetchone()
    )
    assert row is not None and bytes(row[0]) == first
    # Survives a reopen of the same DB.
    client2 = _sqlite_client(tmp_path, strict=False)
    assert client2.get_secret("auto") == first


def test_file_non_strict_is_ephemeral(tmp_path):
    client = kbm._client_from_config(
        {"strict": False, "secrets": {}}, base_dir=str(tmp_path)
    )
    assert type(client.store).__name__ == "_InMemoryStore"
    assert client.get_secret("x") != client.get_secret("x")


def test_empty_config_file_defaults_strict(tmp_path):
    # A present-but-empty config file must default to strict=True so unknown keys
    # are not silently derived (and, on sqlite, persisted).
    cfg_file = tmp_path / "kbm.yaml"
    cfg_file.write_text("")
    client = kbm.kbm_open_client_connection(str(cfg_file))
    assert client.strict is True


def test_config_file_explicit_non_strict_opts_out(tmp_path):
    cfg_file = tmp_path / "kbm.yaml"
    cfg_file.write_text("strict: false\n")
    client = kbm.kbm_open_client_connection(str(cfg_file))
    assert client.strict is False


def test_no_config_file_defaults_non_strict():
    # Zero-config (no file): keep the permissive in-memory dev default.
    client = kbm.kbm_open_client_connection(None)
    assert client.strict is False


def test_concurrent_generation_converges(tmp_path):
    client = _sqlite_client(tmp_path, strict=False)
    values = []
    barrier = threading.Barrier(8)

    def worker():
        barrier.wait()
        values.append(client.get_secret("race"))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # All racing readers converge on one persisted value.
    assert len(set(values)) == 1


# --------------------------------------------------------------------------
# Concurrency: create-only under contention
# --------------------------------------------------------------------------


def test_concurrent_writers_same_key_one_winner(tmp_path):
    client = _sqlite_client(tmp_path)
    results = []
    barrier = threading.Barrier(8)

    def worker():
        barrier.wait()
        try:
            client.store.put("race", b"v")
            results.append("ok")
        except ValueError:
            results.append("dup")

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert results.count("ok") == 1
    assert results.count("dup") == 7


def test_concurrent_distinct_keys_all_persist(tmp_path):
    client = _sqlite_client(tmp_path)
    barrier = threading.Barrier(10)

    def worker(i):
        barrier.wait()
        client.store.put(f"k{i}", f"v{i}".encode())

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    for i in range(10):
        assert client.get_secret(f"k{i}") == f"v{i}".encode()


# --------------------------------------------------------------------------
# Full get_secret unwrap round-trip
# --------------------------------------------------------------------------


def test_kbm_get_secret_unwrap_roundtrip(tmp_path):
    client = _sqlite_client(tmp_path)
    _seed(client, "wrapme", "top-secret")

    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    res = kbm.kbm_get_secret(client, "wrapme", pub_pem)
    aes_key = priv.decrypt(
        base64.b64decode(res["wrapped_key"]),
        ap.OAEP(mgf=ap.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    dec = Cipher(
        algorithms.AES(aes_key),
        modes.GCM(base64.b64decode(res["iv"]), base64.b64decode(res["tag"])),
    ).decryptor()
    plaintext = dec.update(base64.b64decode(res["blob"])) + dec.finalize()
    assert plaintext == b"top-secret"


# --------------------------------------------------------------------------
# Schema versioning + CLI interoperability
# --------------------------------------------------------------------------

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_CLI = os.path.join(_REPO_ROOT, "scripts", "kbm_mock_secret_writer.py")


def _user_version(db_path):
    import sqlite3

    return sqlite3.connect(str(db_path)).execute("PRAGMA user_version").fetchone()[0]


def test_plugin_stamps_schema_version(tmp_path):
    _sqlite_client(tmp_path)  # creates the DB
    db = tmp_path / "kbm_db" / "secrets.db"
    assert _user_version(db) == kbm.SQLITE_SCHEMA_VERSION


def test_plugin_rejects_newer_schema_version(tmp_path):
    import sqlite3

    db = tmp_path / "kbm_db" / "secrets.db"
    _sqlite_client(tmp_path)  # create at current version
    conn = sqlite3.connect(str(db))
    conn.execute(f"PRAGMA user_version = {kbm.SQLITE_SCHEMA_VERSION + 1}")
    conn.commit()
    conn.close()
    with pytest.raises(ValueError, match="newer than supported"):
        _sqlite_client(tmp_path)


def test_cli_writes_plugin_readable_db(tmp_path):
    # The self-contained CLI must produce a DB the plugin can read (same schema).
    db = tmp_path / "kbm_db" / "secrets.db"
    res = subprocess.run(
        [
            sys.executable,
            _CLI,
            "--db",
            str(db),
            "--key-id",
            "cli-key",
            "--secret",
            "cli-val",
        ],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0, res.stderr
    assert _user_version(db) == kbm.SQLITE_SCHEMA_VERSION
    # Plugin reads the CLI-written value back.
    client = kbm._client_from_config(
        {"backend": "sqlite", "db_path": "kbm_db/secrets.db", "strict": True},
        base_dir=str(tmp_path),
    )
    assert client.get_secret("cli-key") == b"cli-val"


def test_cli_create_only_duplicate(tmp_path):
    db = tmp_path / "kbm_db" / "secrets.db"
    args = [sys.executable, _CLI, "--db", str(db), "--key-id", "dup", "--secret", "v"]
    first = subprocess.run(args, capture_output=True, text=True)
    assert first.returncode == 0, first.stderr
    second = subprocess.run(args, capture_output=True, text=True)
    assert second.returncode == 1
    assert "already exists" in second.stderr


# --------------------------------------------------------------------------
# Multi-process writes (models gunicorn's separate worker processes)
# --------------------------------------------------------------------------

# gunicorn spawns worker *processes* (fork on Linux). These tests use real
# processes -- each opening its OWN client/connection against one shared DB file
# -- to exercise SQLite's cross-process file locking (not just threads).

_FORK_AVAILABLE = "fork" in multiprocessing.get_all_start_methods()


def _mp_put_worker(db_path, key_id, value, result_q):
    """Runs in a separate process: open a fresh client and attempt one write."""
    from plugins import tas_kbm_mock as kbm

    client = kbm._client_from_config({}, db_path_override=db_path)
    try:
        client.store.put(key_id, kbm._secret_to_bytes(value))
        result_q.put("ok")
    except ValueError:
        result_q.put("dup")


@pytest.mark.skipif(
    not _FORK_AVAILABLE,
    reason="fork start method (gunicorn-style workers) unavailable on this platform",
)
def test_multiprocess_writers_same_key_one_winner(tmp_path):
    ctx = multiprocessing.get_context("fork")
    # Pre-create the DB + schema in the parent so workers race only on INSERT.
    # (No open connection is inherited: the store opens/closes per operation.)
    _sqlite_client(tmp_path)
    db = str(tmp_path / "kbm_db" / "secrets.db")

    result_q = ctx.Queue()
    procs = [
        ctx.Process(target=_mp_put_worker, args=(db, "shared", f"v{i}", result_q))
        for i in range(6)
    ]
    for pr in procs:
        pr.start()
    for pr in procs:
        pr.join(timeout=30)
        assert pr.exitcode == 0

    results = [result_q.get() for _ in procs]
    assert results.count("ok") == 1
    assert results.count("dup") == 5

    # Exactly one row persisted for the contended key.
    reader = _sqlite_client(tmp_path, strict=True)
    assert reader.get_secret("shared") in {f"v{i}".encode() for i in range(6)}


@pytest.mark.skipif(
    not _FORK_AVAILABLE,
    reason="fork start method (gunicorn-style workers) unavailable on this platform",
)
def test_multiprocess_distinct_keys_all_persist(tmp_path):
    ctx = multiprocessing.get_context("fork")
    _sqlite_client(tmp_path)
    db = str(tmp_path / "kbm_db" / "secrets.db")

    n = 8
    result_q = ctx.Queue()
    procs = [
        ctx.Process(target=_mp_put_worker, args=(db, f"k{i}", f"v{i}", result_q))
        for i in range(n)
    ]
    for pr in procs:
        pr.start()
    for pr in procs:
        pr.join(timeout=30)
        assert pr.exitcode == 0

    results = [result_q.get() for _ in procs]
    assert results.count("ok") == n

    reader = _sqlite_client(tmp_path, strict=True)
    for i in range(n):
        assert reader.get_secret(f"k{i}") == f"v{i}".encode()


# --------------------------------------------------------------------------
# Graceful behavior when the sqlite3 module is unavailable
# --------------------------------------------------------------------------


def test_file_backend_works_without_sqlite3(monkeypatch):
    # Simulate a minimal Python build lacking sqlite3. The default file backend
    # must still import and work, since it never touches sqlite3.
    monkeypatch.setattr(kbm, "sqlite3", None)
    client = kbm._client_from_config({"strict": True, "secrets": {"k": "v"}})
    assert type(client.store).__name__ == "_InMemoryStore"
    assert client.get_secret("k") == b"v"


def test_sqlite_backend_errors_clearly_without_sqlite3(tmp_path, monkeypatch):
    monkeypatch.setattr(kbm, "sqlite3", None)
    with pytest.raises(RuntimeError, match="sqlite3 module is"):
        kbm._client_from_config(
            {"backend": "sqlite", "db_path": "kbm_db/s.db"}, base_dir=str(tmp_path)
        )


# --------------------------------------------------------------------------
# DB file permissions (plaintext mock secrets must not be group/world readable)
# --------------------------------------------------------------------------


@pytest.mark.skipif(os.name == "nt", reason="POSIX directory mode bits only")
def test_sqlite_db_dir_is_owner_only(tmp_path):
    import stat

    # A permissive umask must not leak into the DB directory perms; the
    # owner-only directory is what protects the DB and its WAL/SHM sidecars.
    old = os.umask(0o022)
    try:
        client = _sqlite_client(tmp_path)
        _seed(client, "k", "v")
    finally:
        os.umask(old)
    d = tmp_path / "kbm_db"
    mode = stat.S_IMODE(d.stat().st_mode)
    assert mode & 0o077 == 0, oct(mode)


@pytest.mark.skipif(os.name == "nt", reason="POSIX file mode bits only")
def test_sqlite_db_file_is_owner_only(tmp_path):
    import stat

    old = os.umask(0o022)
    try:
        client = _sqlite_client(tmp_path)
        _seed(client, "k", "v")
    finally:
        os.umask(old)
    db = tmp_path / "kbm_db" / "secrets.db"
    # The DB file is tightened to owner-only despite the permissive umask.
    assert stat.S_IMODE(db.stat().st_mode) & 0o077 == 0


@pytest.mark.skipif(os.name == "nt", reason="POSIX file mode bits only")
def test_sqlite_rejects_group_readable_db_file(tmp_path, monkeypatch):
    # Simulate a filesystem where chmod cannot tighten the file: init must warn
    # and stop rather than serve a group/world-readable secret DB.
    _sqlite_client(tmp_path)  # create a valid DB first
    db = tmp_path / "kbm_db" / "secrets.db"
    os.chmod(db, 0o644)
    monkeypatch.setattr(kbm.os, "chmod", lambda *a, **k: None)
    with pytest.raises(ValueError, match="permissive|mode"):
        _sqlite_client(tmp_path)


@pytest.mark.skipif(os.name == "nt", reason="POSIX directory mode bits only")
def test_sqlite_refuses_group_world_accessible_dir(tmp_path):
    # A pre-existing, too-permissive DB directory must fail fast (warn + stop)
    # rather than silently writing plaintext secrets where others can read them.
    loose = tmp_path / "loose"
    loose.mkdir()
    os.chmod(loose, 0o755)
    with pytest.raises(ValueError, match="permissive|mode"):
        kbm._client_from_config(
            {"backend": "sqlite", "db_path": "loose/s.db"}, base_dir=str(tmp_path)
        )


# ----------------------------------------------------------------------------
# Schema validation: refuse to adopt an incompatible unversioned database
# ----------------------------------------------------------------------------


def _make_unversioned_db(tmp_path, create_sql):
    """Create an owner-only kbm_db/secrets.db with user_version 0 and a custom
    `secrets` table, returning the db path."""
    import sqlite3

    db_dir = tmp_path / "kbm_db"
    db_dir.mkdir(mode=0o700)
    db = db_dir / "secrets.db"
    conn = sqlite3.connect(str(db))
    try:
        conn.execute(create_sql)
        conn.commit()
    finally:
        conn.close()
    return db


def _user_version_of(db):
    import sqlite3

    return sqlite3.connect(str(db)).execute("PRAGMA user_version").fetchone()[0]


def test_sqlite_rejects_incompatible_unversioned_schema(tmp_path):
    db = _make_unversioned_db(
        tmp_path, "CREATE TABLE secrets (key_id TEXT PRIMARY KEY)"
    )
    with pytest.raises(ValueError, match="incompatible"):
        _sqlite_client(tmp_path)
    # The foreign DB must NOT be silently stamped as schema version 1.
    assert _user_version_of(db) == 0


def test_sqlite_adopts_compatible_unversioned_schema(tmp_path):
    # A pre-existing table that exactly matches the v1 layout but was never
    # stamped is adopted (stamped) and works.
    db = _make_unversioned_db(
        tmp_path,
        "CREATE TABLE secrets ("
        "key_id TEXT PRIMARY KEY, secret BLOB NOT NULL, created_at TEXT)",
    )
    client = _sqlite_client(tmp_path)
    assert _user_version_of(db) == kbm.SQLITE_SCHEMA_VERSION
    assert _seed(client, "k", "v") is True
    assert client.get_secret("k") == b"v"


def test_cli_rejects_incompatible_unversioned_schema(tmp_path):
    import sqlite3

    db = _make_unversioned_db(
        tmp_path, "CREATE TABLE secrets (key_id TEXT PRIMARY KEY)"
    )
    res = subprocess.run(
        [sys.executable, _CLI, "--db", str(db), "--key-id", "k", "--secret", "v"],
        capture_output=True,
        text=True,
    )
    assert res.returncode != 0
    assert "incompatible" in res.stderr
    # Not stamped, and no row inserted.
    assert _user_version_of(db) == 0
    assert (
        sqlite3.connect(str(db)).execute("SELECT count(*) FROM secrets").fetchone()[0]
        == 0
    )


# ----------------------------------------------------------------------------
# Filesystem trust: reject symlinks and wrong ownership (POSIX)
# ----------------------------------------------------------------------------


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink semantics only")
def test_sqlite_rejects_symlinked_db_dir(tmp_path):
    realdir = tmp_path / "realdir"
    realdir.mkdir(mode=0o700)
    link = tmp_path / "kbm_db"
    os.symlink(realdir, link, target_is_directory=True)
    with pytest.raises(ValueError, match="symbolic link"):
        _sqlite_client(tmp_path)


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink semantics only")
def test_sqlite_rejects_symlinked_db_file(tmp_path):
    db_dir = tmp_path / "kbm_db"
    db_dir.mkdir(mode=0o700)
    target = db_dir / "target.db"
    link = db_dir / "secrets.db"
    os.symlink(target, link)
    with pytest.raises(ValueError, match="symbolic link"):
        _sqlite_client(tmp_path)


@pytest.mark.skipif(os.name == "nt", reason="POSIX ownership semantics only")
def test_sqlite_rejects_wrong_owner_dir(tmp_path, monkeypatch):
    # Simulate a directory owned by a different user by making the effective uid
    # differ from the (test-user-owned) directory's owner.
    monkeypatch.setattr(kbm.os, "geteuid", lambda: os.getuid() + 1)
    with pytest.raises(ValueError, match="owned by uid"):
        _sqlite_client(tmp_path)


@pytest.mark.skipif(os.name == "nt", reason="POSIX ownership semantics only")
def test_ensure_db_file_private_rejects_wrong_owner(tmp_path, monkeypatch):
    # Build a valid DB first (owner == effective uid), then simulate a foreign
    # owner and check the file-level trust helper in isolation.
    client = _sqlite_client(tmp_path)
    _seed(client, "k", "v")
    db = tmp_path / "kbm_db" / "secrets.db"
    monkeypatch.setattr(kbm.os, "geteuid", lambda: os.getuid() + 1)
    with pytest.raises(ValueError, match="owned by uid"):
        kbm._ensure_db_file_private(str(db))
