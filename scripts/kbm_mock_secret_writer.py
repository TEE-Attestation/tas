#!/usr/bin/env python3
#
# TEE Attestation Service - Mock KBM local secret injector
#
# Copyright 2026 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# This file is part of the TEE Attestation Service.
#
# Self-contained CLI to inject secrets into the Mock KBM's SQLite database.
# It intentionally does NOT import the tas_kbm_mock plugin, so it can run
# standalone (e.g. copied to another host) without the TAS package on sys.path.
# It writes the SAME schema the plugin uses; SQLITE_SCHEMA_VERSION (PRAGMA
# user_version) must be kept in sync with plugins/tas_kbm_mock.py.
#
# Writes are create-only (an existing key_id is rejected -- no overwrite/delete)
#
# There is no delete/remove command by design (prevents accidental loss). To
# remove a key, use sqlite3 directly, e.g.:
#   sqlite3 config/kbm_db/kbm_mock_secrets.db "DELETE FROM secrets WHERE key_id='k';"
#
# Examples:
#   # single secret via a config file that selects the sqlite backend
#   python scripts/kbm_mock_secret_writer.py --config config/kbm_mock_config.yaml \
#       --key-id my-key-1 --secret "0xdeadbeef"
#
# Prefer --secret - (stdin) or --secret-file for real material: a literal
# --secret VALUE is visible in the process list (ps) and shell history.
#
#   # secret from stdin (keeps it out of shell history)
#   printf '0xdeadbeef' | python scripts/kbm_mock_secret_writer.py \
#       --db config/kbm_db/kbm_mock_secrets.db --key-id my-key-1 --secret -
#
#   # secret from a file
#   python scripts/kbm_mock_secret_writer.py \
#       --db config/kbm_db/kbm_mock_secrets.db --key-id my-key-1 --secret-file ./secret.bin
#
#   # bulk import every entry from a YAML `secrets:` map
#   python scripts/kbm_mock_secret_writer.py --config config/kbm_mock_config.yaml \
#       --import config/kbm_mock_config.yaml

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Dict, Optional

try:
    import yaml  # PyYAML (optional; only needed for YAML config files)
except Exception:
    yaml = None

if TYPE_CHECKING:
    # For type checkers, sqlite3 is always the module so annotations like
    # `sqlite3.Connection` resolve. At runtime it may be absent (below).
    import sqlite3
else:
    try:
        import sqlite3
    except Exception:  # sqlite3 is stdlib but may be absent in minimal builds
        sqlite3 = None

# SQLite schema version (stored via `PRAGMA user_version`). MUST match
# plugins/tas_kbm_mock.py so the plugin and this CLI interoperate on one DB file.
SQLITE_SCHEMA_VERSION = 1

# Expected column layout for schema version 1 (kept in sync with
# plugins/tas_kbm_mock.py). Maps column name -> (declared type upper-cased,
# notnull, pk). A non-INTEGER PRIMARY KEY is not implicitly NOT NULL in SQLite,
# so key_id has notnull=0, pk=1; secret is NOT NULL; created_at is a plain column.
_EXPECTED_SECRETS_COLUMNS = {
    "key_id": ("TEXT", 0, 1),
    "secret": ("BLOB", 1, 0),
    "created_at": ("TEXT", 0, 0),
}

# The plaintext secret DB (and its transient WAL/SHM sidecars) are protected by
# owner-only *directory* permissions rather than per-file chmod (SQLite recreates
# the sidecars with the umask on each write). Created 0o700; refuse to run if the
# directory is group/world accessible.
DB_DIR_MODE = 0o700

# The DB file itself is tightened to owner-only (0o600) and verified at init.
DB_FILE_MODE = 0o600

# Default SQLite location, relative to the config file's directory.
DEFAULT_DB_DIRNAME = "kbm_db"
DEFAULT_DB_FILENAME = "kbm_mock_secrets.db"


# --------------------------------------------------------------------------
# Config parsing (mirrors the plugin's semantics; kept local for standalone use)
# --------------------------------------------------------------------------
def _load_config_file(config_file: Optional[str]) -> Dict[str, Any]:
    if not config_file:
        return {}
    path = os.path.abspath(config_file)
    if not os.path.isfile(path):
        raise SystemExit(f"error: config file not found: {path}")
    _, ext = os.path.splitext(path.lower())
    if ext in (".yaml", ".yml"):
        if yaml is None:
            raise SystemExit("error: PyYAML is required to read a YAML config file")
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    else:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f) or {}
    if not isinstance(data, dict):
        raise SystemExit(f"error: config file is not a mapping: {path}")
    return data


def _secret_to_bytes(v: Any) -> bytes:
    """Normalize a secret value to bytes (matches the plugin's rules)."""
    if isinstance(v, bytes):
        return v
    if isinstance(v, bytearray):
        return bytes(v)
    if isinstance(v, str):
        return v.encode("utf-8")
    return json.dumps(v, separators=(",", ":")).encode("utf-8")


def _secrets_map_from_config(cfg: Dict[str, Any]) -> Dict[str, bytes]:
    out: Dict[str, bytes] = {}
    raw = cfg.get("secrets")
    if not isinstance(raw, dict):
        return out
    for k, v in raw.items():
        if isinstance(k, str):
            out[k] = _secret_to_bytes(v)
    return out


def _resolve_db_path(db_path: Optional[str], base_dir: str) -> str:
    if db_path:
        p = db_path if os.path.isabs(db_path) else os.path.join(base_dir, db_path)
    else:
        p = os.path.join(base_dir, DEFAULT_DB_DIRNAME, DEFAULT_DB_FILENAME)
    return os.path.abspath(p)


# --------------------------------------------------------------------------
# SQLite store (inlined; schema-versioned)
# --------------------------------------------------------------------------
def _secrets_table_state(conn) -> str:
    """Classify the ``secrets`` table as 'absent', 'compatible', or 'incompatible'.

    Mirrors the plugin's check so the standalone CLI refuses to adopt a foreign
    or incompatible unversioned database before stamping ``PRAGMA user_version``.
    """
    rows = conn.execute("PRAGMA table_info(secrets)").fetchall()
    if not rows:
        return "absent"
    # rows: (cid, name, type, notnull, dflt_value, pk)
    found = {
        name: ((ctype or "").upper(), int(notnull), int(pk))
        for _cid, name, ctype, notnull, _dflt, pk in rows
    }
    if set(found) != set(_EXPECTED_SECRETS_COLUMNS):
        return "incompatible"
    for name, (exp_type, exp_notnull, exp_pk) in _EXPECTED_SECRETS_COLUMNS.items():
        act_type, act_notnull, act_pk = found[name]
        if act_type != exp_type or act_notnull != exp_notnull:
            return "incompatible"
        if bool(exp_pk) != bool(act_pk):
            return "incompatible"
    return "compatible"


def _fs_owner_enforced() -> bool:
    """Return True when POSIX owner/mode enforcement applies to this platform."""
    return os.name != "nt" and hasattr(os, "geteuid")


def _ensure_private_db_dir(db_path: str) -> None:
    """Ensure the DB sits in an owner-only directory; fail fast if not.

    The plaintext secret DB and its transient WAL/SHM sidecars are protected by
    directory permissions (0o700), not per-file chmod: SQLite creates the sidecars
    with the umask and removes them when the last connection closes, so per-file
    tightening is unreliable. Created 0o700 when missing; a pre-existing group/
    world accessible directory is rejected rather than exposing secrets.
    """
    parent = os.path.dirname(db_path) or "."
    if not os.path.isdir(parent):
        os.makedirs(parent, mode=DB_DIR_MODE, exist_ok=True)
        try:
            os.chmod(parent, DB_DIR_MODE)
        except OSError:
            pass
    if os.path.islink(parent):
        raise SystemExit(
            f"error: SQLite DB directory {parent} is a symbolic link; refusing "
            "to use it."
        )
    st = os.stat(parent)
    mode = stat.S_IMODE(st.st_mode)
    if mode & 0o077:
        raise SystemExit(
            f"error: SQLite DB directory {parent} has mode {oct(mode)}, which is "
            "accessible to group/other and would expose plaintext secrets; "
            f"restrict it (chmod 700 {parent}) and retry."
        )
    if _fs_owner_enforced() and st.st_uid != os.geteuid():
        raise SystemExit(
            f"error: SQLite DB directory {parent} is owned by uid {st.st_uid}, "
            f"not the current user (uid {os.geteuid()}); refusing to use it."
        )


def _ensure_db_file_private(db_path: str) -> None:
    """Ensure the DB file is owner-only (0o600); warn and stop otherwise."""
    if not os.path.exists(db_path):
        return
    if os.path.islink(db_path):
        raise SystemExit(
            f"error: SQLite DB file {db_path} is a symbolic link; refusing to "
            "use it."
        )
    try:
        os.chmod(db_path, DB_FILE_MODE)
    except OSError as e:
        print(f"warning: could not set {db_path} to 0o600: {e}", file=sys.stderr)
    st = os.stat(db_path)
    mode = stat.S_IMODE(st.st_mode)
    if mode & 0o077:
        raise SystemExit(
            f"error: SQLite DB file {db_path} has mode {oct(mode)}, which is "
            "accessible to group/other and would expose plaintext secrets; "
            f"restrict it (chmod 600 {db_path}) and retry."
        )
    if _fs_owner_enforced() and st.st_uid != os.geteuid():
        raise SystemExit(
            f"error: SQLite DB file {db_path} is owned by uid {st.st_uid}, not "
            f"the current user (uid {os.geteuid()}); refusing to use it."
        )


class SecretDB:
    """Create-only, schema-versioned SQLite writer for mock KBM secrets."""

    def __init__(self, db_path: str):
        if sqlite3 is None:
            raise SystemExit(
                "error: Python's sqlite3 module is unavailable; "
                "this tool requires SQLite support."
            )
        self.db_path = db_path
        _ensure_private_db_dir(db_path)
        conn = self._connect()
        try:
            self._init_schema(conn)
        finally:
            conn.close()
        _ensure_db_file_private(db_path)

    def _connect(self) -> sqlite3.Connection:
        # journal_mode=WAL is persistent DB state (set once in _init_schema);
        # busy_timeout is per-connection.
        conn = sqlite3.connect(self.db_path, timeout=5.0)
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    def _init_schema(self, conn: sqlite3.Connection) -> None:
        conn.execute("PRAGMA journal_mode=WAL")
        (version,) = conn.execute("PRAGMA user_version").fetchone()
        if version == 0:
            # Fresh or pre-versioning DB. Refuse to adopt a foreign or
            # incompatible `secrets` table: validate its shape before stamping
            # user_version so a mismatched database is never marked version 1.
            state = _secrets_table_state(conn)
            if state == "incompatible":
                raise SystemExit(
                    "error: SQLite database has an unversioned but incompatible "
                    "'secrets' table; refusing to use it. Point --db at a fresh "
                    "file or migrate it deliberately."
                )
            if state == "absent":
                conn.execute(
                    "CREATE TABLE secrets ("
                    "key_id TEXT PRIMARY KEY, secret BLOB NOT NULL, created_at TEXT)"
                )
            conn.execute(f"PRAGMA user_version = {SQLITE_SCHEMA_VERSION}")
            conn.commit()
        elif version > SQLITE_SCHEMA_VERSION:
            raise SystemExit(
                f"error: database schema version {version} is newer than supported "
                f"{SQLITE_SCHEMA_VERSION}; upgrade this tool"
            )
        elif version < SQLITE_SCHEMA_VERSION:
            raise SystemExit(
                f"error: database schema version {version} predates supported "
                f"{SQLITE_SCHEMA_VERSION}; migration required"
            )

    def put(self, key_id: str, value: bytes) -> None:
        """Create-only insert. Raises ValueError if the key_id already exists."""
        created_at = datetime.now(timezone.utc).isoformat()
        conn = self._connect()
        try:
            conn.execute(
                "INSERT INTO secrets (key_id, secret, created_at) VALUES (?, ?, ?)",
                (key_id, sqlite3.Binary(value), created_at),
            )
            conn.commit()
        except sqlite3.IntegrityError as e:
            raise ValueError("Secret already exists") from e
        finally:
            conn.close()


# --------------------------------------------------------------------------
# Target resolution + commands
# --------------------------------------------------------------------------
def _db_path_from_args(args) -> str:
    if args.db:
        return _resolve_db_path(args.db, os.getcwd())

    cfg = _load_config_file(args.config)
    backend = str(cfg.get("backend") or "").strip().lower()
    if backend not in ("", "file", "sqlite"):
        raise SystemExit(f"error: invalid backend {backend!r} in {args.config}")
    if backend != "sqlite":
        raise SystemExit(
            "error: the selected config does not enable the SQLite backend.\n"
            "       Set `backend: sqlite` in the config, or pass --db PATH."
        )
    base_dir = os.path.dirname(os.path.abspath(args.config))
    return _resolve_db_path(cfg.get("db_path"), base_dir)


def _read_single_secret(args) -> bytes:
    if args.secret is not None:
        if args.secret == "-":
            return sys.stdin.buffer.read()
        return args.secret.encode("utf-8")
    if args.secret_file is not None:
        with open(args.secret_file, "rb") as f:
            return f.read()
    raise SystemExit(
        "error: provide one of --secret, --secret-file, or --secret - (stdin)"
    )


def _do_single(db: SecretDB, args) -> int:
    value = _read_single_secret(args)
    if not value:
        raise SystemExit("error: refusing to store an empty secret")
    try:
        db.put(args.key_id, value)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    print(f"stored secret for key_id: {args.key_id}")
    return 0


def _do_import(db: SecretDB, args) -> int:
    cfg = _load_config_file(args.import_file)
    secrets_map = _secrets_map_from_config(cfg)
    if not secrets_map:
        print(f"no secrets found in {args.import_file}", file=sys.stderr)
        return 1
    added, skipped = 0, 0
    for key_id, value in secrets_map.items():
        try:
            db.put(key_id, value)
            added += 1
            print(f"added: {key_id}")
        except ValueError:
            skipped += 1
            print(f"skipped (exists): {key_id}")
    print(f"import complete: {added} added, {skipped} skipped")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Inject secrets into the Mock KBM SQLite database (create-only).",
    )
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument(
        "--config", help="Mock KBM config file selecting the sqlite backend"
    )
    target.add_argument(
        "--db", help="Explicit SQLite DB path (writes directly to this file)"
    )

    parser.add_argument("--key-id", help="Key id for a single secret write")
    parser.add_argument(
        "--secret",
        help="Secret value; use '-' to read from stdin. NOTE: a literal value "
        "is visible in the process list and shell history -- prefer '-' "
        "(stdin) or --secret-file for real material.",
    )
    parser.add_argument("--secret-file", help="Read the secret value from this file")
    parser.add_argument(
        "--import",
        dest="import_file",
        help="Bulk import every entry from a YAML/JSON `secrets:` map",
    )

    args = parser.parse_args(argv)

    if args.import_file and (args.key_id or args.secret or args.secret_file):
        parser.error("--import cannot be combined with --key-id/--secret/--secret-file")
    if not args.import_file and not args.key_id:
        parser.error("provide --key-id (single write) or --import FILE (bulk)")
    if sum(x is not None for x in (args.secret, args.secret_file)) > 1:
        parser.error("use only one of --secret or --secret-file")

    db = SecretDB(_db_path_from_args(args))

    if args.import_file:
        return _do_import(db, args)
    return _do_single(db, args)


if __name__ == "__main__":
    raise SystemExit(main())
