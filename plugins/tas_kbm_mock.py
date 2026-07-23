#
# TEE Attestation Service - Mock KBM (software, no KMIP)
#
# Copyright 2025 - 2026 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# This file is part of the TEE Attestation Service.
#
# This is a mock Key Management Backend (KBM) client implementation for testing.
#  DO NOT USE IN PRODUCTION.
# - Uses pure Python crypto (cryptography) for test purposes.
# - If a config file (YAML/JSON) provides `secrets`, they are used as-is.
# - When a config file is present and no `strict` is specified, strict defaults to True
#   so missing keys will NOT be derived (prevents implicit derivation from plaintext files).
# - Returns: {"wrapped_key": b64, "blob": b64, "iv": b64, "tag": b64}
#
# Storage backends (selected via config, see kbm_open_client_connection):
# - "file" (default): secrets are loaded from the config `secrets:` map into an
#   in-memory dict. READ-ONLY -- writes are rejected.
# - "sqlite" (opt-in): secrets are persisted in a local SQLite database file.
#   WRITE-ENABLED and safe across multiple worker processes (create-only; no
#   overwrite and no delete). The config `secrets:` map is NOT used to seed the
#   database -- populated  explicitly via scripts/kbm_mock_secret_writer.py, for example. In
#   non-strict + sqlite mode, secrets generated for unknown keys are persisted
#   so the same key_id returns a stable value on later calls.

from __future__ import annotations

import base64
import json
import os
import secrets as _secrets
import stat
import threading
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Dict, Optional

try:
    import yaml  # PyYAML (listed in requirements)
except Exception:
    yaml = None

if TYPE_CHECKING:
    # For type checkers, sqlite3 is always needed so annotations like
    # `sqlite3.Connection` resolve. At runtime it may be absent (below).
    import sqlite3
else:
    try:
        import sqlite3
    except (
        Exception
    ):  # sqlite3 is a dev only requirment so may be absent in minimal builds
        sqlite3 = None

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding as sympadding
from cryptography.hazmat.primitives.asymmetric import padding as asympadding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import (
    load_der_public_key,
    load_pem_public_key,
)

from tas.tas_logging import get_logger

# Setup logging for the mock KBM plugin
logger = get_logger("tas.plugins.tas_kbm_mock")

AES_KEY_LEN = 32  # AES-256
IV_LEN = 12  # AES-GCM IV size
SECRET_LEN = 32  # default secret length when derivation is allowed

# SQLite backend defaults. The DB lives in a dedicated subdirectory (relative to
# the config file's directory) so the three WAL artifacts stay isolated.
DEFAULT_DB_DIRNAME = "kbm_db"
DEFAULT_DB_FILENAME = "kbm_mock_secrets.db"

# SQLite schema version, stored via `PRAGMA user_version`. Keep in sync with
# scripts/kbm_mock_secret_writer.py (both read/write the same database file).
SQLITE_SCHEMA_VERSION = 1

# The plaintext mock secret DB (and its transient WAL/SHM sidecars) are protected
# by owner-only *directory* permissions rather than per-file chmod: SQLite creates
# the sidecars using the umask and deletes them when the last connection closes, so
# per-file tightening is unreliable. A 0o700 parent dir blocks group/other from
# every artifact; we create it 0o700 and refuse to run if it is more permissive.
DB_DIR_MODE = 0o700

# The DB file itself is tightened to owner-only (0o600) and verified at init; if
# it stays group/world accessible we warn and stop rather than serve readable
# secrets. The transient WAL/SHM sidecars remain protected by the directory.
DB_FILE_MODE = 0o600


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _load_rsa_public_key(raw: bytes):
    try:
        return load_pem_public_key(raw)
    except Exception:
        pass
    try:
        return load_der_public_key(raw)
    except Exception as e:
        raise ValueError("Invalid RSA public key format") from e


def _aes_gcm_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
    enc = cipher.encryptor()
    return enc.update(plaintext) + enc.finalize(), enc.tag


def _secret_to_bytes(v: Any) -> bytes:
    """Normalize a secret value to bytes (same rules as config secret parsing)."""
    if isinstance(v, bytes):
        return v
    if isinstance(v, bytearray):
        return bytes(v)
    if isinstance(v, str):
        # Use as-is (plaintext), encoded to bytes
        return v.encode("utf-8")
    # For non-strings, store their compact JSON representation as bytes
    return json.dumps(v, separators=(",", ":")).encode("utf-8")


# Expected column layout for schema version 1. Used to reject a pre-existing but
# incompatible ``secrets`` table before stamping ``PRAGMA user_version`` on a
# foreign database. Maps column name -> (declared type upper-cased, notnull, pk).
# In SQLite a non-INTEGER PRIMARY KEY column is not implicitly NOT NULL, so
# key_id has notnull=0, pk=1; secret is NOT NULL; created_at is a plain column.
_EXPECTED_SECRETS_COLUMNS = {
    "key_id": ("TEXT", 0, 1),
    "secret": ("BLOB", 1, 0),
    "created_at": ("TEXT", 0, 0),
}


def _secrets_table_state(conn) -> str:
    """Classify the ``secrets`` table as 'absent', 'compatible', or 'incompatible'.

    Uses ``PRAGMA table_info(secrets)``, which returns an empty result set when
    the table does not exist. Any deviation from the version-1 layout (missing,
    extra, or mistyped columns, a wrong PRIMARY KEY, or a nullable secret column)
    is reported as incompatible so the caller can fail fast rather than stamp
    ``user_version`` onto a database this plugin did not create.
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
        # ``pk`` is the 1-based position in the primary key for members, else 0.
        if bool(exp_pk) != bool(act_pk):
            return "incompatible"
    return "compatible"


def _fs_owner_enforced() -> bool:
    """Return True when POSIX owner/mode enforcement applies to this platform.

    ``os.geteuid`` does not exist on Windows, where uid/mode semantics are not
    reliable, so ownership checks are skipped there.
    """
    return os.name != "nt" and hasattr(os, "geteuid")


def _ensure_private_db_dir(db_path: str) -> str:
    """Ensure the SQLite DB sits in an owner-only directory; fail if it does not.

    The plaintext mock secret DB and its transient WAL/SHM sidecars are protected
    by *directory* permissions, not per-file chmod: SQLite creates the sidecars
    with the process umask and deletes them when the last connection closes, so
    per-file tightening is unreliable. A 0o700 parent directory blocks group/other
    from every artifact.

    The directory is created 0o700 when missing. If it already exists but is
    group/world accessible, this warns and raises (fail-fast) instead of exposing
    secrets. Returns the directory path.
    """
    parent = os.path.dirname(db_path) or "."
    if not os.path.isdir(parent):
        os.makedirs(parent, mode=DB_DIR_MODE, exist_ok=True)
        try:
            os.chmod(parent, DB_DIR_MODE)
        except OSError:
            pass
    if os.path.islink(parent):
        logger.error(f"SQLite DB directory {parent} is a symlink; refusing to use it")
        raise ValueError(
            f"Refusing to use SQLite DB directory {parent!r}: it is a symbolic link."
        )
    st = os.stat(parent)
    mode = stat.S_IMODE(st.st_mode)
    if mode & 0o077:
        logger.error(
            f"SQLite DB directory {parent} is too permissive (mode {oct(mode)}); "
            "plaintext secrets would be readable by group/other"
        )
        raise ValueError(
            f"Refusing to use SQLite DB directory {parent!r}: mode {oct(mode)} is "
            f"group/world accessible. Restrict it (e.g. `chmod 700 {parent}`)."
        )
    if _fs_owner_enforced() and st.st_uid != os.geteuid():
        logger.error(
            f"SQLite DB directory {parent} is owned by uid {st.st_uid}, not the "
            "current user; plaintext secrets could be exposed to another owner"
        )
        raise ValueError(
            f"Refusing to use SQLite DB directory {parent!r}: owned by uid "
            f"{st.st_uid}, expected effective uid {os.geteuid()}."
        )
    return parent


def _ensure_db_file_private(db_path: str) -> None:
    """Ensure the SQLite DB file is owner-only (0o600); warn and stop otherwise.

    Complements the private-directory check. sqlite3.connect() creates the file
    with the process umask (often 0o644), so it is tightened to 0o600 and then
    verified. If the file is still group/world accessible, fail fast rather than
    serving plaintext secrets from a readable file.
    """
    if not os.path.exists(db_path):
        return
    if os.path.islink(db_path):
        logger.error(f"SQLite DB file {db_path} is a symlink; refusing to use it")
        raise ValueError(
            f"Refusing to use SQLite DB file {db_path!r}: it is a symbolic link."
        )
    try:
        os.chmod(db_path, DB_FILE_MODE)
    except OSError as e:
        logger.warning(f"Could not set {db_path} to {oct(DB_FILE_MODE)}: {e}")
    st = os.stat(db_path)
    mode = stat.S_IMODE(st.st_mode)
    if mode & 0o077:
        logger.error(
            f"SQLite DB file {db_path} is too permissive (mode {oct(mode)}); "
            "plaintext secrets would be readable by group/other"
        )
        raise ValueError(
            f"Refusing to use SQLite DB file {db_path!r}: mode {oct(mode)} is "
            f"group/world accessible. Restrict it (e.g. `chmod 600 {db_path}`)."
        )
    if _fs_owner_enforced() and st.st_uid != os.geteuid():
        logger.error(
            f"SQLite DB file {db_path} is owned by uid {st.st_uid}, not the "
            "current user; plaintext secrets could be exposed to another owner"
        )
        raise ValueError(
            f"Refusing to use SQLite DB file {db_path!r}: owned by uid "
            f"{st.st_uid}, expected effective uid {os.geteuid()}."
        )


class _InMemoryStore:
    """Read-only in-memory secret store backed by the config `secrets:` map."""

    supports_write = False

    def __init__(self, secrets_map: Dict[str, bytes]):
        self._secrets = dict(secrets_map)
        self._lock = threading.RLock()

    def get(self, key_id: str) -> Optional[bytes]:
        with self._lock:
            return self._secrets.get(key_id)

    def put(self, key_id: str, value: bytes) -> bool:
        raise ValueError("write not supported by file backend")


class _SQLiteStore:
    """Write-enabled SQLite secret store.

    Create-only: a duplicate key_id raises ValueError. Uses WAL journalling and a
    busy timeout so concurrent writers (threads or processes) are serialized
    safely.

    Connections are short-lived (opened per operation) rather than cached on the
    store, which is created once and reused across requests. This avoids two
    documented hazards:
      * Python's sqlite3 defaults to check_same_thread=True, so a Connection may
        only be used by the thread that created it (otherwise ProgrammingError).
        In the default "multi-thread" mode, threads "may share the module, but
        not connections".
        https://docs.python.org/3/library/sqlite3.html
      * A SQLite connection must not cross a process boundary (e.g. inherited
        over fork()); doing so causes locking problems and possible corruption.
        https://www.sqlite.org/howtocorrupt.html  (2.7 "Carrying an open
        database connection across a fork()")
    Opening a fresh connection per operation sidesteps both.
    """

    supports_write = True

    def __init__(self, db_path: str):
        if sqlite3 is None:
            raise RuntimeError(
                "SQLite backend requested but Python's sqlite3 module is "
                "unavailable; use the file backend (backend: file) or install/"
                "rebuild Python with sqlite3 support."
            )
        self.db_path = db_path
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        # journal_mode=WAL is persistent database state, so it is set once during
        # _init_db rather than on every connection. busy_timeout is a per-
        # connection setting and must be applied each time.
        conn = sqlite3.connect(self.db_path, timeout=5.0)
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    def _init_db(self) -> None:
        # Secrets are protected by an owner-only directory (see
        # _ensure_private_db_dir); refuse to run if it is group/world accessible.
        _ensure_private_db_dir(self.db_path)
        conn = self._connect()
        try:
            # Persisted once for the DB file; harmless to re-assert on an
            # existing WAL database.
            conn.execute("PRAGMA journal_mode=WAL")
            (version,) = conn.execute("PRAGMA user_version").fetchone()
            if version == 0:
                # Fresh or pre-versioning DB. Refuse to adopt a foreign or
                # incompatible `secrets` table: validate its shape before
                # stamping user_version, so we never silently mark a mismatched
                # database as schema version 1.
                state = _secrets_table_state(conn)
                if state == "incompatible":
                    raise ValueError(
                        "Mock KBM SQLite database has an unversioned but "
                        "incompatible 'secrets' table; refusing to use it. Point "
                        "db_path at a fresh file or migrate it deliberately."
                    )
                if state == "absent":
                    conn.execute(
                        "CREATE TABLE secrets ("
                        "key_id TEXT PRIMARY KEY, "
                        "secret BLOB NOT NULL, "
                        "created_at TEXT)"
                    )
                conn.execute(f"PRAGMA user_version = {SQLITE_SCHEMA_VERSION}")
                conn.commit()
            elif version > SQLITE_SCHEMA_VERSION:
                raise ValueError(
                    f"Mock KBM SQLite schema version {version} is newer than "
                    f"supported {SQLITE_SCHEMA_VERSION}; upgrade the plugin"
                )
            elif version < SQLITE_SCHEMA_VERSION:
                raise ValueError(
                    f"Mock KBM SQLite schema version {version} predates supported "
                    f"{SQLITE_SCHEMA_VERSION}; migration required"
                )
        finally:
            conn.close()
        # The DB file now exists; enforce owner-only (0o600) or stop.
        _ensure_db_file_private(self.db_path)

    def get(self, key_id: str) -> Optional[bytes]:
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT secret FROM secrets WHERE key_id = ?", (key_id,)
            ).fetchone()
        finally:
            conn.close()
        if row is None or row[0] is None:
            return None
        return bytes(row[0])

    def put(self, key_id: str, value: bytes) -> bool:
        """Create-only insert. Raises ValueError if the key_id already exists."""
        created_at = datetime.now(timezone.utc).isoformat()
        conn = self._connect()
        try:
            conn.execute(
                "INSERT INTO secrets (key_id, secret, created_at) VALUES (?, ?, ?)",
                (key_id, sqlite3.Binary(value), created_at),
            )
            conn.commit()
            return True
        except sqlite3.IntegrityError as e:
            # PRIMARY KEY conflict -> create-only violation
            raise ValueError("Secret already exists") from e
        finally:
            conn.close()


class _MockKBMClient:
    def __init__(self, strict: bool, store):
        self.strict = bool(strict)
        self.store = store
        logger.debug(
            f"Initialized mock KBM client with strict={self.strict}, "
            f"backend={type(store).__name__}, "
            f"write={getattr(store, 'supports_write', False)}"
        )

    def get_secret(self, key_id: str) -> bytes:
        logger.debug(f"Retrieving secret for key_id: {key_id}")
        value = self.store.get(key_id)
        if value is not None:
            logger.debug(f"Found stored secret for key_id: {key_id}")
            return value
        if self.strict:
            logger.error(f"Secret not found for key_id: {key_id} (strict mode)")
            raise ValueError("Secret not found")
        # Non-strict mode: generate a random secret to satisfy the request.
        logger.debug(f"Generating random secret for key_id: {key_id} (non-strict mode)")
        generated = _secrets.token_bytes(SECRET_LEN)
        if not getattr(self.store, "supports_write", False):
            # Read-only backend (file): the generated secret is ephemeral and
            # is never written back; a different value is produced each call.
            return generated
        # Write-enabled backend (sqlite): persist the generated secret so the
        # same key_id returns a stable value on later calls (get-or-create).
        try:
            self.store.put(key_id, generated)
            logger.debug(f"Persisted generated secret for key_id: {key_id}")
            return generated
        except ValueError:
            # Lost a create race -> return the value the winning writer stored.
            existing = self.store.get(key_id)
            if existing is not None:
                logger.debug(
                    f"Concurrent create for key_id: {key_id}; returning stored value"
                )
                return existing
            # The row vanished between the failed insert and this read (e.g. a
            # concurrent manual delete). Do not hand back an unpersisted value
            # that later calls could not reproduce.
            logger.error(f"Secret for key_id {key_id} disappeared during get-or-create")
            raise ValueError("Secret not found") from None


def _load_config_file(config_file: Optional[str]) -> Dict[str, Any]:
    if not config_file:
        logger.debug("No config file specified")
        return {}
    path = os.path.abspath(config_file)
    if not os.path.isfile(path):
        logger.warning(f"Config file not found: {path}")
        return {}

    logger.info(f"Loading mock KBM config from: {path}")
    # Try YAML first if extension suggests YAML and PyYAML is available
    _, ext = os.path.splitext(path.lower())
    if ext in (".yaml", ".yml") and yaml:
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
            if isinstance(data, dict):
                logger.debug(
                    f"Successfully loaded YAML config with keys: {list(data.keys())}"
                )
                return data
        except Exception as e:
            logger.warning(f"Failed to parse config as YAML: {e}")
    # Fallback JSON
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f) or {}
        logger.debug(f"Successfully loaded JSON config with keys: {list(data.keys())}")
        return data
    except Exception as e:
        logger.warning(f"Failed to parse config as JSON: {e}")
        return {}


def _secrets_map_from_config(cfg: Dict[str, Any]) -> Dict[str, bytes]:
    out: Dict[str, bytes] = {}
    raw = cfg.get("secrets")
    if not isinstance(raw, dict):
        logger.debug("No secrets section found in config")
        return out

    logger.debug(f"Processing {len(raw)} secrets from config")
    for k, v in raw.items():
        if not isinstance(k, str):
            logger.warning(f"Skipping non-string key: {k}")
            continue
        out[k] = _secret_to_bytes(v)
        logger.debug(f"Added secret for key: {k}")
    return out


def _client_from_config(
    cfg: Dict[str, Any],
    base_dir: str = None,
    db_path_override: str = None,
    config_present: bool = False,
) -> _MockKBMClient:
    """
    Build a _MockKBMClient from configuration dict, selecting backend and options.

    Args:
        cfg: Configuration dictionary (from YAML/JSON)
        base_dir: Base directory for relative db_path; defaults to cwd if not provided
        db_path_override: Explicit SQLite DB path (for TAS_KBM_DB_PATH env var override)
        config_present: True if a config file was loaded (affects strict default)

    Returns:
        _MockKBMClient with appropriate backend store

    Raises:
        ValueError: If configuration is invalid or conflicting
    """
    base_dir = base_dir or os.getcwd()

    # Determine which backend to use
    backend = cfg.get("backend", "file")
    db_path = cfg.get("db_path")
    strict = cfg.get("strict")
    backend_explicitly_set = "backend" in cfg

    # If db_path_override is provided, it takes precedence (select SQLite)
    if db_path_override:
        if backend_explicitly_set and backend == "file":
            # Explicit file backend conflicts with db_path_override
            raise ValueError(
                "conflicting mock KBM configuration: "
                "backend=file conflicts with explicit db_path_override"
            )
        backend = "sqlite"
        db_path = db_path_override

    # Validate backend choice
    if backend not in ("file", "sqlite"):
        raise ValueError(
            f"Invalid mock KBM backend: {backend!r}; must be 'file' or 'sqlite'"
        )

    # Determine strict mode
    if strict is None:
        # If a config file was present, default to True (no implicit derivation)
        # If no config file, default to False (allow ephemeral generation)
        strict = config_present

    # Build the appropriate backend store
    if backend == "sqlite":
        # SQLite backend: resolve db_path relative to base_dir
        if not db_path:
            db_path = os.path.join(base_dir, DEFAULT_DB_DIRNAME, DEFAULT_DB_FILENAME)
        else:
            if not os.path.isabs(db_path):
                db_path = os.path.join(base_dir, db_path)
        logger.debug(f"Using SQLite backend with db_path: {db_path}")
        store = _SQLiteStore(db_path)
    else:
        # File (in-memory) backend: load secrets from config
        secrets_map = _secrets_map_from_config(cfg)
        logger.debug(f"Using file (in-memory) backend with {len(secrets_map)} secrets")
        store = _InMemoryStore(secrets_map)

    return _MockKBMClient(strict=strict, store=store)


def kbm_open_client_connection(config_file: str = None):
    """
    Initialize the mock KBM client.

    Config file (YAML or JSON) format (all optional):
      strict: bool          # if true, missing keys raise; defaults to True when a config file exists
      backend: file|sqlite  # storage backend; defaults to "file" (read-only)
      db_path: <path>       # SQLite DB path, relative to this config file's directory;
                            #   only used when `backend: sqlite` is set
      secrets:              # key_id -> plaintext secret (file backend only; see below)
        my-key-1: "plain-text-secret"
        my-key-2: "ffeeddccbbaa"   # kept as the exact string content, not decoded

    Args:
        config_file: Path to YAML/JSON config file
    """
    logger.info("Initializing mock KBM client connection")
    cfg = _load_config_file(config_file)
    config_present = bool(config_file) and os.path.isfile(os.path.abspath(config_file))
    base_dir = (
        os.path.dirname(os.path.abspath(config_file)) if config_file else os.getcwd()
    )
    client = _client_from_config(cfg, base_dir=base_dir, config_present=config_present)
    logger.info(f"Mock KBM client initialized with strict={client.strict}")
    return client


def kbm_close_client_connection(kmip_client) -> None:
    logger.info("Closing mock KBM client connection")
    return None


def kbm_get_secret(kmip_client, key_id: str, wrapping_key: bytes):
    """
    Return dict: {"wrapped_key": b64, "blob": b64, "iv": b64, "tag": b64}
    """
    logger.info(f"Mock KBM get_secret request for key_id: {key_id}")

    if not isinstance(kmip_client, _MockKBMClient):
        logger.error("Invalid client handle provided")
        raise ValueError("Invalid client handle")
    if not key_id:
        logger.error("key_id is required but not provided")
        raise ValueError("key_id required")
    if not wrapping_key:
        logger.error("wrapping_key is required but not provided")
        raise ValueError("wrapping_key (client RSA public key) is required")

    logger.debug("Loading RSA public key from wrapping_key")
    pub = _load_rsa_public_key(wrapping_key)
    secret = kmip_client.get_secret(key_id)

    logger.debug("Generating AES key and IV for secret wrapping")
    aes_key = _secrets.token_bytes(AES_KEY_LEN)
    iv = _secrets.token_bytes(IV_LEN)

    logger.debug("Encrypting secret with AES-GCM")
    blob, tag = _aes_gcm_encrypt(aes_key, iv, secret)

    logger.debug("Wrapping AES key with RSA public key")
    wrapped_key = pub.encrypt(
        aes_key,
        asympadding.OAEP(
            mgf=asympadding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    result = {
        "wrapped_key": _b64(wrapped_key),
        "blob": _b64(blob),
        "iv": _b64(iv),
        "tag": _b64(tag),
    }

    logger.info(f"Successfully wrapped secret for key_id: {key_id}")
    return result


__all__ = [
    # Public KBM plugin API
    "kbm_open_client_connection",
    "kbm_close_client_connection",
    "kbm_get_secret",
]
