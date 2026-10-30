#
# TEE Attestation Service - PostgreSQL Policy Storage Adapter
#
# Copyright 2026 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# This file is part of the TEE Attestation Service.
#
# This module implements the PostgreSQL policy storage backend using `psycopg` 3
# directly. It opens one connection per operation and closes it on completion
# so database sessions are never held across external attestation or KBM calls.
#

from collections.abc import Generator
from typing import Optional

import psycopg
from psycopg.conninfo import conninfo_to_dict

from .policy_store import (
    PolicyAlreadyExists,
    PolicyStore,
    PolicyStoreUnavailable,
    validate_policy_namespace,
)
from .tas_logging import get_logger

logger = get_logger(__name__)

EXPECTED_SCHEMA_VERSION = 1
DEFAULT_CONNECT_TIMEOUT_SECONDS = 5
DEFAULT_STATEMENT_TIMEOUT_SECONDS = 5

_INSERT_SQL = (
    "INSERT INTO tas_policies (namespace, policy_id, document) VALUES (%s, %s, %s)"
)
_SELECT_ONE_SQL = (
    "SELECT document FROM tas_policies WHERE namespace = %s AND policy_id = %s"
)
_SELECT_NAMESPACE_SQL = (
    "SELECT document FROM tas_policies WHERE namespace = %s ORDER BY policy_id"
)
_DELETE_SQL = "DELETE FROM tas_policies WHERE namespace = %s AND policy_id = %s"

_CHECK_VERSION_SQL = "SELECT version FROM tas_schema_version"
_CHECK_POLICIES_TABLE_SQL = "SELECT 1 FROM tas_policies LIMIT 0"


def _safe_driver_error(exc: BaseException) -> str:
    """Describe a driver error by type and SQLSTATE, omitting its message text."""
    error_type = type(exc).__name__
    sqlstate = getattr(exc, "sqlstate", None) or getattr(exc, "pgcode", None)
    if sqlstate:
        return f"{error_type} (SQLSTATE {sqlstate})"
    return error_type


def _is_pk_unique_violation(exc: psycopg.errors.UniqueViolation) -> bool:
    """Return True if UniqueViolation targets the `tas_policies` primary key."""
    diag = getattr(exc, "diag", None)
    constraint_name = getattr(diag, "constraint_name", None)
    return constraint_name in (None, "tas_policies_pkey")


def _split_libpq_options(options: str) -> list[str]:
    arguments = []
    argument = []
    escaped = False

    for char in options:
        if escaped:
            if char.isspace() or char == "\\":
                argument.append(char)
            else:
                argument.extend(("\\", char))
            escaped = False
        elif char == "\\":
            escaped = True
        elif char.isspace():
            if argument:
                arguments.append("".join(argument))
                argument = []
        else:
            argument.append(char)

    if escaped:
        argument.append("\\")
    if argument:
        arguments.append("".join(argument))
    return arguments


class PostgresPolicyStore(PolicyStore):
    """PolicyStore backed by PostgreSQL using one connection per operation."""

    backend_name = "postgresql"

    def __init__(
        self,
        dsn: str,
        connect_timeout: int = DEFAULT_CONNECT_TIMEOUT_SECONDS,
        statement_timeout_seconds: int = DEFAULT_STATEMENT_TIMEOUT_SECONDS,
    ):
        if not dsn or not isinstance(dsn, str) or not dsn.strip():
            raise ValueError(
                "TAS_POSTGRES_DSN is required when TAS_POLICY_BACKEND=postgresql"
            )
        self._dsn = dsn.strip()
        self._connect_timeout = int(connect_timeout)
        self._statement_timeout_ms = int(statement_timeout_seconds) * 1000
        self._dsn_parameters = self._parse_dsn_parameters()
        self._dsn_statement_timeout = self._dsn_sets_statement_timeout()

    def _parse_dsn_parameters(self) -> dict[str, str]:
        try:
            return conninfo_to_dict(self._dsn)
        except psycopg.Error:
            # Let psycopg.connect report malformed DSNs through the normal
            # policy-store error handling path.
            return {}

    def _dsn_sets_statement_timeout(self) -> bool:
        options = _split_libpq_options(self._dsn_parameters.get("options", ""))
        for index, option in enumerate(options):
            setting = None
            if option == "-c" and index + 1 < len(options):
                setting = options[index + 1]
            elif option.startswith("--"):
                setting = option[2:]
            elif option.startswith("-c"):
                setting = option[2:]
            if setting and "=" in setting:
                name = setting.split("=", 1)[0].lower().replace("-", "_")
                if name == "statement_timeout":
                    return True
        return False

    def _connect(self):
        connect_options = {}
        if "connect_timeout" not in self._dsn_parameters:
            connect_options["connect_timeout"] = self._connect_timeout
        return psycopg.connect(
            self._dsn,
            **connect_options,
        )

    def _apply_statement_timeout(self, cur) -> None:
        if not self._dsn_statement_timeout:
            cur.execute(f"SET LOCAL statement_timeout = {self._statement_timeout_ms}")

    def verify_schema(self) -> None:
        """Verify at startup that the PostgreSQL schema is initialized at v1.

        Raises:
            RuntimeError: If the database is unreachable, required tables are
                missing, or ``tas_schema_version`` does not match
                ``EXPECTED_SCHEMA_VERSION``.
        """
        try:
            with self._connect() as conn, conn.transaction():
                with conn.cursor() as cur:
                    self._apply_statement_timeout(cur)
                    cur.execute(_CHECK_VERSION_SQL)
                    rows = cur.fetchall()
                    cur.execute(_CHECK_POLICIES_TABLE_SQL)
        except psycopg.errors.UndefinedTable:
            raise RuntimeError(
                "PostgreSQL policy schema is not initialized (missing "
                "tas_schema_version or tas_policies table). Apply "
                "db/postgresql/schema_v1.sql with 'psql -f "
                "db/postgresql/schema_v1.sql' before starting TAS."
            ) from None
        except psycopg.Error as e:
            safe_err = _safe_driver_error(e)
            raise RuntimeError(
                f"Failed to verify PostgreSQL policy schema at startup: {safe_err}"
            ) from None

        if len(rows) != 1 or rows[0][0] != EXPECTED_SCHEMA_VERSION:
            found = [r[0] for r in rows]
            raise RuntimeError(
                f"Unsupported PostgreSQL policy schema version {found!r}; "
                f"expected version {EXPECTED_SCHEMA_VERSION}."
            )

    def create(self, namespace: str, policy_id: str, document: str) -> None:
        validate_policy_namespace(namespace)
        try:
            with self._connect() as conn, conn.transaction():
                with conn.cursor() as cur:
                    self._apply_statement_timeout(cur)
                    cur.execute(_INSERT_SQL, (namespace, policy_id, document))
        except psycopg.errors.UniqueViolation as e:
            if _is_pk_unique_violation(e):
                raise PolicyAlreadyExists(namespace, policy_id) from None
            safe_err = _safe_driver_error(e)
            logger.error(
                f"PostgreSQL integrity error creating '{namespace}:{policy_id}': "
                f"{safe_err}"
            )
            raise PolicyStoreUnavailable() from None
        except psycopg.Error as e:
            safe_err = _safe_driver_error(e)
            logger.error(
                f"PostgreSQL policy store create failed for '{namespace}:{policy_id}': "
                f"{safe_err}"
            )
            raise PolicyStoreUnavailable() from None

    def get(self, namespace: str, policy_id: str) -> Optional[str]:
        validate_policy_namespace(namespace)
        try:
            with self._connect() as conn, conn.transaction():
                with conn.cursor() as cur:
                    self._apply_statement_timeout(cur)
                    cur.execute(_SELECT_ONE_SQL, (namespace, policy_id))
                    row = cur.fetchone()
                    return row[0] if row is not None else None
        except psycopg.Error as e:
            safe_err = _safe_driver_error(e)
            logger.error(
                f"PostgreSQL policy store get failed for '{namespace}:{policy_id}': "
                f"{safe_err}"
            )
            raise PolicyStoreUnavailable() from None

    def list(self, namespace: str) -> Generator[str, None, None]:
        validate_policy_namespace(namespace)
        try:
            with self._connect() as conn, conn.transaction():
                with conn.cursor() as cur:
                    self._apply_statement_timeout(cur)
                # A named cursor avoids buffering the result set in libpq.
                with conn.cursor(name="tas_policy_list") as cur:
                    cur.itersize = 1
                    cur.execute(_SELECT_NAMESPACE_SQL, (namespace,))
                    for row in cur:
                        yield row[0]
        except psycopg.Error as e:
            safe_err = _safe_driver_error(e)
            logger.error(
                f"PostgreSQL policy store list failed for namespace '{namespace}': "
                f"{safe_err}"
            )
            raise PolicyStoreUnavailable() from None

    def delete(self, namespace: str, policy_id: str) -> bool:
        validate_policy_namespace(namespace)
        try:
            with self._connect() as conn, conn.transaction():
                with conn.cursor() as cur:
                    self._apply_statement_timeout(cur)
                    cur.execute(_DELETE_SQL, (namespace, policy_id))
                    return bool(cur.rowcount and cur.rowcount > 0)
        except psycopg.Error as e:
            safe_err = _safe_driver_error(e)
            logger.error(
                f"PostgreSQL policy store delete failed for '{namespace}:{policy_id}': "
                f"{safe_err}"
            )
            raise PolicyStoreUnavailable() from None

    def is_reachable(self) -> bool:
        try:
            with self._connect() as conn, conn.transaction():
                with conn.cursor() as cur:
                    self._apply_statement_timeout(cur)
                    cur.execute("SELECT 1")
                    row = cur.fetchone()
                    return bool(row and row[0] == 1)
        except Exception as e:
            safe_err = _safe_driver_error(e)
            logger.warning(
                f"PostgreSQL policy store reachability check failed: {safe_err}"
            )
            return False
