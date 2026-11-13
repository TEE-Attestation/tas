#
# TEE Attestation Service - PostgreSQL Immutable Policy Publication Storage
#
# Copyright 2026 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# This file is part of the TEE Attestation Service.
#

from collections.abc import Sequence
from typing import Optional

import psycopg

from .policy_store import PolicyStoreUnavailable
from .postgres_policy_store import (
    DEFAULT_CONNECT_TIMEOUT_SECONDS,
    DEFAULT_STATEMENT_TIMEOUT_SECONDS,
    EXPECTED_SCHEMA_VERSION,
    _safe_driver_error,
)
from .publication_store import (
    PublicationKey,
    PublicationStore,
    validate_publication_key,
)
from .tas_logging import get_logger

logger = get_logger(__name__)

# A conflict on the full publication key is a no-op, preserving the first document.
_INSERT_SQL = """
    INSERT INTO tas_policy_publications
        (namespace, policy_id, publication_id, document)
    VALUES (%s, %s, %s, %s)
    ON CONFLICT (namespace, policy_id, publication_id) DO NOTHING
"""
_SELECT_SQL = """
    SELECT document FROM tas_policy_publications
    WHERE namespace = %s AND policy_id = %s AND publication_id = %s
"""
_SELECT_MANY_SQL = """
    SELECT requested.namespace, requested.policy_id,
           requested.publication_id, p.document
    FROM unnest(%s::text[], %s::text[], %s::text[])
         AS requested(namespace, policy_id, publication_id)
    JOIN tas_policy_publications AS p
      USING (namespace, policy_id, publication_id)
"""
_LIST_IDS_SQL = """
    SELECT publication_id FROM tas_policy_publications
    WHERE namespace = %s AND policy_id = %s
"""
_DELETE_SQL = """
    DELETE FROM tas_policy_publications
    WHERE namespace = %s AND policy_id = %s AND publication_id = %s
"""
_CHECK_TABLE_SQL = "SELECT 1 FROM tas_policy_publications LIMIT 0"
_CHECK_VERSION_SQL = "SELECT version FROM tas_schema_version"


class PostgresPublicationStore(PublicationStore):
    """Immutable publication storage using PostgreSQL.

    The composite key ``(namespace, policy_id, publication_id)`` identifies
    one immutable document. The etcd approval record selects a publication;
    this table stores versions but does not decide which one is active.
    """

    backend_name = "postgresql"

    def __init__(
        self,
        dsn: str,
        connect_timeout: int = DEFAULT_CONNECT_TIMEOUT_SECONDS,
        statement_timeout_seconds: int = DEFAULT_STATEMENT_TIMEOUT_SECONDS,
    ):
        self._dsn = dsn
        self._connect_timeout = int(connect_timeout)
        self._statement_timeout_ms = int(statement_timeout_seconds) * 1000

    def _connect(self):
        return psycopg.connect(
            self._dsn,
            connect_timeout=self._connect_timeout,
        )

    def _apply_statement_timeout(self, cursor) -> None:
        cursor.execute(f"SET LOCAL statement_timeout = {self._statement_timeout_ms}")

    def verify_schema(self) -> None:
        # Check both the shared schema version and this backend's table before
        # accepting traffic, so a partially or incompatibly migrated database
        # fails during startup rather than on the first policy operation.
        try:
            with self._connect() as conn, conn.transaction():
                with conn.cursor() as cur:
                    self._apply_statement_timeout(cur)
                    cur.execute(_CHECK_VERSION_SQL)
                    versions = cur.fetchall()
                    cur.execute(_CHECK_TABLE_SQL)
        except psycopg.Error as exc:
            safe_error = _safe_driver_error(exc)
            raise RuntimeError(
                "PostgreSQL publication schema is not initialized; apply "
                f"db/postgresql/schema_v1.sql: {safe_error}"
            ) from None
        if len(versions) != 1 or versions[0][0] != EXPECTED_SCHEMA_VERSION:
            found = [row[0] for row in versions]
            raise RuntimeError(
                "PostgreSQL publication storage requires schema version "
                f"{EXPECTED_SCHEMA_VERSION}; "
                f"found {found!r}"
            )

    def insert(
        self, namespace: str, policy_id: str, publication_id: str, document: str
    ) -> bool:
        validate_publication_key(namespace, policy_id, publication_id)
        try:
            with self._connect() as conn, conn.transaction():
                with conn.cursor() as cur:
                    self._apply_statement_timeout(cur)
                    # The composite-key conflict is a no-op, not an update:
                    # callers can safely retry and verify an existing row
                    # without changing a document already named by etcd.
                    cur.execute(
                        _INSERT_SQL,
                        (namespace, policy_id, publication_id, document),
                    )
                    return cur.rowcount > 0
        except psycopg.Error as exc:
            safe_error = _safe_driver_error(exc)
            logger.error(
                "PostgreSQL publication insert failed for '%s:%s': %s",
                namespace,
                policy_id,
                safe_error,
            )
            raise PolicyStoreUnavailable() from None

    def get(self, namespace: str, policy_id: str, publication_id: str) -> Optional[str]:
        validate_publication_key(namespace, policy_id, publication_id)
        try:
            with self._connect() as conn, conn.transaction():
                with conn.cursor() as cur:
                    self._apply_statement_timeout(cur)
                    cur.execute(_SELECT_SQL, (namespace, policy_id, publication_id))
                    row = cur.fetchone()
                    return row[0] if row is not None else None
        except psycopg.Error as exc:
            logger.error(
                "PostgreSQL publication read failed for '%s:%s': %s",
                namespace,
                policy_id,
                _safe_driver_error(exc),
            )
            raise PolicyStoreUnavailable() from None

    def get_many(self, keys: Sequence[PublicationKey]) -> dict[PublicationKey, str]:
        if not keys:
            return {}
        for namespace, policy_id, publication_id in keys:
            validate_publication_key(namespace, policy_id, publication_id)
        namespaces, policy_ids, publication_ids = map(list, zip(*keys))
        try:
            with self._connect() as conn, conn.transaction():
                with conn.cursor() as cur:
                    self._apply_statement_timeout(cur)
                    # Pass requested keys as parallel arrays and join them in
                    # one parameterised query. This avoids one query per
                    # publication while retaining each full key in the result.
                    cur.execute(
                        _SELECT_MANY_SQL,
                        (namespaces, policy_ids, publication_ids),
                    )
                    return {
                        (namespace, policy_id, publication_id): document
                        for namespace, policy_id, publication_id, document in cur
                    }
        except psycopg.Error as exc:
            logger.error(
                "PostgreSQL publication batch read failed: %s",
                _safe_driver_error(exc),
            )
            raise PolicyStoreUnavailable() from None

    def list_ids(self, namespace: str, policy_id: str) -> list[str]:
        validate_publication_key(namespace, policy_id, "unused")
        try:
            with self._connect() as conn, conn.transaction():
                with conn.cursor() as cur:
                    self._apply_statement_timeout(cur)
                    cur.execute(_LIST_IDS_SQL, (namespace, policy_id))
                    return [row[0] for row in cur]
        except psycopg.Error as exc:
            logger.error(
                "PostgreSQL publication list failed for '%s:%s': %s",
                namespace,
                policy_id,
                _safe_driver_error(exc),
            )
            raise PolicyStoreUnavailable() from None

    def delete(self, namespace: str, policy_id: str, publication_id: str) -> bool:
        validate_publication_key(namespace, policy_id, publication_id)
        try:
            with self._connect() as conn, conn.transaction():
                with conn.cursor() as cur:
                    self._apply_statement_timeout(cur)
                    cur.execute(_DELETE_SQL, (namespace, policy_id, publication_id))
                    # rowcount is zero when already absent, making cleanup
                    # safely repeatable after an interrupted delete.
                    return cur.rowcount > 0
        except psycopg.Error as exc:
            logger.error(
                "PostgreSQL publication delete failed for '%s:%s': %s",
                namespace,
                policy_id,
                _safe_driver_error(exc),
            )
            raise PolicyStoreUnavailable() from None

    def is_reachable(self) -> bool:
        try:
            with self._connect() as conn, conn.transaction():
                with conn.cursor() as cur:
                    self._apply_statement_timeout(cur)
                    cur.execute("SELECT 1")
                    return cur.fetchone() == (1,)
        except psycopg.Error as exc:
            logger.warning(
                "PostgreSQL publication store reachability check failed: %s",
                _safe_driver_error(exc),
            )
            return False
