#
# TEE Attestation Service - Policy Storage Contract and Redis Adapter
#
# Copyright 2026 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# This file is part of the TEE Attestation Service.
#
# This module defines the backend-neutral policy storage interface, shared
# exception types, and the Redis policy store implementation.
#

from abc import ABC, abstractmethod
from collections.abc import Generator
from dataclasses import dataclass
from typing import Optional, Sequence

from .tas_logging import get_logger

logger = get_logger(__name__)

POLICY_NAMESPACE = "policy"
CERTIFY_POLICY_NAMESPACE = "certify-policy"
DOMAIN_POLICY_NAMESPACE = "domain-policy"

VALID_POLICY_NAMESPACES = frozenset(
    {
        POLICY_NAMESPACE,
        CERTIFY_POLICY_NAMESPACE,
        DOMAIN_POLICY_NAMESPACE,
    }
)


class PolicyStoreError(RuntimeError):
    """Base exception for policy storage operations.

    Intentionally subclasses RuntimeError rather than ValueError so that
    storage errors are never caught by attestation verification handlers that
    treat ValueError as a policy validation failure.
    """


class PolicyAlreadyExists(PolicyStoreError):
    """Raised when attempting to create a policy that already exists."""

    def __init__(self, namespace: str, policy_id: str):
        self.namespace = namespace
        self.policy_id = policy_id
        super().__init__(f"Policy '{namespace}:{policy_id}' already exists")


class PolicyStoreUnavailable(PolicyStoreError):
    """Raised when the configured policy store is unreachable or fails."""

    public_message = "Policy store is unavailable"

    def __init__(
        self, message: Optional[str] = None, *, reason_code: str = "store_unavailable"
    ):
        self.reason_code = reason_code
        super().__init__(message or self.public_message)


class PolicyAuthorizationDenied(PolicyStoreError):
    """Raised when an approval changed before the final authorization check."""


@dataclass(frozen=True)
class PolicyApproval:
    namespace: str
    policy_id: str
    revision: int


@dataclass(frozen=True)
class ApprovedPolicy:
    document: str
    approval: Optional[PolicyApproval] = None


def validate_policy_namespace(namespace: str) -> None:
    """Ensure `namespace` is one of the supported policy namespaces."""
    if namespace not in VALID_POLICY_NAMESPACES:
        raise ValueError(f"Unsupported policy namespace: {namespace!r}")


class PolicyStore(ABC):
    """Abstract interface for TAS policy storage backends."""

    backend_name: str = ""

    @abstractmethod
    def create(self, namespace: str, policy_id: str, document: str) -> None:
        """Atomically store a new serialized policy document.

        Raises:
            PolicyAlreadyExists: If a policy with the same `namespace` and ID exists.
            PolicyStoreUnavailable: If the storage backend fails or cannot be reached.
        """

    @abstractmethod
    def get(self, namespace: str, policy_id: str) -> Optional[str]:
        """Retrieve a serialized policy document, or None if not found.

        Raises:
            PolicyStoreUnavailable: If the storage backend fails or cannot be reached.
        """

    @abstractmethod
    def list(self, namespace: str) -> Generator[str, None, None]:
        """Yield serialized policy documents without retaining the full collection.

        Consume or close the generator to release backend resources. Validation
        and storage errors may be raised during iteration.

        Raises:
            PolicyStoreUnavailable: If the storage backend fails or cannot be reached.
        """

    @abstractmethod
    def delete(self, namespace: str, policy_id: str) -> bool:
        """Delete a policy and return True if it existed, False otherwise.

        Raises:
            PolicyStoreUnavailable: If the storage backend fails or cannot be reached.
        """

    @abstractmethod
    def is_reachable(self) -> bool:
        """Return True if the policy store responds to a live connectivity check."""

    def load_approved(self, namespace: str, policy_id: str) -> ApprovedPolicy | None:
        """Load a policy and its approval revision when the backend has one."""
        document = self.get(namespace, policy_id)
        if document is None:
            return None
        return ApprovedPolicy(document)

    def check_approvals(self, approvals: Sequence[PolicyApproval]) -> None:
        """Check approval revisions immediately before a protected operation."""


class RedisPolicyStore(PolicyStore):
    """PolicyStore backed by Redis using ``<namespace>:<policy_id>`` keys."""

    backend_name = "redis"

    def __init__(self, redis_client):
        self._redis = redis_client

    @staticmethod
    def _make_key(namespace: str, policy_id: str) -> str:
        validate_policy_namespace(namespace)
        return f"{namespace}:{policy_id}"

    def create(self, namespace: str, policy_id: str, document: str) -> None:
        key = self._make_key(namespace, policy_id)
        try:
            created = self._redis.set(key, document, nx=True)
        except Exception as e:
            logger.error(f"Redis policy store create failed for '{key}': {e}")
            raise PolicyStoreUnavailable() from e

        if not created:
            raise PolicyAlreadyExists(namespace, policy_id)

    def get(self, namespace: str, policy_id: str) -> Optional[str]:
        key = self._make_key(namespace, policy_id)
        try:
            raw = self._redis.get(key)
        except Exception as e:
            logger.error(f"Redis policy store get failed for '{key}': {e}")
            raise PolicyStoreUnavailable() from e

        if raw is None:
            return None
        if isinstance(raw, bytes):
            return raw.decode("utf-8")
        return raw

    def list(self, namespace: str) -> Generator[str, None, None]:
        validate_policy_namespace(namespace)
        pattern = f"{namespace}:*"
        try:
            if hasattr(self._redis, "scan_iter"):
                raw_keys = self._redis.scan_iter(match=pattern, count=100)
            else:
                raw_keys = self._redis.keys(pattern)

            seen_keys: set[str] = set()
            for key in raw_keys:
                normalized_key = (
                    key.decode("utf-8") if isinstance(key, bytes) else str(key)
                )
                if normalized_key in seen_keys:
                    continue
                seen_keys.add(normalized_key)

                raw = self._redis.get(key)
                if raw is None:
                    continue
                if isinstance(raw, bytes):
                    raw = raw.decode("utf-8")
                yield raw
        except Exception as e:
            logger.error(
                f"Redis policy store list failed for namespace '{namespace}': {e}"
            )
            raise PolicyStoreUnavailable() from e

    def delete(self, namespace: str, policy_id: str) -> bool:
        key = self._make_key(namespace, policy_id)
        try:
            deleted = self._redis.delete(key)
        except Exception as e:
            logger.error(f"Redis policy store delete failed for '{key}': {e}")
            raise PolicyStoreUnavailable() from e

        return bool(deleted and deleted > 0)

    def is_reachable(self) -> bool:
        try:
            return bool(self._redis.ping())
        except Exception as e:
            logger.warning(f"Redis policy store reachability check failed: {e}")
            return False


def init_policy_store(app, redis_client) -> PolicyStore:
    """Initialize the policy store selected by `TAS_POLICY_BACKEND` on `app`.

    In Redis mode, only `RedisPolicyStore` is constructed and the PostgreSQL
    adapter module is never imported. In PostgreSQL mode, `PostgresPolicyStore`
    is imported lazily, its schema version is verified at startup, and Redis is
    never used for policy operations.
    """
    backend = app.config.get("TAS_POLICY_BACKEND", "redis")
    authorization_mode = app.config.get("TAS_POLICY_AUTHORIZATION", "none")
    if authorization_mode not in ("none", "etcd"):
        raise RuntimeError("TAS_POLICY_AUTHORIZATION must be 'none' or 'etcd'")
    if backend == "redis":
        policy_store: PolicyStore = RedisPolicyStore(redis_client)
    elif backend == "postgresql":
        dsn = app.config.get("TAS_POSTGRES_DSN", "")
        if not isinstance(dsn, str) or not dsn.strip():
            raise RuntimeError(
                "TAS_POSTGRES_DSN is required when TAS_POLICY_BACKEND='postgresql'"
            )
        from .postgres_policy_store import (
            DEFAULT_CONNECT_TIMEOUT_SECONDS,
            DEFAULT_STATEMENT_TIMEOUT_SECONDS,
            PostgresPolicyStore,
        )

        policy_store = PostgresPolicyStore(
            dsn,
            connect_timeout=app.config.get(
                "TAS_POSTGRES_CONNECT_TIMEOUT_SECONDS",
                DEFAULT_CONNECT_TIMEOUT_SECONDS,
            ),
            statement_timeout_seconds=app.config.get(
                "TAS_POSTGRES_STATEMENT_TIMEOUT_SECONDS",
                DEFAULT_STATEMENT_TIMEOUT_SECONDS,
            ),
        )
        policy_store.verify_schema()
    else:
        raise RuntimeError(
            f"Unsupported TAS_POLICY_BACKEND={backend!r}; expected 'redis' or 'postgresql'"
        )

    if authorization_mode == "etcd":
        from .etcd_client import EtcdClient
        from .etcd_protected_policy_store import EtcdProtectedPolicyStore

        etcd = EtcdClient(
            app.config["TAS_ETCD_ENDPOINTS"],
            ca_file=app.config["TAS_ETCD_CA_FILE"],
            username=app.config["TAS_ETCD_USERNAME"],
            password=app.config["TAS_ETCD_PASSWORD"],
            timeout_seconds=app.config.get("TAS_ETCD_TIMEOUT_SECONDS", 5),
            cert_file=app.config.get("TAS_ETCD_CERT_FILE") or None,
            key_file=app.config.get("TAS_ETCD_KEY_FILE") or None,
        )
        if backend == "redis":
            from .redis_publication_store import RedisPublicationStore

            publications = RedisPublicationStore(redis_client)
        else:
            from .postgres_publication_store import PostgresPublicationStore

            publications = PostgresPublicationStore(
                app.config["TAS_POSTGRES_DSN"],
                connect_timeout=app.config.get(
                    "TAS_POSTGRES_CONNECT_TIMEOUT_SECONDS",
                    5,
                ),
                statement_timeout_seconds=app.config.get(
                    "TAS_POSTGRES_STATEMENT_TIMEOUT_SECONDS",
                    5,
                ),
            )
            publications.verify_schema()
        policy_store = EtcdProtectedPolicyStore(
            etcd,
            publications,
            unprotected_policy_store=policy_store,
            operation_timeout_seconds=app.config.get(
                "TAS_POLICY_OPERATION_TIMEOUT_SECONDS", 20
            ),
        )
        logger.info(
            "Policy rollback protection enabled with etcd; document backend: %s",
            backend,
        )
    else:
        logger.info("Policy storage backend initialized: %s", backend)

    app.config["TAS_POLICY_AUTHORIZATION"] = authorization_mode
    app.extensions["policy_store"] = policy_store
    return policy_store
