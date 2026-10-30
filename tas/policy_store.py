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
from typing import Optional

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

    def __init__(self, message: Optional[str] = None):
        super().__init__(message or self.public_message)


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
    if backend == "redis":
        policy_store: PolicyStore = RedisPolicyStore(redis_client)
        app.extensions["policy_store"] = policy_store
        logger.info("Policy storage backend initialized: redis")
        return policy_store

    if backend == "postgresql":
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
        app.extensions["policy_store"] = policy_store
        logger.info("Policy storage backend initialized: postgresql")
        return policy_store

    raise RuntimeError(
        f"Unsupported TAS_POLICY_BACKEND={backend!r}; expected 'redis' or 'postgresql'"
    )
