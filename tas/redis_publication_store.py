#
# TEE Attestation Service - Redis Immutable Policy Publication Storage
#
# Copyright 2026 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# This file is part of the TEE Attestation Service.
#

from collections.abc import Sequence
from typing import Optional

from .policy_store import PolicyStoreUnavailable
from .publication_store import (
    PublicationKey,
    PublicationStore,
    validate_publication_key,
)
from .tas_logging import get_logger

logger = get_logger(__name__)


class RedisPublicationStore(PublicationStore):
    """Immutable publication storage using Redis hashes.

    Each policy has one hash (``tas-pub:<namespace>:<policy_id>``); each
    publication ID is a field whose value is the complete policy document.
    etcd, not this class, decides which publication is authorised. Keeping
    versions under distinct fields lets an etcd approval point to an exact
    immutable document while an update creates a new publication.
    """

    backend_name = "redis"

    def __init__(self, redis_client):
        self._redis = redis_client

    @staticmethod
    def _make_key(namespace: str, policy_id: str) -> str:
        validate_publication_key(namespace, policy_id, "unused")
        # Keep each policy's versions in one hash, keyed by publication ID.
        return f"tas-pub:{namespace}:{policy_id}"

    @staticmethod
    def _decode(value):
        if isinstance(value, bytes):
            return value.decode("utf-8")
        return value

    def insert(
        self, namespace: str, policy_id: str, publication_id: str, document: str
    ) -> bool:
        validate_publication_key(namespace, policy_id, publication_id)
        key = self._make_key(namespace, policy_id)
        try:
            # HSETNX is atomic and write-once: False means this ID already
            # exists, so the caller can read it back and verify a retry rather
            # than overwrite a document that an approval may already name.
            return bool(self._redis.hsetnx(key, publication_id, document))
        except Exception as exc:
            logger.error(
                "Redis publication insert failed for '%s:%s': %s",
                namespace,
                policy_id,
                type(exc).__name__,
            )
            raise PolicyStoreUnavailable() from exc

    def get(self, namespace: str, policy_id: str, publication_id: str) -> Optional[str]:
        validate_publication_key(namespace, policy_id, publication_id)
        key = self._make_key(namespace, policy_id)
        try:
            raw = self._redis.hget(key, publication_id)
        except Exception as exc:
            logger.error(
                "Redis publication read failed for '%s:%s': %s",
                namespace,
                policy_id,
                type(exc).__name__,
            )
            raise PolicyStoreUnavailable() from exc
        return self._decode(raw) if raw is not None else None

    def get_many(self, keys: Sequence[PublicationKey]) -> dict[PublicationKey, str]:
        if not keys:
            return {}
        redis_keys = []
        for namespace, policy_id, publication_id in keys:
            validate_publication_key(namespace, policy_id, publication_id)
            redis_keys.append((self._make_key(namespace, policy_id), publication_id))
        try:
            # Pipeline the individual hash lookups into one Redis round trip;
            # execute() returns values in request order, keeping them aligned
            # with keys when the result mapping is built below.
            pipeline = self._redis.pipeline()
            for redis_key, publication_id in redis_keys:
                pipeline.hget(redis_key, publication_id)
            values = pipeline.execute()
        except Exception as exc:
            logger.error("Redis publication batch read failed: %s", type(exc).__name__)
            raise PolicyStoreUnavailable() from exc

        return {
            key: self._decode(value)
            for key, value in zip(keys, values)
            if value is not None
        }

    def list_ids(self, namespace: str, policy_id: str) -> list[str]:
        validate_publication_key(namespace, policy_id, "unused")
        key = self._make_key(namespace, policy_id)
        try:
            return [self._decode(value) for value in self._redis.hkeys(key)]
        except Exception as exc:
            logger.error(
                "Redis publication list failed for '%s:%s': %s",
                namespace,
                policy_id,
                type(exc).__name__,
            )
            raise PolicyStoreUnavailable() from exc

    def delete(self, namespace: str, policy_id: str, publication_id: str) -> bool:
        validate_publication_key(namespace, policy_id, publication_id)
        key = self._make_key(namespace, policy_id)
        try:
            # Remove only this version's field; other immutable publications
            # for the same policy remain available for cleanup or recovery.
            return bool(self._redis.hdel(key, publication_id))
        except Exception as exc:
            logger.error(
                "Redis publication delete failed for '%s:%s': %s",
                namespace,
                policy_id,
                type(exc).__name__,
            )
            raise PolicyStoreUnavailable() from exc

    def is_reachable(self) -> bool:
        try:
            return bool(self._redis.ping())
        except Exception as exc:
            # Reachability is a status probe, so report false here; actual
            # read/write methods raise PolicyStoreUnavailable to callers.
            logger.warning(
                "Redis publication store reachability check failed: %s",
                type(exc).__name__,
            )
            return False
