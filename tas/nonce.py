#
# TEE Attestation Service - Nonce helpers
#
# Copyright 2026 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# This file is part of the TEE Attestation Service.
#
# This module provides helpers for storing and atomically validating nonces.
#

import re

from .tas_logging import get_logger

logger = get_logger(__name__)


MINIMUM_REDIS_VERSION = (6, 2)
NONCE_KEY_PREFIX = "nonce:"
NONCE_PATTERN = re.compile(r"[0-9a-f]{64}")


def _valid_nonce_format(nonce):
    """Return True iff ``nonce`` is a canonical 64-char lowercase hex string."""
    return isinstance(nonce, str) and NONCE_PATTERN.fullmatch(nonce) is not None


def _nonce_key(nonce):
    """Derive the namespaced Redis key for a canonical nonce."""
    return f"{NONCE_KEY_PREFIX}{nonce}"


def check_redis_version(redis_client):
    """Verify the Redis server is 6.2+ (required for GETDEL).

    Returns the version string on success.
    Raises ``RuntimeError`` if the server is too old.
    """
    version_str = redis_client.info("server").get("redis_version", "0.0.0")
    version = tuple(int(x) for x in version_str.split(".")[:2])
    if version < MINIMUM_REDIS_VERSION:
        raise RuntimeError(
            f"TAS requires Redis 6.2 or later (detected {version_str}). "
            "Atomic nonce validation depends on the GETDEL command "
            "introduced in Redis 6.2."
        )
    logger.info(f"Redis server version: {version_str}")
    return version_str


def store_nonce(redis_client, nonce, expiration_seconds):
    """Store a canonical 64-character hex nonce in Redis under the ``nonce:``
    namespace with a TTL.

    Redis requires every key to have a value, even when the nonce itself is
    part of the key name (``nonce:<nonce>``). We store ``"1"`` as a placeholder
    value to mark the nonce as active until it is consumed or expires.
    """
    if not _valid_nonce_format(nonce):
        logger.error("Cannot store a malformed nonce")
        raise ValueError("Nonce must be 64 lowercase hexadecimal characters")
    if (
        not isinstance(expiration_seconds, int)
        or isinstance(expiration_seconds, bool)
        or expiration_seconds <= 0
    ):
        logger.error("Nonce expiration must be a positive integer")
        raise ValueError("Nonce expiration must be a positive integer")
    logger.debug(f"Storing nonce {nonce} with expiration: {expiration_seconds}s")
    stored = redis_client.set(
        _nonce_key(nonce),
        "1",
        ex=expiration_seconds,
        nx=True,
    )
    if not stored:
        logger.error(f"Failed to store nonce {nonce}: key already exists")
        raise RuntimeError("Failed to store nonce: key already exists")
    logger.info(
        f"Nonce stored successfully: {nonce} (expiration: {expiration_seconds}s)"
    )


def validate_nonce(redis_client, nonce):
    """Atomically consume a nonce.  Returns ``(True, None)`` on success or
    ``(False, error_message)`` if the nonce is malformed, missing, or expired.

    Uses ``GETDEL`` (Redis 6.2+) on the ``nonce:`` keyspace so the
    read-and-delete is a single round-trip with no race window for concurrent
    replay and cannot target non-nonce Redis keys.
    """
    if not _valid_nonce_format(nonce):
        logger.warning("Nonce validation failed: Malformed nonce")
        return False, "Invalid or expired nonce"

    logger.info(f"Validating nonce: {nonce}")
    result = redis_client.getdel(_nonce_key(nonce))
    if result not in ("1", b"1"):
        logger.warning(
            f"Nonce validation failed for nonce {nonce}: Invalid or expired nonce"
        )
        return False, "Invalid or expired nonce"

    logger.info(f"Nonce validation successful (consumed atomically): {nonce}")
    return True, None
