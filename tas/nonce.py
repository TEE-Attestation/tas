#
# TEE Attestation Service - Nonce helpers
#
# Copyright 2026 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# This file is part of the TEE Attestation Service.
# See LICENSE file for details.
#

from .tas_logging import get_logger

logger = get_logger(__name__)


MINIMUM_REDIS_VERSION = (6, 2)


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
    """Store a nonce in Redis with a TTL.  The value is a sentinel; only
    presence/absence matters."""
    logger.debug(f"Storing nonce with expiration: {expiration_seconds}s")
    redis_client.setex(nonce, expiration_seconds, "1")
    logger.debug("Nonce stored successfully")


def validate_nonce(redis_client, nonce):
    """Atomically consume a nonce.  Returns ``(True, None)`` on success or
    ``(False, error_message)`` if the nonce is missing / expired.

    Uses ``GETDEL`` (Redis 6.2+) so the read-and-delete is a single
    round-trip with no race window for concurrent replay.
    """
    logger.debug(f"Validating nonce: {nonce[:8]}...")
    result = redis_client.getdel(nonce)
    if not result:
        logger.warning("Nonce validation failed: Invalid or expired nonce")
        return False, "Invalid or expired nonce"

    logger.debug("Nonce validation successful (consumed atomically)")
    return True, None
