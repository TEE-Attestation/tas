#
# TEE Attestation Service - Tests for Policy Publication Stores
#
# Copyright 2026 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# This file is part of the TEE Attestation Service.
#
# Tests for tas/redis_publication_store.py, using a fake Redis client.
#

from tas.redis_publication_store import RedisPublicationStore


class FakeRedisPipeline:
    def __init__(self, client):
        self._client = client
        self._commands = []

    def hget(self, key, field):
        self._commands.append((key, field))
        return self

    def execute(self):
        return [
            self._client.hashes.get(key, {}).get(field) for key, field in self._commands
        ]


class FakeRedis:
    def __init__(self):
        self.hashes = {}

    def hsetnx(self, key, field, value):
        values = self.hashes.setdefault(key, {})
        if field in values:
            return 0
        values[field] = value
        return 1

    def hget(self, key, field):
        return self.hashes.get(key, {}).get(field)

    def hkeys(self, key):
        return list(self.hashes.get(key, {}))

    def hdel(self, key, field):
        return int(self.hashes.get(key, {}).pop(field, None) is not None)

    def pipeline(self):
        return FakeRedisPipeline(self)

    def ping(self):
        return True


def test_redis_publication_store_uses_immutable_hash_fields_and_batches_reads():
    redis = FakeRedis()
    store = RedisPublicationStore(redis)
    first = ("policy", "policy-1", "pub-1")
    second = ("policy", "policy-1", "pub-2")

    assert store.insert(*first, "document one")
    assert not store.insert(*first, "changed document")
    assert store.insert(*second, "document two")
    assert store.get(*first) == "document one"
    assert store.get_many([first, second]) == {
        first: "document one",
        second: "document two",
    }
    assert store.list_ids("policy", "policy-1") == ["pub-1", "pub-2"]
    assert store.delete(*first)
    assert not store.delete(*first)
    assert store.is_reachable()
