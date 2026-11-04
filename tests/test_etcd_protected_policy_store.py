#
# TEE Attestation Service - Tests for the etcd-Protected Policy Store
#
# Copyright 2026 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# This file is part of the TEE Attestation Service.
#
# Tests for policy approval, rollback detection and repair in
# tas/etcd_protected_policy_store.py, using an in-memory etcd.
#

import json
import threading

import pytest

from tas.etcd_client import EtcdKV
from tas.etcd_protected_policy_store import (
    POLICY_AUTH_FORMAT,
    POLICY_AUTH_FORMAT_KEY,
    EtcdProtectedPolicyStore,
)
from tas.policy_store import (
    PolicyAlreadyExists,
    PolicyAuthorizationDenied,
    PolicyStore,
    PolicyStoreUnavailable,
)
from tas.publication_store import PublicationStore


class MemoryEtcd:
    def __init__(self):
        self.values = {}
        self.revision = 1
        self.lock = threading.Lock()
        self.before_delete = None

    def get(self, key):
        with self.lock:
            return self.values.get(key)

    def range_prefix(self, prefix):
        with self.lock:
            return [
                value
                for key, value in sorted(self.values.items())
                if key.startswith(prefix)
            ]

    def put_if_absent(self, key, value):
        with self.lock:
            if key in self.values:
                return False, None
            self.revision += 1
            self.values[key] = EtcdKV(key, value, self.revision, self.revision, 1)
            return True, self.revision

    def put_if_revision(self, key, revision, value):
        with self.lock:
            current = self.values.get(key)
            if current is None or current.mod_revision != revision:
                return False, None
            self.revision += 1
            self.values[key] = EtcdKV(
                key, value, current.create_revision, self.revision, current.version + 1
            )
            return True, self.revision

    def delete_if_revision(self, key, revision):
        hook = self.before_delete
        if hook is not None:
            self.before_delete = None
            hook()
        with self.lock:
            current = self.values.get(key)
            if current is None or current.mod_revision != revision:
                return False
            self.revision += 1
            del self.values[key]
            return True

    def check_revisions(self, revisions):
        with self.lock:
            return all(
                self.values.get(key) is not None
                and self.values[key].mod_revision == revision
                for key, revision in revisions
            )


class MemoryPublicationStore(PublicationStore):
    def __init__(self):
        self.documents = {}
        self.before_insert = None
        self.reachable = True

    def insert(self, namespace, policy_id, publication_id, document):
        if self.before_insert:
            hook = self.before_insert
            self.before_insert = None
            hook()
        key = (namespace, policy_id, publication_id)
        if key in self.documents:
            return False
        self.documents[key] = document
        return True

    def get(self, namespace, policy_id, publication_id):
        return self.documents.get((namespace, policy_id, publication_id))

    def get_many(self, keys):
        return {key: self.documents[key] for key in keys if key in self.documents}

    def list_ids(self, namespace, policy_id):
        return [
            publication_id
            for ns, pid, publication_id in self.documents
            if ns == namespace and pid == policy_id
        ]

    def delete(self, namespace, policy_id, publication_id):
        return (
            self.documents.pop((namespace, policy_id, publication_id), None) is not None
        )

    def is_reachable(self):
        return self.reachable


class MemoryUnprotectedPolicyStore(PolicyStore):
    backend_name = "memory"

    def __init__(self):
        self.documents = {}
        self.reachable = True

    def create(self, namespace, policy_id, document):
        key = (namespace, policy_id)
        if key in self.documents:
            raise PolicyAlreadyExists(namespace, policy_id)
        self.documents[key] = document

    def get(self, namespace, policy_id):
        return self.documents.get((namespace, policy_id))

    def list(self, namespace):
        return iter(
            document
            for (stored_namespace, _), document in self.documents.items()
            if stored_namespace == namespace
        )

    def delete(self, namespace, policy_id):
        return self.documents.pop((namespace, policy_id), None) is not None

    def is_reachable(self):
        return self.reachable


@pytest.fixture
def store_parts():
    etcd = MemoryEtcd()
    etcd.put_if_absent(POLICY_AUTH_FORMAT_KEY, POLICY_AUTH_FORMAT)
    publications = MemoryPublicationStore()
    unprotected_policy_store = MemoryUnprotectedPolicyStore()
    store = EtcdProtectedPolicyStore(
        etcd, publications, unprotected_policy_store=unprotected_policy_store
    )
    return store, etcd, publications, unprotected_policy_store


def _document(policy_id, marker="value"):
    return json.dumps({"metadata": {"policy_id": policy_id}, "marker": marker})


def test_create_read_list_final_check_and_delete(store_parts):
    store, _, publications, _ = store_parts
    store.create("policy", "policy-1", _document("policy-1"))

    approved = store.load_approved("policy", "policy-1")
    assert approved is not None
    assert approved.document == _document("policy-1")
    assert approved.approval is not None
    store.check_approvals([approved.approval])
    assert list(store.list("policy")) == [_document("policy-1")]

    assert store.delete("policy", "policy-1")
    assert store.get("policy", "policy-1") is None
    assert not publications.documents
    assert not store.delete("policy", "policy-1")


def test_reachability_requires_each_store_component(store_parts):
    store, _, publications, unprotected_policy_store = store_parts

    assert store.backend_name == unprotected_policy_store.backend_name
    assert store.is_reachable()
    publications.reachable = False
    assert not store.is_reachable()
    publications.reachable = True
    unprotected_policy_store.reachable = False
    assert not store.is_reachable()


def test_create_conflict_and_recreate_uses_new_publication(store_parts):
    store, _, publications, _ = store_parts
    store.create("policy", "policy-1", _document("policy-1"))
    first = set(publications.documents)
    with pytest.raises(PolicyAlreadyExists):
        store.create("policy", "policy-1", _document("policy-1", "other"))

    assert store.delete("policy", "policy-1")
    store.create("policy", "policy-1", _document("policy-1"))
    assert len(publications.documents) == 1
    assert not (first & set(publications.documents))


def test_delete_fences_create_paused_before_publication_insert(store_parts):
    store, _, publications, _ = store_parts
    entered = threading.Event()
    resume = threading.Event()
    publications.before_insert = lambda: (entered.set(), resume.wait(timeout=3))
    failures = []

    def create():
        try:
            store.create("policy", "policy-1", _document("policy-1"))
        except Exception as exc:
            failures.append(exc)

    worker = threading.Thread(target=create)
    worker.start()
    assert entered.wait(timeout=3)
    assert store.delete("policy", "policy-1")
    resume.set()
    worker.join(timeout=3)

    assert not worker.is_alive()
    assert failures and isinstance(failures[0], PolicyAlreadyExists)
    assert store.get("policy", "policy-1") is None
    assert not publications.documents


def test_stale_delete_does_not_remove_new_publication(store_parts):
    store, etcd, publications, _ = store_parts
    store.create("policy", "policy-1", _document("policy-1", "old"))
    entered = threading.Event()
    resume = threading.Event()
    etcd.before_delete = lambda: (entered.set(), resume.wait(timeout=3))
    result = []

    worker = threading.Thread(
        target=lambda: result.append(store.delete("policy", "policy-1"))
    )
    worker.start()
    assert entered.wait(timeout=3)

    assert store.delete("policy", "policy-1")
    store.create("policy", "policy-1", _document("policy-1", "new"))
    resume.set()
    worker.join(timeout=3)

    assert not worker.is_alive()
    assert store.get("policy", "policy-1") == _document("policy-1", "new")
    assert len(publications.documents) == 1
    approved = store.load_approved("policy", "policy-1")
    assert approved is not None and approved.approval is not None
    store.check_approvals([approved.approval])


def test_final_check_rejects_revoked_snapshot(store_parts):
    store, _, _, _ = store_parts
    store.create("policy", "policy-1", _document("policy-1"))
    approved = store.load_approved("policy", "policy-1")
    assert approved is not None and approved.approval is not None

    store.delete("policy", "policy-1")
    with pytest.raises(PolicyAuthorizationDenied):
        store.check_approvals([approved.approval])


def test_active_record_with_missing_publication_fails_closed(store_parts):
    store, etcd, _, _ = store_parts
    store.create("policy", "policy-1", _document("policy-1"))
    active = etcd.get(b"/tas/policy-auth/policy/policy-1")
    assert active is not None

    key = ("policy", "policy-1", json.loads(active.value)["publication_id"])
    store._publications.documents.pop(key)
    with pytest.raises(PolicyStoreUnavailable, match="missing"):
        store.get("policy", "policy-1")


def test_delete_removes_unprotected_policy_even_without_approval(store_parts):
    store, _, _, unprotected_policy_store = store_parts
    unprotected_policy_store.create(
        "policy", "policy-1", _document("policy-1", "unprotected")
    )
    assert store.delete("policy", "policy-1")
    assert unprotected_policy_store.get("policy", "policy-1") is None
