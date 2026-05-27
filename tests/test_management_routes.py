#
# TEE Attestation Service - Tests for Management Routes & Deprecation
#
# Copyright 2026 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# This file is part of the TEE Attestation Service.
#

import json
import os

import pytest
from flask import Flask

from tas.auth import init_client_auth, init_management_auth
from tas.management_routes import management_bp

CLIENT_API_KEY = "a" * 64
MGMT_API_KEY = "b" * 64

VALID_POLICY_PAYLOAD = {
    "metadata": {
        "name": "Test Policy",
        "version": "1.0",
        "description": "A test policy",
        "policy_type": "SEV",
        "policy_id": "test-sev-policy-001",
        "key_id": "test-key-1",
    },
    "validation_rules": {
        "host_data": {"exact_match": "abc123"},
        "policy": {"debug_allowed": False},
    },
}


class FakeRedis:
    """Minimal in-memory Redis stub for testing."""

    def __init__(self):
        self._store = {}

    def set(self, key, value):
        self._store[key] = value

    def get(self, key):
        return self._store.get(key)

    def delete(self, key):
        if key in self._store:
            del self._store[key]
            return 1
        return 0

    def keys(self, pattern="*"):
        import fnmatch

        return [k for k in self._store if fnmatch.fnmatch(k, pattern)]

    def setex(self, key, ttl, value):
        self._store[key] = value

    def config_get(self, key):
        defaults = {"appendonly": "no"}
        return {key: defaults.get(key, "")}


@pytest.fixture()
def app():
    """Create a test Flask app with management blueprint registered."""
    test_app = Flask(__name__)
    test_app.config["TESTING"] = True
    test_app.config["TAS_API_KEY"] = CLIENT_API_KEY
    test_app.config["TAS_MANAGEMENT_API_KEY"] = MGMT_API_KEY
    test_app.config["TAS_ENFORCE_SIGNED_POLICIES"] = False

    fake_redis = FakeRedis()
    test_app.extensions["redis"] = fake_redis
    test_app.extensions["redis_config_rewrite_ok"] = None

    init_client_auth(test_app)
    init_management_auth(test_app)

    test_app.register_blueprint(management_bp)

    return test_app


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def mgmt_headers():
    return {"X-MANAGEMENT-API-KEY": MGMT_API_KEY, "Content-Type": "application/json"}


@pytest.fixture()
def client_headers():
    return {"X-API-KEY": CLIENT_API_KEY, "Content-Type": "application/json"}


# -- Management route tests --


class TestManagementStorePolicy:
    def test_store_policy_success(self, client, mgmt_headers):
        resp = client.post(
            "/management/policy/v0/store",
            headers=mgmt_headers,
            data=json.dumps(VALID_POLICY_PAYLOAD),
        )
        assert resp.status_code == 201
        data = resp.get_json()
        assert "stored successfully" in data["message"]

    def test_store_policy_wrong_key_rejected(self, client, client_headers):
        """Using the client API key (X-API-KEY) should be rejected."""
        resp = client.post(
            "/management/policy/v0/store",
            headers=client_headers,
            data=json.dumps(VALID_POLICY_PAYLOAD),
        )
        assert resp.status_code == 401

    def test_store_policy_no_key_rejected(self, client):
        resp = client.post(
            "/management/policy/v0/store",
            headers={"Content-Type": "application/json"},
            data=json.dumps(VALID_POLICY_PAYLOAD),
        )
        assert resp.status_code == 401

    def test_store_policy_missing_body(self, client, mgmt_headers):
        resp = client.post("/management/policy/v0/store", headers=mgmt_headers)
        assert resp.status_code == 400

    def test_store_policy_missing_policy_type(self, client, mgmt_headers):
        payload = json.loads(json.dumps(VALID_POLICY_PAYLOAD))
        del payload["metadata"]["policy_type"]
        resp = client.post(
            "/management/policy/v0/store",
            headers=mgmt_headers,
            data=json.dumps(payload),
        )
        assert resp.status_code == 400

    def test_store_policy_missing_policy_id(self, client, mgmt_headers):
        payload = json.loads(json.dumps(VALID_POLICY_PAYLOAD))
        del payload["metadata"]["policy_id"]
        resp = client.post(
            "/management/policy/v0/store",
            headers=mgmt_headers,
            data=json.dumps(payload),
        )
        assert resp.status_code == 400

    def test_store_policy_missing_key_id(self, client, mgmt_headers):
        payload = json.loads(json.dumps(VALID_POLICY_PAYLOAD))
        del payload["metadata"]["key_id"]
        resp = client.post(
            "/management/policy/v0/store",
            headers=mgmt_headers,
            data=json.dumps(payload),
        )
        assert resp.status_code == 400

    def test_store_policy_invalid_policy_id(self, client, mgmt_headers):
        payload = json.loads(json.dumps(VALID_POLICY_PAYLOAD))
        payload["metadata"]["policy_id"] = "bad chars!@#"
        resp = client.post(
            "/management/policy/v0/store",
            headers=mgmt_headers,
            data=json.dumps(payload),
        )
        assert resp.status_code == 400

    def test_store_policy_duplicate_rejected(self, client, mgmt_headers, app):
        """Storing a policy with the same policy_id twice should return 409."""
        app.extensions["redis"].set(
            "policy:test-sev-policy-001",
            json.dumps(VALID_POLICY_PAYLOAD),
        )
        resp = client.post(
            "/management/policy/v0/store",
            headers=mgmt_headers,
            data=json.dumps(VALID_POLICY_PAYLOAD),
        )
        assert resp.status_code == 409


class TestManagementGetPolicy:
    def test_get_policy_success(self, client, mgmt_headers, app):
        # Store a policy first
        app.extensions["redis"].set(
            "policy:test-sev-policy-001",
            json.dumps(VALID_POLICY_PAYLOAD),
        )
        resp = client.get(
            "/management/policy/v0/get/test-sev-policy-001",
            headers=mgmt_headers,
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["policy_key"] == "policy:test-sev-policy-001"

    def test_get_policy_not_found(self, client, mgmt_headers):
        resp = client.get(
            "/management/policy/v0/get/nonexistent-policy",
            headers=mgmt_headers,
        )
        assert resp.status_code == 404

    def test_get_policy_invalid_key_format(self, client, mgmt_headers):
        resp = client.get(
            "/management/policy/v0/get/bad key!@#",
            headers=mgmt_headers,
        )
        assert resp.status_code == 400


class TestManagementListPolicies:
    def test_list_policies_empty(self, client, mgmt_headers):
        resp = client.get("/management/policy/v0/list", headers=mgmt_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["count"] == 0
        assert data["policies"] == []

    def test_list_policies_with_data(self, client, mgmt_headers, app):
        app.extensions["redis"].set(
            "policy:test-sev-policy-001",
            json.dumps(VALID_POLICY_PAYLOAD),
        )
        resp = client.get("/management/policy/v0/list", headers=mgmt_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["count"] == 1
        assert data["policies"][0]["policy_id"] == "test-sev-policy-001"
        assert data["policies"][0]["key_id"] == "test-key-1"


class TestManagementDeletePolicy:
    def test_delete_policy_success(self, client, mgmt_headers, app):
        app.extensions["redis"].set(
            "policy:to-delete",
            json.dumps(VALID_POLICY_PAYLOAD),
        )
        resp = client.delete(
            "/management/policy/v0/delete/to-delete",
            headers=mgmt_headers,
        )
        assert resp.status_code == 200
        assert "deleted successfully" in resp.get_json()["message"]

    def test_delete_policy_not_found(self, client, mgmt_headers):
        resp = client.delete(
            "/management/policy/v0/delete/nonexistent-policy",
            headers=mgmt_headers,
        )
        assert resp.status_code == 404


# -- Old policy format rejection tests --


class TestOldPolicyFormatRejected:
    """Ensure the old policy:{policy_type}:{key_id} system is rejected."""

    def test_old_format_policy_id_with_colons_rejected_on_store(
        self, client, mgmt_headers
    ):
        """A policy_id containing colons (old format) should be rejected."""
        payload = json.loads(json.dumps(VALID_POLICY_PAYLOAD))
        payload["metadata"]["policy_id"] = "SEV:test-key-1"
        resp = client.post(
            "/management/policy/v0/store",
            headers=mgmt_headers,
            data=json.dumps(payload),
        )
        assert resp.status_code == 400
        assert "Invalid policy_id" in resp.get_json()["error"]

    def test_old_format_get_with_colons_rejected(self, client, mgmt_headers):
        """GET with old-style colon-separated policy key should be rejected."""
        resp = client.get(
            "/management/policy/v0/get/SEV:test-key-1",
            headers=mgmt_headers,
        )
        assert resp.status_code == 400

    def test_old_format_delete_with_colons_rejected(self, client, mgmt_headers):
        """DELETE with old-style colon-separated policy key should be rejected."""
        resp = client.delete(
            "/management/policy/v0/delete/SEV:test-key-1",
            headers=mgmt_headers,
        )
        assert resp.status_code == 400

    def test_policy_without_policy_id_rejected(self, client, mgmt_headers):
        """A policy relying on old key_id-only identification should be rejected."""
        payload = {
            "metadata": {
                "name": "Old Format Policy",
                "version": "1.0",
                "policy_type": "SEV",
                "key_id": "test-key-1",
            },
            "validation_rules": {
                "host_data": {"exact_match": "abc123"},
            },
        }
        resp = client.post(
            "/management/policy/v0/store",
            headers=mgmt_headers,
            data=json.dumps(payload),
        )
        assert resp.status_code == 400
        assert "Policy ID is required" in resp.get_json()["error"]


# -- Key separation tests --


class TestKeySeparation:
    """Verify that client and management keys are not interchangeable."""

    def test_management_route_rejects_client_key(self, client, client_headers):
        resp = client.get("/management/policy/v0/list", headers=client_headers)
        assert resp.status_code == 401

    def test_management_route_accepts_mgmt_key(self, client, mgmt_headers):
        resp = client.get("/management/policy/v0/list", headers=mgmt_headers)
        assert resp.status_code == 200


class TestStatusEndpoint:
    """Tests for GET /management/status."""

    def test_status_returns_persistence_info(self, client):
        resp = client.get(
            "/management/status",
            headers={"X-MANAGEMENT-API-KEY": MGMT_API_KEY},
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert "redis_persistence_active" in data
        assert "config_rewrite_succeeded" in data

    def test_status_reflects_config_rewrite_ok(self, app, client):
        app.extensions["redis_config_rewrite_ok"] = True
        resp = client.get(
            "/management/status",
            headers={"X-MANAGEMENT-API-KEY": MGMT_API_KEY},
        )
        data = resp.get_json()
        assert data["config_rewrite_succeeded"] is True

    def test_status_reflects_config_rewrite_failed(self, app, client):
        app.extensions["redis_config_rewrite_ok"] = False
        resp = client.get(
            "/management/status",
            headers={"X-MANAGEMENT-API-KEY": MGMT_API_KEY},
        )
        data = resp.get_json()
        assert data["config_rewrite_succeeded"] is False

    def test_status_requires_management_key(self, client):
        resp = client.get("/management/status")
        assert resp.status_code == 401

    def test_status_rejects_wrong_key(self, client):
        resp = client.get(
            "/management/status",
            headers={"X-MANAGEMENT-API-KEY": "wrong-key"},
        )
        assert resp.status_code == 401
