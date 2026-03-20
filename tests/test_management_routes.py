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
from tas.deprecated_routes import deprecated_policy_bp
from tas.management_routes import management_bp

CLIENT_API_KEY = "a" * 64
MGMT_API_KEY = "b" * 64

VALID_POLICY_PAYLOAD = {
    "policy_type": "SEV",
    "key_id": "test-key-1",
    "policy": {
        "metadata": {
            "name": "Test Policy",
            "version": "1.0",
            "description": "A test policy",
        },
        "validation_rules": {
            "host_data": {"exact_match": "abc123"},
            "policy": {"debug_allowed": False},
        },
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


@pytest.fixture()
def app():
    """Create a test Flask app with both blueprints registered."""
    test_app = Flask(__name__)
    test_app.config["TESTING"] = True
    test_app.config["TAS_API_KEY"] = CLIENT_API_KEY
    test_app.config["TAS_MANAGEMENT_API_KEY"] = MGMT_API_KEY
    test_app.config["TAS_ENFORCE_SIGNED_POLICIES"] = False

    fake_redis = FakeRedis()
    test_app.extensions["redis"] = fake_redis

    init_client_auth(test_app)
    init_management_auth(test_app)

    test_app.register_blueprint(management_bp)
    test_app.register_blueprint(deprecated_policy_bp)

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
        payload = {**VALID_POLICY_PAYLOAD, "policy_type": None}
        resp = client.post(
            "/management/policy/v0/store",
            headers=mgmt_headers,
            data=json.dumps(payload),
        )
        assert resp.status_code == 400

    def test_store_policy_invalid_policy_type(self, client, mgmt_headers):
        payload = {**VALID_POLICY_PAYLOAD, "policy_type": "bad chars!@#"}
        resp = client.post(
            "/management/policy/v0/store",
            headers=mgmt_headers,
            data=json.dumps(payload),
        )
        assert resp.status_code == 400


class TestManagementGetPolicy:
    def test_get_policy_success(self, client, mgmt_headers, app):
        # Store a policy first
        app.extensions["redis"].set(
            "policy:SEV:test-key-1",
            json.dumps(VALID_POLICY_PAYLOAD["policy"]),
        )
        resp = client.get(
            "/management/policy/v0/get/policy:SEV:test-key-1",
            headers=mgmt_headers,
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["policy_key"] == "policy:SEV:test-key-1"

    def test_get_policy_not_found(self, client, mgmt_headers):
        resp = client.get(
            "/management/policy/v0/get/policy:SEV:nonexistent",
            headers=mgmt_headers,
        )
        assert resp.status_code == 404

    def test_get_policy_invalid_key_format(self, client, mgmt_headers):
        resp = client.get(
            "/management/policy/v0/get/bad-key-format",
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
            "policy:SEV:key1",
            json.dumps(VALID_POLICY_PAYLOAD["policy"]),
        )
        resp = client.get("/management/policy/v0/list", headers=mgmt_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["count"] == 1


class TestManagementDeletePolicy:
    def test_delete_policy_success(self, client, mgmt_headers, app):
        app.extensions["redis"].set(
            "policy:SEV:to-delete",
            json.dumps(VALID_POLICY_PAYLOAD["policy"]),
        )
        resp = client.delete(
            "/management/policy/v0/delete/policy:SEV:to-delete",
            headers=mgmt_headers,
        )
        assert resp.status_code == 200
        assert "deleted successfully" in resp.get_json()["message"]

    def test_delete_policy_not_found(self, client, mgmt_headers):
        resp = client.delete(
            "/management/policy/v0/delete/policy:SEV:nonexistent",
            headers=mgmt_headers,
        )
        assert resp.status_code == 404


# -- Deprecated route tests --


class TestDeprecatedRoutes:
    """Verify old /policy/v0/* routes still work but emit deprecation headers."""

    def test_deprecated_store_works(self, client, mgmt_headers):
        resp = client.post(
            "/policy/v0/store",
            headers=mgmt_headers,
            data=json.dumps(VALID_POLICY_PAYLOAD),
        )
        assert resp.status_code == 201

    def test_deprecated_store_has_deprecation_header(self, client, mgmt_headers):
        resp = client.post(
            "/policy/v0/store",
            headers=mgmt_headers,
            data=json.dumps(VALID_POLICY_PAYLOAD),
        )
        assert resp.headers.get("Deprecation") == "true"
        assert resp.headers.get("Sunset") is not None
        assert "successor-version" in resp.headers.get("Link", "")

    def test_deprecated_store_body_has_warning(self, client, mgmt_headers):
        resp = client.post(
            "/policy/v0/store",
            headers=mgmt_headers,
            data=json.dumps(VALID_POLICY_PAYLOAD),
        )
        data = resp.get_json()
        assert "deprecation_warning" in data

    def test_deprecated_list_has_deprecation_header(self, client, mgmt_headers):
        resp = client.get("/policy/v0/list", headers=mgmt_headers)
        assert resp.status_code == 200
        assert resp.headers.get("Deprecation") == "true"

    def test_deprecated_get_has_deprecation_header(self, client, mgmt_headers, app):
        app.extensions["redis"].set(
            "policy:SEV:dep-test",
            json.dumps(VALID_POLICY_PAYLOAD["policy"]),
        )
        resp = client.get(
            "/policy/v0/get/policy:SEV:dep-test",
            headers=mgmt_headers,
        )
        assert resp.status_code == 200
        assert resp.headers.get("Deprecation") == "true"
        data = resp.get_json()
        assert "deprecation_warning" in data

    def test_deprecated_delete_has_deprecation_header(self, client, mgmt_headers, app):
        app.extensions["redis"].set(
            "policy:SEV:dep-del",
            json.dumps(VALID_POLICY_PAYLOAD["policy"]),
        )
        resp = client.delete(
            "/policy/v0/delete/policy:SEV:dep-del",
            headers=mgmt_headers,
        )
        assert resp.status_code == 200
        assert resp.headers.get("Deprecation") == "true"

    def test_deprecated_routes_use_management_key(self, client, client_headers):
        """Old routes should require X-MANAGEMENT-API-KEY, not X-API-KEY."""
        resp = client.get("/policy/v0/list", headers=client_headers)
        assert resp.status_code == 401

    def test_deprecated_routes_no_key_rejected(self, client):
        resp = client.get("/policy/v0/list")
        assert resp.status_code == 401


# -- Key separation tests --


class TestKeySeparation:
    """Verify that client and management keys are not interchangeable."""

    def test_management_route_rejects_client_key(self, client, client_headers):
        resp = client.get("/management/policy/v0/list", headers=client_headers)
        assert resp.status_code == 401

    def test_management_route_accepts_mgmt_key(self, client, mgmt_headers):
        resp = client.get("/management/policy/v0/list", headers=mgmt_headers)
        assert resp.status_code == 200
