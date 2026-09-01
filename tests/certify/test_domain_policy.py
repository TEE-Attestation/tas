#
# TEE Attestation Service - Domain-policy / Certify-policy Tests
#
# Copyright 2026 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# This file is part of the TEE Attestation Service.
#

import json

import pytest
from flask import Flask

from tas import tas_vm
from tas.auth import init_client_auth, init_management_auth
from tas.certify.policy_routes import certify_policy_bp

CLIENT_API_KEY = "a" * 64
MGMT_API_KEY = "b" * 64


def _certify_policy(policy_id, policy_type="SEV"):
    return {
        "metadata": {
            "name": f"Certify Policy {policy_id}",
            "policy_type": policy_type,
            "policy_id": policy_id,
            "key_id": f"key-{policy_id}",
        },
        "validation_rules": {"policy": {"debug_allowed": False}},
    }


def _domain_policy(policy_id, member_ids, tee_type="amd-sev-snp"):
    return {
        "metadata": {"policy_id": policy_id, "description": "test domain"},
        "certify_policies": {tee_type: list(member_ids)},
    }


class FakeRedis:
    """Minimal in-memory Redis stub for testing."""

    def __init__(self):
        self._store = {}

    def set(self, key, value, nx=False):
        if nx and key in self._store:
            return None
        self._store[key] = value
        return True

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

    def scan_iter(self, match="*", count=None):
        import fnmatch

        return [k for k in list(self._store) if fnmatch.fnmatch(k, match)]


@pytest.fixture()
def app():
    test_app = Flask(__name__)
    test_app.config["TESTING"] = True
    test_app.config["TAS_API_KEY"] = CLIENT_API_KEY
    test_app.config["TAS_MANAGEMENT_API_KEY"] = MGMT_API_KEY
    test_app.config["TAS_ENFORCE_SIGNED_POLICIES"] = False
    test_app.config["TAS_CERTIFY_MAX_POLICIES"] = 32

    test_app.extensions["redis"] = FakeRedis()

    init_client_auth(test_app)
    init_management_auth(test_app)
    test_app.register_blueprint(certify_policy_bp)
    return test_app


@pytest.fixture()
def redis(app):
    return app.extensions["redis"]


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def mgmt_headers():
    return {"X-MANAGEMENT-API-KEY": MGMT_API_KEY, "Content-Type": "application/json"}


@pytest.fixture()
def client_headers():
    return {"X-API-KEY": CLIENT_API_KEY, "Content-Type": "application/json"}


# --------------------------------------------------------------------------- #
# Certify-policy management endpoints
# --------------------------------------------------------------------------- #


class TestCertifyPolicyManagement:
    def _store(self, client, mgmt_headers, policy):
        return client.post(
            "/management/certify-policy/v0/store",
            headers=mgmt_headers,
            data=json.dumps(policy),
        )

    def test_store_success(self, client, mgmt_headers, redis):
        resp = self._store(client, mgmt_headers, _certify_policy("pol-a"))
        assert resp.status_code == 201
        assert "stored successfully" in resp.get_json()["message"]
        assert redis.get("certify-policy:pol-a") is not None

    def test_store_uses_separate_keyspace(self, client, mgmt_headers, redis):
        self._store(client, mgmt_headers, _certify_policy("pol-a"))
        # The secret-release policy:* store must be untouched.
        assert redis.get("policy:pol-a") is None

    def test_store_requires_management_key(self, client, client_headers):
        resp = self._store(client, client_headers, _certify_policy("pol-a"))
        assert resp.status_code == 401

    def test_store_duplicate_rejected(self, client, mgmt_headers):
        self._store(client, mgmt_headers, _certify_policy("pol-a"))
        resp = self._store(client, mgmt_headers, _certify_policy("pol-a"))
        assert resp.status_code == 409

    def test_store_missing_policy_id(self, client, mgmt_headers):
        policy = _certify_policy("pol-a")
        del policy["metadata"]["policy_id"]
        resp = self._store(client, mgmt_headers, policy)
        assert resp.status_code == 400
        assert "Policy ID is required" in resp.get_json()["error"]

    def test_store_invalid_policy_id(self, client, mgmt_headers):
        resp = self._store(client, mgmt_headers, _certify_policy("bad:id"))
        assert resp.status_code == 400
        assert "Invalid policy_id" in resp.get_json()["error"]

    def test_get_success(self, client, mgmt_headers, redis):
        redis.set("certify-policy:pol-a", json.dumps(_certify_policy("pol-a")))
        resp = client.get(
            "/management/certify-policy/v0/get/pol-a", headers=mgmt_headers
        )
        assert resp.status_code == 200
        assert resp.get_json()["policy_id"] == "pol-a"

    def test_get_not_found(self, client, mgmt_headers):
        resp = client.get(
            "/management/certify-policy/v0/get/missing", headers=mgmt_headers
        )
        assert resp.status_code == 404

    def test_list(self, client, mgmt_headers, redis):
        redis.set("certify-policy:pol-a", json.dumps(_certify_policy("pol-a")))
        redis.set("certify-policy:pol-b", json.dumps(_certify_policy("pol-b")))
        resp = client.get("/management/certify-policy/v0/list", headers=mgmt_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["count"] == 2
        assert {p["policy_id"] for p in data["certify_policies"]} == {"pol-a", "pol-b"}

    def test_delete(self, client, mgmt_headers, redis):
        redis.set("certify-policy:pol-a", json.dumps(_certify_policy("pol-a")))
        resp = client.delete(
            "/management/certify-policy/v0/delete/pol-a", headers=mgmt_headers
        )
        assert resp.status_code == 200
        assert redis.get("certify-policy:pol-a") is None

    def test_store_without_key_id_succeeds(self, client, mgmt_headers, redis):
        # Certify-policies do not release secrets, so key_id is optional.
        policy = _certify_policy("pol-a")
        del policy["metadata"]["key_id"]
        resp = self._store(client, mgmt_headers, policy)
        assert resp.status_code == 201
        assert redis.get("certify-policy:pol-a") is not None

    def test_store_with_key_id_succeeds(self, client, mgmt_headers, redis):
        # key_id remains accepted (and stored) when provided.
        resp = self._store(client, mgmt_headers, _certify_policy("pol-a"))
        assert resp.status_code == 201
        stored = json.loads(redis.get("certify-policy:pol-a"))
        assert stored["metadata"]["key_id"] == "key-pol-a"


# --------------------------------------------------------------------------- #
# Domain-policy management endpoints
# --------------------------------------------------------------------------- #


class TestDomainPolicyManagement:
    def _store(self, client, mgmt_headers, policy):
        return client.post(
            "/management/domain-policy/v0/store",
            headers=mgmt_headers,
            data=json.dumps(policy),
        )

    def test_store_success_warns_on_missing_members(self, client, mgmt_headers, redis):
        resp = self._store(client, mgmt_headers, _domain_policy("prod", ["pol-a"]))
        assert resp.status_code == 201
        body = resp.get_json()
        assert "stored successfully" in body["message"]
        # pol-a does not exist yet, so a warning is surfaced but store succeeds.
        assert "not found" in body["warning"]
        assert redis.get("domain-policy:prod") is not None

    def test_no_missing_member_warning_when_members_exist(
        self, client, mgmt_headers, redis
    ):
        redis.set("certify-policy:pol-a", json.dumps(_certify_policy("pol-a")))
        resp = self._store(client, mgmt_headers, _domain_policy("prod", ["pol-a"]))
        assert resp.status_code == 201
        # An unsigned-policy warning may still appear; only the missing-member
        # warning must be absent when every referenced policy exists.
        assert "not found" not in resp.get_json().get("warning", "")

    def test_store_missing_policy_id(self, client, mgmt_headers):
        policy = _domain_policy("prod", ["pol-a"])
        del policy["metadata"]["policy_id"]
        resp = self._store(client, mgmt_headers, policy)
        assert resp.status_code == 400
        assert "domain policy id is required" in resp.get_json()["error"]

    def test_store_empty_members(self, client, mgmt_headers):
        resp = self._store(client, mgmt_headers, _domain_policy("prod", []))
        assert resp.status_code == 400
        assert "non-empty list" in resp.get_json()["error"]

    def test_store_duplicate_members_rejected(self, client, mgmt_headers):
        resp = self._store(
            client, mgmt_headers, _domain_policy("prod", ["pol-a", "pol-a"])
        )
        assert resp.status_code == 400
        assert "duplicates" in resp.get_json()["error"]

    def test_store_too_many_members(self, client, mgmt_headers, app):
        app.config["TAS_CERTIFY_MAX_POLICIES"] = 2
        resp = self._store(
            client, mgmt_headers, _domain_policy("prod", ["a", "b", "c"])
        )
        assert resp.status_code == 400
        assert "at most 2" in resp.get_json()["error"]

    def test_store_invalid_member_id(self, client, mgmt_headers):
        resp = self._store(client, mgmt_headers, _domain_policy("prod", ["bad:id"]))
        assert resp.status_code == 400
        assert "Invalid certify policy id" in resp.get_json()["error"]

    def test_store_duplicate_domain_rejected(self, client, mgmt_headers, redis):
        redis.set("domain-policy:prod", json.dumps(_domain_policy("prod", ["pol-a"])))
        resp = self._store(client, mgmt_headers, _domain_policy("prod", ["pol-a"]))
        assert resp.status_code == 409

    def test_get_and_list_and_delete(self, client, mgmt_headers, redis):
        redis.set(
            "domain-policy:prod", json.dumps(_domain_policy("prod", ["pol-a", "pol-b"]))
        )
        get_resp = client.get(
            "/management/domain-policy/v0/get/prod", headers=mgmt_headers
        )
        assert get_resp.status_code == 200
        assert get_resp.get_json()["domain_policy"]["certify_policies"] == {
            "amd-sev-snp": ["pol-a", "pol-b"]
        }

        list_resp = client.get(
            "/management/domain-policy/v0/list", headers=mgmt_headers
        )
        assert list_resp.status_code == 200
        assert list_resp.get_json()["count"] == 1

        del_resp = client.delete(
            "/management/domain-policy/v0/delete/prod", headers=mgmt_headers
        )
        assert del_resp.status_code == 200
        assert redis.get("domain-policy:prod") is None

    def test_store_unsupported_tee_type(self, client, mgmt_headers):
        policy = {
            "metadata": {"policy_id": "prod"},
            "certify_policies": {"bogus-tee": ["pol-a"]},
        }
        resp = self._store(client, mgmt_headers, policy)
        assert resp.status_code == 400
        assert "Unsupported TEE type" in resp.get_json()["error"]

    def test_store_empty_certify_policies_map(self, client, mgmt_headers):
        policy = {"metadata": {"policy_id": "prod"}, "certify_policies": {}}
        resp = self._store(client, mgmt_headers, policy)
        assert resp.status_code == 400
        assert "certify_policies" in resp.get_json()["error"]

    def test_store_warns_on_type_mismatch(self, client, mgmt_headers, redis):
        # pol-tdx is a TDX policy but listed under the amd-sev-snp group.
        redis.set(
            "certify-policy:pol-tdx",
            json.dumps(_certify_policy("pol-tdx", "TDX")),
        )
        resp = self._store(client, mgmt_headers, _domain_policy("prod", ["pol-tdx"]))
        assert resp.status_code == 201
        assert "does not match their TEE group" in resp.get_json()["warning"]


# --------------------------------------------------------------------------- #
# domain_verify: OR semantics + optional requested policy id
# --------------------------------------------------------------------------- #


def _seed_domain(redis, name, member_ids, tee_type="amd-sev-snp"):
    redis.set(
        f"domain-policy:{name}",
        json.dumps(_domain_policy(name, member_ids, tee_type)),
    )
    policy_type = tas_vm.POLICY_TYPE_BY_TEE[tee_type]
    for member_id in member_ids:
        redis.set(
            f"certify-policy:{member_id}",
            json.dumps(_certify_policy(member_id, policy_type)),
        )


def _fake_verify_passing(passing_id):
    """Return a verify() replacement that only passes for one policy id."""

    def _verify(redis_client, nonce, tee_type, tee_evidence, policy_json, **kwargs):
        if policy_json.get("metadata", {}).get("policy_id") == passing_id:
            return True, None
        return False, "attestation did not match"

    return _verify


class TestDomainVerify:
    def test_passes_on_first_matching_member(self, app, redis, monkeypatch):
        _seed_domain(redis, "prod", ["pol-a", "pol-b"])
        monkeypatch.setattr(tas_vm, "verify", _fake_verify_passing("pol-b"))
        with app.app_context():
            ok, key_id, err = tas_vm.domain_verify(
                redis, "nonce", "amd-sev-snp", "evidence", "prod"
            )
        assert ok is True
        assert key_id == "key-pol-b"
        assert err is None

    def test_fails_when_no_member_matches(self, app, redis, monkeypatch):
        _seed_domain(redis, "prod", ["pol-a", "pol-b"])
        monkeypatch.setattr(tas_vm, "verify", _fake_verify_passing("none"))
        with app.app_context():
            ok, key_id, err = tas_vm.domain_verify(
                redis, "nonce", "amd-sev-snp", "evidence", "prod"
            )
        assert ok is False
        assert key_id is None
        assert err == "attestation did not match"

    def test_unknown_domain_policy(self, app, redis, monkeypatch):
        monkeypatch.setattr(tas_vm, "verify", _fake_verify_passing("pol-a"))
        with app.app_context():
            ok, key_id, err = tas_vm.domain_verify(
                redis, "nonce", "amd-sev-snp", "evidence", "missing"
            )
        assert ok is False
        assert err == "Domain policy not found"

    def test_requested_policy_id_only_evaluates_that_policy(
        self, app, redis, monkeypatch
    ):
        _seed_domain(redis, "prod", ["pol-a", "pol-b"])
        calls = []

        def _verify(redis_client, nonce, tee_type, tee_evidence, policy_json, **kwargs):
            calls.append(policy_json["metadata"]["policy_id"])
            return True, None

        monkeypatch.setattr(tas_vm, "verify", _verify)
        with app.app_context():
            ok, key_id, err = tas_vm.domain_verify(
                redis,
                "nonce",
                "amd-sev-snp",
                "evidence",
                "prod",
                requested_policy_id="pol-b",
            )
        assert ok is True
        assert key_id == "key-pol-b"
        assert calls == ["pol-b"]

    def test_requested_policy_id_not_permitted(self, app, redis, monkeypatch):
        _seed_domain(redis, "prod", ["pol-a", "pol-b"])
        monkeypatch.setattr(tas_vm, "verify", _fake_verify_passing("pol-a"))
        with app.app_context():
            ok, key_id, err = tas_vm.domain_verify(
                redis,
                "nonce",
                "amd-sev-snp",
                "evidence",
                "prod",
                requested_policy_id="pol-x",
            )
        assert ok is False
        assert (
            err
            == "Requested policy-id is not permitted by the domain policy for this TEE type"
        )

    def test_missing_member_is_skipped(self, app, redis, monkeypatch):
        # pol-a referenced but not stored; pol-b stored and passes.
        redis.set(
            "domain-policy:prod",
            json.dumps(_domain_policy("prod", ["pol-a", "pol-b"])),
        )
        redis.set("certify-policy:pol-b", json.dumps(_certify_policy("pol-b")))
        monkeypatch.setattr(tas_vm, "verify", _fake_verify_passing("pol-b"))
        with app.app_context():
            ok, key_id, err = tas_vm.domain_verify(
                redis, "nonce", "amd-sev-snp", "evidence", "prod"
            )
        assert ok is True
        assert key_id == "key-pol-b"

    def test_no_certify_policies_for_tee_type(self, app, redis, monkeypatch):
        _seed_domain(redis, "prod", ["pol-a"], tee_type="amd-sev-snp")
        monkeypatch.setattr(tas_vm, "verify", _fake_verify_passing("pol-a"))
        with app.app_context():
            ok, key_id, err = tas_vm.domain_verify(
                redis, "nonce", "intel-tdx", "evidence", "prod"
            )
        assert ok is False
        assert "no certify policies for TEE type 'intel-tdx'" in err

    def test_selects_only_matching_tee_type(self, app, redis, monkeypatch):
        # prod lists a SEV policy for amd-sev-snp and a TDX policy for intel-tdx;
        # an amd-sev-snp request must only evaluate the SEV member.
        redis.set(
            "domain-policy:prod",
            json.dumps(
                {
                    "metadata": {"policy_id": "prod"},
                    "certify_policies": {
                        "amd-sev-snp": ["sev-pol"],
                        "intel-tdx": ["tdx-pol"],
                    },
                }
            ),
        )
        redis.set(
            "certify-policy:sev-pol", json.dumps(_certify_policy("sev-pol", "SEV"))
        )
        redis.set(
            "certify-policy:tdx-pol", json.dumps(_certify_policy("tdx-pol", "TDX"))
        )

        calls = []

        def _verify(redis_client, nonce, tee_type, tee_evidence, policy_json, **kwargs):
            calls.append(policy_json["metadata"]["policy_id"])
            return True, None

        monkeypatch.setattr(tas_vm, "verify", _verify)
        with app.app_context():
            ok, key_id, err = tas_vm.domain_verify(
                redis, "nonce", "amd-sev-snp", "evidence", "prod"
            )
        assert ok is True
        assert key_id == "key-sev-pol"
        assert calls == ["sev-pol"]  # tdx-pol is never fetched or evaluated

    def test_mismatched_member_type_is_skipped(self, app, redis, monkeypatch):
        # A TDX-typed policy mis-grouped under amd-sev-snp must be skipped by the
        # defense-in-depth guard even though verify() would otherwise pass.
        redis.set(
            "domain-policy:prod",
            json.dumps(
                {
                    "metadata": {"policy_id": "prod"},
                    "certify_policies": {"amd-sev-snp": ["pol-tdx"]},
                }
            ),
        )
        redis.set(
            "certify-policy:pol-tdx", json.dumps(_certify_policy("pol-tdx", "TDX"))
        )
        monkeypatch.setattr(tas_vm, "verify", lambda *a, **k: (True, None))
        with app.app_context():
            ok, key_id, err = tas_vm.domain_verify(
                redis, "nonce", "amd-sev-snp", "evidence", "prod"
            )
        assert ok is False
        assert err == "certify policy type does not match the attestation evidence"

    def test_gpu_evidence_verified_once_across_candidates(
        self, app, redis, monkeypatch
    ):
        # With multiple candidate certify-policies, the (expensive) GPU evidence
        # verification must run a single time, not once per candidate.
        _seed_domain(redis, "prod", ["pol-a", "pol-b"])
        monkeypatch.setattr(tas_vm, "verify", _fake_verify_passing("pol-b"))

        calls = {"n": 0}

        def _fake_gpu(redis_client, gpu_list, nonce):
            calls["n"] += 1
            return (
                True,
                None,
                [
                    {
                        "device_index": 0,
                        "type": "gpu-nvidia",
                        "claims": None,
                        "evidence_hash": b"\x00" * 64,
                    }
                ],
            )

        monkeypatch.setattr(tas_vm, "_verify_gpu_evidence_list", _fake_gpu)
        gpu_list = [{"type": "gpu-nvidia", "evidence": "x", "device-index": 0}]
        with app.app_context():
            ok, key_id, err = tas_vm.domain_verify(
                redis,
                "nonce",
                "amd-sev-snp",
                "evidence",
                "prod",
                wrapping_key=b"wk",
                report_data_binding=True,
                gpu_list=gpu_list,
            )
        assert ok is True
        assert key_id == "key-pol-b"
        assert calls["n"] == 1

    def test_gpu_evidence_failure_short_circuits_domain(self, app, redis, monkeypatch):
        # Invalid GPU evidence is policy-independent, so the domain must fail
        # immediately without evaluating any certify-policy.
        _seed_domain(redis, "prod", ["pol-a", "pol-b"])

        verify_calls = {"n": 0}

        def _counting_verify(*args, **kwargs):
            verify_calls["n"] += 1
            return True, None

        monkeypatch.setattr(tas_vm, "verify", _counting_verify)
        monkeypatch.setattr(
            tas_vm,
            "_verify_gpu_evidence_list",
            lambda *a, **k: (False, "GPU 0: bad evidence", None),
        )
        gpu_list = [{"type": "gpu-nvidia", "evidence": "x", "device-index": 0}]
        with app.app_context():
            ok, key_id, err = tas_vm.domain_verify(
                redis,
                "nonce",
                "amd-sev-snp",
                "evidence",
                "prod",
                wrapping_key=b"wk",
                report_data_binding=True,
                gpu_list=gpu_list,
            )
        assert ok is False
        assert err == "GPU 0: bad evidence"
        assert verify_calls["n"] == 0
