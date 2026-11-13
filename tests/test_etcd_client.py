#
# TEE Attestation Service - Tests for the etcd HTTP Gateway Client
#
# Copyright 2026 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# This file is part of the TEE Attestation Service.
#
# Tests for authentication, endpoint failover, timeouts and transaction
# handling in tas/etcd_client.py, using a fake HTTP gateway.
#

import base64
import sys
from unittest.mock import Mock

import pytest
import requests

from tas.etcd_client import EtcdClient
from tas.policy_store import PolicyStoreUnavailable


class FakeResponse:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload or {}

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"HTTP {self.status_code}")


def _client(endpoints=("https://etcd-a",)):
    client = EtcdClient(endpoints, "/ca.pem", "tas", "secret")
    client._session.post = Mock()
    return client


def _authenticated():
    return FakeResponse(payload={"token": "test-token"})


def test_missing_requests_reports_installation_guidance(monkeypatch):
    monkeypatch.setitem(sys.modules, "requests", None)

    with pytest.raises(
        RuntimeError, match=r"requires requests.*requirements\.txt"
    ) as error:
        EtcdClient(["https://etcd-a"], "/ca.pem", "tas", "secret")

    assert isinstance(error.value.__cause__, ImportError)


def test_put_if_absent_posts_base64_transaction_with_tls_options():
    client = _client()
    client._session.post.side_effect = [
        _authenticated(),
        FakeResponse(payload={"succeeded": True, "header": {"revision": "8"}}),
    ]

    assert client.put_if_absent(b"/tas/key", b"value") == (True, 8)

    auth_call, txn_call = client._session.post.call_args_list
    assert auth_call.args == ("https://etcd-a/v3/auth/authenticate",)
    assert auth_call.kwargs["json"] == {"name": "tas", "password": "secret"}
    assert auth_call.kwargs["verify"] == "/ca.pem"
    assert txn_call.args == ("https://etcd-a/v3/kv/txn",)
    assert txn_call.kwargs["headers"]["Authorization"] == "test-token"
    assert txn_call.kwargs["json"] == {
        "compare": [
            {
                "key": base64.b64encode(b"/tas/key").decode("ascii"),
                "target": "VERSION",
                "result": "EQUAL",
                "version": "0",
            }
        ],
        "success": [
            {
                "request_put": {
                    "key": base64.b64encode(b"/tas/key").decode("ascii"),
                    "value": base64.b64encode(b"value").decode("ascii"),
                }
            }
        ],
        "failure": [],
    }


def test_mutation_network_failure_is_not_retried_on_another_endpoint():
    client = _client(("https://etcd-a", "https://etcd-b"))
    client._session.post.side_effect = [
        _authenticated(),
        requests.ConnectionError("connection lost"),
    ]

    with pytest.raises(PolicyStoreUnavailable) as error:
        client.put_if_absent(b"/tas/key", b"value")

    assert error.value.reason_code == "authority_unavailable"
    assert client._session.post.call_count == 2
    assert client._session.post.call_args_list[-1].args == ("https://etcd-a/v3/kv/txn",)


def test_revision_guarded_put_and_delete_compare_mod_revision():
    client = _client()
    client._session.post.side_effect = [
        _authenticated(),
        FakeResponse(payload={"succeeded": True, "header": {"revision": "9"}}),
        FakeResponse(payload={"succeeded": True, "header": {"revision": "10"}}),
    ]

    assert client.put_if_revision(b"/tas/key", 8, b"active") == (True, 9)
    assert client.delete_if_revision(b"/tas/key", 9)

    put_body = client._session.post.call_args_list[1].kwargs["json"]
    delete_body = client._session.post.call_args_list[2].kwargs["json"]
    encoded_key = base64.b64encode(b"/tas/key").decode("ascii")
    assert put_body["compare"] == [
        {
            "key": encoded_key,
            "target": "MOD",
            "result": "EQUAL",
            "mod_revision": "8",
        }
    ]
    assert delete_body == {
        "compare": [
            {
                "key": encoded_key,
                "target": "MOD",
                "result": "EQUAL",
                "mod_revision": "9",
            }
        ],
        "success": [{"request_delete_range": {"key": encoded_key}}],
        "failure": [],
    }


def test_check_revisions_compares_all_approvals_in_one_read_only_transaction():
    client = _client()
    client._token = "test-token"
    client._session.post.return_value = FakeResponse(
        payload={"succeeded": True, "header": {"revision": "4"}}
    )

    assert client.check_revisions([(b"/tas/a", 3), (b"/tas/b", 4)])

    body = client._session.post.call_args.kwargs["json"]
    assert body == {
        "compare": [
            {
                "key": base64.b64encode(b"/tas/a").decode("ascii"),
                "target": "MOD",
                "result": "EQUAL",
                "mod_revision": "3",
            },
            {
                "key": base64.b64encode(b"/tas/b").decode("ascii"),
                "target": "MOD",
                "result": "EQUAL",
                "mod_revision": "4",
            },
        ],
        "success": [],
        "failure": [],
    }


def test_read_fails_over_to_next_endpoint_after_server_error():
    client = _client(("https://etcd-a", "https://etcd-b"))
    client._session.post.side_effect = [
        _authenticated(),
        FakeResponse(status_code=503),
        _authenticated(),
        FakeResponse(payload={"kvs": []}),
    ]

    assert client.get(b"/tas/key") is None

    assert client._session.post.call_args_list[1].args == (
        "https://etcd-a/v3/kv/range",
    )
    assert client._session.post.call_args_list[3].args == (
        "https://etcd-b/v3/kv/range",
    )


def test_authentication_rejection_is_reported_as_denied():
    client = _client()
    client._session.post.return_value = FakeResponse(status_code=401)

    with pytest.raises(PolicyStoreUnavailable) as error:
        client.get(b"/tas/key")

    assert error.value.reason_code == "authority_denied"
    assert client._session.post.call_count == 1


def test_prefix_range_rejects_malformed_records():
    client = _client()
    client._token = "test-token"
    client._session.post.return_value = FakeResponse(payload={"kvs": [None]})

    with pytest.raises(PolicyStoreUnavailable) as error:
        client.range_prefix(b"/tas/")

    assert error.value.reason_code == "authority_invalid_response"


@pytest.mark.parametrize(
    ("method", "args", "expected"),
    [
        ("put_if_absent", (b"/tas/key", b"value"), (False, None)),
        ("put_if_revision", (b"/tas/key", 4, b"value"), (False, None)),
        ("delete_if_revision", (b"/tas/key", 4), False),
        ("check_revisions", ([(b"/tas/key", 4)],), False),
    ],
)
def test_gateway_omits_default_false_transaction_result(method, args, expected):
    client = _client()
    client._token = "test-token"
    client._session.post.return_value = FakeResponse(
        payload={"header": {"revision": "5"}}
    )

    assert getattr(client, method)(*args) == expected


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"succeeded": False},
        {"header": None},
        {"header": {"revision": "invalid"}},
        {"header": {"revision": "5"}, "succeeded": None},
    ],
)
def test_transaction_defaults_do_not_hide_malformed_responses(payload):
    client = _client()
    client._token = "test-token"
    client._session.post.return_value = FakeResponse(payload=payload)

    with pytest.raises(PolicyStoreUnavailable) as error:
        client.check_revisions([(b"/tas/key", 4)])

    assert error.value.reason_code == "authority_invalid_response"


@pytest.mark.parametrize("revision", [True, 1.5, " 1", "-1"])
def test_malformed_revision_is_rejected(revision):
    with pytest.raises(PolicyStoreUnavailable) as error:
        EtcdClient._revision(revision, "revision")

    assert error.value.reason_code == "authority_invalid_response"
