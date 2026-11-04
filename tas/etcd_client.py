#
# TEE Attestation Service - Optional etcd HTTP Gateway Client
#
# Copyright 2026 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# This file is part of the TEE Attestation Service.
#

import base64
import json
import threading
from dataclasses import dataclass
from urllib.parse import urlparse

from .policy_store import PolicyStoreUnavailable
from .tas_logging import get_logger

logger = get_logger(__name__)


@dataclass(frozen=True)
class EtcdKV:
    key: bytes
    value: bytes
    create_revision: int
    mod_revision: int
    version: int


class EtcdClient:
    """Small optional client for the etcd v3 JSON HTTP gateway.

    Keys and values use etcd's base64-encoded JSON representation. Reads may
    fail over between configured endpoints; writes deliberately use only one
    endpoint because a lost response leaves the commit outcome unknown, and
    retrying a mutation against another endpoint could duplicate or obscure
    that outcome. Compare-and-swap methods below let callers resolve it by
    reading the authoritative key back.
    """

    def __init__(
        self,
        endpoints,
        ca_file: str,
        username: str,
        password: str,
        timeout_seconds: int = 5,
        cert_file: str | None = None,
        key_file: str | None = None,
    ):
        try:
            import requests
        except ImportError as exc:
            raise RuntimeError(
                "TAS_POLICY_AUTHORIZATION=etcd requires requests; "
                "install dependencies from requirements.txt"
            ) from exc

        if isinstance(endpoints, str):
            endpoints = [item.strip() for item in endpoints.split(",") if item.strip()]
        if not isinstance(endpoints, (tuple, list)) or not endpoints:
            raise RuntimeError("TAS_ETCD_ENDPOINTS must contain at least one URL")
        for endpoint in endpoints:
            parsed = urlparse(endpoint)
            if parsed.scheme != "https" or not parsed.netloc:
                raise RuntimeError("TAS_ETCD_ENDPOINTS must contain HTTPS URLs")

        self._requests = requests
        self._endpoints = [endpoint.rstrip("/") for endpoint in endpoints]
        self._ca_file = ca_file
        self._credentials = (username, password)
        self._timeout_seconds = timeout_seconds
        self._client_cert = (cert_file, key_file) if cert_file and key_file else None
        self._session = requests.Session()
        self._token: str | None = None
        self._endpoint_index = 0
        # Round-robin reads can run concurrently, so keep index rotation atomic.
        self._lock = threading.Lock()
        # requests.Session and the cached bearer token are shared mutable state.
        self._request_lock = threading.Lock()

    @staticmethod
    def _b64(value: bytes) -> str:
        return base64.b64encode(value).decode("ascii")

    @staticmethod
    def _unb64(value: str) -> bytes:
        if not isinstance(value, str):
            raise ValueError("Expected base64 string")
        return base64.b64decode(value, validate=True)

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self._token:
            headers["Authorization"] = self._token
        return headers

    def _post(self, endpoint: str, path: str, body: dict, *, mutation: bool):
        start = self._endpoints.index(endpoint)
        # A read is safe to retry on another member after a transient failure.
        # A mutation is not: after a timeout, etcd may have committed it even
        # though TAS did not receive the response.
        candidates = (
            [endpoint]
            if mutation
            else self._endpoints[start:] + self._endpoints[:start]
        )
        last_error = None
        with self._request_lock:
            for candidate in candidates:
                try:
                    if not self._token:
                        self._authenticate(candidate)
                    response = self._session.post(
                        f"{candidate}{path}",
                        json=body,
                        headers=self._headers(),
                        timeout=self._timeout_seconds,
                        verify=self._ca_file,
                        cert=self._client_cert,
                        allow_redirects=False,
                    )
                except self._requests.RequestException as exc:
                    self._token = None
                    last_error = PolicyStoreUnavailable(
                        "etcd request failed", reason_code="authority_unavailable"
                    )
                    if mutation:
                        raise last_error from exc
                    continue
                except PolicyStoreUnavailable as exc:
                    self._token = None
                    if mutation or exc.reason_code == "authority_denied":
                        raise
                    last_error = exc
                    continue

                if response.status_code == 401:
                    self._token = None
                    if not mutation:
                        try:
                            self._authenticate(candidate)
                            response = self._session.post(
                                f"{candidate}{path}",
                                json=body,
                                headers=self._headers(),
                                timeout=self._timeout_seconds,
                                verify=self._ca_file,
                                cert=self._client_cert,
                                allow_redirects=False,
                            )
                        except self._requests.RequestException as exc:
                            last_error = PolicyStoreUnavailable(
                                "etcd request failed",
                                reason_code="authority_unavailable",
                            )
                            if candidate == candidates[-1]:
                                raise last_error from exc
                            continue
                        except PolicyStoreUnavailable as exc:
                            if candidate == candidates[-1]:
                                raise
                            last_error = exc
                            continue
                        if response.status_code != 401:
                            if 200 <= response.status_code < 300:
                                try:
                                    payload = response.json()
                                except (ValueError, json.JSONDecodeError) as exc:
                                    raise PolicyStoreUnavailable(
                                        "etcd returned an invalid response",
                                        reason_code="authority_invalid_response",
                                    ) from exc
                                if isinstance(payload, dict):
                                    return payload
                                raise PolicyStoreUnavailable(
                                    "etcd returned an invalid response",
                                    reason_code="authority_invalid_response",
                                )
                            if response.status_code >= 500:
                                last_error = PolicyStoreUnavailable(
                                    f"etcd returned HTTP {response.status_code}",
                                    reason_code="authority_unavailable",
                                )
                                continue
                    last_error = PolicyStoreUnavailable(
                        "etcd rejected TAS credentials",
                        reason_code="authority_denied",
                    )
                    if mutation:
                        raise last_error
                    continue
                if response.status_code < 200 or response.status_code >= 300:
                    self._token = None
                    last_error = PolicyStoreUnavailable(
                        f"etcd returned HTTP {response.status_code}",
                        reason_code="authority_unavailable",
                    )
                    if mutation or response.status_code < 500:
                        raise last_error
                    continue
                try:
                    payload = response.json()
                except (ValueError, json.JSONDecodeError) as exc:
                    raise PolicyStoreUnavailable(
                        "etcd returned an invalid response",
                        reason_code="authority_invalid_response",
                    ) from exc
                if not isinstance(payload, dict):
                    raise PolicyStoreUnavailable(
                        "etcd returned an invalid response",
                        reason_code="authority_invalid_response",
                    )
                return payload

        if last_error is not None:
            raise last_error
        raise PolicyStoreUnavailable(
            "etcd request failed", reason_code="authority_unavailable"
        )

    def _authenticate(self, endpoint: str) -> None:
        username, password = self._credentials
        try:
            response = self._session.post(
                f"{endpoint}/v3/auth/authenticate",
                json={"name": username, "password": password},
                timeout=self._timeout_seconds,
                verify=self._ca_file,
                cert=self._client_cert,
                allow_redirects=False,
            )
            if response.status_code in (401, 403):
                raise PolicyStoreUnavailable(
                    "etcd rejected TAS credentials",
                    reason_code="authority_denied",
                )
            response.raise_for_status()
            payload = response.json()
        except PolicyStoreUnavailable:
            raise
        except self._requests.RequestException as exc:
            raise PolicyStoreUnavailable(
                "etcd authentication failed", reason_code="authority_unavailable"
            ) from exc
        except (ValueError, json.JSONDecodeError) as exc:
            raise PolicyStoreUnavailable(
                "etcd returned an invalid authentication response",
                reason_code="authority_invalid_response",
            ) from exc
        token = payload.get("token") if isinstance(payload, dict) else None
        if not isinstance(token, str) or not token:
            raise PolicyStoreUnavailable(
                "etcd returned an invalid authentication response",
                reason_code="authority_invalid_response",
            )
        self._token = token

    def _read_endpoint(self):
        with self._lock:
            endpoint = self._endpoints[self._endpoint_index]
            self._endpoint_index = (self._endpoint_index + 1) % len(self._endpoints)
            return endpoint

    @staticmethod
    def _revision(value, name: str) -> int:
        if isinstance(value, bool) or not isinstance(value, (int, str)):
            raise PolicyStoreUnavailable(
                f"etcd response has invalid {name}",
                reason_code="authority_invalid_response",
            )
        if isinstance(value, str) and not value.isdecimal():
            raise PolicyStoreUnavailable(
                f"etcd response has invalid {name}",
                reason_code="authority_invalid_response",
            )
        try:
            revision = int(value)
        except (TypeError, ValueError) as exc:
            raise PolicyStoreUnavailable(
                f"etcd response has invalid {name}",
                reason_code="authority_invalid_response",
            ) from exc
        if revision < 0:
            raise PolicyStoreUnavailable(
                f"etcd response has invalid {name}",
                reason_code="authority_invalid_response",
            )
        return revision

    def _decode_kv(self, raw: dict) -> EtcdKV:
        try:
            return EtcdKV(
                key=self._unb64(raw["key"]),
                value=self._unb64(raw["value"]),
                create_revision=self._revision(
                    raw["create_revision"], "create_revision"
                ),
                mod_revision=self._revision(raw["mod_revision"], "mod_revision"),
                version=self._revision(raw["version"], "version"),
            )
        except (KeyError, TypeError, ValueError) as exc:
            if isinstance(exc, PolicyStoreUnavailable):
                raise
            raise PolicyStoreUnavailable(
                "etcd returned a malformed key-value record",
                reason_code="authority_invalid_response",
            ) from exc

    @classmethod
    def _transaction_result(cls, payload: dict) -> tuple[bool, int]:
        header = payload.get("header")
        if not isinstance(header, dict):
            raise PolicyStoreUnavailable(
                "etcd returned an invalid transaction response",
                reason_code="authority_invalid_response",
            )
        revision = cls._revision(header.get("revision"), "revision")
        # Protobuf JSON omits the succeeded field when its value is false.
        succeeded = payload.get("succeeded", False)
        if not isinstance(succeeded, bool):
            raise PolicyStoreUnavailable(
                "etcd returned an invalid transaction response",
                reason_code="authority_invalid_response",
            )
        return succeeded, revision

    def get(self, key: bytes) -> EtcdKV | None:
        endpoint = self._read_endpoint()
        payload = self._post(
            endpoint,
            "/v3/kv/range",
            {"key": self._b64(key)},
            mutation=False,
        )
        kvs = payload.get("kvs", [])
        if not isinstance(kvs, list):
            raise PolicyStoreUnavailable(
                "etcd returned an invalid range response",
                reason_code="authority_invalid_response",
            )
        if not kvs:
            return None
        if len(kvs) != 1 or not isinstance(kvs[0], dict):
            raise PolicyStoreUnavailable(
                "etcd returned an invalid exact-key range response",
                reason_code="authority_invalid_response",
            )
        return self._decode_kv(kvs[0])

    @staticmethod
    def _prefix_end(prefix: bytes) -> bytes:
        # etcd range queries use an exclusive upper bound. Incrementing the
        # last non-0xff byte yields the smallest key just beyond this prefix.
        result = bytearray(prefix)
        for index in range(len(result) - 1, -1, -1):
            if result[index] < 0xFF:
                result[index] += 1
                return bytes(result[: index + 1])
        return b"\x00"

    def range_prefix(self, prefix: bytes) -> list[EtcdKV]:
        endpoint = self._read_endpoint()
        payload = self._post(
            endpoint,
            "/v3/kv/range",
            {
                "key": self._b64(prefix),
                "range_end": self._b64(self._prefix_end(prefix)),
            },
            mutation=False,
        )
        kvs = payload.get("kvs", [])
        if not isinstance(kvs, list):
            raise PolicyStoreUnavailable(
                "etcd returned an invalid range response",
                reason_code="authority_invalid_response",
            )
        if any(not isinstance(raw, dict) for raw in kvs):
            raise PolicyStoreUnavailable(
                "etcd returned a malformed key-value record",
                reason_code="authority_invalid_response",
            )
        return [self._decode_kv(raw) for raw in kvs]

    def put_if_absent(self, key: bytes, value: bytes) -> tuple[bool, int | None]:
        """Create a key only if absent; return its txn revision on success.

        VERSION == 0 is an atomic reservation, so competing TAS instances
        cannot both claim the same policy ID.
        """
        endpoint = self._read_endpoint()
        payload = self._post(
            endpoint,
            "/v3/kv/txn",
            {
                "compare": [
                    {
                        "key": self._b64(key),
                        "target": "VERSION",
                        "result": "EQUAL",
                        "version": "0",
                    }
                ],
                "success": [
                    {
                        "request_put": {
                            "key": self._b64(key),
                            "value": self._b64(value),
                        }
                    }
                ],
                "failure": [],
            },
            mutation=True,
        )
        succeeded, revision = self._transaction_result(payload)
        return succeeded, revision if succeeded else None

    def put_if_revision(
        self, key: bytes, revision: int, value: bytes
    ) -> tuple[bool, int | None]:
        """Replace a key only if its modification revision is unchanged.

        This compare-and-swap fences updates against concurrent create/delete
        operations; a failed comparison means the caller must re-read state.
        """
        endpoint = self._read_endpoint()
        payload = self._post(
            endpoint,
            "/v3/kv/txn",
            {
                "compare": [
                    {
                        "key": self._b64(key),
                        "target": "MOD",
                        "result": "EQUAL",
                        "mod_revision": str(revision),
                    }
                ],
                "success": [
                    {
                        "request_put": {
                            "key": self._b64(key),
                            "value": self._b64(value),
                        }
                    }
                ],
                "failure": [],
            },
            mutation=True,
        )
        succeeded, revision = self._transaction_result(payload)
        return succeeded, revision if succeeded else None

    def delete_if_revision(self, key: bytes, revision: int) -> bool:
        """Delete a key only if it still has the supplied modification revision."""
        endpoint = self._read_endpoint()
        payload = self._post(
            endpoint,
            "/v3/kv/txn",
            {
                "compare": [
                    {
                        "key": self._b64(key),
                        "target": "MOD",
                        "result": "EQUAL",
                        "mod_revision": str(revision),
                    }
                ],
                "success": [{"request_delete_range": {"key": self._b64(key)}}],
                "failure": [],
            },
            mutation=True,
        )
        succeeded, _ = self._transaction_result(payload)
        return succeeded

    def check_revisions(self, revisions: list[tuple[bytes, int]]) -> bool:
        """Atomically verify that all supplied keys still have their revisions.

        The single transaction prevents a mixed-time check: every approval
        must still match at the transaction's linearization point.
        """
        if not revisions:
            return True
        endpoint = self._read_endpoint()
        compares = [
            {
                "key": self._b64(key),
                "target": "MOD",
                "result": "EQUAL",
                "mod_revision": str(revision),
            }
            for key, revision in revisions
        ]
        payload = self._post(
            endpoint,
            "/v3/kv/txn",
            {"compare": compares, "success": [], "failure": []},
            mutation=False,
        )
        succeeded, _ = self._transaction_result(payload)
        return succeeded
