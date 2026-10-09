#
# TEE Attestation Service - OpenBao KBM Plugin Unit Tests
#
# Copyright 2026 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#

import base64
import io
import json
import os
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import MagicMock, patch

import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import padding as asympadding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from requests.exceptions import ConnectionError
from urllib3.exceptions import EmptyPoolError
from urllib3.response import HTTPResponse

from plugins.tas_kbm_openbao import (
    OpenBaoPoolTimeoutError,
    OpenBaoResponseError,
    OpenBaoUnavailableError,
    _build_url,
    _load_config_file,
    _load_rsa_public_key,
    _OpenBaoClient,
    _parse_bool,
    _read_secret_file,
    _validate_base_url,
    _validate_config,
    _validate_key_id,
    _validate_mount_name,
    kbm_close_client_connection,
    kbm_get_secret,
    kbm_open_client_connection,
)


class _ConcurrentOpenBaoHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    active_requests = 0
    peak_active_requests = 0
    lock = threading.Lock()

    def do_GET(self):
        with self.lock:
            type(self).active_requests += 1
            type(self).peak_active_requests = max(
                type(self).peak_active_requests, type(self).active_requests
            )

        try:
            time.sleep(0.05)
            body = json.dumps(
                {"data": {"data": {"secret": "concurrent-secret"}}}
            ).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        finally:
            with self.lock:
                type(self).active_requests -= 1

    def log_message(self, format, *args):
        pass


class TestOpenBaoKBM(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rsa_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        cls.rsa_pub_pem = cls.rsa_key.public_key().public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo,
        )
        # Provide default valid test environment for tests invoking kbm_open_client_connection()
        cls.env_patcher = patch.dict(os.environ, {"BAO_URL": "https://127.0.0.1:8200"})
        cls.env_patcher.start()

    @classmethod
    def tearDownClass(cls):
        cls.env_patcher.stop()

    def _decrypt_wrapped_secret(self, wrapped_dict: dict) -> bytes:
        """Helper to unwrap and decrypt the payload using the test RSA private key."""
        enc_aes_key = base64.b64decode(wrapped_dict["wrapped_key"])
        blob = base64.b64decode(wrapped_dict["blob"])
        iv = base64.b64decode(wrapped_dict["iv"])
        tag = base64.b64decode(wrapped_dict["tag"])

        aes_key = self.rsa_key.decrypt(
            enc_aes_key,
            asympadding.OAEP(
                mgf=asympadding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv, tag))
        dec = cipher.decryptor()
        return dec.update(blob) + dec.finalize()

    def test_load_config_file_with_env_substitution(self):
        with patch.dict(os.environ, {"TEST_BAO_TOKEN": "my-secret-token"}):
            with (
                patch("os.path.exists", return_value=True),
                patch("os.path.isfile", return_value=True),
                patch("os.access", return_value=True),
                patch(
                    "builtins.open",
                    unittest.mock.mock_open(
                        read_data="BAO_URL: https://localhost:8200\nBAO_TOKEN: ${TEST_BAO_TOKEN}\n"
                    ),
                ),
            ):
                cfg = _load_config_file("fake_config.yaml")
                self.assertEqual(cfg["BAO_URL"], "https://localhost:8200")
                self.assertEqual(cfg["BAO_TOKEN"], "my-secret-token")

    def test_load_config_file_not_found_raises(self):
        """None returns empty dict, but explicit non-existent path raises ValueError."""
        self.assertEqual(_load_config_file(None), {})
        with self.assertRaises(ValueError) as ctx:
            _load_config_file("/nonexistent/path/config.yaml")
        self.assertIn("not found", str(ctx.exception).lower())

    def test_load_config_file_unreadable_raises(self):
        """Explicit unreadable config file raises ValueError."""
        import tempfile

        with tempfile.NamedTemporaryFile("w", delete=False) as tf:
            tf.write("url: https://127.0.0.1:8200\n")
            path = tf.name
        try:
            with patch("os.access", return_value=False):
                with self.assertRaises(ValueError) as ctx:
                    _load_config_file(path)
                self.assertIn("readable", str(ctx.exception).lower())
        finally:
            os.remove(path)

    def test_load_config_file_malformed_yaml_raises(self):
        """Malformed YAML syntax raises ValueError immediately."""
        import tempfile

        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".yaml") as tf:
            tf.write("url: [unclosed yaml list\n")
            path = tf.name
        try:
            with self.assertRaises(ValueError) as ctx:
                _load_config_file(path)
            self.assertIn("yaml", str(ctx.exception).lower())
        finally:
            os.remove(path)

    def test_load_config_file_malformed_json_raises(self):
        """Malformed JSON syntax raises ValueError immediately."""
        import tempfile

        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".json") as tf:
            tf.write('{"url": "https://localhost:8200", unclosed json')
            path = tf.name
        try:
            with self.assertRaises(ValueError) as ctx:
                _load_config_file(path)
            self.assertIn("json", str(ctx.exception).lower())
        finally:
            os.remove(path)

    def test_load_config_file_not_a_mapping_raises(self):
        """Config file root that does not evaluate to a mapping raises ValueError."""
        import tempfile

        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".yaml") as tf:
            tf.write("- item1\n- item2\n")
            path = tf.name
        try:
            with self.assertRaises(ValueError) as ctx:
                _load_config_file(path)
            self.assertIn("dictionary", str(ctx.exception).lower())
        finally:
            os.remove(path)

    def test_client_connection_pooling_and_retry_config(self):
        client = _OpenBaoClient(
            retry_total=4,
            retry_backoff_factor=0.1,
            pool_connections=15,
            pool_maxsize=25,
        )
        self.assertEqual(client.retry_total, 4)
        self.assertEqual(client.retry_backoff_factor, 0.1)
        self.assertEqual(client.pool_connections, 15)
        self.assertEqual(client.pool_maxsize, 25)

        adapter = client.session.get_adapter("http://localhost:8200")
        self.assertEqual(adapter._pool_connections, 15)
        self.assertEqual(adapter._pool_maxsize, 25)
        self.assertTrue(adapter._pool_block)
        self.assertEqual(adapter.max_retries.total, 4)
        self.assertEqual(adapter.max_retries.backoff_factor, 0.1)

        # Verify urllib3 pool reflects the block=True configuration
        pool = adapter.poolmanager.connection_from_url("http://localhost:8200")
        self.assertTrue(pool.block)
        self.assertEqual(pool.pool.maxsize, 25)
        client.close()

    def test_missing_url_fails_startup(self):
        """Plugin fails startup if URL is omitted from both config and environment."""
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(ValueError) as ctx:
                kbm_open_client_connection()
            self.assertIn("url is required", str(ctx.exception).lower())

    def test_invalid_url_scheme_fails(self):
        """URL with non-HTTP/HTTPS scheme fails startup."""
        with patch.dict(os.environ, {"BAO_URL": "ftp://127.0.0.1:8200"}):
            with self.assertRaises(ValueError) as ctx:
                kbm_open_client_connection()
            self.assertIn("scheme", str(ctx.exception).lower())

    def test_insecure_http_with_verify_ssl_true_fails(self):
        """Insecure http:// scheme fails validation when verify_ssl is True."""
        with patch.dict(
            os.environ, {"BAO_URL": "http://127.0.0.1:8200", "BAO_VERIFY_SSL": "true"}
        ):
            with self.assertRaises(ValueError) as ctx:
                kbm_open_client_connection()
            self.assertIn("insecure", str(ctx.exception).lower())

    def test_insecure_http_with_verify_ssl_false_succeeds(self):
        """Insecure http:// scheme is permitted only when verify_ssl is False."""
        with patch.dict(
            os.environ, {"BAO_URL": "http://127.0.0.1:8200", "BAO_VERIFY_SSL": "false"}
        ):
            client = kbm_open_client_connection()
            self.assertEqual(client.url, "http://127.0.0.1:8200")
            self.assertFalse(client.verify_ssl)
            kbm_close_client_connection(client)

    def test_https_with_verify_ssl_true_succeeds(self):
        """HTTPS URL with verify_ssl True succeeds."""
        with patch.dict(
            os.environ, {"BAO_URL": "https://127.0.0.1:8200", "BAO_VERIFY_SSL": "true"}
        ):
            client = kbm_open_client_connection()
            self.assertEqual(client.url, "https://127.0.0.1:8200")
            self.assertTrue(client.verify_ssl)
            kbm_close_client_connection(client)

    def test_retry_on_server_error_and_success(self):
        """Verify that transient 5xx errors are retried automatically until successful."""
        client = _OpenBaoClient(retry_total=2, retry_backoff_factor=0.01)

        raw_503 = HTTPResponse(
            body=io.BytesIO(b"Service Unavailable"),
            headers={},
            status=503,
            reason="Service Unavailable",
            preload_content=False,
            request_method="GET",
        )
        body_200 = json.dumps({"data": {"data": {"secret": "retry-success"}}}).encode(
            "utf-8"
        )
        raw_200 = HTTPResponse(
            body=io.BytesIO(body_200),
            headers={"Content-Type": "application/json"},
            status=200,
            reason="OK",
            preload_content=False,
            request_method="GET",
        )

        with (
            patch("urllib3.connectionpool.HTTPConnectionPool._get_conn"),
            patch(
                "urllib3.connectionpool.HTTPConnectionPool._make_request",
                side_effect=[raw_503, raw_200],
            ) as mock_make_request,
        ):
            secret_bytes = client.get_secret("test-retry")
            self.assertEqual(secret_bytes, b"retry-success")
            self.assertEqual(mock_make_request.call_count, 2)

        client.close()

    @patch("requests.Session.get")
    def test_kbm_get_secret_success_kv2(self, mock_get):
        """Verify full retrieval and decryption flow for KV v2."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {"data": {"secret": "super-secret-payload"}}
        }
        mock_get.return_value = mock_resp

        client = kbm_open_client_connection()
        result = kbm_get_secret(client, "my-key-v2", self.rsa_pub_pem)

        for key in ("wrapped_key", "blob", "iv", "tag"):
            self.assertIn(key, result)

        decrypted = self._decrypt_wrapped_secret(result)
        self.assertEqual(decrypted, b"super-secret-payload")
        kbm_close_client_connection(client)

    @patch("requests.Session.get")
    def test_kbm_get_secret_success_kv1(self, mock_get):
        """Verify full retrieval and decryption flow for KV v1."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"data": {"secret": "kv1-secret-payload"}}
        mock_get.return_value = mock_resp

        client = _OpenBaoClient(kv_version=1)
        result = kbm_get_secret(client, "my-key-v1", self.rsa_pub_pem)
        decrypted = self._decrypt_wrapped_secret(result)
        self.assertEqual(decrypted, b"kv1-secret-payload")
        client.close()

    @patch("requests.Session.get")
    def test_kbm_get_secret_not_found(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_get.return_value = mock_resp

        client = kbm_open_client_connection()
        with self.assertRaises(ValueError) as ctx:
            kbm_get_secret(client, "nonexistent-key", self.rsa_pub_pem)
        self.assertNotIn("nonexistent-key", str(ctx.exception))
        kbm_close_client_connection(client)

    @patch("requests.Session.get")
    def test_kbm_get_secret_server_error(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_resp.text = "Internal Server Error"
        mock_get.return_value = mock_resp

        client = kbm_open_client_connection()
        with self.assertRaises(OpenBaoResponseError) as ctx:
            kbm_get_secret(client, "err-key", self.rsa_pub_pem)
        self.assertEqual(
            str(ctx.exception), "Secret service returned an invalid response"
        )
        self.assertNotIn("Internal Server Error", str(ctx.exception))
        self.assertNotIn("err-key", str(ctx.exception))
        kbm_close_client_connection(client)

    @patch("requests.Session.get")
    def test_kbm_get_secret_request_failure_is_unavailable(self, mock_get):
        mock_get.side_effect = ConnectionError("connection refused")

        client = kbm_open_client_connection()
        try:
            with self.assertRaises(OpenBaoUnavailableError) as ctx:
                client.get_secret("request-failure")
            self.assertNotIsInstance(ctx.exception, OpenBaoPoolTimeoutError)
            self.assertIsNone(ctx.exception.__cause__)
            self.assertNotIn("request-failure", str(ctx.exception))
        finally:
            kbm_close_client_connection(client)

    def test_kbm_get_secret_invalid_arguments(self):
        client = kbm_open_client_connection()

        with self.assertRaises(ValueError):
            kbm_get_secret("not-a-client", "key", self.rsa_pub_pem)

        with self.assertRaises(ValueError):
            kbm_get_secret(client, "", self.rsa_pub_pem)

        with self.assertRaises(ValueError):
            kbm_get_secret(client, "key", b"")

        with self.assertRaises(ValueError):
            kbm_get_secret(client, "key", b"invalid-pem-data")

        kbm_close_client_connection(client)

    def test_shipped_config_file_loading(self):
        """Verify that the shipped openbao.yaml uses and parses BAO_* options."""
        config_path = os.path.join(
            os.path.dirname(__file__), "..", "config", "openbao", "openbao.yaml"
        )
        self.assertTrue(
            os.path.isfile(config_path), f"Config file not found at {config_path}"
        )

        cfg = _load_config_file(config_path)
        self.assertIn(
            "BAO_REQUESTS_TIMEOUT",
            cfg,
            "BAO_REQUESTS_TIMEOUT key is missing or misspelled in config",
        )
        self.assertEqual(cfg["BAO_REQUESTS_TIMEOUT"], 30)
        self.assertIn("BAO_MOUNT_POINT", cfg)
        self.assertIn("BAO_KV_VERSION", cfg)
        self.assertEqual(cfg["BAO_URL"], "https://127.0.0.1:8200")
        self.assertIsNone(cfg.get("BAO_CA_BUNDLE"))
        with patch.dict(os.environ, {}, clear=True):
            client = kbm_open_client_connection(config_path)
            try:
                self.assertIs(client.verify_param, True)
            finally:
                client.close()

    def test_token_file_reading(self):
        """Verify token is correctly read from token_file when env token is not set."""
        import tempfile

        with tempfile.NamedTemporaryFile("w", delete=False) as tf:
            tf.write("secret-from-token-file\n")
            token_file_path = tf.name

        cfg_content = (
            f"BAO_URL: https://localhost:8200\nBAO_TOKEN_FILE: {token_file_path}\n"
        )
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".yaml") as cf:
            cf.write(cfg_content)
            config_yaml_path = cf.name

        try:
            with patch.dict(os.environ, {"BAO_TOKEN": "environment-token"}, clear=True):
                client = kbm_open_client_connection(config_yaml_path)
                self.assertEqual(client.token, "environment-token")
                kbm_close_client_connection(client)
        finally:
            os.remove(token_file_path)
            os.remove(config_yaml_path)

    def test_kv_mount_and_string_configuration_validation(self):
        for mount in ("secret", "kv", "/custom-mount/", "team/kv", "/team/kv/"):
            with self.subTest(mount=mount):
                client = _OpenBaoClient(mount_point=mount)
                try:
                    self.assertEqual(client.mount_point, mount.strip("/"))
                finally:
                    client.close()

        for mount in (
            "../../sys",
            "%2e%2e",
            "%252e%252e",
            "team//kv",
            "team/./kv",
            "team/../kv",
            r"team\kv",
            "team?kv",
            "team#kv",
        ):
            with self.subTest(mount=mount), self.assertRaises(ValueError):
                _OpenBaoClient(mount_point=mount)

        for kwargs in (
            {"mount_point": ["secret"]},
            {"secret_field": True},
            {"token": 123},
            {"secret_id_file": 123},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                _OpenBaoClient(**kwargs)

    def test_factory_rejects_invalid_string_configuration(self):
        invalid_configs = (
            {"BAO_MOUNT_POINT": ["secret"]},
            {"BAO_SECRET_FIELD": True},
            {"BAO_TOKEN": 123},
            {"BAO_TOKEN_FILE": 123},
            {"BAO_APPROLE_MOUNT": ["approle"]},
            {"BAO_MOUNT_POINT": "team//kv"},
            {"BAO_APPROLE_MOUNT": "team/../approle"},
        )
        for config in invalid_configs:
            with self.subTest(config=config):
                with patch(
                    "plugins.tas_kbm_openbao._load_config_file", return_value=config
                ):
                    with self.assertRaises(ValueError):
                        kbm_open_client_connection("ignored.yaml")

    def test_validate_key_id_positive(self):
        """Verify valid key_id patterns pass validation without error."""
        valid_keys = [
            "customer/key1",
            "prod/app/secret",
            "customer/app key",
            "my-key-v2",
        ]
        for key in valid_keys:
            with self.subTest(key=key):
                # Should not raise
                _validate_key_id(key)

    def test_validate_key_id_negative(self):
        """Verify invalid key_id values, traversal attempts, and special characters raise ValueError."""
        invalid_keys = [
            "..",
            "../secret",
            "secret/../admin",
            "abc?test=1",
            "abc#fragment",
            "abc\\test",
            "%2e%2e",
            "%2e%2e%2fadmin",
            "%252e%252e",
            "%252e%252e%252fadmin",
            "%252f",
            "%252F",
            "%255c",
            "%255C",
            "",
            "   ",
            "/leading/slash",
            "trailing/slash/",
            "double//slash",
            "secret\x00null",
            "secret\nnewline",
        ]
        for key in invalid_keys:
            with self.subTest(key=key):
                with self.assertRaises(ValueError):
                    _validate_key_id(key)

    def test_build_url_encoding_and_scope(self):
        """Verify URL encoding of path segments and scope verification."""
        # KV v2 encoding
        url_v2 = _build_url(
            base_url="http://127.0.0.1:8200",
            mount_point="secret",
            kv_version=2,
            key_id="customer/app key",
        )
        self.assertEqual(
            url_v2,
            "http://127.0.0.1:8200/v1/secret/data/customer/app%20key",
        )

        # KV v1 encoding
        url_v1 = _build_url(
            base_url="http://127.0.0.1:8200",
            mount_point="secret",
            kv_version=1,
            key_id="customer/app key",
        )
        self.assertEqual(
            url_v1,
            "http://127.0.0.1:8200/v1/secret/customer/app%20key",
        )

        for kv_version, suffix in (
            (1, "team/kv/customer/app"),
            (2, "team/kv/data/customer/app"),
        ):
            with self.subTest(kv_version=kv_version):
                self.assertEqual(
                    _build_url(
                        base_url="http://127.0.0.1:8200",
                        mount_point="team/kv",
                        kv_version=kv_version,
                        key_id="customer/app",
                    ),
                    f"http://127.0.0.1:8200/v1/{suffix}",
                )

    def test_parse_bool_valid(self):
        """Verify valid truthy and falsy boolean inputs."""
        self.assertTrue(_parse_bool(True, "test"))
        self.assertTrue(_parse_bool("true", "test"))
        self.assertTrue(_parse_bool("True", "test"))
        self.assertTrue(_parse_bool("1", "test"))
        self.assertTrue(_parse_bool(1, "test"))

        self.assertFalse(_parse_bool(False, "test"))
        self.assertFalse(_parse_bool("false", "test"))
        self.assertFalse(_parse_bool("FALSE", "test"))
        self.assertFalse(_parse_bool("0", "test"))
        self.assertFalse(_parse_bool(0, "test"))

    def test_parse_bool_invalid(self):
        """Verify invalid boolean values raise ValueError immediately."""
        invalid_values = ["yes", "no", "enabled", "on", "off", None, 2, -1, "", []]
        for val in invalid_values:
            with self.subTest(val=val):
                with self.assertRaises(ValueError):
                    _parse_bool(val, "verify_ssl")

    def test_verify_ssl_invalid_fails_startup(self):
        """Verify startup fails immediately on invalid verify_ssl configuration."""
        with patch.dict(os.environ, {"BAO_VERIFY_SSL": "invalid_val"}):
            with self.assertRaises(ValueError):
                kbm_open_client_connection()

    def test_ca_bundle_nonexistent_fails(self):
        """Configuring a non-existent CA bundle raises ValueError."""
        with patch.dict(
            os.environ,
            {
                "BAO_URL": "https://127.0.0.1:8200",
                "BAO_CA_BUNDLE": "/path/to/missing-ca.pem",
            },
        ):
            with self.assertRaises(ValueError) as ctx:
                kbm_open_client_connection()
            self.assertIn("ca_bundle", str(ctx.exception).lower())

    def test_ca_bundle_valid_file_succeeds(self):
        """Configuring an existing readable CA bundle passes validation."""
        import tempfile

        with tempfile.NamedTemporaryFile("w", delete=False) as tf:
            tf.write("-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n")
            ca_path = tf.name
        try:
            with patch.dict(
                os.environ,
                {
                    "BAO_URL": "https://127.0.0.1:8200",
                    "BAO_CA_BUNDLE": ca_path,
                },
            ):
                client = kbm_open_client_connection()
                self.assertEqual(client.ca_bundle, ca_path)
                self.assertEqual(client.verify_param, ca_path)
                kbm_close_client_connection(client)
        finally:
            os.remove(ca_path)

    def test_invalid_kv_version_fails(self):
        """kv_version values other than 1 or 2 raise ValueError."""
        invalid_versions = [0, 3, -1, 999, "invalid"]
        for ver in invalid_versions:
            with self.subTest(ver=ver):
                with patch.dict(
                    os.environ,
                    {
                        "BAO_URL": "https://127.0.0.1:8200",
                        "BAO_KV_VERSION": str(ver),
                    },
                ):
                    with self.assertRaises(ValueError) as ctx:
                        kbm_open_client_connection()
                    self.assertIn("kv_version", str(ctx.exception).lower())

    def test_valid_kv_version_succeeds(self):
        """kv_version 1 and 2 pass validation."""
        for ver in (1, 2):
            with self.subTest(ver=ver):
                with patch.dict(
                    os.environ,
                    {
                        "BAO_URL": "https://127.0.0.1:8200",
                        "BAO_KV_VERSION": str(ver),
                    },
                ):
                    client = kbm_open_client_connection()
                    self.assertEqual(client.kv_version, ver)
                    kbm_close_client_connection(client)

    def test_invalid_requests_timeout_fails(self):
        """requests_timeout <= 0 or non-numeric raises ValueError."""
        invalid_timeouts = [0, -1, -30, "not-a-number"]
        for timeout in invalid_timeouts:
            with self.subTest(timeout=timeout):
                with patch.dict(
                    os.environ,
                    {
                        "BAO_URL": "https://127.0.0.1:8200",
                        "BAO_REQUESTS_TIMEOUT": str(timeout),
                    },
                ):
                    with self.assertRaises(ValueError) as ctx:
                        kbm_open_client_connection()
                    self.assertIn("requests_timeout", str(ctx.exception).lower())

    def test_invalid_pool_connections_fails(self):
        """pool_connections <= 0 or invalid type raises ValueError."""
        for val in [0, -5, "abc"]:
            with self.subTest(val=val):
                with patch.dict(
                    os.environ,
                    {
                        "BAO_URL": "https://127.0.0.1:8200",
                        "BAO_POOL_CONNECTIONS": str(val),
                    },
                ):
                    with self.assertRaises(ValueError) as ctx:
                        kbm_open_client_connection()
                    self.assertIn("pool_connections", str(ctx.exception).lower())

    def test_invalid_pool_maxsize_fails(self):
        """pool_maxsize <= 0 or invalid type raises ValueError."""
        for val in [0, -10, "xyz"]:
            with self.subTest(val=val):
                with patch.dict(
                    os.environ,
                    {
                        "BAO_URL": "https://127.0.0.1:8200",
                        "BAO_POOL_MAXSIZE": str(val),
                    },
                ):
                    with self.assertRaises(ValueError) as ctx:
                        kbm_open_client_connection()
                    self.assertIn("pool_maxsize", str(ctx.exception).lower())

    def test_invalid_retry_total_fails(self):
        """retry_total < 0 or invalid type raises ValueError."""
        for val in [-1, -5, "bad"]:
            with self.subTest(val=val):
                with patch.dict(
                    os.environ,
                    {
                        "BAO_URL": "https://127.0.0.1:8200",
                        "BAO_RETRY_TOTAL": str(val),
                    },
                ):
                    with self.assertRaises(ValueError) as ctx:
                        kbm_open_client_connection()
                    self.assertIn("retry_total", str(ctx.exception).lower())

    def test_invalid_retry_backoff_factor_fails(self):
        """retry_backoff_factor < 0.0 or invalid type raises ValueError."""
        for val in [-0.1, -1.0, "bad"]:
            with self.subTest(val=val):
                with patch.dict(
                    os.environ,
                    {
                        "BAO_URL": "https://127.0.0.1:8200",
                        "BAO_RETRY_BACKOFF_FACTOR": str(val),
                    },
                ):
                    with self.assertRaises(ValueError) as ctx:
                        kbm_open_client_connection()
                    self.assertIn("retry_backoff_factor", str(ctx.exception).lower())

    def test_validate_config_helper_all_valid(self):
        """_validate_config passes cleanly with valid parameters."""
        # Should not raise
        _validate_config(
            url="https://bao.internal:8200",
            verify_ssl=True,
            ca_bundle=None,
            kv_version=2,
            requests_timeout=30,
            pool_connections=10,
            pool_maxsize=20,
            retry_total=3,
            retry_backoff_factor=0.05,
            max_secret_file_bytes=1024,
        )

    def test_validate_config_helper_catches_zero_timeout(self):
        """_validate_config raises ValueError if requests_timeout is zero."""
        with self.assertRaises(ValueError):
            _validate_config(
                url="https://bao.internal:8200",
                verify_ssl=True,
                ca_bundle=None,
                kv_version=2,
                requests_timeout=0,
                pool_connections=10,
                pool_maxsize=20,
                retry_total=3,
                retry_backoff_factor=0.05,
                max_secret_file_bytes=1024,
            )

    def test_rsa_public_key_succeeds(self):
        """1. Verify valid RSA public key succeeds and returns RSAPublicKey instance."""
        pub_key = _load_rsa_public_key(self.rsa_pub_pem)
        self.assertIsInstance(pub_key, rsa.RSAPublicKey)

    def test_non_rsa_public_key_raises(self):
        """2. Verify non-RSA (EC) public key is rejected with ValueError."""
        ec_key = ec.generate_private_key(ec.SECP256R1())
        ec_pub_pem = ec_key.public_key().public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo,
        )

        with self.assertRaises(ValueError) as ctx:
            _load_rsa_public_key(ec_pub_pem)
        self.assertIn("rsa public key", str(ctx.exception).lower())

        client = kbm_open_client_connection()
        try:
            with self.assertRaises(ValueError) as ctx:
                kbm_get_secret(client, "my-key", ec_pub_pem)
            self.assertIn("rsa public key", str(ctx.exception).lower())
        finally:
            kbm_close_client_connection(client)

    @patch("requests.Session.get")
    def test_missing_secret_field_raises(self, mock_get):
        """3. Verify missing secret_field raises ValueError without returning sibling data."""
        # KV v2 with single sibling field that should NOT be returned
        mock_resp_v2 = MagicMock()
        mock_resp_v2.status_code = 200
        mock_resp_v2.json.return_value = {
            "data": {"data": {"sibling_secret": "sibling-value"}}
        }
        mock_get.return_value = mock_resp_v2

        client = kbm_open_client_connection()
        try:
            with self.assertRaises(ValueError) as ctx:
                kbm_get_secret(client, "key-v2", self.rsa_pub_pem)
            self.assertIn("not found", str(ctx.exception).lower())
        finally:
            kbm_close_client_connection(client)

        # KV v1 with multi-field data missing configured secret_field
        mock_resp_v1 = MagicMock()
        mock_resp_v1.status_code = 200
        mock_resp_v1.json.return_value = {
            "data": {"field_a": "val_a", "field_b": "val_b"}
        }
        mock_get.return_value = mock_resp_v1

        client_v1 = _OpenBaoClient(kv_version=1, secret_field="target_key")
        try:
            with self.assertRaises(ValueError) as ctx:
                client_v1.get_secret("key-v1")
            self.assertNotIn("target_key", str(ctx.exception))
        finally:
            client_v1.close()

    @patch("requests.Session.get")
    def test_null_response_data_raises(self, mock_get):
        """4. Verify null response data raises ValueError."""
        # KV v2 outer data null
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"data": None}
        mock_get.return_value = mock_resp

        client = kbm_open_client_connection()
        try:
            with self.assertRaises(OpenBaoResponseError) as ctx:
                client.get_secret("key-null-v2-outer")
            self.assertEqual(
                str(ctx.exception), "Secret service returned an invalid response"
            )

            # KV v2 inner secret data null
            mock_resp.json.return_value = {"data": {"data": None}}
            with self.assertRaises(OpenBaoResponseError) as ctx:
                client.get_secret("key-null-v2-inner")
            self.assertEqual(
                str(ctx.exception), "Secret service returned an invalid response"
            )
        finally:
            kbm_close_client_connection(client)

        # KV v1 data null
        mock_resp.json.return_value = {"data": None}
        client_v1 = _OpenBaoClient(kv_version=1)
        try:
            with self.assertRaises(OpenBaoResponseError) as ctx:
                client_v1.get_secret("key-null-v1")
            self.assertEqual(
                str(ctx.exception), "Secret service returned an invalid response"
            )
        finally:
            client_v1.close()

    @patch("requests.Session.get")
    def test_invalid_response_structure_raises(self, mock_get):
        """5. Verify malformed payloads and invalid response structures raise ValueError."""
        client = kbm_open_client_connection()
        try:
            # Malformed JSON in response
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.side_effect = ValueError("Expecting value: line 1 column 1")
            mock_get.return_value = mock_resp
            with self.assertRaises(OpenBaoResponseError) as ctx:
                client.get_secret("key-malformed-json")
            self.assertEqual(
                str(ctx.exception), "Secret service returned an invalid response"
            )

            # Top-level is not a dictionary (e.g. JSON list)
            mock_resp.json.side_effect = None
            mock_resp.json.return_value = ["not", "a", "dict"]
            with self.assertRaises(OpenBaoResponseError) as ctx:
                client.get_secret("key-list-payload")
            self.assertEqual(
                str(ctx.exception), "Secret service returned an invalid response"
            )

            # KV v2 outer data is not a dictionary
            mock_resp.json.return_value = {"data": "not-a-dict"}
            with self.assertRaises(OpenBaoResponseError) as ctx:
                client.get_secret("key-invalid-v2-outer")
            self.assertEqual(
                str(ctx.exception), "Secret service returned an invalid response"
            )

            # KV v2 inner secret data is not a dictionary
            mock_resp.json.return_value = {"data": {"data": "not-a-dict"}}
            with self.assertRaises(OpenBaoResponseError) as ctx:
                client.get_secret("key-invalid-v2-inner")
            self.assertEqual(
                str(ctx.exception), "Secret service returned an invalid response"
            )

            # KV v1 secret data is not a dictionary
            client_v1 = _OpenBaoClient(kv_version=1)
            mock_resp.json.return_value = {"data": [1, 2, 3]}
            try:
                with self.assertRaises(OpenBaoResponseError) as ctx:
                    client_v1.get_secret("key-invalid-v1")
                self.assertEqual(
                    str(ctx.exception), "Secret service returned an invalid response"
                )
            finally:
                client_v1.close()
        finally:
            kbm_close_client_connection(client)

    def test_connection_pool_bounded_concurrency(self):
        """Verify real HTTP concurrency stays within the configured pool bound."""
        pool_maxsize = 2
        num_workers = 6
        _ConcurrentOpenBaoHandler.active_requests = 0
        _ConcurrentOpenBaoHandler.peak_active_requests = 0
        server = ThreadingHTTPServer(("127.0.0.1", 0), _ConcurrentOpenBaoHandler)
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()

        client = _OpenBaoClient(
            url=f"http://127.0.0.1:{server.server_port}",
            pool_connections=1,
            pool_maxsize=pool_maxsize,
            retry_total=0,
            requests_timeout=10,
        )

        lock = threading.Lock()
        results = []
        errors = []
        threads = []

        def worker():
            try:
                result = client.get_secret("test-concurrency")
                with lock:
                    results.append(result)
            except Exception as error:
                with lock:
                    errors.append(error)

        try:
            for _ in range(num_workers):
                thread = threading.Thread(target=worker)
                threads.append(thread)
                thread.start()

            for thread in threads:
                thread.join(timeout=10)

            self.assertTrue(all(not thread.is_alive() for thread in threads))
            self.assertEqual(errors, [])
            self.assertEqual(len(results), num_workers)
            self.assertTrue(all(result == b"concurrent-secret" for result in results))
            self.assertGreater(_ConcurrentOpenBaoHandler.peak_active_requests, 0)
            self.assertLessEqual(
                _ConcurrentOpenBaoHandler.peak_active_requests, pool_maxsize
            )
        finally:
            client.close()
            server.shutdown()
            server.server_close()
            server_thread.join(timeout=5)

    def test_request_connection_failure_is_unavailable(self):
        """Request failures are unavailable, even when caused by pool exhaustion."""
        client = _OpenBaoClient(
            url="http://127.0.0.1:8200",
            pool_connections=1,
            pool_maxsize=1,
            requests_timeout=0.1,
            retry_total=0,
        )

        adapter = client.session.get_adapter("http://127.0.0.1:8200")
        pool = adapter.poolmanager.connection_from_url("http://127.0.0.1:8200")
        err = EmptyPoolError(pool, "Pool is full and request timed out")
        req_err = ConnectionError(err)

        with patch.object(client.session, "send", side_effect=req_err):
            with self.assertRaises(OpenBaoUnavailableError) as ctx:
                client.get_secret("test-exhaustion")

            self.assertEqual(
                str(ctx.exception), "Secret service is temporarily unavailable"
            )
            self.assertNotIsInstance(ctx.exception, OpenBaoPoolTimeoutError)
            self.assertIsNone(ctx.exception.__cause__)

        client.close()

    def test_connection_pool_semaphore_exhaustion_timeout(self):
        """Demonstrate that semaphore acquisition bounds pool exhaustion wait time."""
        client = _OpenBaoClient(
            url="http://127.0.0.1:8200",
            pool_connections=1,
            pool_maxsize=1,
            requests_timeout=0.05,
            retry_total=0,
        )

        # Acquire the single semaphore permit so any call to get_secret must block
        self.assertTrue(client._pool_semaphore.acquire(blocking=False))
        try:
            with self.assertRaises(OpenBaoPoolTimeoutError) as ctx:
                client.get_secret("test-semaphore-exhaustion")
            self.assertEqual(
                str(ctx.exception), "Secret service is temporarily unavailable"
            )
            self.assertNotIn("test-semaphore-exhaustion", str(ctx.exception))
            self.assertNotIn("0.05", str(ctx.exception))
        finally:
            client._pool_semaphore.release()
            client.close()

    def test_rsa_public_key_under_2048_bits_raises(self):
        """Verify RSA public keys smaller than 2048 bits are rejected with ValueError."""
        weak_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=1024,
        )
        weak_pub_pem = weak_key.public_key().public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo,
        )

        with self.assertRaises(ValueError) as ctx:
            _load_rsa_public_key(weak_pub_pem)
        self.assertIn(
            "minimum required rsa key size is 2048 bits", str(ctx.exception).lower()
        )

        client = kbm_open_client_connection()
        try:
            with self.assertRaises(ValueError) as ctx:
                kbm_get_secret(client, "my-key", weak_pub_pem)
            self.assertIn(
                "minimum required rsa key size is 2048 bits", str(ctx.exception).lower()
            )
        finally:
            kbm_close_client_connection(client)

    @patch("requests.Session.get")
    def test_null_secret_field_value_raises(self, mock_get):
        """Verify that a secret field present with a null value is an invalid response."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"data": {"data": {"secret": None}}}
        mock_get.return_value = mock_resp

        client = kbm_open_client_connection()
        try:
            with self.assertRaises(OpenBaoResponseError) as ctx:
                client.get_secret("key-with-null-val")
            self.assertEqual(
                str(ctx.exception), "Secret service returned an invalid response"
            )
        finally:
            kbm_close_client_connection(client)

    def test_integer_settings_reject_booleans_and_fractions(self):
        for bad_val in [True, False, 1.5, "1.5", "nan", "inf"]:
            with self.subTest(bad_val=bad_val):
                with patch.dict(
                    os.environ,
                    {
                        "BAO_URL": "https://127.0.0.1:8200",
                        "BAO_KV_VERSION": str(bad_val),
                    },
                ):
                    with self.assertRaises(ValueError):
                        kbm_open_client_connection()

    def test_retry_backoff_factor_rejects_nan_and_inf(self):
        for bad_val in ["nan", "inf", "-inf", float("nan"), float("inf")]:
            with self.subTest(bad_val=bad_val):
                with patch.dict(
                    os.environ,
                    {
                        "BAO_URL": "https://127.0.0.1:8200",
                        "BAO_RETRY_BACKOFF_FACTOR": str(bad_val),
                    },
                ):
                    with self.assertRaises(ValueError):
                        kbm_open_client_connection()

    @patch("requests.Session.post")
    def test_approle_login_sets_token_and_uses_expected_request(self, mock_post):
        response = MagicMock(status_code=200)
        response.json.return_value = {"auth": {"client_token": " client-token "}}
        mock_post.return_value = response
        client = _OpenBaoClient(
            url="https://bao.example:8200",
            auth_method="approle",
            role_id="role-id",
            secret_id="secret-id",
        )
        try:
            mock_post.assert_called_once_with(
                "https://bao.example:8200/v1/auth/approle/login",
                verify=True,
                timeout=30,
                allow_redirects=False,
                json={"role_id": "role-id", "secret_id": "secret-id"},
            )
            self.assertEqual(client.token, "client-token")
            self.assertEqual(client.session.headers["X-Vault-Token"], "client-token")
        finally:
            client.close()

    def test_approle_constructor_requires_credentials_and_valid_types(self):
        cases = [
            {"auth_method": "approle"},
            {"auth_method": "approle", "role_id": "role"},
            {"auth_method": 1},
            {"auth_method": "approle", "role_id": 1, "secret_id": "secret"},
            {
                "auth_method": "approle",
                "role_id": "role",
                "secret_id": "secret",
                "token_renew_on_401": 1,
            },
        ]
        for kwargs in cases:
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                _OpenBaoClient(url="https://bao.example:8200", **kwargs)

    def test_factory_rejects_invalid_renewal_configuration(self):
        with patch(
            "plugins.tas_kbm_openbao._load_config_file",
            return_value={"BAO_TOKEN_RENEW_ON_401": "maybe"},
        ):
            with self.assertRaises(ValueError):
                kbm_open_client_connection("ignored.yaml")

    def test_approle_mount_validation(self):
        self.assertEqual(
            _validate_mount_name("/custom-mount/", "approle_mount"), "custom-mount"
        )
        self.assertEqual(_validate_mount_name("team/approle"), "team/approle")
        for value in (
            "",
            ".",
            "..",
            "a//b",
            "a/./b",
            "a/../b",
            "a?b",
            "a#b",
            r"a\b",
            "%2e%2e",
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                _validate_mount_name(value, "approle_mount")

    @patch("requests.Session.post")
    def test_approle_secret_file_takes_precedence(self, mock_post):
        import tempfile

        response = MagicMock(status_code=200)
        response.json.return_value = {"auth": {"client_token": "client-token"}}
        mock_post.return_value = response
        with tempfile.NamedTemporaryFile("w", delete=False) as secret_file:
            secret_file.write("file-secret\n")
            path = secret_file.name
        try:
            client = _OpenBaoClient(
                url="https://bao.example:8200",
                auth_method="approle",
                role_id="role-id",
                secret_id="inline-secret",
                secret_id_file=path,
            )
            try:
                self.assertEqual(
                    mock_post.call_args.kwargs["json"]["secret_id"], "file-secret"
                )
            finally:
                client.close()
        finally:
            os.remove(path)

    def test_secret_id_file_rejects_directory_and_empty_file(self):
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                _read_secret_file(directory, "secret_id_file")
        with tempfile.NamedTemporaryFile("w", delete=False) as secret_file:
            path = secret_file.name
        try:
            with self.assertRaises(ValueError):
                _read_secret_file(path, "secret_id_file")
        finally:
            os.remove(path)

    def test_configured_secret_file_size_limit_is_applied(self):
        import tempfile

        with tempfile.NamedTemporaryFile("w", delete=False) as secret_file:
            secret_file.write("12345")
            path = secret_file.name
        try:
            with (
                patch("plugins.tas_kbm_openbao._load_config_file", return_value={}),
                patch.dict(
                    os.environ,
                    {
                        "BAO_AUTH_METHOD": "approle",
                        "BAO_ROLE_ID": "role-id",
                        "BAO_SECRET_ID_FILE": path,
                        "BAO_MAX_SECRET_FILE_BYTES": "3",
                    },
                ),
            ):
                with self.assertRaisesRegex(
                    ValueError, "maximum allowed size of 4 bytes"
                ):
                    kbm_open_client_connection("ignored.yaml")
        finally:
            os.remove(path)

    def test_secret_id_file_rejects_symlink(self):
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            target = os.path.join(directory, "secret")
            link = os.path.join(directory, "secret-link")
            with open(target, "w", encoding="utf-8") as secret_file:
                secret_file.write("secret")
            os.symlink(target, link)
            with self.assertRaises(ValueError):
                _read_secret_file(link, "secret_id_file")

    @patch("requests.Session.post")
    def test_approle_login_status_classification(self, mock_post):
        for status in (401, 403, 418):
            response = MagicMock(status_code=status)
            mock_post.return_value = response
            with self.subTest(status=status), self.assertRaises(OpenBaoResponseError):
                _OpenBaoClient(
                    url="https://bao.example:8200",
                    auth_method="approle",
                    role_id="role-id",
                    secret_id="secret-id",
                )
        for status in (429, 500, 502, 503, 504):
            response = MagicMock(status_code=status)
            mock_post.return_value = response
            with (
                self.subTest(status=status),
                self.assertRaises(OpenBaoUnavailableError),
            ):
                _OpenBaoClient(
                    url="https://bao.example:8200",
                    auth_method="approle",
                    role_id="role-id",
                    secret_id="secret-id",
                )

    @patch("requests.Session.post")
    def test_failed_approle_initialization_closes_session(self, mock_post):
        mock_post.side_effect = ConnectionError(
            "https://role-id:secret-id@bao.example/login"
        )
        with patch.object(requests.Session, "close") as mock_close:
            with self.assertRaises(OpenBaoUnavailableError) as context:
                _OpenBaoClient(
                    url="https://bao.example:8200",
                    auth_method="approle",
                    role_id="role-id",
                    secret_id="secret-id",
                )
        mock_close.assert_called_once()
        self.assertNotIn("role-id", str(context.exception))
        self.assertNotIn("secret-id", str(context.exception))

    @patch("requests.Session.get")
    @patch("requests.Session.post")
    def test_approle_401_renews_token_before_retry(self, mock_post, mock_get):
        login_response = MagicMock(status_code=200)
        login_response.json.return_value = {"auth": {"client_token": "token-a"}}
        renew_response = MagicMock(status_code=200)
        renew_response.json.return_value = {"auth": {"client_token": "token-b"}}
        mock_post.side_effect = [login_response, renew_response]
        first = MagicMock(status_code=401)
        second = MagicMock(status_code=200)
        second.json.return_value = {"data": {"data": {"secret": "value"}}}
        mock_get.side_effect = [first, second]
        client = _OpenBaoClient(
            url="https://bao.example:8200",
            auth_method="approle",
            role_id="role-id",
            secret_id="secret-id",
        )
        try:
            client.get_secret("key")
            self.assertEqual(mock_post.call_count, 2)
            self.assertTrue(
                mock_post.call_args_list[1]
                .args[0]
                .endswith("/v1/auth/token/renew-self")
            )
            self.assertNotIn("json", mock_post.call_args_list[1].kwargs)
            self.assertEqual(mock_get.call_count, 2)
            self.assertEqual(client.token, "token-b")
        finally:
            client.close()

    @patch("requests.Session.post")
    def test_nested_approle_mount_login_url(self, mock_post):
        response = MagicMock(status_code=200)
        response.json.return_value = {"auth": {"client_token": "token-a"}}
        mock_post.return_value = response
        client = _OpenBaoClient(
            url="https://bao.example:8200",
            auth_method="approle",
            role_id="role-id",
            secret_id="secret-id",
            approle_mount="team/approle",
        )
        try:
            self.assertEqual(
                mock_post.call_args.args[0],
                "https://bao.example:8200/v1/auth/team/approle/login",
            )
        finally:
            client.close()

    @patch("requests.Session.get")
    @patch("requests.Session.post")
    def test_renewal_rejection_falls_back_to_approle_once(self, mock_post, mock_get):
        initial_login = MagicMock(status_code=200)
        initial_login.json.return_value = {"auth": {"client_token": "token-a"}}
        renewal_rejected = MagicMock(status_code=403)
        fallback_login = MagicMock(status_code=200)
        fallback_login.json.return_value = {"auth": {"client_token": "token-b"}}
        mock_post.side_effect = [initial_login, renewal_rejected, fallback_login]
        mock_get.side_effect = [MagicMock(status_code=401), MagicMock(status_code=401)]
        client = _OpenBaoClient(
            url="https://bao.example:8200",
            auth_method="approle",
            role_id="role-id",
            secret_id="secret-id",
        )
        try:
            response = client._make_request("GET", "https://bao.example:8200/v1/key")
            self.assertEqual(response.status_code, 401)
            self.assertEqual(mock_post.call_count, 3)
            self.assertEqual(mock_get.call_count, 2)
            self.assertEqual(
                mock_post.call_args_list[1].args[0],
                "https://bao.example:8200/v1/auth/token/renew-self",
            )
            self.assertNotIn("json", mock_post.call_args_list[1].kwargs)
        finally:
            client.close()

    @patch("requests.Session.get")
    @patch("requests.Session.post")
    def test_approle_relogin_reads_rotated_secret_id_file(self, mock_post, mock_get):
        import tempfile

        initial_login = MagicMock(status_code=200)
        initial_login.json.return_value = {"auth": {"client_token": "token-a"}}
        renewal_rejected = MagicMock(status_code=403)
        fallback_login = MagicMock(status_code=200)
        fallback_login.json.return_value = {"auth": {"client_token": "token-b"}}
        mock_post.side_effect = [initial_login, renewal_rejected, fallback_login]
        mock_get.side_effect = [MagicMock(status_code=401), MagicMock(status_code=200)]
        with tempfile.NamedTemporaryFile("w", delete=False) as secret_file:
            secret_file.write("old-secret")
            path = secret_file.name

        client = _OpenBaoClient(
            url="https://bao.example:8200",
            auth_method="approle",
            role_id="role-id",
            secret_id_file=path,
            max_secret_file_bytes=32,
        )
        try:
            with open(path, "w", encoding="utf-8") as secret_file:
                secret_file.write("rotated-secret")

            response = client._make_request("GET", "https://bao.example:8200/v1/key")

            self.assertEqual(response.status_code, 200)
            self.assertEqual(
                mock_post.call_args_list[0].kwargs["json"]["secret_id"], "old-secret"
            )
            self.assertEqual(
                mock_post.call_args_list[2].kwargs["json"]["secret_id"],
                "rotated-secret",
            )
        finally:
            client.close()
            os.remove(path)

    @patch("requests.Session.post")
    def test_static_token_mode_never_logs_in(self, mock_post):
        client = _OpenBaoClient(url="https://bao.example:8200", token="static-token")
        try:
            self.assertEqual(mock_post.call_count, 0)
            self.assertEqual(client.session.headers["X-Vault-Token"], "static-token")
        finally:
            client.close()

    @patch("requests.Session.get")
    @patch("requests.Session.post")
    def test_401_renewal_disabled_returns_original_response(self, mock_post, mock_get):
        login_response = MagicMock(status_code=200)
        login_response.json.return_value = {"auth": {"client_token": "token-a"}}
        mock_post.return_value = login_response
        mock_get.return_value = MagicMock(status_code=401)
        client = _OpenBaoClient(
            url="https://bao.example:8200",
            auth_method="approle",
            role_id="role-id",
            secret_id="secret-id",
            token_renew_on_401=False,
        )
        try:
            response = client._make_request(
                "GET", "https://bao.example:8200/v1/secret/data/key"
            )
            self.assertEqual(response.status_code, 401)
            self.assertEqual(mock_post.call_count, 1)
            self.assertEqual(mock_get.call_count, 1)
        finally:
            client.close()

    @patch("requests.Session.get")
    @patch("requests.Session.post")
    def test_second_401_does_not_trigger_another_login(self, mock_post, mock_get):
        login_response = MagicMock(status_code=200)
        login_response.json.return_value = {"auth": {"client_token": "token-b"}}
        mock_post.return_value = login_response
        mock_get.side_effect = [MagicMock(status_code=401), MagicMock(status_code=401)]
        client = _OpenBaoClient(
            url="https://bao.example:8200",
            auth_method="approle",
            role_id="role-id",
            secret_id="secret-id",
        )
        try:
            response = client._make_request(
                "GET", "https://bao.example:8200/v1/secret/data/key"
            )
            self.assertEqual(response.status_code, 401)
            self.assertEqual(mock_post.call_count, 2)
            self.assertEqual(mock_get.call_count, 2)
        finally:
            client.close()

    @patch("requests.Session.post")
    def test_login_rejects_malformed_success_payloads(self, mock_post):
        for payload in (
            {},
            {"auth": {}},
            {"auth": {"client_token": 1}},
            {"auth": {"client_token": ""}},
            {"auth": {"client_token": "   "}},
        ):
            response = MagicMock(status_code=200)
            response.json.return_value = payload
            mock_post.return_value = response
            with self.subTest(payload=payload), self.assertRaises(OpenBaoResponseError):
                _OpenBaoClient(
                    url="https://bao.example:8200",
                    auth_method="approle",
                    role_id="role-id",
                    secret_id="secret-id",
                )

    def test_credential_bearing_url_is_rejected_without_leaking_credentials(self):
        with self.assertRaises(ValueError) as context:
            _validate_config(
                url="https://user:password@bao.example:8200",
                verify_ssl=True,
                ca_bundle=None,
                kv_version=2,
                requests_timeout=30,
                pool_connections=1,
                pool_maxsize=1,
                retry_total=0,
                retry_backoff_factor=0,
                max_secret_file_bytes=1024,
            )
        self.assertNotIn("user", str(context.exception))
        self.assertNotIn("password", str(context.exception))

    def test_validate_config_rejects_invalid_secret_file_size_limit(self):
        for value in (0, -1, True, 1.5):
            with (
                self.subTest(value=value),
                self.assertRaisesRegex(ValueError, "max_secret_file_bytes"),
            ):
                _validate_config(
                    url="https://bao.internal:8200",
                    verify_ssl=True,
                    ca_bundle=None,
                    kv_version=2,
                    requests_timeout=30,
                    pool_connections=10,
                    pool_maxsize=20,
                    retry_total=3,
                    retry_backoff_factor=0.05,
                    max_secret_file_bytes=value,
                )

    @patch("requests.Session.get")
    @patch("requests.Session.post")
    def test_concurrent_401_requests_share_one_refresh(self, mock_post, mock_get):
        from concurrent.futures import ThreadPoolExecutor

        login = MagicMock(status_code=200)
        login.json.return_value = {"auth": {"client_token": "same-token"}}
        renew = MagicMock(status_code=200)
        renew.json.return_value = {"auth": {"client_token": "same-token"}}
        mock_post.side_effect = [login, renew]
        barrier = threading.Barrier(4)
        request_tokens = []
        request_counts = []
        request_lock = threading.Lock()
        thread_state = threading.local()

        def get_secret_response(*args, **kwargs):
            thread_state.request_count = getattr(thread_state, "request_count", 0) + 1
            with request_lock:
                request_tokens.append(client.session.headers.get("X-Vault-Token"))
                request_counts.append(thread_state.request_count)
            if thread_state.request_count == 1:
                barrier.wait(timeout=5)
                return MagicMock(status_code=401)
            return MagicMock(
                status_code=200,
                json=lambda: {"data": {"data": {"secret": "value"}}},
            )

        mock_get.side_effect = get_secret_response
        client = _OpenBaoClient(
            url="https://bao.example:8200",
            auth_method="approle",
            role_id="role-id",
            secret_id="secret-id",
        )

        def worker():
            barrier.wait()
            return client.get_secret("key")

        try:
            with ThreadPoolExecutor(max_workers=4) as executor:
                results = list(executor.map(lambda _: worker(), range(4)))
            self.assertEqual(results, [b"value"] * 4)
            self.assertEqual(mock_post.call_count, 2)
            self.assertEqual(mock_get.call_count, 8)
            self.assertEqual(client.session.headers["X-Vault-Token"], "same-token")
            self.assertEqual(request_tokens, ["same-token"] * 8)
            self.assertEqual(sorted(request_counts), [1, 1, 1, 1, 2, 2, 2, 2])
            self.assertEqual(client._pool_semaphore._value, client.pool_maxsize)
        finally:
            client.close()

    @patch("requests.Session.get")
    @patch("requests.Session.post")
    def test_concurrent_401_requests_share_failed_refresh(self, mock_post, mock_get):
        from concurrent.futures import ThreadPoolExecutor

        scenarios = (
            ([503], OpenBaoUnavailableError, 2),
            ([400, 403], OpenBaoResponseError, 3),
        )
        for refresh_statuses, expected_error, expected_post_count in scenarios:
            with self.subTest(expected_error=expected_error.__name__):
                mock_post.reset_mock()
                mock_get.reset_mock()
                login = MagicMock(status_code=200)
                login.json.return_value = {"auth": {"client_token": "token-a"}}
                mock_post.side_effect = [
                    login,
                    *(MagicMock(status_code=status) for status in refresh_statuses),
                ]
                request_barrier = threading.Barrier(4)

                def unauthorized_response(*args, **kwargs):
                    request_barrier.wait(timeout=5)
                    return MagicMock(status_code=401)

                mock_get.side_effect = unauthorized_response
                client = _OpenBaoClient(
                    url="https://bao.example:8200",
                    auth_method="approle",
                    role_id="role-id",
                    secret_id="secret-id",
                )

                def worker():
                    try:
                        return client.get_secret("key")
                    except Exception as error:
                        return error
                    self.fail("Expected failed reauthentication to be shared")

                try:
                    with ThreadPoolExecutor(max_workers=4) as executor:
                        errors = list(executor.map(lambda _: worker(), range(4)))
                    self.assertTrue(
                        all(isinstance(error, expected_error) for error in errors)
                    )
                    self.assertEqual(len({id(error) for error in errors}), 1)
                    self.assertEqual(mock_post.call_count, expected_post_count)
                    self.assertEqual(client._reauth_generation, 1)
                    self.assertEqual(client._token_generation, 1)
                    self.assertEqual(mock_get.call_count, 4)
                finally:
                    client.close()

    @patch("requests.Session.post")
    def test_later_request_retries_after_failed_refresh(self, mock_post):
        login = MagicMock(status_code=200)
        login.json.return_value = {"auth": {"client_token": "token-a"}}
        mock_post.return_value = login
        client = _OpenBaoClient(
            url="https://bao.example:8200",
            auth_method="approle",
            role_id="role-id",
            secret_id="secret-id",
        )
        success = MagicMock(status_code=200)
        with (
            patch.object(
                client,
                "_execute_request",
                side_effect=[
                    MagicMock(status_code=401),
                    MagicMock(status_code=401),
                    success,
                ],
            ),
            patch.object(
                client,
                "_renew_token",
                side_effect=[OpenBaoUnavailableError(), True],
            ) as renew_token,
        ):
            try:
                with self.assertRaises(OpenBaoUnavailableError):
                    client._make_request("GET", "https://bao.example:8200/v1/key")

                response = client._make_request(
                    "GET", "https://bao.example:8200/v1/key"
                )

                self.assertIs(response, success)
                self.assertEqual(renew_token.call_count, 2)
                self.assertEqual(client._reauth_generation, 2)
                self.assertIsNone(client._last_reauth_error)
            finally:
                client.close()
