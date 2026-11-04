#
# TEE Attestation Service - Test for config_loader.py
#
# Copyright 2025 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# This file is part of the TEE Attestation Service.
#
# This module is responsible for config_loader.py.
#

# config.py

import os
import textwrap

import pytest
from flask import Flask

from tas.config_loader import load_configuration

LONG_API_KEY = "a" * 64
LONG_MGMT_KEY = "b" * 64


def new_app():
    return Flask(__name__)


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    # Clear relevant env vars before each test
    for k in list(os.environ):
        if k.startswith(("TAS_", "FLASK_", "TAS_OVERRIDE__")) or k in (
            "TAS_CONFIG_FILE",
            "TAS_CONFIG_CLASS",
        ):
            monkeypatch.delenv(k, raising=False)
    # Set TAS_CONFIG_FILE to a non-existent file to prevent loading default config
    monkeypatch.setenv("TAS_CONFIG_FILE", "/nonexistent/config.yaml")
    yield


def test_requires_api_key():
    app = new_app()
    with pytest.raises(
        RuntimeError, match="TAS_API_KEY environment variable is not set"
    ):
        load_configuration(app)


def test_api_key_min_length(monkeypatch):
    monkeypatch.setenv("TAS_API_KEY", "short")
    app = new_app()
    with pytest.raises(RuntimeError, match="must be at least .* characters long"):
        load_configuration(app)


def test_flask_env_overrides(monkeypatch):
    monkeypatch.setenv("TAS_API_KEY", LONG_API_KEY)
    monkeypatch.setenv("TAS_MANAGEMENT_API_KEY", LONG_MGMT_KEY)
    monkeypatch.setenv("FLASK_DEBUG", "true")
    monkeypatch.setenv("FLASK_JSON_SORT_KEYS", "false")
    app = new_app()
    load_configuration(app)
    assert app.config["DEBUG"] is True
    assert app.config["JSON_SORT_KEYS"] is False


def test_tas_direct_env_overrides(monkeypatch):
    monkeypatch.setenv("TAS_API_KEY", LONG_API_KEY)
    monkeypatch.setenv("TAS_MANAGEMENT_API_KEY", LONG_MGMT_KEY)
    monkeypatch.setenv("TAS_REDIS_HOST", "redis.internal")
    monkeypatch.setenv("TAS_REDIS_PORT", "6380")
    app = new_app()
    load_configuration(app)
    assert app.config["TAS_REDIS_HOST"] == "redis.internal"
    assert app.config["TAS_REDIS_PORT"] == 6380  # coerced to int


def test_structured_file_uppercase_only(tmp_path, monkeypatch):
    yaml_text = textwrap.dedent(
        """
        TAS_REDIS_HOST: "filehost"
        TAS_REDIS_PORT: 6390
        tas:
          limits:
            max_nonce_per_minute: 200
        """
    )
    cfg = tmp_path / "tas_config.yaml"
    cfg.write_text(yaml_text, encoding="utf-8")

    monkeypatch.setenv("TAS_CONFIG_FILE", str(cfg))
    monkeypatch.setenv("TAS_API_KEY", LONG_API_KEY)
    monkeypatch.setenv("TAS_MANAGEMENT_API_KEY", LONG_MGMT_KEY)

    app = new_app()
    load_configuration(app)

    # Uppercase keys applied
    assert app.config["TAS_REDIS_HOST"] == "filehost"
    assert app.config["TAS_REDIS_PORT"] == 6390
    # Lowercase top-level 'tas' ignored by loader policy
    assert "tas" not in app.config
    assert (
        "TAS" not in app.config
        or not isinstance(app.config.get("TAS"), dict)
        or "limits" not in app.config["TAS"]
    )


def test_structured_file_TAS_bucket_deep_merge(tmp_path, monkeypatch):
    yaml_text = textwrap.dedent(
        """
        TAS:
          limits:
            max_nonce_per_minute: 200
          logging:
            level: "INFO"
        TAS_REDIS_HOST: "filehost"
        """
    )
    cfg = tmp_path / "tas_config.yaml"
    cfg.write_text(yaml_text, encoding="utf-8")

    monkeypatch.setenv("TAS_CONFIG_FILE", str(cfg))
    monkeypatch.setenv("TAS_API_KEY", LONG_API_KEY)
    monkeypatch.setenv("TAS_MANAGEMENT_API_KEY", LONG_MGMT_KEY)
    # Add an env override that should merge/override nested value
    monkeypatch.setenv("TAS_OVERRIDE__limits__max_nonce_per_minute", "250")

    app = new_app()
    load_configuration(app)

    assert app.config["TAS_REDIS_HOST"] == "filehost"
    # TAS bucket present and merged
    assert app.config["TAS"]["limits"]["max_nonce_per_minute"] == 250
    assert app.config["TAS"]["logging"]["level"] == "INFO"


def test_env_precedence_over_file(tmp_path, monkeypatch):
    yaml_text = "TAS_REDIS_HOST: from_file\nTAS_REDIS_PORT: 7000\n"
    cfg = tmp_path / "tas_config.yaml"
    cfg.write_text(yaml_text, encoding="utf-8")

    monkeypatch.setenv("TAS_CONFIG_FILE", str(cfg))
    monkeypatch.setenv("TAS_API_KEY", LONG_API_KEY)
    monkeypatch.setenv("TAS_MANAGEMENT_API_KEY", LONG_MGMT_KEY)
    monkeypatch.setenv("TAS_REDIS_HOST", "from_env")

    app = new_app()
    load_configuration(app)

    assert app.config["TAS_REDIS_HOST"] == "from_env"
    assert app.config["TAS_REDIS_PORT"] == 7000


def test_tas_override_nested_lowercasing(monkeypatch):
    # Loader lowercases TAS_OVERRIDE__ path parts
    monkeypatch.setenv("TAS_API_KEY", LONG_API_KEY)
    monkeypatch.setenv("TAS_MANAGEMENT_API_KEY", LONG_MGMT_KEY)
    monkeypatch.setenv("TAS_OVERRIDE__Auth__JWKS__cache_seconds", "300")
    app = new_app()
    load_configuration(app)
    assert app.config["TAS"]["auth"]["jwks"]["cache_seconds"] == 300


def test_requires_management_api_key(monkeypatch):
    monkeypatch.setenv("TAS_API_KEY", LONG_API_KEY)
    app = new_app()
    with pytest.raises(
        RuntimeError, match="TAS_MANAGEMENT_API_KEY environment variable is not set"
    ):
        load_configuration(app)


def test_management_api_key_min_length(monkeypatch):
    monkeypatch.setenv("TAS_API_KEY", LONG_API_KEY)
    monkeypatch.setenv("TAS_MANAGEMENT_API_KEY", "short")
    app = new_app()
    with pytest.raises(RuntimeError, match="TAS_MANAGEMENT_API_KEY must be at least"):
        load_configuration(app)


def _set_required_keys(monkeypatch):
    monkeypatch.setenv("TAS_API_KEY", LONG_API_KEY)
    monkeypatch.setenv("TAS_MANAGEMENT_API_KEY", LONG_MGMT_KEY)


def test_gpu_settings_defaults(monkeypatch):
    _set_required_keys(monkeypatch)
    app = new_app()
    load_configuration(app)
    assert app.config["TAS_NVIDIA_GPU_VERIFICATION_MODE"] == "remote"
    assert app.config["TAS_GPU_MAX_EVIDENCE_ENTRIES"] == 16


def test_postgresql_timeout_defaults(monkeypatch):
    _set_required_keys(monkeypatch)
    app = new_app()
    load_configuration(app)
    assert app.config["TAS_POSTGRES_CONNECT_TIMEOUT_SECONDS"] == 5
    assert app.config["TAS_POSTGRES_STATEMENT_TIMEOUT_SECONDS"] == 5


def test_postgresql_timeout_env_overrides(monkeypatch):
    _set_required_keys(monkeypatch)
    monkeypatch.setenv("TAS_POSTGRES_CONNECT_TIMEOUT_SECONDS", "12")
    monkeypatch.setenv("TAS_POSTGRES_STATEMENT_TIMEOUT_SECONDS", "2")
    app = new_app()
    load_configuration(app)
    assert app.config["TAS_POSTGRES_CONNECT_TIMEOUT_SECONDS"] == 12
    assert app.config["TAS_POSTGRES_STATEMENT_TIMEOUT_SECONDS"] == 2


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("TAS_POSTGRES_CONNECT_TIMEOUT_SECONDS", "0"),
        ("TAS_POSTGRES_CONNECT_TIMEOUT_SECONDS", "-1"),
        ("TAS_POSTGRES_CONNECT_TIMEOUT_SECONDS", "false"),
        ("TAS_POSTGRES_STATEMENT_TIMEOUT_SECONDS", "0"),
        ("TAS_POSTGRES_STATEMENT_TIMEOUT_SECONDS", "-1"),
        ("TAS_POSTGRES_STATEMENT_TIMEOUT_SECONDS", "five"),
    ],
)
def test_postgresql_timeouts_must_be_positive_integers(monkeypatch, key, value):
    _set_required_keys(monkeypatch)
    monkeypatch.setenv(key, value)
    app = new_app()
    with pytest.raises(RuntimeError, match=f"{key} must be a positive integer"):
        load_configuration(app)


def test_gpu_settings_env_overrides(monkeypatch):
    _set_required_keys(monkeypatch)
    monkeypatch.setenv("TAS_NVIDIA_GPU_VERIFICATION_MODE", "local")
    monkeypatch.setenv("TAS_GPU_MAX_EVIDENCE_ENTRIES", "32")
    app = new_app()
    load_configuration(app)
    assert app.config["TAS_NVIDIA_GPU_VERIFICATION_MODE"] == "local"
    assert app.config["TAS_GPU_MAX_EVIDENCE_ENTRIES"] == 32


def test_gpu_settings_file_overrides(tmp_path, monkeypatch):
    _set_required_keys(monkeypatch)
    cfg = tmp_path / "tas.yaml"
    cfg.write_text(
        textwrap.dedent(
            """
            TAS_NVIDIA_GPU_VERIFICATION_MODE: "local"
            TAS_GPU_MAX_EVIDENCE_ENTRIES: 8
            """
        )
    )
    monkeypatch.setenv("TAS_CONFIG_FILE", str(cfg))
    app = new_app()
    load_configuration(app)
    assert app.config["TAS_NVIDIA_GPU_VERIFICATION_MODE"] == "local"
    assert app.config["TAS_GPU_MAX_EVIDENCE_ENTRIES"] == 8


@pytest.mark.parametrize("bad_mode", ["nras", "Remote", "LOCAL", "", "offline"])
def test_invalid_gpu_verification_mode_rejected(monkeypatch, bad_mode):
    _set_required_keys(monkeypatch)
    monkeypatch.setenv("TAS_NVIDIA_GPU_VERIFICATION_MODE", bad_mode)
    app = new_app()
    with pytest.raises(
        RuntimeError,
        match="TAS_NVIDIA_GPU_VERIFICATION_MODE must be 'remote' or 'local'",
    ):
        load_configuration(app)


@pytest.mark.parametrize("bad_max", ["0", "-1", "sixteen", "1.5", "true", "[16]"])
def test_invalid_gpu_max_evidence_entries_rejected(monkeypatch, bad_max):
    _set_required_keys(monkeypatch)
    monkeypatch.setenv("TAS_GPU_MAX_EVIDENCE_ENTRIES", bad_max)
    app = new_app()
    with pytest.raises(
        RuntimeError, match="TAS_GPU_MAX_EVIDENCE_ENTRIES must be a positive integer"
    ):
        load_configuration(app)


def test_policy_backend_defaults_to_redis(monkeypatch):
    monkeypatch.setenv("TAS_API_KEY", LONG_API_KEY)
    monkeypatch.setenv("TAS_MANAGEMENT_API_KEY", LONG_MGMT_KEY)
    app = new_app()
    load_configuration(app)
    assert app.config["TAS_POLICY_BACKEND"] == "redis"
    assert app.config["TAS_POSTGRES_DSN"] == ""


def _set_etcd_settings(monkeypatch):
    _set_required_keys(monkeypatch)
    monkeypatch.setenv("TAS_POLICY_AUTHORIZATION", "etcd")
    monkeypatch.setenv("TAS_ETCD_ENDPOINTS", "https://etcd.internal:2379")
    monkeypatch.setenv("TAS_ETCD_CA_FILE", "/etc/tas/etcd-ca.pem")
    monkeypatch.setenv("TAS_ETCD_USERNAME", "tas")
    monkeypatch.setenv("TAS_ETCD_PASSWORD", "secret")


def test_etcd_authorization_settings_are_loaded(monkeypatch):
    _set_etcd_settings(monkeypatch)
    app = new_app()

    load_configuration(app)

    assert app.config["TAS_POLICY_AUTHORIZATION"] == "etcd"
    assert app.config["TAS_POLICY_OPERATION_TIMEOUT_SECONDS"] == 20
    assert app.config["TAS_ETCD_TIMEOUT_SECONDS"] == 5


@pytest.mark.parametrize(
    "missing_setting",
    [
        "TAS_ETCD_ENDPOINTS",
        "TAS_ETCD_CA_FILE",
        "TAS_ETCD_USERNAME",
        "TAS_ETCD_PASSWORD",
    ],
)
def test_etcd_authorization_requires_connection_settings(monkeypatch, missing_setting):
    _set_etcd_settings(monkeypatch)
    monkeypatch.delenv(missing_setting)
    app = new_app()

    with pytest.raises(RuntimeError, match=missing_setting):
        load_configuration(app)


def test_etcd_timeout_must_not_exceed_operation_deadline(monkeypatch):
    _set_etcd_settings(monkeypatch)
    monkeypatch.setenv("TAS_ETCD_TIMEOUT_SECONDS", "21")
    app = new_app()

    with pytest.raises(
        RuntimeError,
        match="TAS_ETCD_TIMEOUT_SECONDS must not exceed "
        "TAS_POLICY_OPERATION_TIMEOUT_SECONDS",
    ):
        load_configuration(app)


def test_etcd_mutual_tls_files_must_be_configured_together(monkeypatch):
    _set_etcd_settings(monkeypatch)
    monkeypatch.setenv("TAS_ETCD_CERT_FILE", "/etc/tas/client.pem")
    app = new_app()

    with pytest.raises(
        RuntimeError,
        match="TAS_ETCD_CERT_FILE and TAS_ETCD_KEY_FILE must be configured together",
    ):
        load_configuration(app)


def test_etcd_settings_load_from_config_file(tmp_path, monkeypatch):
    # Every etcd setting, including the password, can come from the config file.
    cfg = tmp_path / "tas_config.yaml"
    cfg.write_text(
        textwrap.dedent(
            """
            TAS_POLICY_AUTHORIZATION: "etcd"
            TAS_POLICY_OPERATION_TIMEOUT_SECONDS: 30
            TAS_ETCD_ENDPOINTS:
              - "https://etcd-1.internal:2379"
              - "https://etcd-2.internal:2379"
            TAS_ETCD_CA_FILE: "/etc/tas/etcd/ca.pem"
            TAS_ETCD_USERNAME: "tas"
            TAS_ETCD_PASSWORD: "secret"
            TAS_ETCD_CERT_FILE: "/etc/tas/etcd/client.pem"
            TAS_ETCD_KEY_FILE: "/etc/tas/etcd/client-key.pem"
            TAS_ETCD_TIMEOUT_SECONDS: 7
            """
        ),
        encoding="utf-8",
    )
    _set_required_keys(monkeypatch)
    monkeypatch.setenv("TAS_CONFIG_FILE", str(cfg))
    app = new_app()

    load_configuration(app)

    assert app.config["TAS_POLICY_AUTHORIZATION"] == "etcd"
    assert app.config["TAS_POLICY_OPERATION_TIMEOUT_SECONDS"] == 30
    assert app.config["TAS_ETCD_ENDPOINTS"] == [
        "https://etcd-1.internal:2379",
        "https://etcd-2.internal:2379",
    ]
    assert app.config["TAS_ETCD_CA_FILE"] == "/etc/tas/etcd/ca.pem"
    assert app.config["TAS_ETCD_USERNAME"] == "tas"
    assert app.config["TAS_ETCD_PASSWORD"] == "secret"
    assert app.config["TAS_ETCD_CERT_FILE"] == "/etc/tas/etcd/client.pem"
    assert app.config["TAS_ETCD_KEY_FILE"] == "/etc/tas/etcd/client-key.pem"
    assert app.config["TAS_ETCD_TIMEOUT_SECONDS"] == 7


def test_etcd_env_settings_override_config_file(tmp_path, monkeypatch):
    cfg = tmp_path / "tas_config.yaml"
    cfg.write_text(
        'TAS_ETCD_ENDPOINTS: "https://from-file:2379"\nTAS_ETCD_TIMEOUT_SECONDS: 3\n',
        encoding="utf-8",
    )
    _set_etcd_settings(monkeypatch)
    monkeypatch.setenv("TAS_CONFIG_FILE", str(cfg))
    monkeypatch.setenv("TAS_ETCD_TIMEOUT_SECONDS", "4")
    app = new_app()

    load_configuration(app)

    assert app.config["TAS_ETCD_ENDPOINTS"] == "https://etcd.internal:2379"
    assert app.config["TAS_ETCD_TIMEOUT_SECONDS"] == 4


def test_etcd_password_masked_in_debug_logs(monkeypatch, caplog):
    import logging

    _set_etcd_settings(monkeypatch)
    monkeypatch.setenv("TAS_ETCD_PASSWORD", "etcd_secret_pw_123")
    app = new_app()

    with caplog.at_level(logging.DEBUG, logger="tas"):
        load_configuration(app)

    assert app.config["TAS_ETCD_PASSWORD"] == "etcd_secret_pw_123"
    assert "etcd_secret_pw_123" not in caplog.text
    assert "TAS_ETCD_PASSWORD=***" in caplog.text


@pytest.mark.parametrize("invalid_backend", ["dual", "migrate", "both", "sqlite", ""])
def test_policy_backend_rejects_invalid_values(monkeypatch, invalid_backend):
    monkeypatch.setenv("TAS_API_KEY", LONG_API_KEY)
    monkeypatch.setenv("TAS_MANAGEMENT_API_KEY", LONG_MGMT_KEY)
    monkeypatch.setenv("TAS_POLICY_BACKEND", invalid_backend)
    app = new_app()
    with pytest.raises(RuntimeError, match="Unsupported TAS_POLICY_BACKEND"):
        load_configuration(app)


def test_postgresql_backend_requires_dsn(monkeypatch):
    monkeypatch.setenv("TAS_API_KEY", LONG_API_KEY)
    monkeypatch.setenv("TAS_MANAGEMENT_API_KEY", LONG_MGMT_KEY)
    monkeypatch.setenv("TAS_POLICY_BACKEND", "postgresql")
    app = new_app()
    with pytest.raises(
        RuntimeError,
        match="TAS_POSTGRES_DSN is required when TAS_POLICY_BACKEND='postgresql'",
    ):
        load_configuration(app)


def test_postgresql_dsn_masked_in_debug_logs(monkeypatch, caplog):
    import logging

    secret_dsn = "postgresql://tas_user:super_secret_pw_999@db.internal:5432/tas"
    monkeypatch.setenv("TAS_API_KEY", LONG_API_KEY)
    monkeypatch.setenv("TAS_MANAGEMENT_API_KEY", LONG_MGMT_KEY)
    monkeypatch.setenv("TAS_POLICY_BACKEND", "postgresql")
    monkeypatch.setenv("TAS_POSTGRES_DSN", secret_dsn)

    app = new_app()
    with caplog.at_level(logging.DEBUG, logger="tas"):
        load_configuration(app)

    assert app.config["TAS_POLICY_BACKEND"] == "postgresql"
    assert app.config["TAS_POSTGRES_DSN"] == secret_dsn
    assert "super_secret_pw_999" not in caplog.text
    assert secret_dsn not in caplog.text
    assert "TAS_POSTGRES_DSN=***" in caplog.text


def test_flask_and_nested_override_secrets_masked_in_debug_logs(monkeypatch, caplog):
    import logging

    _set_required_keys(monkeypatch)
    monkeypatch.setenv("FLASK_SECRET_KEY", "flask_secret_value_1")
    monkeypatch.setenv(
        "FLASK_RATELIMIT_STORAGE_URI",
        "redis://rl:uri_secret_value_2@rl.internal:6379/0",
    )
    monkeypatch.setenv("TAS_OVERRIDE__KBM__PASSWORD", "nested_secret_value_3")
    monkeypatch.setenv("TAS_OVERRIDE__AUTH__CLIENT_TOKEN", "nested_secret_value_4")
    monkeypatch.setenv(
        "TAS_OVERRIDE__CACHE__URL", "redis://user:uri_secret_value_5@cache.internal/0"
    )
    monkeypatch.setenv("TAS_OVERRIDE__LIMITS__MAX_NONCE_PER_MINUTE", "250")
    monkeypatch.setenv("TAS_ETCD_KEY_FILE", "/etc/tas/etcd/client-key.pem")
    app = new_app()

    with caplog.at_level(logging.DEBUG, logger="tas"):
        load_configuration(app)

    # Values still reach app.config unchanged; only the logs are redacted.
    assert app.config["SECRET_KEY"] == "flask_secret_value_1"
    assert app.config["TAS"]["kbm"]["password"] == "nested_secret_value_3"
    for n in range(1, 6):
        assert f"secret_value_{n}" not in caplog.text
    assert "SECRET_KEY=***" in caplog.text
    assert "RATELIMIT_STORAGE_URI=***" in caplog.text
    assert "TAS.kbm.password=***" in caplog.text
    assert "TAS.auth.client_token=***" in caplog.text
    assert "TAS.cache.url=redis://***@cache.internal/0" in caplog.text
    # Non-secret values stay visible so operators can debug configuration.
    assert "TAS.limits.max_nonce_per_minute=250" in caplog.text
    assert "TAS_ETCD_KEY_FILE=/etc/tas/etcd/client-key.pem" in caplog.text
