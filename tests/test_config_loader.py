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
    monkeypatch.setenv("FLASK_DEBUG", "true")
    monkeypatch.setenv("FLASK_JSON_SORT_KEYS", "false")
    app = new_app()
    load_configuration(app)
    assert app.config["DEBUG"] is True
    assert app.config["JSON_SORT_KEYS"] is False


def test_tas_direct_env_overrides(monkeypatch):
    monkeypatch.setenv("TAS_API_KEY", LONG_API_KEY)
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
    monkeypatch.setenv("TAS_REDIS_HOST", "from_env")

    app = new_app()
    load_configuration(app)

    assert app.config["TAS_REDIS_HOST"] == "from_env"
    assert app.config["TAS_REDIS_PORT"] == 7000


def test_tas_override_nested_lowercasing(monkeypatch):
    # Loader lowercases TAS_OVERRIDE__ path parts
    monkeypatch.setenv("TAS_API_KEY", LONG_API_KEY)
    monkeypatch.setenv("TAS_OVERRIDE__Auth__JWKS__cache_seconds", "300")
    app = new_app()
    load_configuration(app)
    assert app.config["TAS"]["auth"]["jwks"]["cache_seconds"] == 300
