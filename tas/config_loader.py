#
# TEE Attestation Service - Configuration Loader Module
#
# Copyright 2025 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# This file is part of the TEE Attestation Service.
#
# This module is responsible for loading additional configurations.
#

import copy
import glob
import json

# config_loader.py
import os
from typing import Any, Dict

import yaml
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from .tas_logging import get_logger

logger = get_logger(__name__)

KNOWN_TAS_KEYS = {
    "TAS_VERSION",
    "TAS_API_KEY",
    "TAS_API_KEY_MIN_LENGTH",
    "TAS_NONCE_EXPIRATION_SECONDS",
    "TAS_REDIS_HOST",
    "TAS_REDIS_PORT",
    "TAS_PLUGIN_PREFIX",
    "TAS_KBM_CONFIG_FILE",
    "TAS_KBM_PLUGIN",
    "TAS_EXTRA_PLUGIN_DIR",
}


def _coerce(val: str):
    # Try JSON first
    try:
        return json.loads(val)
    except Exception:
        pass
    lv = val.lower()
    if lv in ("true", "false"):
        return lv == "true"
    try:
        return int(val)
    except ValueError:
        pass
    return val


def apply_flask_env_overrides(app):
    # Map FLASK_DEBUG -> app.config['DEBUG'], etc.
    flask_overrides = []
    for k, v in os.environ.items():
        if not k.startswith("FLASK_"):
            continue
        cfg_key = k[len("FLASK_") :]
        if cfg_key:  # ignore empty
            app.config[cfg_key] = _coerce(v.strip())
            flask_overrides.append(f"{cfg_key}={app.config[cfg_key]}")

    if flask_overrides:
        logger.debug(
            f"Applied Flask environment overrides: {', '.join(flask_overrides)}"
        )
    else:
        logger.debug("No Flask environment overrides found")


def _deep_merge(a: Dict[str, Any], b: Dict[str, Any]):
    r = copy.deepcopy(a)
    for k, v in b.items():
        if isinstance(v, dict) and isinstance(r.get(k), dict):
            r[k] = _deep_merge(r[k], v)
        else:
            r[k] = v
    return r


def _load_structured(path: str):
    if not path or not os.path.isfile(path):
        logger.warning(f"Config file not found or empty path: {path}")
        return {}

    logger.info(f"Loading structured config from: {path}")
    with open(path, "r", encoding="utf-8") as f:
        text = f.read()

    # Try YAML first
    if yaml:
        try:
            data = yaml.safe_load(text)
            if isinstance(data, dict):
                logger.debug(
                    f"Successfully loaded YAML config with keys: {list(data.keys())}"
                )
                return data
        except Exception as e:
            logger.warning(f"Failed to parse as YAML: {e}")

    # Fall back to JSON
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            logger.debug(
                f"Successfully loaded JSON config with keys: {list(data.keys())}"
            )
            return data
    except Exception as e:
        logger.warning(f"Failed to parse as JSON: {e}")

    logger.error(f"Could not parse config file {path} as YAML or JSON")
    return {}


def _load_trusted_keys(path: str):
    """Load public keys from a file or directory containing certificates/public keys."""
    public_keys = []

    if os.path.isfile(path):
        # Single file - try to load as certificate or public key
        try:
            with open(path, "rb") as f:
                data = f.read()

            # Try to load as X.509 certificate first
            try:
                cert = x509.load_pem_x509_certificate(data)
                public_keys.append(("certificate", path, cert.public_key()))
                logger.debug(f"Loaded certificate from: {path}")
            except Exception:
                # Try to load as public key
                try:
                    public_key = serialization.load_pem_public_key(data)
                    public_keys.append(("public_key", path, public_key))
                    logger.debug(f"Loaded public key from: {path}")
                except Exception as e:
                    logger.error(
                        f"Failed to load certificate or public key from {path}: {e}"
                    )

        except Exception as e:
            logger.error(f"Failed to read file {path}: {e}")

    elif os.path.isdir(path):
        # Directory - scan for certificate and public key files
        patterns = [
            os.path.join(path, "*.pem"),
            os.path.join(path, "*.crt"),
            os.path.join(path, "*.cer"),
            os.path.join(path, "*.pub"),
        ]

        files = []
        for pattern in patterns:
            files.extend(glob.glob(pattern))

        logger.debug(
            f"Found {len(files)} potential certificate/key files in directory: {path}"
        )

        for file in files:
            try:
                with open(file, "rb") as f:
                    data = f.read()

                # Try to load as X.509 certificate first
                try:
                    cert = x509.load_pem_x509_certificate(data)
                    public_keys.append(("certificate", file, cert.public_key()))
                    logger.debug(f"Loaded certificate from: {file}")
                except Exception:
                    # Try to load as public key
                    try:
                        public_key = serialization.load_pem_public_key(data)
                        public_keys.append(("public_key", file, public_key))
                        logger.debug(f"Loaded public key from: {file}")
                    except Exception:
                        logger.debug(
                            f"Skipping file {file} - not a valid certificate or public key"
                        )

            except Exception as e:
                logger.debug(f"Failed to read file {file}: {e}")
    else:
        logger.error(f"Path does not exist: {path}")

    logger.info(f"Loaded {len(public_keys)} public keys from: {path}")
    return public_keys


def apply_tas_env_overrides(app):
    # Direct overrides (exact match)
    direct_overrides = []
    for key in KNOWN_TAS_KEYS:
        if key in os.environ:
            app.config[key] = _coerce(os.environ[key])
            direct_overrides.append(f"{key}={app.config[key]}")

    if direct_overrides:
        logger.debug(
            f"Applied direct TAS environment overrides: {', '.join(direct_overrides)}"
        )

    # Nested override support: TAS_OVERRIDE__SECTION__KEY=value
    nested_overrides = []
    for raw_k, raw_v in os.environ.items():
        if not raw_k.startswith("TAS_OVERRIDE__"):
            continue
        parts = [p for p in raw_k[len("TAS_OVERRIDE__") :].split("__") if p]
        if not parts:
            continue  # ignore malformed keys
        cursor = app.config.setdefault("TAS", {})
        for part in parts[:-1]:
            cursor = cursor.setdefault(part.lower(), {})
        leaf = parts[-1].lower()
        cursor[leaf] = _coerce(raw_v.strip())
        nested_overrides.append(
            f"TAS.{'.'.join(p.lower() for p in parts)}={cursor[leaf]}"
        )

    if nested_overrides:
        logger.debug(
            f"Applied nested TAS environment overrides: {', '.join(nested_overrides)}"
        )

    if not direct_overrides and not nested_overrides:
        logger.debug("No TAS environment overrides found")


def load_configuration(app):
    logger.info("Starting configuration loading")

    # Select base class
    config_class = os.getenv("TAS_CONFIG_CLASS", "tas.config.BaseConfig")
    logger.info(f"Loading base config class: {config_class}")
    app.config.from_object(config_class)

    # Optional structured file
    structured_path = os.getenv("TAS_CONFIG_FILE", "./config/tas_config.yaml")
    logger.info(f"Loading structured config from: {structured_path}")
    data = _load_structured(structured_path)
    if data:
        logger.debug(f"Loaded config data with top-level keys: {list(data.keys())}")

        # Handle all config items, not just uppercase ones
        # Flask config keys are typically uppercase, but we also need to handle nested structures
        for key, value in data.items():
            if isinstance(key, str):
                if key.isupper():
                    # Direct Flask config keys
                    if key == "TAS" and isinstance(value, dict):
                        # Handle TAS bucket specially: deep-merge into app.config['TAS']
                        logger.debug(
                            f"Merging TAS config section with keys: {list(value.keys())}"
                        )
                        existing_tas = app.config.get("TAS", {})
                        if isinstance(existing_tas, dict):
                            app.config["TAS"] = _deep_merge(existing_tas, value)
                        else:
                            app.config["TAS"] = value
                    else:
                        logger.debug(
                            f"Setting config key {key} = {type(value).__name__}"
                        )
                        app.config[key] = value
                else:
                    # Ignore lowercase keys as per loader policy
                    logger.debug(f"Ignoring non-uppercase config key: {key}")
    else:
        logger.warning(f"No valid config data loaded from {structured_path}")

    # Apply FLASK_ env overrides
    logger.debug("Applying Flask environment overrides")
    apply_flask_env_overrides(app)

    # Final env overrides
    logger.debug("Applying TAS environment overrides")
    apply_tas_env_overrides(app)

    # Log final TAS config structure
    if "TAS" in app.config:
        logger.debug(
            f"Final TAS config keys: {list(app.config['TAS'].keys()) if isinstance(app.config['TAS'], dict) else 'not a dict'}"
        )

    # Validation
    api_key = app.config.get("TAS_API_KEY", "")
    if not api_key:
        logger.error("TAS_API_KEY environment variable is not set")
        raise RuntimeError("TAS_API_KEY environment variable is not set")
    if len(api_key) < app.config["TAS_API_KEY_MIN_LENGTH"]:
        logger.error(
            f"TAS_API_KEY length {len(api_key)} is less than required minimum {app.config['TAS_API_KEY_MIN_LENGTH']}"
        )
        raise RuntimeError(
            f"TAS_API_KEY must be at least {app.config['TAS_API_KEY_MIN_LENGTH']} characters long"
        )

    logger.debug("Loading trusted keys for policy verification")
    if "TAS_POLICY_TRUST" in app.config:
        trusted_keys = _load_trusted_keys(app.config["TAS_POLICY_TRUST"])
        if not trusted_keys:
            logger.error(
                f"No valid trusted keys loaded from {app.config['TAS_POLICY_TRUST']}"
            )
            raise RuntimeError(
                f"No valid trusted keys loaded from {app.config['TAS_POLICY_TRUST']}"
            )
        app.config["TAS_TRUSTED_KEYS"] = trusted_keys

    logger.info("Configuration loading completed successfully")
