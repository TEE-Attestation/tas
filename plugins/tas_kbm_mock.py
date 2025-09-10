#
# TEE Attestation Service - Mock KBM (software, no KMIP)
#
# Copyright 2025 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# This file is part of the TEE Attestation Service.
#
# This is a mock Key Management Backend (KBM) client implementation for testing.
#  DO NOT USE IN PRODUCTION.
# - Uses pure Python crypto (cryptography) for test purposes.
# - If a config file (YAML/JSON) provides `secrets`, they are used as-is.
# - When a config file is present and no `strict` is specified, strict defaults to True
#   so missing keys will NOT be derived (prevents implicit derivation from plaintext files).
# - Returns: {"wrapped_key": b64, "blob": b64, "iv": b64}

from __future__ import annotations

import base64
import json
import os
import secrets as _secrets
import threading
from typing import Any, Dict, Optional

try:
    import yaml  # PyYAML (listed in requirements)
except Exception:
    yaml = None

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding as sympadding
from cryptography.hazmat.primitives.asymmetric import padding as asympadding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import (
    load_der_public_key,
    load_pem_public_key,
)

from tas.tas_logging import get_logger

# Setup logging for the mock KBM plugin
logger = get_logger("tas.plugins.tas_kbm_mock")

AES_KEY_LEN = 32  # AES-256
IV_LEN = 16  # AES-CBC IV size
SECRET_LEN = 32  # default secret length when derivation is allowed


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _load_rsa_public_key(raw: bytes):
    try:
        return load_pem_public_key(raw)
    except Exception:
        pass
    try:
        return load_der_public_key(raw)
    except Exception as e:
        raise ValueError("Invalid RSA public key format") from e


def _pkcs7_pad(data: bytes) -> bytes:
    padder = sympadding.PKCS7(128).padder()
    return padder.update(data) + padder.finalize()


def _aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    enc = cipher.encryptor()
    return enc.update(_pkcs7_pad(plaintext)) + enc.finalize()


class _MockKBMClient:
    def __init__(self, strict: bool, secrets_map: Dict[str, bytes]):
        self.strict = bool(strict)
        self._secrets = dict(secrets_map)
        self._lock = threading.RLock()
        logger.debug(
            f"Initialized mock KBM client with strict={strict} and {len(secrets_map)} pre-configured secrets"
        )

    def get_secret(self, key_id: str) -> bytes:
        logger.debug(f"Retrieving secret for key_id: {key_id}")
        with self._lock:
            if key_id in self._secrets:
                logger.debug(f"Found pre-configured secret for key_id: {key_id}")
                return self._secrets[key_id]
            if self.strict:
                logger.error(f"Secret not found for key_id: {key_id} (strict mode)")
                raise ValueError("Secret not found")
            # Derivation allowed only when not strict (no plaintext file mandate)
            logger.debug(
                f"Generating random secret for key_id: {key_id} (non-strict mode)"
            )
            return _secrets.token_bytes(SECRET_LEN)


def _load_config_file(config_file: Optional[str]) -> Dict[str, Any]:
    if not config_file:
        logger.debug("No config file specified")
        return {}
    path = os.path.abspath(config_file)
    if not os.path.isfile(path):
        logger.warning(f"Config file not found: {path}")
        return {}

    logger.info(f"Loading mock KBM config from: {path}")
    # Try YAML first if extension suggests YAML and PyYAML is available
    _, ext = os.path.splitext(path.lower())
    if ext in (".yaml", ".yml") and yaml:
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
            if isinstance(data, dict):
                logger.debug(
                    f"Successfully loaded YAML config with keys: {list(data.keys())}"
                )
                return data
        except Exception as e:
            logger.warning(f"Failed to parse config as YAML: {e}")
    # Fallback JSON
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f) or {}
        logger.debug(f"Successfully loaded JSON config with keys: {list(data.keys())}")
        return data
    except Exception as e:
        logger.warning(f"Failed to parse config as JSON: {e}")
        return {}


def _secrets_map_from_config(cfg: Dict[str, Any]) -> Dict[str, bytes]:
    out: Dict[str, bytes] = {}
    raw = cfg.get("secrets")
    if not isinstance(raw, dict):
        logger.debug("No secrets section found in config")
        return out

    logger.debug(f"Processing {len(raw)} secrets from config")
    for k, v in raw.items():
        if not isinstance(k, str):
            logger.warning(f"Skipping non-string key: {k}")
            continue
        if isinstance(v, bytes):
            out[k] = v
        elif isinstance(v, bytearray):
            out[k] = bytes(v)
        elif isinstance(v, str):
            # Use as-is (plaintext), encoded to bytes
            out[k] = v.encode("utf-8")
        else:
            # For non-strings, store their JSON representation as bytes
            out[k] = json.dumps(v, separators=(",", ":")).encode("utf-8")
        logger.debug(f"Added secret for key: {k}")
    return out


def kbm_open_client_connection(config_file: str = None):
    """
    Initialize the mock KBM client.

    Config file (YAML or JSON) format (all optional):
      strict: bool         # if true, missing keys raise; defaults to True when a config file exists
      secrets:             # key_id -> plaintext secret (used as-is, no derivation)
        my-key-1: "plain-text-secret"
        my-key-2: "ffeeddccbbaa"   # kept as the exact string content, not decoded
    """
    logger.info("Initializing mock KBM client connection")
    cfg = _load_config_file(config_file)
    secrets_map = _secrets_map_from_config(cfg)

    # If a config file exists and strict not specified, default to True to avoid derivation
    if cfg:
        strict = bool(cfg.get("strict", True))
    else:
        strict = bool(cfg.get("strict", False)) if isinstance(cfg, dict) else False

    logger.info(f"Mock KBM client initialized with strict={strict}")
    return _MockKBMClient(strict=strict, secrets_map=secrets_map)


def kbm_close_client_connection(kmip_client) -> None:
    logger.info("Closing mock KBM client connection")
    return None


def kbm_get_secret(kmip_client, key_id: str, wrapping_key: bytes):
    """
    Return dict: {"wrapped_key": b64, "blob": b64, "iv": b64}
    """
    logger.info(f"Mock KBM get_secret request for key_id: {key_id}")

    if not isinstance(kmip_client, _MockKBMClient):
        logger.error("Invalid client handle provided")
        raise ValueError("Invalid client handle")
    if not key_id:
        logger.error("key_id is required but not provided")
        raise ValueError("key_id required")
    if not wrapping_key:
        logger.error("wrapping_key is required but not provided")
        raise ValueError("wrapping_key (client RSA public key) is required")

    logger.debug("Loading RSA public key from wrapping_key")
    pub = _load_rsa_public_key(wrapping_key)
    secret = kmip_client.get_secret(key_id)

    logger.debug("Generating AES key and IV for secret wrapping")
    aes_key = _secrets.token_bytes(AES_KEY_LEN)
    iv = _secrets.token_bytes(IV_LEN)

    logger.debug("Encrypting secret with AES-CBC")
    blob = _aes_cbc_encrypt(aes_key, iv, secret)

    logger.debug("Wrapping AES key with RSA public key")
    wrapped_key = pub.encrypt(
        aes_key,
        asympadding.OAEP(
            mgf=asympadding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    result = {
        "wrapped_key": _b64(wrapped_key),
        "blob": _b64(blob),
        "iv": _b64(iv),
    }

    logger.info(f"Successfully wrapped secret for key_id: {key_id}")
    return result


__all__ = [
    # Public KBM plugin API
    "kbm_open_client_connection",
    "kbm_close_client_connection",
    "kbm_get_secret",
]
