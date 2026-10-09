#
# TEE Attestation Service - OpenBao Plugin Integration
#
# Copyright 2026 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# This file is part of the TEE Attestation Service.
#
# This plugin provides integration with OpenBao for key management and
# secret retrieval for the TEE Attestation Service (TAS) via HTTP REST.

from __future__ import annotations

import base64
import errno
import json
import math
import os
import posixpath
import re
import secrets as _secrets
import stat
import threading
from typing import Any, Dict, Optional
from urllib.parse import quote, urljoin, urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

try:
    import yaml  # PyYAML (listed in requirements.txt)
except Exception:
    yaml = None

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as asympadding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import (
    load_der_public_key,
    load_pem_public_key,
)

from tas.exceptions import KBMResponseError, KBMUnavailableError
from tas.tas_logging import get_logger

# Setup logging for the OpenBao KBM plugin
logger = get_logger("tas.plugins.tas_kbm_openbao")

# Declare host dependencies (opt-in): currently no extra host kwargs required
KBM_HOST_KWARGS = set()

AES_KEY_LEN = 32  # AES-256
IV_LEN = 12  # AES-GCM IV size


# Crypto Helpers


def _b64(b: bytes) -> str:
    """Encode bytes to ASCII Base64 string."""
    return base64.b64encode(b).decode("ascii")


def _load_rsa_public_key(raw: bytes) -> rsa.RSAPublicKey:
    """Load RSA public key from PEM or DER format and verify key type."""
    key = None
    try:
        key = load_pem_public_key(raw)
    except Exception:
        pass

    if key is None:
        try:
            key = load_der_public_key(raw)
        except ValueError as e:
            raise ValueError("Invalid RSA public key format") from e

    if not isinstance(key, rsa.RSAPublicKey):
        raise ValueError(
            f"Invalid public key type: expected an RSA public key (RSAPublicKey), got {type(key).__name__}. "
            "Only RSA public keys are supported for secret wrapping."
        )

    if key.key_size < 2048:
        raise ValueError(
            f"RSA public key size ({key.key_size} bits) is insufficient. "
            "Minimum required RSA key size is 2048 bits."
        )

    return key


def _aes_gcm_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    """Encrypt plaintext using AES-256-GCM, returning ciphertext and auth tag."""
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
    enc = cipher.encryptor()
    ciphertext = enc.update(plaintext) + enc.finalize()
    return ciphertext, enc.tag


def _secret_to_bytes(v: Any) -> bytes:
    """Normalize a secret value to bytes."""
    if isinstance(v, bytes):
        return v
    if isinstance(v, bytearray):
        return bytes(v)
    if isinstance(v, str):
        return v.encode("utf-8")
    return json.dumps(v, separators=(",", ":")).encode("utf-8")


# Configuration File Handling


def _load_config_file(config_file: Optional[str]) -> Dict[str, Any]:
    """Load configuration from YAML or JSON file with environment variable substitution.

    Raises ValueError if an explicit config_file path was supplied but does not exist,
    cannot be read, or fails to parse.
    """
    if not config_file:
        logger.debug("No config file specified for OpenBao KBM")
        return {}

    path = os.path.abspath(config_file)
    if not os.path.exists(path):
        raise ValueError(f"OpenBao config file not found: {path}")
    if not os.path.isfile(path) or not os.access(path, os.R_OK):
        raise ValueError(f"OpenBao config file is not a readable regular file: {path}")

    logger.info(f"Loading OpenBao KBM config from: {path}")

    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
    except Exception as e:
        raise ValueError(f"Failed to read OpenBao config file '{path}': {e}") from e

    def env_replacer(match):
        env_var = match.group(1)
        env_value = os.getenv(env_var)
        if env_value is None:
            logger.warning(
                f"Environment variable {env_var} not found, replacing with empty string"
            )
            return ""
        return env_value

    content = re.sub(r"\$\{([^}]+)\}", env_replacer, content)

    data = None
    _, ext = os.path.splitext(path.lower())
    if ext in (".yaml", ".yml"):
        if not yaml:
            raise RuntimeError("PyYAML is required to parse YAML config files")
        try:
            data = yaml.safe_load(content)
        except Exception as e:
            raise ValueError(
                f"Failed to parse OpenBao YAML config '{path}': {e}"
            ) from e
    else:
        try:
            data = json.loads(content)
        except Exception as e:
            raise ValueError(
                f"Failed to parse OpenBao JSON config '{path}': {e}"
            ) from e

    if data is None:
        data = {}
    elif not isinstance(data, dict):
        raise ValueError(
            f"Config file '{path}' must parse to a key-value dictionary, got {type(data).__name__}"
        )

    return data


def _validate_config(
    url: Optional[str],
    verify_ssl: bool,
    ca_bundle: Optional[str],
    kv_version: int,
    requests_timeout: int,
    pool_connections: int,
    pool_maxsize: int,
    retry_total: int,
    retry_backoff_factor: float,
    max_secret_file_bytes: int = 1024,
) -> None:
    """Validate all OpenBao configuration parameters at startup.

    Raises:
        ValueError: If any configuration parameter fails validation.
    """
    # Require explicit URL
    if not url or not isinstance(url, str) or not url.strip():
        raise ValueError(
            "OpenBao URL is required. Specify 'BAO_URL' in configuration or set BAO_URL."
        )

    url = _validate_base_url(url)
    parsed = urlparse(url)

    if parsed.scheme == "http" and verify_ssl:
        raise ValueError("Insecure OpenBao URL is not permitted when verify_ssl=True")

    # Validate CA bundle
    if ca_bundle:
        bundle_path = os.path.abspath(ca_bundle)
        if not os.path.exists(bundle_path):
            raise ValueError(f"Configured ca_bundle does not exist: {bundle_path}")
        if not os.path.isfile(bundle_path) or not os.access(bundle_path, os.R_OK):
            raise ValueError(
                f"Configured ca_bundle is not a readable regular file: {bundle_path}"
            )

    # Validate kv_version
    if kv_version not in (1, 2):
        raise ValueError(
            f"Invalid kv_version: {kv_version}. OpenBao KV engine version must be 1 or 2."
        )

    # Validate requests_timeout
    if (
        not isinstance(requests_timeout, (int, float))
        or not math.isfinite(requests_timeout)
        or requests_timeout <= 0
    ):
        raise ValueError(
            f"Invalid requests_timeout: {requests_timeout}. Timeout must be a positive finite number."
        )

    # Validate connection pools
    if (
        isinstance(pool_connections, bool)
        or not isinstance(pool_connections, int)
        or pool_connections <= 0
    ):
        raise ValueError(
            f"Invalid pool_connections: {pool_connections}. Must be an integer greater than 0."
        )
    if (
        isinstance(pool_maxsize, bool)
        or not isinstance(pool_maxsize, int)
        or pool_maxsize <= 0
    ):
        raise ValueError(
            f"Invalid pool_maxsize: {pool_maxsize}. Must be an integer greater than 0."
        )

    # Validate retries
    if (
        isinstance(retry_total, bool)
        or not isinstance(retry_total, int)
        or retry_total < 0
    ):
        raise ValueError(
            f"Invalid retry_total: {retry_total}. Must be an integer >= 0."
        )
    if (
        isinstance(retry_backoff_factor, bool)
        or not isinstance(retry_backoff_factor, (int, float))
        or not math.isfinite(retry_backoff_factor)
        or retry_backoff_factor < 0.0
    ):
        raise ValueError(
            f"Invalid retry_backoff_factor: {retry_backoff_factor}. Must be a finite number >= 0.0."
        )

    if (
        isinstance(max_secret_file_bytes, bool)
        or not isinstance(max_secret_file_bytes, int)
        or max_secret_file_bytes < 1
    ):
        raise ValueError(
            "Invalid max_secret_file_bytes: must be an integer greater than 0."
        )


# Validation and URL Safety Helpers


def _validate_base_url(url: str) -> str:
    if not isinstance(url, str) or not url.strip():
        raise ValueError("OpenBao URL must be a non-empty string")

    normalized = url.strip().rstrip("/")

    try:
        parsed = urlparse(normalized)
    except ValueError as exc:
        raise ValueError("Invalid OpenBao URL") from exc

    port = parsed.port

    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError(
            "Invalid OpenBao URL: URL must include an http(s) scheme and host"
        )

    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError(
            "Invalid OpenBao URL: credentials, query strings, and fragments are not allowed"
        )

    if port is not None and not 1 <= port <= 65535:
        raise ValueError("Invalid OpenBao URL port")

    return normalized


def _read_secret_file(path: str, name: str, max_bytes: int = 1024) -> str:
    if not isinstance(path, str) or not path.strip():
        raise ValueError(f"{name} must be a non-empty string")
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 1:
        raise ValueError("max_bytes must be a positive integer")

    flags = os.O_RDONLY | getattr(
        os, "O_NOFOLLOW", 0
    )  # Request the file is read only and that the file is not a symlink if O_NOFOLLOW is available

    try:
        fd = os.open(path, flags)
    except FileNotFoundError as exc:
        raise ValueError(f"Configured {name} not found") from exc
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise ValueError(f"Configured {name} must not be a symlink") from exc
        raise ValueError(f"Configured {name} is not accessible") from exc

    try:
        if not stat.S_ISREG(
            os.fstat(fd).st_mode
        ):  # Check if the file is a regular file (not directory)
            raise ValueError(f"Configured {name} is not a readable regular file")

        if os.fstat(fd).st_size > max_bytes + 1:
            raise ValueError(
                f"Configured {name} exceeds the maximum allowed size of {max_bytes + 1} bytes"
            )

        secret_file = os.fdopen(fd, "rb")
        fd = None
    finally:
        if fd is not None:
            os.close(fd)

    with secret_file:
        content = secret_file.read(max_bytes + 2)
    if len(content) > max_bytes + 1:
        raise ValueError(
            f"Configured {name} exceeds the maximum allowed size of {max_bytes + 1} bytes"
        )
    value = content.decode("utf-8").strip()
    if not value:
        raise ValueError(f"Configured {name} is empty")
    return value


def _validate_key_id(key_id: str) -> None:
    """
    Validate that key_id is safe and cannot alter the intended OpenBao path.

    Rejects:
    - Empty, whitespace, or non-string values
    - Path traversal segments ('.' and '..') and empty segments
    - Characters '?', '#', and '\\'
    - ASCII control characters
    - URL-encoded traversal sequences (%2e, %2f, %5c)
    """
    if not isinstance(key_id, str) or not key_id.strip():
        raise ValueError("key_id must be a non-empty string")

    # Reject ?, #, and \
    if any(c in key_id for c in ("?", "#", "\\")):
        raise ValueError("key_id contains invalid characters ('?', '#', or '\\')")

    # Reject ASCII control characters (0x00-0x1F and 0x7F)
    if any(ord(c) < 32 or ord(c) == 127 for c in key_id):
        raise ValueError("key_id contains control characters")

    # Reject URL-encoded and double-URL-encoded traversal attempts (%2e, %2f, %5c, %252e, etc.)
    if re.search(r"(?i)%(?:25)*(?:2e|2f|5c)", key_id):
        raise ValueError("key_id contains URL-encoded traversal sequences")

    # Reject empty segments and '.' / '..' path components
    segments = key_id.split("/")
    for segment in segments:
        if segment in ("", ".", ".."):
            raise ValueError(f"key_id contains invalid path segment: '{segment}'")


def _build_url(
    base_url: str,
    mount_point: str,
    kv_version: int,
    key_id: str,
) -> str:
    """
    Validate key_id, safely quote path components, and construct endpoint URL.

    Verifies the resulting URL path remains strictly scoped to the configured mount point.
    """
    _validate_key_id(key_id)

    # Split key_id into segments, quote each, and reconstruct
    segments = key_id.split("/")
    encoded_path = "/".join(quote(seg, safe="") for seg in segments)

    mount = mount_point.strip("/")
    if int(kv_version) == 2:
        expected_prefix = f"/v1/{mount}/data/"
    else:
        expected_prefix = f"/v1/{mount}/"

    endpoint = f"{expected_prefix}{encoded_path}"
    url = urljoin(f"{base_url.rstrip('/')}/", endpoint.lstrip("/"))

    # Verify URL Scope: ensure path does not escape the configured mount path
    parsed = urlparse(url)
    norm_path = posixpath.normpath(parsed.path)
    norm_prefix = posixpath.normpath(expected_prefix)
    if not (norm_path == norm_prefix or norm_path.startswith(norm_prefix + "/")):
        raise ValueError(
            f"URL path '{norm_path}' escapes configured mount path '{norm_prefix}'"
        )

    return url


def _parse_bool(value: Any, name: str = "value") -> bool:
    """
    Strictly parse a boolean configuration value.

    Accepts:
        True, False (bool)
        "true", "false", "1", "0" (case-insensitive str)
        1, 0 (int)

    Raises:
        ValueError for any other value (does not silently fall back).
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        v = value.strip().lower()
        if v in ("true", "1"):
            return True
        if v in ("false", "0"):
            return False
    elif isinstance(value, int) and value in (0, 1):
        return bool(value)

    raise ValueError(
        f"Invalid boolean value for '{name}': {value!r}. "
        f"Expected true/false or 1/0."
    )


def _validate_mount_name(value: str, name: str = "mount") -> str:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string")

    normalized = value.strip("/")
    if not normalized:
        raise ValueError(f"{name} must be a non-empty mount name")

    if any(
        ord(c) < 32 or ord(c) == 127 for c in normalized
    ):  # No control characters allowed
        raise ValueError(f"{name} contains control characters")

    if re.search(
        r"(?i)%(?:25)*(?:2e|2f|5c)", normalized
    ):  # No traversal sequences allowed
        raise ValueError(f"{name} contains encoded traversal")

    segments = normalized.split("/")
    for segment in segments:
        # Ensure segment does not contain control characters
        if segment in ("", ".", ".."):
            raise ValueError(f"{name} contains an invalid path segment")

        if not re.fullmatch(r"[A-Za-z0-9._-]+", segment):
            raise ValueError(f"{name} contains invalid characters")

    return normalized


def _normalize_optional_string(value: Any, name: str) -> Optional[str]:
    if value is None:
        return None

    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string or None")

    normalized = value.strip()
    return normalized or None


def _require_nonempty_string(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    return value.strip()


__all__ = [
    # Public KBM plugin API
    "kbm_open_client_connection",
    "kbm_close_client_connection",
    "kbm_get_secret",
    "OpenBaoUnavailableError",
    "OpenBaoPoolTimeoutError",
    "OpenBaoResponseError",
]

# OpenBao Client Implementation


class OpenBaoUnavailableError(KBMUnavailableError):
    """Raised when the OpenBao backend is temporarily unavailable."""

    public_message = "Secret service is temporarily unavailable"

    def __init__(self, *, retry_after: int = 1):
        super().__init__(retry_after=retry_after)


class OpenBaoPoolTimeoutError(OpenBaoUnavailableError):
    """Raised when OpenBao connection acquisition or pool times out."""

    pass


class OpenBaoResponseError(KBMResponseError):
    """Raised when OpenBao returns an invalid response."""

    public_message = "Secret service returned an invalid response"

    pass


class _OpenBaoClient:
    """OpenBao Key Management Backend client using HTTP REST."""

    def __init__(
        self,
        url: str = "http://127.0.0.1:8200",
        token: Optional[str] = None,
        mount_point: str = "secret",
        kv_version: int = 2,
        secret_field: str = "secret",
        verify_ssl: bool = True,
        ca_bundle: Optional[str] = None,
        requests_timeout: int = 30,
        retry_total: int = 3,
        retry_backoff_factor: float = 0.05,
        pool_connections: int = 10,
        pool_maxsize: int = 20,
        auth_method: str = "token",
        role_id: Optional[str] = None,
        secret_id: Optional[str] = None,
        secret_id_file: Optional[str] = None,
        max_secret_file_bytes: int = 1024,
        approle_mount: str = "approle",
        token_renew_on_401: bool = True,
    ):
        url = _require_nonempty_string(url, "url")
        auth_method = _require_nonempty_string(auth_method, "auth_method").lower()
        secret_field = _require_nonempty_string(secret_field, "secret_field")
        if not isinstance(token_renew_on_401, bool):
            raise ValueError("token_renew_on_401 must be a boolean")
        role_id = _normalize_optional_string(role_id, "role_id")
        secret_id = _normalize_optional_string(secret_id, "secret_id")
        secret_id_file = _normalize_optional_string(secret_id_file, "secret_id_file")
        token = _normalize_optional_string(token, "token")
        mount_point = _validate_mount_name(mount_point, "mount_point")
        approle_mount = _validate_mount_name(approle_mount, "approle_mount")
        if auth_method not in ("token", "approle"):
            raise ValueError("auth_method must be 'token' or 'approle'")
        self.url = _validate_base_url(url)
        self.token = token
        self.mount_point = mount_point
        self.kv_version = kv_version
        self.secret_field = secret_field
        self.verify_ssl = verify_ssl
        self.ca_bundle = ca_bundle
        self.requests_timeout = requests_timeout
        self.retry_total = retry_total
        self.retry_backoff_factor = retry_backoff_factor
        self.pool_connections = pool_connections
        self.pool_maxsize = pool_maxsize
        self.auth_method = auth_method
        self.role_id = role_id
        self.secret_id = secret_id
        self.secret_id_file = secret_id_file
        self.max_secret_file_bytes = max_secret_file_bytes
        self.approle_mount = approle_mount
        self.token_renew_on_401 = token_renew_on_401
        self._token_generation = 0
        self._reauth_generation = 0
        self._last_reauth_error: Optional[Exception] = None

        if self.auth_method == "approle" and not self.role_id:
            raise ValueError("role_id is required for AppRole authentication")
        if (
            self.auth_method == "approle"
            and not self.secret_id
            and not self.secret_id_file
        ):
            raise ValueError(
                "secret_id or secret_id_file is required for AppRole authentication"
            )
        self._reauth_lock = threading.Lock()

        # Bounded semaphore to strictly bound connection acquisition queue times.
        # This prevents threads from blocking indefinitely when pool_maxsize is reached.
        self._pool_semaphore = threading.BoundedSemaphore(value=self.pool_maxsize)

        # Configure SSL verify parameter for requests library
        # verify can be: False (disable verification), True (use system CAs), or str (path to CA bundle)
        if not self.verify_ssl:
            self.verify_param: Any = False
            logger.warning(
                "TLS verification is DISABLED for OpenBao connections (verify_ssl=false). "
                "This should only be used for development/debug environments."
            )
        else:
            # verify_ssl is True: use CA bundle if provided, otherwise use system defaults
            if self.ca_bundle and os.path.isfile(self.ca_bundle):
                self.verify_param = self.ca_bundle
                logger.debug(f"Using custom CA bundle: {self.ca_bundle}")
            else:
                self.verify_param = True
                logger.debug("Using system default CA certificates")

        # HTTP session for REST communication
        self.session = requests.Session()
        if self.token:
            self.session.headers.update({"X-Vault-Token": self.token})

        # Retry strategy
        retry_strategy = Retry(
            total=self.retry_total,
            connect=self.retry_total,
            read=self.retry_total,
            backoff_factor=self.retry_backoff_factor,  # exponential backoff factor for retries
            status_forcelist=[
                429,
                500,
                502,
                503,
                504,
            ],  # HTTP status codes (429: Rate limits, 500: Internal Server Error, 502: Bad Gateway, 503: Service Unavailable, 504: Gateway Timeout)
            allowed_methods=frozenset(["GET", "HEAD", "OPTIONS"]),
            raise_on_status=False,  # allows the application layer to parse non-transient HTTP errors cleanly
        )

        # Connection pool adapter configured with pool_block=True:
        # - pool_connections: Controls the number of distinct host connection pools cached by urllib3.
        # - pool_maxsize: Hard upper bound on concurrent connections maintained per host pool.
        # - pool_block=True: Enforces pool_maxsize as a strict ceiling. When all connections in the
        #   pool are in use, subsequent connection acquisition requests block until an active connection
        #   is returned to the pool (or until timeout), preventing connection storms and descriptor churn.
        # - Process scope: These limits apply per TAS worker process. Total concurrent connections
        #   to OpenBao across a deployment will be (number of worker processes * pool_maxsize).
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=self.pool_connections,
            pool_maxsize=self.pool_maxsize,
            pool_block=True,
        )
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)

        try:
            if self.auth_method == "approle":
                self._login_approle()
        except Exception:
            self.token = None
            self.session.headers.pop("X-Vault-Token", None)
            self.session.close()
            raise

        logger.info(
            "OpenBao KBM client initialized "
            f"(scheme: {urlparse(self.url).scheme}, host: {urlparse(self.url).hostname}, "
            f"port: {urlparse(self.url).port}, mount: {self.mount_point}, KV v{self.kv_version})"
        )

    def close(self) -> None:
        """Close the underlying HTTP session."""
        if self.session:
            self.session.close()

    def _execute_request(
        self, method: str, url: str, **kwargs: Any
    ) -> requests.Response:
        acquired = self._pool_semaphore.acquire(
            timeout=self.requests_timeout
        )  # acquire semaphore

        if not acquired:
            raise OpenBaoPoolTimeoutError()
        try:
            request_method = getattr(self.session, method.lower())
            return request_method(
                url,
                verify=self.verify_param,
                timeout=self.requests_timeout,
                allow_redirects=False,
                **kwargs,
            )  # Execute the HTTP request

        except requests.RequestException:
            logger.error("OpenBao request failed")
            raise OpenBaoUnavailableError() from None
        finally:
            self._pool_semaphore.release()

    def _login_approle(self) -> None:
        secret_id = (
            _read_secret_file(
                self.secret_id_file,
                "secret_id_file",
                self.max_secret_file_bytes,
            )
            if self.secret_id_file
            else self.secret_id
        )

        url = f"{self.url}/v1/auth/{self.approle_mount}/login"
        response = self._execute_request(
            "POST", url, json={"role_id": self.role_id, "secret_id": secret_id}
        )

        if response.status_code in (429, 500, 502, 503, 504):
            raise OpenBaoUnavailableError()
        if response.status_code in (401, 403):
            raise OpenBaoResponseError()
        if response.status_code != 200:
            raise OpenBaoResponseError()
        try:
            payload = response.json()
        except Exception:
            raise OpenBaoResponseError() from None

        auth = payload.get("auth") if isinstance(payload, dict) else None
        token = auth.get("client_token") if isinstance(auth, dict) else None

        if not isinstance(token, str) or not token.strip():
            raise OpenBaoResponseError()

        self.token = token.strip()
        self.session.headers.update({"X-Vault-Token": self.token})
        self._token_generation += (
            1  # Increment token generation to indicate a new token has been obtained
        )

    def _make_request(self, method: str, url: str, **kwargs: Any) -> requests.Response:
        token_generation = self._token_generation
        reauth_generation = self._reauth_generation
        response = self._execute_request(method, url, **kwargs)

        if response.status_code == 401:
            if (
                self.auth_method == "approle" and self.token_renew_on_401
            ):  # 401 reiceived, approle selected and token renewal on 401 is enabled, attempt to renew the token or re-login via approle and try again.
                with self._reauth_lock:
                    # Another request already refreshed the token successfully.
                    if self._token_generation != token_generation:
                        pass
                    # Another request already tried and failed authentication, share the failure.
                    elif self._reauth_generation != reauth_generation:
                        error = self._last_reauth_error
                        if error is not None:
                            raise error
                    else:
                        try:
                            if not self._renew_token():
                                self._login_approle()
                        except Exception as error:
                            self._last_reauth_error = error
                            raise
                        else:
                            self._last_reauth_error = None
                        finally:
                            self._reauth_generation += (
                                1  # Publish reauthentication even when it fails
                            )
                response = self._execute_request(method, url, **kwargs)

        return response

    def _renew_token(self) -> bool:
        response = self._execute_request("POST", f"{self.url}/v1/auth/token/renew-self")

        if response.status_code in (429, 500, 502, 503, 504):
            raise OpenBaoUnavailableError()
        if response.status_code in (400, 401, 403, 404):
            return False
        if response.status_code != 200:
            raise OpenBaoResponseError()
        try:
            payload = response.json()
        except (TypeError, ValueError):
            raise OpenBaoResponseError() from None

        auth = payload.get("auth") if isinstance(payload, dict) else None
        token = auth.get("client_token") if isinstance(auth, dict) else None
        if not isinstance(token, str) or not token.strip():
            raise OpenBaoResponseError()

        self.token = token.strip()
        self.session.headers.update({"X-Vault-Token": self.token})
        self._token_generation += 1
        return True

    def get_secret(self, key_id: str) -> bytes:
        """
        Retrieve secret bytes for the given key_id from OpenBao via REST API.

        Supports both KV version 1 and KV version 2 engines.
        """
        url = _build_url(
            base_url=self.url,
            mount_point=self.mount_point,
            kv_version=self.kv_version,
            key_id=key_id,
        )
        logger.debug("Fetching secret from OpenBao for validated key_id")

        resp = self._make_request("GET", url)

        if resp.status_code == 404:
            logger.error(f"Secret not found in OpenBao: {key_id}")
            raise ValueError("Secret not found")
        elif resp.status_code != 200:
            logger.error(
                f"OpenBao secret retrieval failed ({resp.status_code}) for key_id {key_id}"
            )
            raise OpenBaoResponseError()

        try:
            payload = resp.json()
        except Exception as e:
            logger.error(
                f"Failed to parse OpenBao response as JSON for key_id: {key_id}"
            )
            raise OpenBaoResponseError() from e

        if not isinstance(payload, dict):
            logger.error(
                f"Invalid OpenBao response structure for key_id {key_id}: expected JSON object, got {type(payload).__name__}"
            )
            raise OpenBaoResponseError()

        if self.kv_version == 2:
            top_data = payload.get("data")
            if top_data is None:
                logger.error(
                    f"OpenBao response contains null data for key_id: {key_id}"
                )
                raise OpenBaoResponseError()
            if not isinstance(top_data, dict):
                logger.error(
                    f"Invalid OpenBao response structure for key_id {key_id}: expected data dictionary, got {type(top_data).__name__}"
                )
                raise OpenBaoResponseError()
            data = top_data.get("data")
        else:
            data = payload.get("data")

        if data is None:
            logger.error(
                f"OpenBao response contains null secret data for key_id: {key_id}"
            )
            raise OpenBaoResponseError()

        if not isinstance(data, dict):
            logger.error(
                f"Invalid OpenBao response structure for key_id {key_id}: expected secret data dictionary, got {type(data).__name__}"
            )
            raise OpenBaoResponseError()

        if self.secret_field not in data:
            logger.error(
                f"Secret field '{self.secret_field}' not found in OpenBao secret data for key_id: {key_id}"
            )
            raise ValueError("Secret field not found in OpenBao secret data")

        val = data[self.secret_field]
        if val is None:
            logger.error(
                f"OpenBao returned a null value for the configured secret field for key_id: {key_id}"
            )
            raise OpenBaoResponseError()
        return _secret_to_bytes(val)


# KBM Plugin Interface


def kbm_open_client_connection(config_file: Optional[str] = None) -> _OpenBaoClient:
    """
    Initialize and return the OpenBao KBM client handle.

    Args:
        config_file: Path to plugin configuration file (YAML or JSON)

    Returns:
        _OpenBaoClient handle for use with kbm_get_secret
    """
    logger.info("Initializing OpenBao KBM client connection")
    cfg = _load_config_file(config_file)

    def _get_required_int(key: str, env_var: str, default: int) -> int:
        val = os.getenv(env_var)
        if val is None:
            val = cfg.get(f"BAO_{key.upper()}", default)
        if val is None:
            return default

        # Reject booleans
        if isinstance(val, bool):
            raise ValueError(
                f"Boolean not allowed for integer setting '{key}' / '{env_var}': {val!r}"
            )

        # If it's already an int (and not a bool)
        if isinstance(val, int):
            return val

        # Reject float types that have fractional parts or non-finite values
        if isinstance(val, float):
            if not math.isfinite(val) or not val.is_integer():
                raise ValueError(
                    f"Invalid non-integer or non-finite float value for '{key}' / '{env_var}': {val!r}"
                )
            return int(val)

        # For string values (e.g. from environment variables or YAML)
        if isinstance(val, str):
            s = val.strip()
            # Strict regex for optional sign and digits only (rejects decimal dots, 'nan', 'inf')
            if not re.fullmatch(r"[+-]?\d+", s):
                raise ValueError(
                    f"Invalid integer value for '{key}' / '{env_var}': {val!r}"
                )
            return int(s)

        raise ValueError(
            f"Invalid type for '{key}' / '{env_var}': {type(val).__name__}"
        )

    def _get_required_float(key: str, env_var: str, default: float) -> float:
        val = os.getenv(env_var)
        if val is None:
            val = cfg.get(f"BAO_{key.upper()}")
        if val is None:
            return default

        # Reject booleans
        if isinstance(val, bool):
            raise ValueError(
                f"Boolean not allowed for numeric setting '{key}' / '{env_var}': {val!r}"
            )

        try:
            f_val = float(val)
        except (ValueError, TypeError):
            raise ValueError(
                f"Invalid numeric value for '{key}' / '{env_var}': {val!r}"
            )

        if not math.isfinite(f_val):
            raise ValueError(
                f"Numeric value for '{key}' / '{env_var}' must be finite (got {val!r})"
            )

        return f_val

    # Resolve connection & security parameters
    url = os.getenv("BAO_URL") or cfg.get("BAO_URL")
    url = _normalize_optional_string(url, "url")

    #
    raw_verify_ssl = os.getenv("BAO_VERIFY_SSL")
    if raw_verify_ssl is None:
        raw_verify_ssl = cfg.get("BAO_VERIFY_SSL")
    if raw_verify_ssl is None:
        verify_ssl = True
    else:
        verify_ssl = _parse_bool(raw_verify_ssl, "verify_ssl")

    ca_bundle = os.getenv("BAO_CA_BUNDLE") or cfg.get("BAO_CA_BUNDLE")
    ca_bundle = _normalize_optional_string(ca_bundle, "ca_bundle")

    # Resolve engine, timeouts, pool and retry settings
    kv_version = _get_required_int("kv_version", "BAO_KV_VERSION", 2)
    requests_timeout = _get_required_int("requests_timeout", "BAO_REQUESTS_TIMEOUT", 30)
    pool_connections = _get_required_int("pool_connections", "BAO_POOL_CONNECTIONS", 10)
    pool_maxsize = _get_required_int("pool_maxsize", "BAO_POOL_MAXSIZE", 20)
    retry_total = _get_required_int("retry_total", "BAO_RETRY_TOTAL", 3)
    max_secret_file_bytes = _get_required_int(
        "max_secret_file_bytes", "BAO_MAX_SECRET_FILE_BYTES", 1024
    )
    retry_backoff_factor = _get_required_float(
        "retry_backoff_factor", "BAO_RETRY_BACKOFF_FACTOR", 0.05
    )

    # Validate entire configuration before continuing
    _validate_config(
        url=url,
        verify_ssl=verify_ssl,
        ca_bundle=ca_bundle,
        kv_version=kv_version,
        requests_timeout=requests_timeout,
        pool_connections=pool_connections,
        pool_maxsize=pool_maxsize,
        retry_total=retry_total,
        retry_backoff_factor=retry_backoff_factor,
        max_secret_file_bytes=max_secret_file_bytes,
    )

    raw_auth_method = os.getenv("BAO_AUTH_METHOD")
    if raw_auth_method is None:
        raw_auth_method = cfg.get("BAO_AUTH_METHOD")
    if raw_auth_method is None:
        raw_auth_method = "token"
    if not isinstance(raw_auth_method, str):
        raise ValueError("auth_method must be a string")
    auth_method = raw_auth_method.strip().lower()
    if auth_method not in ("token", "approle"):
        raise ValueError("auth_method must be 'token' or 'approle'")
    token = None
    role_id = secret_id = secret_id_file = None

    if auth_method == "token":
        # Load token from environment variable or configuration
        token = _normalize_optional_string(
            os.getenv("BAO_TOKEN") or cfg.get("BAO_TOKEN"),
            "token",
        )
        token_file = None

        if token is None:  # If no token is provided, try to read it from the file
            token_file = _normalize_optional_string(
                os.getenv("BAO_TOKEN_FILE") or cfg.get("BAO_TOKEN_FILE"),
                "token_file",
            )

        if token is None and token_file:  # Read the token from the file if it exists
            token = _read_secret_file(token_file, "token_file", max_secret_file_bytes)
    else:
        # Load AppRole authentication parameters from environment var or config
        for name, env_var in (
            ("role_id", "BAO_ROLE_ID"),
            ("secret_id", "BAO_SECRET_ID"),
            ("secret_id_file", "BAO_SECRET_ID_FILE"),
        ):
            value = os.getenv(env_var)
            if value is None:
                value = cfg.get(f"BAO_{name.upper()}")

            normalized = _normalize_optional_string(value, name)

            if name == "role_id":
                role_id = normalized
            elif name == "secret_id":
                secret_id = normalized
            else:
                secret_id_file = normalized

    raw_renew = os.getenv("BAO_TOKEN_RENEW_ON_401")
    if raw_renew is None:
        raw_renew = cfg.get("BAO_TOKEN_RENEW_ON_401")
    token_renew_on_401 = (
        _parse_bool(raw_renew, "token_renew_on_401") if raw_renew is not None else True
    )

    # Load AppRole mount, mount point and secret field from environment var or config
    approle_mount = os.getenv("BAO_APPROLE_MOUNT")
    if approle_mount is None:
        approle_mount = cfg.get("BAO_APPROLE_MOUNT", "approle")
    approle_mount = _validate_mount_name(approle_mount, "approle_mount")
    mount_point = os.getenv("BAO_MOUNT_POINT")
    if mount_point is None:
        mount_point = cfg.get("BAO_MOUNT_POINT", "secret")
    mount_point = _validate_mount_name(mount_point, "mount_point")
    secret_field = os.getenv("BAO_SECRET_FIELD")
    if secret_field is None:
        secret_field = cfg.get("BAO_SECRET_FIELD", "secret")
    secret_field = _normalize_optional_string(secret_field, "secret_field")

    if not secret_field:
        raise ValueError("secret_field must be a non-empty string")

    client = _OpenBaoClient(
        url=url,
        token=token,
        mount_point=mount_point,
        kv_version=kv_version,
        secret_field=secret_field,
        verify_ssl=verify_ssl,
        ca_bundle=ca_bundle,
        requests_timeout=requests_timeout,
        retry_total=retry_total,
        retry_backoff_factor=retry_backoff_factor,
        pool_connections=pool_connections,
        pool_maxsize=pool_maxsize,
        auth_method=auth_method,
        role_id=role_id,
        secret_id=secret_id,
        secret_id_file=secret_id_file,
        max_secret_file_bytes=max_secret_file_bytes,
        approle_mount=approle_mount,
        token_renew_on_401=token_renew_on_401,
    )
    return client


def kbm_close_client_connection(client: Any) -> None:
    """
    Clean up the OpenBao client connection.

    Args:
        client: Client handle to close
    """
    logger.info("Closing OpenBao KBM client connection")
    if hasattr(client, "close"):
        client.close()


def kbm_get_secret(client: Any, key_id: str, wrapping_key: bytes) -> Dict[str, str]:
    """
    Retrieve secret from OpenBao and wrap with client RSA public key.

    Args:
        client: _OpenBaoClient handle from kbm_open_client_connection
        key_id: Identifier for the secret to retrieve
        wrapping_key: Client RSA public key for wrapping the secret

    Returns:
        Dictionary with keys: wrapped_key, blob, iv, tag (all base64-encoded)
    """
    logger.info(f"OpenBao KBM get_secret request for key_id: {key_id}")

    if not isinstance(client, _OpenBaoClient):
        logger.error("Invalid client handle provided")
        raise ValueError("Invalid client handle")
    if not isinstance(key_id, str) or not key_id.strip():
        logger.error("key_id is required but not provided")
        raise ValueError("key_id required")
    _validate_key_id(key_id)
    if not wrapping_key:
        logger.error("wrapping_key is required but not provided")
        raise ValueError("wrapping_key (client RSA public key) is required")

    # Load and validate client RSA public key
    pub = _load_rsa_public_key(wrapping_key)

    # Retrieve secret bytes from OpenBao
    secret_bytes = client.get_secret(key_id)

    # Generate ephemeral AES-256 key and 12-byte IV
    aes_key = _secrets.token_bytes(AES_KEY_LEN)
    iv = _secrets.token_bytes(IV_LEN)

    # Encrypt secret using AES-256-GCM
    blob, tag = _aes_gcm_encrypt(aes_key, iv, secret_bytes)

    # Wrap ephemeral AES key using client's RSA public key (RSA-OAEP SHA-256)
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
        "tag": _b64(tag),
    }

    logger.info(f"Successfully wrapped secret for key_id: {key_id}")
    return result
