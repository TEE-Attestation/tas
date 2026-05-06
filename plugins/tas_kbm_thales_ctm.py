#
# TEE Attestation Service - Thales CipherTrust Manager (CTM) Plugin Integration
#
# Copyright 2026 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# This file is part of the TEE Attestation Service.
#
# This plugin provides integration with Thales CipherTrust Manager (CTM)
# for key management and secret wrapping operations.
# The plugin implements the necessary methods to interact with CTM's API.


from __future__ import annotations

import base64
import json
import logging
import os
import re
import threading
import time
from typing import Any, Dict, Optional
from urllib.parse import urljoin

import requests
import urllib3

try:
    import yaml  # PyYAML (listed in requirements)
except Exception:
    yaml = None

from cryptography.hazmat.primitives.serialization import (
    load_der_public_key,
    load_pem_public_key,
)

from tas.tas_logging import get_logger

# Setup logging for the Thales CTM KBM plugin
logger = get_logger("tas.plugins.tas_kbm_thales_ctm")

AES_KEY_LEN = 32  # AES-256
IV_LEN = 12  # AES-GCM IV size
REQUEST_TIMEOUT_SECONDS = 30
REQUEST_RETRY_ATTEMPTS = 3
REQUEST_RETRY_BASE_SLEEP_SECONDS = 0.75
RETRYABLE_HTTP_STATUS_CODES = {408, 425, 429, 500, 502, 503, 504}


class CTMRequestError(RuntimeError):
    """Error raised for Thales CTM request failures."""

    def __init__(
        self, message: str, status_code: Optional[int] = None, retryable: bool = False
    ):
        super().__init__(message)
        self.status_code = status_code
        self.retryable = retryable

    def __str__(self):
        details = super().__str__()
        if self.status_code is None:
            return details
        return f"{details} (status={self.status_code}, retryable={self.retryable})"


def _response_message(response: requests.Response) -> str:
    """Extract the best human-readable message from a CTM response."""
    try:
        payload = response.json()
    except Exception:
        payload = None

    if isinstance(payload, dict):
        for field in ("message", "error", "detail", "description", "msg"):
            value = payload.get(field)
            if value:
                return str(value)
        try:
            return json.dumps(payload, separators=(",", ":"))
        except Exception:
            pass

    text = (response.text or "").strip()
    return text or response.reason or "unknown CTM response"


def _is_retryable_status(status_code: int) -> bool:
    return status_code in RETRYABLE_HTTP_STATUS_CODES


def _sleep_for_retry(attempt: int) -> None:
    sleep_seconds = REQUEST_RETRY_BASE_SLEEP_SECONDS * attempt
    time.sleep(sleep_seconds)


def _load_rsa_public_key(raw: bytes):
    """Load RSA public key from PEM or DER format"""
    try:
        pub_key = load_pem_public_key(raw)
        logger.debug("Successfully loaded PEM public key")
        return pub_key
    except Exception:
        pass
    try:
        pub_key = load_der_public_key(raw)
        logger.debug("Successfully loaded DER public key")
        key_size = pub_key.key_size
        logger.info(f"Loaded RSA public key: {key_size} bits")
        return pub_key
    except Exception as e:
        raise ValueError("Invalid RSA public key format") from e


def _load_config_file(config_file: Optional[str]) -> Dict[str, Any]:
    """Load configuration from YAML or JSON file with environment variable substitution"""
    if not config_file:
        logger.debug("No config file specified")
        return {}
    path = os.path.abspath(config_file)
    if not os.path.isfile(path):
        logger.warning(f"Config file not found: {path}")
        return {}

    logger.info(f"Loading Thales CTM KBM config from: {path}")

    # Read the raw file content first
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()

    # Perform environment variable substitution
    def env_replacer(match):
        env_var = match.group(1)
        env_value = os.getenv(env_var)
        if env_value is None:
            logger.warning(
                f"Environment variable {env_var} not found, keeping placeholder"
            )
            return match.group(0)  # Keep original ${VAR} if not found
        logger.debug(f"Substituted environment variable: {env_var}")
        return env_value

    # Replace ${VAR_NAME} with environment variable values
    content = re.sub(r"\$\{([^}]+)\}", env_replacer, content)

    # Try YAML first if extension suggests YAML and PyYAML is available
    _, ext = os.path.splitext(path.lower())
    if ext in (".yaml", ".yml") and yaml:
        try:
            data = yaml.safe_load(content) or {}
            if isinstance(data, dict):
                logger.debug(
                    f"Successfully loaded YAML config with keys: {list(data.keys())}"
                )
                return data
        except Exception as e:
            logger.warning(f"Failed to parse config as YAML: {e}")
    # Fallback JSON
    try:
        data = json.loads(content) or {}
        logger.debug(f"Successfully loaded JSON config with keys: {list(data.keys())}")
        return data
    except Exception as e:
        logger.warning(f"Failed to parse config as JSON: {e}")
        return {}


class _CTMKBMClient:
    """Thales CTM Key Management Backend client"""

    def __init__(
        self,
        host: str,
        verify_ssl: bool = True,
        ca_cert: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        cert_file: Optional[str] = None,
        key_file: Optional[str] = None,
        certificate_login: bool = False,
        domain: str = "root",
        key_wrap_algorithm: str = "AES-KWP",
    ):
        self.host = host
        self.username = username
        self.password = password
        self.domain = domain
        self.verify_ssl = verify_ssl
        self.ca_cert = ca_cert
        self.cert_file = cert_file
        self.key_file = key_file
        self.certificate_login = certificate_login
        self.bearer_token = None
        self.key_wrap_algorithm = key_wrap_algorithm
        self._lock = threading.RLock()

        # Disable SSL warnings if not verifying
        if not verify_ssl:
            logger.warning("SSL verification is disabled for Thales CTM client")

        # Validate authentication configuration
        if certificate_login:
            if not cert_file or not key_file:
                raise ValueError(
                    "Certificate and key files required for certificate authentication"
                )
            if not os.path.isfile(cert_file):
                raise ValueError(f"Certificate file not found: {cert_file}")
            if not os.path.isfile(key_file):
                raise ValueError(f"Key file not found: {key_file}")
        else:
            if not username or not password:
                raise ValueError(
                    "Username and password required for password authentication"
                )

        # Validate SSL configuration
        if verify_ssl and ca_cert:
            if not os.path.isfile(ca_cert):
                raise ValueError(f"CA certificate file not found: {ca_cert}")

        auth_type = "certificate" if certificate_login else "password"
        logger.debug(
            f"Initialized Thales CTM KBM client for host: {host} with {auth_type} authentication"
        )

    def authenticate(self):
        """Authenticate to Thales CTM and get bearer token"""
        auth_type = "certificate" if self.certificate_login else "password"
        logger.info(
            f"Authenticating to Thales CTM at {self.host} using {auth_type} authentication"
        )

        # Build auth URL
        auth_url = f"https://{self.host}/api/v1/auth/tokens"

        # Prepare SSL verification
        verify_param = False
        if self.verify_ssl:
            verify_param = self.ca_cert if self.ca_cert else True

        # Prepare request parameters
        request_kwargs = {"verify": verify_param}

        if self.certificate_login:
            # Certificate-based authentication using user_certificate grant type
            auth_data = {"grant_type": "user_certificate", "domain": self.domain}
            request_kwargs["cert"] = (self.cert_file, self.key_file)
            logger.debug(
                "Using certificate authentication with user_certificate grant type"
            )
        else:
            # Username/password authentication
            auth_data = {
                "username": self.username,
                "password": self.password,
                "domain": self.domain,
            }
            logger.debug("Using username/password authentication")

        last_error = None
        for attempt in range(1, REQUEST_RETRY_ATTEMPTS + 1):
            try:
                response = requests.post(
                    auth_url,
                    json=auth_data,
                    timeout=REQUEST_TIMEOUT_SECONDS,
                    **request_kwargs,
                )
            except requests.exceptions.RequestException as exc:
                last_error = CTMRequestError(
                    f"Thales CTM authentication request failed: {exc}", retryable=True
                )
                logger.warning(
                    "Authentication request error on attempt %s/%s: %s",
                    attempt,
                    REQUEST_RETRY_ATTEMPTS,
                    exc,
                )
            else:
                if response.status_code == 200:
                    try:
                        token_data = response.json()
                    except Exception as exc:
                        raise CTMRequestError(
                            f"Thales CTM auth returned invalid JSON: {exc}",
                            status_code=500,
                        )

                    self.bearer_token = token_data.get("jwt")
                    if not self.bearer_token:
                        raise CTMRequestError(
                            "Thales CTM auth response did not include a JWT",
                            status_code=500,
                        )

                    client_verify = response.headers.get("Client-Verify", "N/A")
                    logger.info(
                        f"Successfully authenticated to Thales CTM (Client-Verify: {client_verify})"
                    )
                    return self.bearer_token

                status_code = response.status_code
                response_message = _response_message(response)
                if (
                    _is_retryable_status(status_code)
                    and attempt < REQUEST_RETRY_ATTEMPTS
                ):
                    last_error = CTMRequestError(
                        f"Thales CTM auth failed with status {status_code}: {response_message}",
                        status_code=status_code,
                        retryable=True,
                    )
                    logger.warning(
                        "Authentication returned retryable status %s on attempt %s/%s: %s",
                        status_code,
                        attempt,
                        REQUEST_RETRY_ATTEMPTS,
                        response_message,
                    )
                else:
                    logger.error(
                        f"Authentication failed: {status_code} - {response_message}"
                    )
                    raise CTMRequestError(
                        f"Thales CTM auth failed with status {status_code}: {response_message}",
                        status_code=status_code,
                        retryable=False,
                    )

            if attempt < REQUEST_RETRY_ATTEMPTS:
                _sleep_for_retry(attempt)

        raise last_error or CTMRequestError(
            "Thales CTM authentication failed", retryable=True
        )

    def _ensure_authenticated(self):
        """Ensure we have a valid bearer token"""
        if not self.bearer_token:
            self.authenticate()

    def _make_request(self, method: str, endpoint: str, **kwargs):
        """Make authenticated request to Thales CTM API with retry and token refresh."""
        base_url = f"https://{self.host}/api/v1/"
        url = urljoin(base_url, endpoint)
        last_error = None
        refreshed_token = False

        for attempt in range(1, REQUEST_RETRY_ATTEMPTS + 1):
            self._ensure_authenticated()

            headers = kwargs.setdefault("headers", {})
            headers["Authorization"] = f"Bearer {self.bearer_token}"
            headers.setdefault("Content-Type", "application/json")

            # Set SSL verification based on configuration
            if self.verify_ssl:
                kwargs["verify"] = self.ca_cert if self.ca_cert else True
            else:
                kwargs["verify"] = False
            kwargs["timeout"] = kwargs.get("timeout", REQUEST_TIMEOUT_SECONDS)

            try:
                response = requests.request(method, url, **kwargs)
            except requests.exceptions.Timeout as exc:
                last_error = CTMRequestError(
                    f"Thales CTM request timed out calling {endpoint}: {exc}",
                    retryable=True,
                )
                self.bearer_token = None
                logger.warning(
                    "Timeout calling %s on attempt %s/%s: %s",
                    endpoint,
                    attempt,
                    REQUEST_RETRY_ATTEMPTS,
                    exc,
                )
            except requests.exceptions.ConnectionError as exc:
                last_error = CTMRequestError(
                    f"Thales CTM connection failed calling {endpoint}: {exc}",
                    retryable=True,
                )
                self.bearer_token = None
                logger.warning(
                    "Connection failure calling %s on attempt %s/%s: %s",
                    endpoint,
                    attempt,
                    REQUEST_RETRY_ATTEMPTS,
                    exc,
                )
            except requests.exceptions.RequestException as exc:
                last_error = CTMRequestError(
                    f"Thales CTM request failed calling {endpoint}: {exc}",
                    retryable=True,
                )
                self.bearer_token = None
                logger.warning(
                    "Unexpected request failure calling %s on attempt %s/%s: %s",
                    endpoint,
                    attempt,
                    REQUEST_RETRY_ATTEMPTS,
                    exc,
                )
            else:
                status_code = response.status_code
                response_message = _response_message(response)

                if status_code == 401 and not refreshed_token:
                    logger.info(
                        "CTM returned 401 for %s; clearing bearer token and retrying once",
                        endpoint,
                    )
                    self.bearer_token = None
                    refreshed_token = True
                    last_error = CTMRequestError(
                        f"Thales CTM returned 401 for {endpoint}: {response_message}",
                        status_code=status_code,
                        retryable=True,
                    )
                elif _is_retryable_status(status_code):
                    self.bearer_token = None
                    last_error = CTMRequestError(
                        f"Thales CTM returned {status_code} for {endpoint}: {response_message}",
                        status_code=status_code,
                        retryable=True,
                    )
                    logger.warning(
                        "Retryable CTM status %s calling %s on attempt %s/%s: %s",
                        status_code,
                        endpoint,
                        attempt,
                        REQUEST_RETRY_ATTEMPTS,
                        response_message,
                    )
                elif status_code >= 400:
                    logger.error(
                        "CTM request failed for %s: %s - %s",
                        endpoint,
                        status_code,
                        response_message,
                    )
                    raise CTMRequestError(
                        f"Thales CTM request failed with status {status_code} for {endpoint}: {response_message}",
                        status_code=status_code,
                        retryable=False,
                    )
                else:
                    return response

            if attempt < REQUEST_RETRY_ATTEMPTS:
                _sleep_for_retry(attempt)

        raise last_error or CTMRequestError(
            f"Thales CTM request failed for {endpoint}", retryable=True
        )

    def get_secret(self, key_id: str, wrapping_key: bytes) -> Dict[str, str]:
        """
        Get and wrap a secret from Thales CTM using RSA public key wrapping.

        Args:
            key_id: ID of the secret/key to retrieve from CTM
            wrapping_key: RSA public key (can be raw bytes, PEM, DER, or base64 encoded)

        Returns:
            Dictionary with wrapped_key, blob, iv, and tag in base64 format
        """
        logger.info(f"Thales CTM KBM get_secret request for key_id: {key_id}")

        with self._lock:
            # Print the received public key (base64 encoded)
            if isinstance(wrapping_key, bytes):
                wrapping_key_b64 = base64.b64encode(wrapping_key).decode("ascii")
                print("\n" + "=" * 70)
                print("RECEIVED PUBLIC KEY (base64):")
                print(wrapping_key_b64)
                print("=" * 70 + "\n")

            # Decode base64 if necessary
            if isinstance(wrapping_key, bytes):
                # Check if it's base64 encoded by trying to decode
                try:
                    decoded = base64.b64decode(wrapping_key)
                    # If successful and it looks like a valid key, use the decoded version
                    if b"-----BEGIN" in decoded or len(decoded) > 100:
                        logger.debug(
                            "Detected base64 encoded public key, decoded successfully"
                        )
                        wrapping_key = decoded
                except Exception:
                    # Not base64 or decoding failed, use as-is
                    logger.debug("Using public key as provided (not base64 encoded)")

            # Load and validate the RSA public key
            pub = _load_rsa_public_key(wrapping_key)
            logger.info(f"Validated RSA public key: {pub.key_size} bits")

            temp_wrapping_key_id = None
            try:
                # Step 1: Generate temporary AES-256 wrapping key in CTM
                logger.info("Step 1: Generating temporary AES-256 wrapping key in CTM")
                temp_wrapping_key_id = self._generate_aes_key()

                # Step 2: Wrap the secret with the temporary wrapping key using AES Key Wrap
                logger.info(
                    f"Step 2: Wrapping secret {key_id} with temporary wrapping key"
                )
                wrapped_secret_result = self._wrap_key(key_id, temp_wrapping_key_id)
                wrapped_secret_material = wrapped_secret_result.get("material", "")

                if not wrapped_secret_material:
                    raise Exception("No wrapped secret material returned from CTM")

                logger.info(
                    f"Secret wrapped successfully, material length: {len(wrapped_secret_material)} chars"
                )

                # Step 3: Wrap the temporary wrapping key with the RSA public key
                logger.info(
                    "Step 3: Wrapping temporary wrapping key with RSA public key"
                )
                wrapped_wrapping_key_result = self._wrap_key_with_public_key(
                    temp_wrapping_key_id, wrapping_key
                )
                wrapped_wrapping_key_material = wrapped_wrapping_key_result.get(
                    "material", ""
                )

                if not wrapped_wrapping_key_material:
                    raise Exception(
                        "No wrapped wrapping key material returned from CTM"
                    )

                logger.info(
                    f"Wrapping key wrapped successfully, material length: {len(wrapped_wrapping_key_material)} chars"
                )

                # Step 4: Return in the expected format
                # Note: AES Key Wrap doesn't use IV or tag, but we include empty strings for compatibility

                # To conform to all other data being Base64 encoded, the algorithm is encoded too.
                algorithm_b64 = base64.b64encode(
                    self.key_wrap_algorithm.encode("utf-8")
                ).decode("ascii")

                result = {
                    "wrapped_key": wrapped_wrapping_key_material,  # RSA-wrapped AES wrapping key
                    "blob": wrapped_secret_material,  # AES Key Wrap encrypted secret
                    "iv": "",  # Not used in AES Key Wrap
                    "tag": "",  # Not used in AES Key Wrap
                    "algorithm": algorithm_b64,  # Indicate the wrapping algorithm used
                }

                # Print the payload
                print("\n" + "=" * 70)
                print("PAYLOAD (Result):")
                print(f"wrapped_key: {result['wrapped_key']}")
                print(f"blob: {result['blob']}")
                print(f"iv: {result['iv']}")
                print(f"tag: {result['tag']}")
                print("=" * 70 + "\n")

                logger.info(f"Successfully wrapped secret for key_id: {key_id}")
                return result

            finally:
                # Step 5: Cleanup - delete the temporary wrapping key
                if temp_wrapping_key_id:
                    try:
                        logger.info("Step 4: Cleaning up temporary wrapping key")
                        self._delete_key(temp_wrapping_key_id)
                        logger.info("Temporary wrapping key deleted successfully")
                    except Exception as e:
                        logger.warning(
                            f"Failed to delete temporary wrapping key {temp_wrapping_key_id}: {e}"
                        )
                # Clear bearer token to force fresh authentication on next request
                # Prevents token expiration issues when TAS server runs for > 300 seconds
                self.bearer_token = None
                logger.debug("Bearer token cleared after kbm_get_secret completion")

    def _generate_aes_key(self, key_name: str = None) -> str:
        """Generate a random AES-256 key in Thales CTM and return the key ID"""
        if not key_name:
            timestamp = int(time.time())
            key_name = f"temp-AES-Key-{timestamp}"

        logger.info(f"Generating AES-256 key in CTM with name: {key_name}")

        key_data = {
            "name": key_name,
            "algorithm": "aes",
            "size": 256,
            "usageMask": 81,  # Wrap Key (16) + Export (64) + Encrypt (1) = 81
            "format": "raw",
        }

        response = self._make_request("POST", "vault/keys2/", json=key_data)

        if response.status_code == 201:
            result = response.json()
            key_id = result.get("id")
            if not key_id:
                raise Exception("CTM did not return a key ID")
            logger.info(f"Successfully created AES-256 key: {key_id}")
            return key_id
        else:
            logger.error(
                f"Key generation failed: {response.status_code} - {response.text}"
            )
            raise Exception(f"Thales CTM key generation failed: {response.status_code}")

    def _delete_key(self, key_id: str) -> bool:
        """Delete a key from Thales CTM"""
        logger.info(f"Deleting key from CTM: {key_id}")

        response = self._make_request("DELETE", f"vault/keys2/{key_id}")

        if response.status_code in (200, 204):
            logger.info(f"Successfully deleted key: {key_id}")
            return True
        else:
            logger.error(
                f"Key deletion failed: {response.status_code} - {response.text}"
            )
            raise Exception(f"Thales CTM key deletion failed: {response.status_code}")

    def _wrap_key(self, secret_key_id: str, wrapping_key_id: str) -> Dict[str, Any]:
        """
        Wrap/export a secret key using a wrapping key with AES Key Wrap with Padding (RFC 5649)

        Args:
            secret_key_id: ID of the pre-existing secret to wrap
            wrapping_key_id: ID of the AES-256 wrapping key

        Returns:
            Dictionary containing the wrapped material and metadata from CTM
        """
        logger.info(
            f"Wrapping secret {secret_key_id} with wrapping key {wrapping_key_id}"
        )

        export_data = {
            "format": "raw",
            "wrappingMethod": "encrypt",
            "wrapKeyName": wrapping_key_id,
            "wrappingEncryptionAlgo": f"{self.key_wrap_algorithm}",
            "padded": True,
        }

        response = self._make_request(
            "POST", f"vault/keys2/{secret_key_id}/export", json=export_data
        )

        if response.status_code == 200:
            result = response.json()
            material = result.get("material", "")
            logger.info(
                f"Successfully wrapped secret with AES Key Wrap (RFC 5649), material length: {len(material)} chars"
            )
            return result
        else:
            logger.error(
                f"Key wrapping failed: {response.status_code} - {response.text}"
            )
            raise Exception(f"Thales CTM key wrapping failed: {response.status_code}")

    def _wrap_key_with_public_key(
        self, wrapping_key_id: str, public_key_pem: bytes
    ) -> Dict[str, Any]:
        """
        Wrap/export the wrapping key using an RSA public key

        Args:
            wrapping_key_id: ID of the AES-256 wrapping key to wrap
            public_key_pem: RSA public key in PEM format

        Returns:
            Dictionary containing the wrapped wrapping key material from CTM
        """
        logger.info(f"Wrapping AES key {wrapping_key_id} with RSA public key")

        # Convert bytes to string if needed
        if isinstance(public_key_pem, bytes):
            try:
                public_key_pem = public_key_pem.decode("utf-8")
            except UnicodeDecodeError:
                # If UTF-8 fails, try to load as DER and convert to PEM
                try:
                    from cryptography.hazmat.primitives import serialization

                    public_key_obj = load_der_public_key(public_key_pem)
                    public_key_pem = public_key_obj.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo,
                    ).decode("utf-8")
                    logger.debug("Converted DER public key to PEM format")
                except Exception as e:
                    logger.error(f"Failed to decode public key: {e}")
                    raise ValueError(f"Unable to decode public key: {e}")

        export_data = {
            "format": "raw",
            "wrapPublicKey": public_key_pem,
            "wrapPublicKeyPadding": "oaep256",  # Use OAEP with SHA-256
        }

        response = self._make_request(
            "POST", f"vault/keys2/{wrapping_key_id}/export", json=export_data
        )

        if response.status_code == 200:
            result = response.json()
            material = result.get("material", "")
            logger.info(
                f"Successfully wrapped AES key with RSA public key, material length: {len(material)} chars"
            )
            return result
        else:
            logger.error(
                f"RSA key wrapping failed: {response.status_code} - {response.text}"
            )
            raise Exception(
                f"Thales CTM RSA key wrapping failed: {response.status_code}"
            )


def kbm_open_client_connection(config_file: str = None):
    """
    Initialize the Thales CTM KBM client.

    Config file (YAML or JSON) format:
      host: "ctm-hostname.example.com"
      verify_ssl: false  # optional, defaults to false
      ca_certfile: "/path/to/ca.pem"  # required if verify_ssl is true
      certificate_login: false  # optional, defaults to false

      # For password authentication (certificate_login: false):
      username: "ctm_user"
      password: "ctm_password"

      # For certificate authentication (certificate_login: true):
      auth_certfile: "/path/to/client.pem"
      auth_keyfile: "/path/to/client.key"
    """
    logger.info("Initializing Thales CTM KBM client connection")
    cfg = _load_config_file(config_file)

    # Extract connection parameters
    host = cfg.get("host")
    verify_ssl = cfg.get("verify_ssl", False)
    ca_cert = cfg.get("ca_certfile")
    certificate_login = cfg.get("certificate_login", False)

    if not host:
        raise ValueError("Thales CTM host is required in config file")

    # Authentication parameters
    username = cfg.get("username")
    password = cfg.get("password")
    cert_file = cfg.get("auth_certfile")
    key_file = cfg.get("auth_keyfile")
    domain = cfg.get("domain", "root")  # Default to 'root' if not specified

    logger.info(f"Thales CTM KBM client initialized for host: {host}")
    return _CTMKBMClient(
        host=host,
        verify_ssl=verify_ssl,
        ca_cert=ca_cert,
        username=username,
        password=password,
        cert_file=cert_file,
        key_file=key_file,
        certificate_login=certificate_login,
        domain=domain,
    )


def kbm_close_client_connection(kmip_client) -> None:
    """Close the Thales CTM KBM client connection"""
    logger.info("Closing Thales CTM KBM client connection")
    if self.bearer_token:
        self.bearer_token = None
        logger.debug("Bearer token cleared on client close")
    return None


def kbm_get_secret(kmip_client, key_id: str, wrapping_key: bytes):
    """
    Get and wrap a secret from Thales CTM.

    Returns dict: {"wrapped_key": b64, "blob": b64, "iv": b64, "tag": b64}
    """
    if not isinstance(kmip_client, _CTMKBMClient):
        logger.error("Invalid client handle provided")
        raise ValueError("Invalid client handle")
    if not key_id:
        logger.error("key_id is required but not provided")
        raise ValueError("key_id required")
    if not wrapping_key:
        logger.error("wrapping_key is required but not provided")
        raise ValueError("wrapping_key (client RSA public key) is required")

    return kmip_client.get_secret(key_id, wrapping_key)


__all__ = [
    # Public KBM plugin API
    "kbm_open_client_connection",
    "kbm_close_client_connection",
    "kbm_get_secret",
]
