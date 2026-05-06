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
        requests_timeout: Optional[int] = None,
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
        self.requests_timeout = requests_timeout
        self._lock = threading.RLock()

        # Map canonical algorithm names to the strings Thales CTM accepts
        self._ctm_algorithm_map = {
            "AES-KWP": "AES/AESKEYWRAPPADDING",
        }

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

        # Make auth request
        if self.requests_timeout:
            request_kwargs["timeout"] = self.requests_timeout
        response = requests.post(auth_url, json=auth_data, **request_kwargs)

        if response.status_code == 200:
            token_data = response.json()
            self.bearer_token = token_data.get("jwt")
            client_verify = response.headers.get("Client-Verify", "N/A")
            logger.info(
                f"Successfully authenticated to Thales CTM (Client-Verify: {client_verify})"
            )
            return self.bearer_token
        else:
            logger.error(
                f"Authentication failed: {response.status_code} - {response.text}"
            )
            raise Exception(f"Thales CTM auth failed: {response.status_code}")

    def _ensure_authenticated(self):
        """Ensure we have a valid bearer token"""
        if not self.bearer_token:
            self.authenticate()

    def _make_request(self, method: str, endpoint: str, **kwargs):
        """Make authenticated request to Thales CTM API"""
        self._ensure_authenticated()

        base_url = f"https://{self.host}/api/v1/"
        url = urljoin(base_url, endpoint)

        headers = kwargs.setdefault("headers", {})
        headers["Authorization"] = f"Bearer {self.bearer_token}"
        headers.setdefault("Content-Type", "application/json")

        # Set SSL verification based on configuration
        if self.verify_ssl:
            kwargs.setdefault("verify", self.ca_cert if self.ca_cert else True)
        else:
            kwargs.setdefault("verify", False)

        # Set request timeout if configured
        if self.requests_timeout:
            kwargs.setdefault("timeout", self.requests_timeout)

        return requests.request(method, url, **kwargs)

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
            if isinstance(wrapping_key, bytes):
                wrapping_key_b64 = base64.b64encode(wrapping_key).decode("ascii")
                logger.debug("\n" + "=" * 70)
                logger.debug(f"Received public key (base64): {wrapping_key_b64}")
                logger.debug("\n" + "=" * 70)

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

                # Log the payload
                logger.debug("\n" + "=" * 70)
                logger.debug("PAYLOAD (Result):")
                logger.debug(f"wrapped_key: {result['wrapped_key']}")
                logger.debug(f"blob: {result['blob']}")
                logger.debug(f"iv: {result['iv']}")
                logger.debug(f"tag: {result['tag']}")
                logger.debug("=" * 70 + "\n")

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

        ctm_algo = self._ctm_algorithm_map.get(
            self.key_wrap_algorithm, self.key_wrap_algorithm
        )
        logger.debug(
            f"Translating key wrap algorithm '{self.key_wrap_algorithm}' -> '{ctm_algo}' for CTM API"
        )

        export_data = {
            "format": "raw",
            "wrappingMethod": "encrypt",
            "wrapKeyName": wrapping_key_id,
            "wrappingEncryptionAlgo": ctm_algo,
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
      verify_ssl: true  # optional, defaults to true
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
    key_wrap_algorithm = cfg.get("key_wrap_algorithm", "AES-KWP")
    requests_timeout = cfg.get(
        "requests_timeout"
    )  # Timeout in seconds for HTTP requests
    if requests_timeout is not None:
        requests_timeout = int(requests_timeout)  # Ensure it's an integer

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
        key_wrap_algorithm=key_wrap_algorithm,
        requests_timeout=requests_timeout,
    )


def kbm_close_client_connection(kmip_client) -> None:
    """Close the Thales CTM KBM client connection"""
    logger.info("Closing Thales CTM KBM client connection")
    # No special cleanup needed for CTM client
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
