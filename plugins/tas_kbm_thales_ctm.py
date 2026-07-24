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
import os
import re
import secrets
import threading
import time
from typing import Any, Dict, Optional
from urllib.parse import urljoin

import requests

try:
    import yaml  # PyYAML (listed in requirements)
except Exception:
    yaml = None

try:
    from redis import lock as redis_lock  # Redis locking for distributed sync
except ImportError:
    redis_lock = None

from cryptography.hazmat.primitives.serialization import (
    load_der_public_key,
    load_pem_public_key,
)

from tas.tas_logging import get_logger

# Setup logging for the Thales CTM KBM plugin
logger = get_logger("tas.plugins.tas_kbm_thales_ctm")

# Log if redis_lock module was not available
if redis_lock is None:
    logger.debug(
        "redis.lock module not available - distributed locking will not be available if needed"
    )

# Declare host dependencies (opt-in): this plugin requires redis_client for distributed locking
KBM_HOST_KWARGS = {"redis_client"}

# Module-level constant: Algorithm name mapping for Thales CTM
_CTM_ALGORITHM_MAP = {
    "AES-KWP": "AES/AESKEYWRAPPADDING",
}


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
        create_key_if_absent: bool = False,
        redis_client: Optional[Any] = None,
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
        self.create_key_if_absent = create_key_if_absent
        self.redis_client = redis_client  # Redis client for distributed locking
        self._auth_lock = (
            threading.Lock()
        )  # Guards bearer_token reads/writes across threads

        # Ensure requests_timeout has a reasonable default for lock calculations
        if not self.requests_timeout:
            self.requests_timeout = 30
            logger.warning(
                "No requests_timeout configured, using safe default of 30 seconds. "
                "This is used for calculating lock timeouts. To override, set "
                "requests_timeout in the config file."
            )

        # Validate Redis client connectivity if create_key_if_absent is enabled
        if self.create_key_if_absent:
            if not self.redis_client:
                raise ValueError(
                    "Redis client is required when create_key_if_absent=true. "
                    "Pass a Redis client via the redis_client parameter."
                )
            elif redis_lock is None:
                raise ImportError(
                    "redis-py library with lock support is required when create_key_if_absent=true. "
                    "The redis lock module failed to import. "
                    "Install or reinstall redis-py: pip install 'redis>=4.0'"
                )
            else:
                try:
                    self.redis_client.ping()
                    logger.info(
                        "Redis client is available and healthy for distributed locking"
                    )
                except Exception as e:
                    raise Exception(
                        f"Redis client connection failed: {e}. "
                        f"Redis is required for safe key auto-creation in multi-process deployments."
                    )

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

        # Authenticate immediately to fail fast on credential/connectivity errors
        self.authenticate()

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
        """Safety check: ensure we have a valid bearer token (re-authenticates if needed).

        Even though tokens are obtained in __init__(), this check guards against token expiry
        during long-running operations (slow CTM, network latency, lock contention). If CTM
        takes a long time or the lock waits, the 300-second token TTL could expire mid-request.
        This defensive check re-authenticates if the token is missing.
        """
        if not self.bearer_token:
            self.authenticate()

    def _make_request(self, method: str, endpoint: str, **kwargs):
        """Make authenticated request to Thales CTM API.

        Thread-safe: acquires _auth_lock only to snapshot/refresh the token, so
        concurrent threads can make HTTP calls in parallel without serialising on
        the network round-trip. On a 401 the token is refreshed once under the
        lock and the request is retried.
        """
        # Snapshot the token under the lock so concurrent threads each get their
        # own copy. The HTTP call itself happens outside the lock.
        with self._auth_lock:
            self._ensure_authenticated()
            token = self.bearer_token

        base_url = f"https://{self.host}/api/v1/"
        url = urljoin(base_url, endpoint)

        headers = kwargs.setdefault("headers", {})
        headers["Authorization"] = f"Bearer {token}"
        headers.setdefault("Content-Type", "application/json")

        # Set SSL verification based on configuration
        if self.verify_ssl:
            kwargs.setdefault("verify", self.ca_cert if self.ca_cert else True)
        else:
            kwargs.setdefault("verify", False)

        # Set request timeout if configured
        if self.requests_timeout:
            kwargs.setdefault("timeout", self.requests_timeout)

        response = requests.request(method, url, **kwargs)

        if response.status_code == 401:
            # Token was rejected (expired or invalidated server-side). Refresh
            # under the lock and retry once. Only one thread will re-authenticate;
            # others will pick up the new token via _ensure_authenticated.
            logger.debug("Received 401 from CTM; refreshing bearer token and retrying")
            with self._auth_lock:
                self.bearer_token = None
                self.authenticate()
                token = self.bearer_token
            headers["Authorization"] = f"Bearer {token}"
            response = requests.request(method, url, **kwargs)

        return response

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

        # Load and validate the RSA public key
        pub = _load_rsa_public_key(wrapping_key)
        logger.debug(f"Validated RSA public key: {pub.key_size} bits")

        # Step 1: Perform Key Lookup
        logger.debug("Step 1: Performing key lookup")
        lookup_status, resolved_key_id = self._lookup_key(key_id)
        logger.debug(
            f"Key lookup status: {lookup_status}, resolved_key_id: {resolved_key_id}"
        )

        if not lookup_status:
            # Key not found
            logger.debug(f"Key lookup failed: {key_id}")

            if self.create_key_if_absent:
                logger.debug(
                    f"Key not found and create_key_if_absent=true, acquiring lock to create key: {key_id}"
                )

                # Acquire Redis lock for distributed synchronization
                try:
                    lock_key = f"create_key:{key_id}"

                    # Calculate lock timeouts based on requests_timeout.
                    # Worst case inside the lock: two CTM calls (lookup + create), each
                    # of which may 401-retry (original request + re-auth + retry = 3 HTTP
                    # calls per CTM call). That gives 6 HTTP calls × req_timeout.
                    # Add one extra req_timeout as a safety margin so the lease outlives
                    # the work even under marginal network conditions.
                    req_timeout = self.requests_timeout
                    operation_timeout = 6 * req_timeout  # 6 worst-case HTTP calls
                    lock_timeout = operation_timeout + req_timeout  # + safety margin
                    blocking_timeout = operation_timeout  # wait up to full work time

                    logger.debug(
                        f"Lock timeout calculation: requests_timeout={req_timeout}s, "
                        f"operation_timeout={operation_timeout}s, "
                        f"lock_timeout={lock_timeout}s, "
                        f"blocking_timeout={blocking_timeout}s"
                    )

                    lock = redis_lock.Lock(
                        self.redis_client,
                        lock_key,
                        timeout=lock_timeout,
                        blocking=True,
                        blocking_timeout=blocking_timeout,
                    )
                    logger.debug(f"Using Redis lock for key creation: {key_id}")
                    logger.debug(f"Attempting to acquire lock for key {key_id}")

                    with lock:  # Auto-releases on exit
                        logger.debug(f"Lock acquired for key: {key_id}")

                        # Double-check key still doesn't exist (in case another process created it)
                        lookup_status, resolved_key_id = self._lookup_key(key_id)
                        if not lookup_status:
                            logger.debug(
                                f"Creating key while holding lock (other clients are blocked)"
                            )
                            # Create the key
                            create_status, created_key_id = self._create_secret_key(
                                key_id
                            )
                            if create_status and created_key_id:
                                resolved_key_id = created_key_id
                                logger.info(
                                    f"Successfully created key: {key_id} → ID: {resolved_key_id}"
                                )
                            else:
                                logger.error(f"Failed to create key: {key_id}")
                                raise Exception(
                                    f"Thales CTM key creation failed: {key_id}"
                                )
                        else:
                            logger.info(
                                f"Key was created by another process during lock wait: {key_id}"
                            )
                    # Log after the with-block so the message is emitted after the lock
                    # has actually been released by the context manager.
                    logger.debug(f"Released Redis lock for key creation: {key_id}")
                except Exception as e:
                    logger.error(f"Key creation with lock failed: {e}")
                    raise
            else:
                logger.error(f"Key not found and create_key_if_absent=false: {key_id}")
                raise Exception(f"Thales CTM key not found: {key_id}")

        logger.info(f"Key resolved: {resolved_key_id}")

        temp_wrapping_key_id = None
        try:
            # Step 2: Generate temporary AES-256 wrapping key in CTM
            logger.debug("Step 2: Generating temporary AES-256 wrapping key in CTM")
            temp_wrapping_key_id = self._generate_aes_key()

            # Step 3: Wrap the secret with the temporary wrapping key using AES Key Wrap
            logger.debug(
                f"Step 3: Wrapping secret {resolved_key_id} with temporary wrapping key"
            )
            wrapped_secret_result = self._wrap_key(
                resolved_key_id, temp_wrapping_key_id
            )
            wrapped_secret_material = wrapped_secret_result.get("material", "")

            if not wrapped_secret_material:
                logger.error("No wrapped secret material returned from CTM")
                raise Exception("No wrapped secret material returned from CTM")

            logger.info(
                f"Secret wrapped successfully, material length: {len(wrapped_secret_material)} chars"
            )

            # Step 4: Wrap the temporary wrapping key with the RSA public key
            logger.debug("Step 4: Wrapping temporary wrapping key with RSA public key")
            wrapped_wrapping_key_result = self._wrap_key_with_public_key(
                temp_wrapping_key_id, wrapping_key
            )
            wrapped_wrapping_key_material = wrapped_wrapping_key_result.get(
                "material", ""
            )

            if not wrapped_wrapping_key_material:
                logger.error("No wrapped wrapping key material returned from CTM")
                raise Exception("No wrapped wrapping key material returned from CTM")

            logger.info(
                f"Wrapping key wrapped successfully, material length: {len(wrapped_wrapping_key_material)} chars"
            )

            # Step 5: Return in the expected format
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
            # Step 6: Cleanup - delete the temporary wrapping key
            if temp_wrapping_key_id:
                try:
                    logger.debug("Step 6: Cleaning up temporary wrapping key")
                    self._delete_key(temp_wrapping_key_id)
                    logger.debug("Temporary wrapping key deleted successfully")
                except Exception as e:
                    logger.warning(
                        f"Failed to delete temporary wrapping key {temp_wrapping_key_id}: {e}"
                    )

    def _generate_aes_key(self, key_name: str = None) -> str:
        """Generate a random AES-256 key in Thales CTM and return the key ID"""
        if not key_name:
            # Use microsecond precision + random 32-bit hex to ensure unique names for concurrent requests
            # This guarantees uniqueness even if multiple requests arrive in the same microsecond
            timestamp_microseconds = int(time.time() * 1_000_000)
            random_suffix = secrets.token_hex(4)  # 32-bit random hex (8 characters)
            key_name = f"temp-AES-Key-{timestamp_microseconds}-{random_suffix}"

        logger.debug(f"Generating AES-256 key in CTM with name: {key_name}")

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
            logger.debug(f"Successfully created AES-256 key: {key_id}")
            return key_id
        else:
            logger.error(
                f"Key generation failed: {response.status_code} - {response.text}"
            )
            raise Exception(f"Thales CTM key generation failed: {response.status_code}")

    def _delete_key(self, key_id: str) -> bool:
        """Delete a key from Thales CTM"""
        logger.debug(f"Deleting key from CTM: {key_id}")

        response = self._make_request("DELETE", f"vault/keys2/{key_id}")

        if response.status_code in (200, 204):
            logger.debug(f"Successfully deleted key: {key_id}")
            return True
        else:
            logger.error(
                f"Key deletion failed: {response.status_code} - {response.text}"
            )
            raise Exception(f"Thales CTM key deletion failed: {response.status_code}")

    def _lookup_key(self, key_identifier: str) -> tuple[bool, Optional[str]]:
        """
        Lookup a key by ID or name via GET /vault/keys2/{key_identifier}.

        Args:
            key_identifier: Could be a key ID or key name

        Returns:
            Tuple of (success, key_id) where success is True/False
        """
        logger.debug(f"Looking up key: {key_identifier}")

        # Attempt direct lookup by ID or name
        response = self._make_request("GET", f"vault/keys2/{key_identifier}")

        if response.status_code == 200:
            result = response.json()
            key_id = result.get("id", key_identifier)
            logger.debug(f"Key lookup successful: {key_identifier} → ID: {key_id}")
            return True, key_id
        else:
            logger.debug(f"Key lookup failed with status {response.status_code}")
            return False, None

    def _create_secret_key(self, key_name: str) -> tuple[bool, Optional[str]]:
        """
        Create a new AES-256 secret key in Thales CTM with the given name.

        Args:
            key_name: Name for the new key

        Returns:
            Tuple of (success, key_id) where success is True/False
        """
        logger.debug(f"Creating new AES-256 secret key in CTM with name: {key_name}")

        key_data = {
            "name": key_name,
            "algorithm": "aes",
            "size": 256,
            "usageMask": 124,  # Encrypt (4) + Decrypt (8) + Wrap Key (16) + Unwrap Key (32) + Export Key (64) = 124
            "format": "raw",
        }

        response = self._make_request("POST", "vault/keys2/", json=key_data)

        if response.status_code == 201:
            result = response.json()
            key_id = result.get("id")
            if not key_id:
                logger.error("CTM did not return a key ID for newly created key")
                return False, None
            logger.debug(f"Successfully created secret key: {key_name} → ID: {key_id}")
            return True, key_id
        else:
            logger.error(
                f"Secret key creation failed: {response.status_code} - {response.text}"
            )
            return False, None

    def _wrap_key(self, secret_key_id: str, wrapping_key_id: str) -> Dict[str, Any]:
        """
        Wrap/export a secret key using a wrapping key with AES Key Wrap with Padding (RFC 5649)

        Args:
            secret_key_id: ID of the secret to wrap (must exist in CTM)
            wrapping_key_id: ID of the AES-256 wrapping key

        Returns:
            Dictionary containing the wrapped material and metadata from CTM

        Raises:
            Exception: If key wrapping operation fails
        """
        logger.debug(
            f"Wrapping secret {secret_key_id} with wrapping key {wrapping_key_id}"
        )

        # Prepare wrap parameters
        ctm_algo = _CTM_ALGORITHM_MAP.get(
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

        # Perform the wrap operation
        logger.debug("Performing key wrap operation")
        response = self._make_request(
            "POST", f"vault/keys2/{secret_key_id}/export", json=export_data
        )

        if response.status_code == 200:
            result = response.json()
            material = result.get("material", "")
            logger.debug(
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
        logger.debug(f"Wrapping AES key {wrapping_key_id} with RSA public key")

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
            logger.debug(
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


def kbm_open_client_connection(
    config_file: Optional[str] = None, redis_client: Optional[Any] = None
):
    """
    Initialize the Thales CTM KBM client.

    Args:
        config_file: Path to YAML/JSON config file
        redis_client: Optional Redis client for distributed locking (defaults to Flask app.extensions["redis"])

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
    verify_ssl = cfg.get("verify_ssl", True)
    if not verify_ssl:
        logger.warning(
            "TLS certificate verification is DISABLED for Thales CTM connections "
            "(verify_ssl=false in config). This is insecure and should only be used "
            "for development/testing."
        )
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

    # Auto-create key options
    create_key_if_absent = cfg.get("create_key_if_absent", False)

    if create_key_if_absent:
        if redis_client is None:
            logger.warning(
                "create_key_if_absent=true but no Redis client provided to kbm_open_client_connection(). "
                "Disabling auto-key-creation. To enable, pass redis_client parameter."
            )
            create_key_if_absent = False
        else:
            logger.info(
                "Auto-create secret keys is ENABLED (create_key_if_absent=true)"
            )
            logger.debug("Redis client provided for distributed key creation locking")

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
        create_key_if_absent=create_key_if_absent,
        redis_client=redis_client,
    )


def kbm_close_client_connection(ctm_client) -> None:
    """Close the Thales CTM KBM client connection"""
    logger.info("Closing Thales CTM KBM client connection")
    # No special cleanup needed for CTM client


def kbm_get_secret(ctm_client, key_id: str, wrapping_key: bytes) -> Dict[str, str]:
    """
    Get and wrap a secret from Thales CTM.

    Returns dict: {"wrapped_key": b64, "blob": b64, "iv": b64, "tag": b64}
    """
    if not isinstance(ctm_client, _CTMKBMClient):
        logger.error("Invalid client handle provided")
        raise ValueError("Invalid client handle")
    if not key_id:
        logger.error("key_id is required but not provided")
        raise ValueError("key_id required")
    if not wrapping_key:
        logger.error("wrapping_key is required but not provided")
        raise ValueError("wrapping_key (client RSA public key) is required")

    return ctm_client.get_secret(key_id, wrapping_key)


__all__ = [
    # Public KBM plugin API
    "kbm_open_client_connection",
    "kbm_close_client_connection",
    "kbm_get_secret",
]
