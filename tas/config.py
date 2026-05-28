#
# TEE Attestation Service - Base Configuration Module
#
# Copyright 2025 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# This file is part of the TEE Attestation Service.
#
# This module is responsible for default configurations.
#

# config.py

from tas.tas_logging import get_logger

logger = get_logger(__name__)


class BaseConfig:
    # Flask built-ins
    DEBUG = False
    TESTING = False
    # SECRET_KEY = os.getenv("FLASK_SECRET_KEY", "dev-insecure-change-me")
    JSON_SORT_KEYS = False
    JSONIFY_PRETTYPRINT_REGULAR = False
    PROPAGATE_EXCEPTIONS = False
    TRAP_HTTP_EXCEPTIONS = False
    TRAP_BAD_REQUEST_ERRORS = None
    SESSION_COOKIE_NAME = "tas_session"
    MAX_CONTENT_LENGTH = 2 * 1024 * 1024  # 2 MB

    # TAS specifics
    TAS_VERSION = "0.1.0"
    TAS_API_KEY = ""
    TAS_API_KEY_MIN_LENGTH = 64
    TAS_MANAGEMENT_API_KEY = ""
    TAS_MANAGEMENT_API_KEY_MIN_LENGTH = 64
    TAS_NONCE_EXPIRATION_SECONDS = 120
    TAS_REDIS_HOST = "localhost"
    TAS_REDIS_PORT = 6379
    TAS_REDIS_PASSWORD = ""
    TAS_REDIS_PERSISTENCE = True
    TAS_EPHEMERAL_REDIS_URI = ""
    TAS_EPHEMERAL_REDIS_PASSWORD = ""
    TAS_PLUGIN_PREFIX = "tas_kbm"
    TAS_KBM_CONFIG_FILE = "./config/kbm_mock_config.yaml"
    TAS_KBM_PLUGIN = "tas_kbm_mock"
    TAS_EXTRA_PLUGIN_DIR = None

    # Rate limiting (Flask-Limiter native keys)
    RATELIMIT_ENABLED = True
    RATELIMIT_HEADERS_ENABLED = True
    RATELIMIT_STRATEGY = "fixed-window"
    RATELIMIT_SWALLOW_ERRORS = True
    RATELIMIT_KEY_PREFIX = "tas_ratelimit:"

    # Proxy-aware IP keying
    TAS_CLIENT_RATE_LIMIT = "200 per minute"
    TAS_TRUST_X_FORWARDED_FOR = False

    def __init__(self):
        logger.debug("Initializing BaseConfig with default TAS settings")


class DevelopmentConfig(BaseConfig):
    DEBUG = True

    def __init__(self):
        super().__init__()
        logger.debug("Initializing DevelopmentConfig with DEBUG=True")


class ProductionConfig(BaseConfig):
    PROPAGATE_EXCEPTIONS = False

    def __init__(self):
        super().__init__()
        logger.debug("Initializing ProductionConfig for production use")
