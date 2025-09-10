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
import os

from tas.tas_logging import get_logger

logger = get_logger(__name__)


# TODO Set sensible defaults and document all config options
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

    # TAS specifics
    # TODO remove getenv and use hardcoded defaults as we will overide with env vars in later stages
    TAS_VERSION = "0.1.0"
    TAS_API_KEY = os.getenv("TAS_API_KEY", "")
    TAS_API_KEY_MIN_LENGTH = int(os.getenv("TAS_API_KEY_MIN_LENGTH", "64"))
    TAS_NONCE_EXPIRATION_SECONDS = int(os.getenv("TAS_NONCE_EXPIRATION_SECONDS", "120"))
    TAS_REDIS_HOST = os.getenv("TAS_REDIS_HOST", "localhost")
    TAS_REDIS_PORT = int(os.getenv("TAS_REDIS_PORT", "6379"))
    TAS_PLUGIN_PREFIX = os.getenv("TAS_PLUGIN_PREFIX", "tas_kbm")
    # TODO fix this  to take the config file relative to app.py file
    TAS_KBM_CONFIG_FILE = os.getenv(
        "TAS_KBM_CONFIG_FILE", "./config/kbm_mock_config.yaml"
    )
    TAS_KBM_PLUGIN = "tas_kbm_mock"  # default KBM plugin module name
    TAS_EXTRA_PLUGIN_DIR = None  # optional extra directory to search for plugins

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
