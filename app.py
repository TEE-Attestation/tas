#
# TEE Attestation Service
#
# Copyright 2025 - 2026 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# This file is part of the TEE Attestation Service.
# See LICENSE file for details.
#

import importlib
import os
import pkgutil
import sys

import redis
from flask import Flask, request

from tas.auth import init_client_auth, init_management_auth
from tas.client_routes import client_bp
from tas.config_loader import load_configuration, resolve_ratelimit_storage
from tas.error_handlers import register_error_handlers
from tas.management_routes import management_bp
from tas.nonce import check_redis_version
from tas.rate_limiter import setup_rate_limiter
from tas.tas_logging import configure_external_logging, setup_logging

# Initialize Flask app and load configuration
app = Flask(__name__)

# Set up basic logging first so config_loader can use it
logger = setup_logging(name="tas", level="INFO", cli_mode=True)
logger.debug("Loading in config")

# Load configuration
load_configuration(app)

# Initialise authentication
init_client_auth(app)
init_management_auth(app)

# Reconfigure logging with settings from config if available
tas_config = app.config.get("TAS", {})
log_config = tas_config.get("logging", {}) if isinstance(tas_config, dict) else {}

if log_config:
    # Get logging configuration with defaults
    log_level = log_config.get("level", "INFO")
    log_file = log_config.get("file", None)
    verbose = log_config.get("verbose", False)
    quiet = log_config.get("quiet", False)
    cli = log_config.get("cli", False)

    # Reconfigure the root "tas" logger with settings from config
    logger = setup_logging(
        name="tas",
        level=log_level,
        cli_mode=cli,
        verbose=verbose,
        quiet=quiet,
        log_file=log_file,
    )
else:
    logger.debug("No TAS logging configuration found, using defaults")

# Include logging settings in external loggers
configure_external_logging()
# add ./plugins in sys.path
fpath = os.path.join(os.path.dirname(__file__), "plugins")
sys.path.append(fpath)
logger.debug(sys.path)

logger.info("TAS application initialized successfully")


# Add request logging middleware
@app.before_request
def log_request_info():
    logger.info(f"Request: {request.method} {request.path} from {request.remote_addr}")
    if request.is_json and request.get_json():
        # Log request data without sensitive fields
        data = request.get_json()
        safe_data = {
            k: v
            for k, v in data.items()
            if k not in ["nonce", "wrapping-key", "tee-evidence"]
        }
        if safe_data:
            logger.debug(f"Request data: {safe_data}")


@app.after_request
def log_response_info(response):
    logger.info(f"Response: {response.status_code} for {request.method} {request.path}")
    return response


register_error_handlers(app)
# Optionally add an extra plugin directory to sys.path
extra_plugin_dir = app.config.get("TAS_EXTRA_PLUGIN_DIR")
if extra_plugin_dir:
    if os.path.isdir(extra_plugin_dir):
        sys.path.append(extra_plugin_dir)
        logger.info(f"Added extra plugin directory to sys.path: {extra_plugin_dir}")
    else:
        raise RuntimeError(f"Extra plugin directory does not exist: {extra_plugin_dir}")

# Retrieve the API key from configuration
TAS_API_KEY = app.config["TAS_API_KEY"]

if not TAS_API_KEY:
    raise RuntimeError("TAS_API_KEY environment variable is not set")

# Plugin discovery: respect prefix defined in the configuration
# This allows for dynamic loading of plugins that follow the
# naming convention defined in plugin_prefix.
plugin_prefix = app.config["TAS_PLUGIN_PREFIX"]
discovered_plugins = {
    name: importlib.import_module(name)
    for finder, name, ispkg in pkgutil.iter_modules()
    if name.startswith(plugin_prefix)
}

# Initialize Redis client
try:
    redis_kwargs = {
        "host": app.config["TAS_REDIS_HOST"],
        "port": app.config["TAS_REDIS_PORT"],
        "decode_responses": True,
    }
    redis_password = app.config.get("TAS_REDIS_PASSWORD", "")
    if redis_password:
        redis_kwargs["password"] = redis_password

    redis_client = redis.StrictRedis(**redis_kwargs)
    # Test the connection to ensure Redis is reachable
    redis_client.ping()
    logger.info("Successful Connection to Redis Server")

    check_redis_version(redis_client)

    if redis_password:
        logger.info("Redis AUTH enabled")
    else:
        logger.info("Redis AUTH not configured (no TAS_REDIS_PASSWORD set)")
except redis.ConnectionError as e:
    raise RuntimeError(f"Failed to connect to the Redis server: {e}")
except Exception as e:
    raise RuntimeError(f"An unexpected error occurred while initializing Redis: {e}")

# Configure Redis persistence (AOF + RDB) if enabled
_redis_config_rewrite_ok = None  # None = persistence not attempted
if app.config.get("TAS_REDIS_PERSISTENCE", True):
    try:
        redis_client.config_set("appendonly", "yes")
        redis_client.config_set("appendfsync", "everysec")
        redis_client.config_set("save", "3600 1 300 100 60 10000")
        logger.info("Redis persistence configured (AOF + RDB)")
        try:
            redis_client.config_rewrite()
            _redis_config_rewrite_ok = True
            logger.info(
                "Redis CONFIG REWRITE successful — settings persisted to Redis config file"
            )
        except redis.ResponseError as e:
            _redis_config_rewrite_ok = False
            logger.warning(
                "Redis CONFIG REWRITE failed — if Redis restarts independently, "
                "persistence settings will be lost and policies WILL BE DESTROYED. "
                "Either grant CONFIG REWRITE permission or configure persistence "
                f"in your redis.conf manually: {e}"
            )
    except redis.ResponseError as e:
        _redis_config_rewrite_ok = False
        logger.warning(
            f"Could not configure Redis persistence (CONFIG SET rejected): {e}. "
            "Policies WILL BE LOST if Redis restarts without persistence. "
            "Ensure your Redis server has persistence enabled independently."
        )
else:
    logger.info("Redis persistence disabled by TAS_REDIS_PERSISTENCE=false")

# Expose Redis client and persistence state to blueprints
app.extensions["redis"] = redis_client
app.extensions["redis_config_rewrite_ok"] = _redis_config_rewrite_ok

# Initialize optional ephemeral Redis client for nonces and rate-limit counters
_ephemeral_redis_uri = (app.config.get("TAS_EPHEMERAL_REDIS_URI") or "").strip()
if _ephemeral_redis_uri:
    try:
        _ephemeral_kwargs = {"decode_responses": True}
        _ephemeral_password = app.config.get("TAS_EPHEMERAL_REDIS_PASSWORD", "")
        if _ephemeral_password:
            _ephemeral_kwargs["password"] = _ephemeral_password
        ephemeral_redis_client = redis.StrictRedis.from_url(
            _ephemeral_redis_uri, **_ephemeral_kwargs
        )
        ephemeral_redis_client.ping()
        logger.info("Successful connection to ephemeral Redis")

        check_redis_version(ephemeral_redis_client)

        app.extensions["redis_ephemeral"] = ephemeral_redis_client
    except redis.ConnectionError as e:
        raise RuntimeError(f"Failed to connect to ephemeral Redis: {e}")
    except Exception as e:
        raise RuntimeError(
            f"An unexpected error occurred while initializing ephemeral Redis: {e}"
        )
else:
    logger.info(
        "No ephemeral Redis configured — nonces and rate limiting use primary Redis"
    )

# Register blueprints
app.register_blueprint(management_bp)
app.register_blueprint(client_bp)

# Rate limiting storage resolution
_rl_storage_uri, _rl_storage_options, _rl_mode = resolve_ratelimit_storage(
    app.config, redis_client
)
logger.info("Rate limiter storage: %s", _rl_mode)

if app.config.get("TAS_TRUST_X_FORWARDED_FOR"):
    logger.warning(
        "TAS_TRUST_X_FORWARDED_FOR is enabled — rate limiting will use "
        "X-Forwarded-For header for client IP. Only enable this when TAS "
        "is behind a trusted reverse proxy; otherwise clients can spoof "
        "their IP to bypass rate limits."
    )

# Apply rate limit to all client blueprint routes
limiter = setup_rate_limiter(app, client_bp, _rl_storage_uri, _rl_storage_options)


# log discovered plugins for debugging
logger.debug("Discovered plugins:")
tas_kbm_plugin = None
for plugin_name in discovered_plugins:
    logger.debug(f" - {plugin_name}")
    if plugin_name == app.config["TAS_KBM_PLUGIN"]:
        tas_kbm_plugin = discovered_plugins[plugin_name]
if not tas_kbm_plugin:
    raise RuntimeError("tas_kbm plugin not found in discovered plugins")

# log the selected tas_kbm plugin for debugging
logger.info(f"Using tas_kbm plugin: {app.config['TAS_KBM_PLUGIN']}")
# Ensure the tas_kbm plugin has the required functions
required_functions = [
    "kbm_get_secret",
    "kbm_close_client_connection",
    "kbm_open_client_connection",
]
for func in required_functions:
    if not hasattr(tas_kbm_plugin, func):
        raise RuntimeError(f"Required function '{func}' not found in tas_kbm plugin")

# import the required functions from the tas_kbm plugin
kbm_get_secret = tas_kbm_plugin.kbm_get_secret
kbm_close_client_connection = tas_kbm_plugin.kbm_close_client_connection
kbm_open_client_connection = tas_kbm_plugin.kbm_open_client_connection
# Initialize the KBM client
logger.info("Initializing KBM client connection")
try:
    # use the tas_kbm plugin to open the KBM client connection
    kbm_client = kbm_open_client_connection(
        config_file=app.config["TAS_KBM_CONFIG_FILE"]
    )
    logger.info("KBM client connection established successfully")
    app.extensions["kbm_client"] = kbm_client
    app.extensions["kbm_get_secret"] = kbm_get_secret
except Exception as e:
    logger.error(f"Failed to initialize KBM client: {e}")
    raise RuntimeError(f"Failed to open KBM client connection: {e}")

if __name__ == "__main__":
    # Note: This is a simplified example and should not be used in production
    # without proper security measures such as HTTPS, etc.

    try:
        logger.info(
            f"Starting TAS server on {app.config.get('SERVER_BIND_HOST', '0.0.0.0')}:{app.config.get('SERVER_PORT', 5000)}"
        )
        logger.info(f"Debug mode: {app.config['DEBUG']}")
        app.run(
            host=app.config.get("SERVER_BIND_HOST", "0.0.0.0"),
            port=app.config.get("SERVER_PORT", 5000),
            debug=app.config["DEBUG"],
        )
    except Exception as e:
        logger.error(f"Failed to start TAS server: {e}")
        raise
    finally:
        # Ensure the KMIP client connection is closed when the application exits
        try:
            kbm_close_client_connection(kbm_client)
            logger.info("KMIP client connection closed.")
        except Exception as e:
            logger.error(f"Error closing KMIP client connection: {e}")
