# TAS configuration

This guide makes it explicit how to set and override TAS and Flask configuration values at runtime.

## Config load order (lowest ➜ highest precedence)
1. BaseConfig class defaults (config.py, e.g., BaseConfig)
2. Environment-selected class TAS_CONFIG_CLASS (e.g., config.DevelopmentConfig or config.ProductionConfig)
3. Optional external file TAS_CONFIG_FILE
    - .py: loaded via Flask app.config.from_pyfile
    - .json/.yaml/.yml: parsed and merged into app.config
4. Individual environment variable overrides for known TAS keys (exact key names below)
5. Individual environment variable overrides for known Flask keys (must be prefixed with FLASK_)
6. Per-key deep overrides via TAS_OVERRIDE__ (double underscores split nesting), for nested structures

Higher numbers win.

## How to set configuration values

### 1) Select the base class
- Bash:
```bash
# One of:
export TAS_CONFIG_CLASS=config.DevelopmentConfig
export TAS_CONFIG_CLASS=config.ProductionConfig
```

### 2) Set TAS keys directly via environment variables
- Use the exact key name; examples:
```bash
export TAS_API_KEY='replace-with-a-strong-key-at-least-64-chars'
export TAS_NONCE_EXPIRATION_SECONDS=180
export TAS_REDIS_HOST='redis.internal'
export TAS_REDIS_PORT=6380
export TAS_PLUGIN_PREFIX='tas_kbm'
export TAS_KBM_PLUGIN='tas_kbm_kmip_json'
export TAS_KBM_CONFIG_FILE='./config/pykmip/alt.conf'
export TAS_EXTRA_PLUGIN_DIR='/opt/tas/plugins'
export TAS_POLICY_TRUST='./certs/policy'
```

### 3) Set Flask built-ins via FLASK_ prefix
- Prefix the Flask key with FLASK_; examples:
```bash
export FLASK_DEBUG=false
export FLASK_TESTING=false
export FLASK_SECRET_KEY='replace-with-a-random-secret'
export FLASK_JSON_SORT_KEYS=false
export FLASK_JSONIFY_PRETTYPRINT_REGULAR=false
export FLASK_PROPAGATE_EXCEPTIONS=true
```

Notes on types:
- Booleans: use true/false (case-insensitive) or 1/0.
- Integers: plain numbers, e.g., 6380, 180.
- Strings with spaces: quote them.

### 4) Use an external config file (optional)
Point TAS_CONFIG_FILE to a file. It is applied after TAS_CONFIG_CLASS but before per-key env overrides.

- Yaml file  but json works

- JSON
```bash
export TAS_CONFIG_FILE='/etc/tas/prod.json'
```
/etc/tas/prod.json:
```json
{
  "DEBUG": false,
  "TAS_REDIS_HOST": "redis.internal",
  "TAS_REDIS_PORT": 6380,
  "TAS_NONCE_EXPIRATION_SECONDS": 180,
  "limits": { "max_nonce_per_minute": 120 }
}
```

- YAML
```bash
export TAS_CONFIG_FILE='/etc/tas/prod.yaml'
```
/etc/tas/prod.yaml:
```yaml
DEBUG: false
TAS_REDIS_HOST: redis.internal
TAS_REDIS_PORT: 6380
TAS_NONCE_EXPIRATION_SECONDS: 180
limits:
  max_nonce_per_minute: 120
```
Example config file in config/tas_config.yaml

### 5) Deep override individual nested keys
- Use TAS_OVERRIDE__ with double underscores separating path segments.
- Example (sets limits.max_nonce_per_minute):
```bash
export TAS_OVERRIDE__limits__max_nonce_per_minute=120
export TAS_OVERRIDE__logging__level="DEBUG"
export TAS_OVERRIDE__logging__file="/var/log/tas.log"
```
- This has the highest precedence and will create intermediate objects if needed.

## Supported keys and expected types

- Flask built-in keys (set via FLASK_ prefix when using env):
  - DEBUG (bool)
  - TESTING (bool)
  - SECRET_KEY (str)
  - JSON_SORT_KEYS (bool)
  - JSONIFY_PRETTYPRINT_REGULAR (bool)
  - PROPAGATE_EXCEPTIONS (bool, optional)

### TAS-specific keys

Stored in Flask's config; set directly via env without prefix:

| Key | Type | Default | Required | Description |
|-----|------|---------|----------|-------------|
| TAS_VERSION | str | `"0.1.0"` | No | Application version string returned by the `/version` endpoint. |
| TAS_API_KEY | str | `""` | **Yes** | Shared secret used to authenticate every API request. Must be at least `TAS_API_KEY_MIN_LENGTH` characters long. |
| TAS_API_KEY_MIN_LENGTH | int | `64` | No | Minimum number of characters required for `TAS_API_KEY`. The application refuses to start if the API key is shorter than this value. |
| TAS_NONCE_EXPIRATION_SECONDS | int | `120` | No | Number of seconds a nonce remains valid after creation. Nonces older than this are rejected during attestation verification. |
| TAS_REDIS_HOST | str | `"localhost"` | No | Hostname or IP address of the Redis server used for nonce storage, certificate caching, and policy storage. |
| TAS_REDIS_PORT | int | `6379` | No | Port number of the Redis server. |
| TAS_PLUGIN_PREFIX | str | `"tas_kbm"` | No | Module name prefix used to discover KBM (Key Broker Module) plugins at startup. Only modules whose name starts with this prefix are loaded. |
| TAS_KBM_PLUGIN | str | `"tas_kbm_mock"` | No | Exact module name of the KBM plugin to activate. Must match one of the discovered plugins. Controls which key broker backend TAS uses (e.g., mock, KMIP, KMIP-JSON). |
| TAS_KBM_CONFIG_FILE | str | `"./config/kbm_mock_config.yaml"` | No | Path to the configuration file passed to the selected KBM plugin during initialisation. The format depends on the plugin (e.g., PyKMIP conf, KMIP-JSON YAML). |
| TAS_EXTRA_PLUGIN_DIR | str | `None` | No | Optional filesystem path to an additional directory to search for KBM plugins. Useful for loading out-of-tree or custom plugins without modifying the main `plugins/` folder. |
| TAS_POLICY_TRUST | str | *(not set)* | No | Path to a directory or PEM file containing trusted public keys used to verify policy signatures. If set, keys are loaded at startup; if no valid keys are found and signed-policy enforcement is enabled, the application refuses to start. |
| TAS_ENFORCE_SIGNED_POLICIES | bool | `true` | No | Controls whether policy signatures are checked. When `true` (default), signed policies must pass signature verification and unsigned policies are rejected. When `false`, all signature checks are skipped. **Warning: Set to `false` only for testing. Never disable in production — tampered or fake policies will be accepted.** |

### Nested TAS settings

These live under `app.config["TAS"]` as a nested dictionary. Set them in the YAML/JSON config file under the top-level `TAS:` key, or override individually with `TAS_OVERRIDE__section__key=value`.

#### Logging (`TAS.logging.*`)

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| logging.level | str | `"INFO"` | Python log level. One of `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`. |
| logging.file | str | `"./tas.log"` | File path where TAS writes log output. |
| logging.verbose | bool | `false` | When `true`, forces the log level to `DEBUG` regardless of `logging.level`. |
| logging.quiet | bool | `false` | When `true`, forces the log level to `WARNING` regardless of `logging.level`. |
| logging.cli | bool | `false` | When `true`, enables CLI-friendly log formatting (plain text, no timestamps). |

#### Rate Limits (`TAS.limits.*`)

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| limits.max_nonce_per_minute | int | `120` | Maximum number of nonces that can be generated per minute. Requests exceeding this limit are rejected. |

### Validation at startup

- **TAS_API_KEY** is required and must be at least `TAS_API_KEY_MIN_LENGTH` characters long. The application raises a `RuntimeError` and refuses to start otherwise.
- **TAS_POLICY_TRUST**, if set, must point to a path containing at least one valid PEM certificate. If no valid keys can be loaded and signed-policy enforcement is enabled, the application raises a `RuntimeError`.
- **TAS_ENFORCE_SIGNED_POLICIES** defaults to `true`. Setting it to `false` disables all policy signature checks. This means:
  - Unsigned policies are accepted without error.
  - Signed policies are stored without verifying the signature.
  - Tampered or forged policies cannot be detected.

  **Only set to `false` in development or test environments. In production, always keep this set to `true`.**

Example deep override:
```bash
export TAS_OVERRIDE__limits__max_nonce_per_minute=120
export TAS_OVERRIDE__logging__level="DEBUG"
export TAS_OVERRIDE__logging__file="/var/log/tas.log"
```

## Environment variable examples
```bash
export TAS_CONFIG_CLASS=config.ProductionConfig
export TAS_REDIS_HOST=redis.internal
export TAS_REDIS_PORT=6380
export TAS_NONCE_EXPIRATION_SECONDS=180
export TAS_KBM_CONFIG_FILE=./config/pykmip/alt.conf
export TAS_KBM_PLUGIN=tas_kbm_kmip_json
export TAS_PLUGIN_PREFIX=tas_kbm
export TAS_EXTRA_PLUGIN_DIR=/opt/tas/plugins
export TAS_POLICY_TRUST=./certs/policy
export TAS_API_KEY='...(>=64 chars)...'
```

## Run TAS with ProductionConfig or DevelopmentConfig

### Recommended (no code changes): environment variables

flask:
```bash
export TAS_CONFIG_CLASS=config.ProductionConfig
# or: export TAS_CONFIG_CLASS=config.DevelopmentConfig
export TAS_API_KEY='...>= TAS_API_KEY_MIN_LENGTH...'
flask run -h 0.0.0.0 -p 5000
```

gunicorn:
```bash
export TAS_CONFIG_CLASS=config.ProductionConfig
export TAS_API_KEY='...'
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

