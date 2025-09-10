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
export TAS_KBM_CONFIG_FILE='./config/pykmip/alt.conf'
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

- TAS-specific keys (stored in Flask’s config; set directly via env without prefix):
  - TAS_VERSION (str)
  - TAS_API_KEY (str, must be at least TAS_API_KEY_MIN_LENGTH)
  - TAS_API_KEY_MIN_LENGTH (int)
  - TAS_NONCE_EXPIRATION_SECONDS (int)
  - TAS_REDIS_HOST (str)
  - TAS_REDIS_PORT (int)
  - TAS_PLUGIN_PREFIX (str)
  - TAS_KBM_CONFIG_FILE (str, path)
  - Optional nested structures (e.g., limits.max_nonce_per_minute via TAS_OVERRIDE__)

Example deep override:
```bash
export TAS_OVERRIDE__limits__max_nonce_per_minute=120
```

## Environment variable examples
```bash
export TAS_CONFIG_CLASS=config.ProductionConfig
export TAS_REDIS_HOST=redis.internal
export TAS_REDIS_PORT=6380
export TAS_NONCE_EXPIRATION_SECONDS=180
export TAS_KBM_CONFIG_FILE=./config/pykmip/alt.conf
export TAS_PLUGIN_PREFIX=tas_kbm
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

