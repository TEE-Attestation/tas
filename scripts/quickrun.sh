#!/usr/bin/env bash
#
# TEE Attestation Service - Quick Run Script
#
# Copyright 2025-2026 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# Spins up a local TAS server instance for testing using the Mock KBM plugin.
# No external key manager or policy signing infrastructure is required.
#
# Usage:
#   bash ./quickrun.sh build [OPTIONS]
#   bash ./quickrun.sh run [OPTIONS]
#   bash ./quickrun.sh uninstall

set -euo pipefail

# ── Paths ─────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
QUICKRUN_DIR="${SCRIPT_DIR}/.quickrun"
VENV_DIR="${QUICKRUN_DIR}/venv"
BUILD_CONF="${QUICKRUN_DIR}/build.conf"   # persists build choices for 'run'
SERVICE_NAME="tas-quickrun"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

# ── Logging ───────────────────────────────────────────────────────────────
info()  { echo "[TAS] $*"; }
error() { echo "[TAS] ERROR: $*" >&2; exit 1; }

# ── Help ──────────────────────────────────────────────────────────────────
show_help() {
    cat << 'HELP'
TEE Attestation Service - Quick Run Script

Copyright 2025-2026 Hewlett Packard Enterprise Development LP.
SPDX-License-Identifier: MIT

Spins up a local TAS server instance for testing using the mock KBM plugin.
No external key manager or policy signing infrastructure is required.

The mock KBM plugin uses a local SQLite file to store secrets.
TAS itself always requires a running Redis server for policy and nonce storage.

Usage:
  bash ./quickrun.sh build [OPTIONS]
  bash ./quickrun.sh run [OPTIONS]
  bash ./quickrun.sh uninstall

BUILD COMMAND
  Sets up the virtual environment, installs dependencies, and writes config.
  Run once before the first 'run', or whenever you need to reconfigure.

  Options:
    --host HOST           Host/IP to bind to (default: 127.0.0.1)
    --port PORT           Port to listen on (default: 5000)
    --proxy PROXY_URL     Proxy for pip and git (e.g. http://proxy.example.com:8080)
    --tls                 Generate a self-signed certificate for HTTPS
    --build-env           Wipe and recreate the Python virtual environment
    --include-nvidia      Also install nvidia_pytools for GPU attestation
    --help, -h            Show this help message

RUN COMMAND
  Starts the TAS server using the configuration written by build.
  Host and port default to the values used during build.

  Options:
    --host HOST           Override the host/IP to bind to
    --port PORT           Override the port to listen on
    --tls                 Start with HTTPS (build must have been run with --tls)
    --run-as-service      Install and start as a systemd service (requires sudo)
    --help, -h            Show this help message

UNINSTALL COMMAND
  Removes all artifacts created by build (venv, config, API keys, certificates).
  If a systemd service was installed, stops and removes it too (requires sudo).

    uninstall

    e.g. ./quickrun.sh uninstall

Prerequisites:
  - Python 3.10+
  - openssl
  - Redis server running on localhost:6379

Examples:

  # First-time build
  bash ./quickrun.sh build

  # First-time build behind a corporate proxy
  bash ./quickrun.sh build --proxy "http://proxy.example.com:8080"

  # Build with HTTPS enabled
  bash ./quickrun.sh build --tls

  # Start the server (foreground)
  bash ./quickrun.sh run

  # Start on a different port
  bash ./quickrun.sh run --port 8080

  # Install and start as a persistent systemd service
  sudo bash ./quickrun.sh run --run-as-service

  # Remove everything (including the service if installed)
  sudo bash ./quickrun.sh uninstall
HELP
}

# ── Prerequisites ─────────────────────────────────────────────────────────
_check_prerequisites() {
    info "Checking prerequisites..."

    command -v python3 &>/dev/null || error "Python 3 is not installed."
    info "  Python $(python3 --version 2>&1 | awk '{print $2}') ... OK"

    command -v openssl &>/dev/null || error "openssl is not installed."
    info "  openssl ............. OK"
}

_check_redis() {
    command -v redis-cli &>/dev/null || error "redis-cli not found.
Install Redis:
  Debian/Ubuntu:  sudo apt install redis-server
  RHEL/Fedora:    sudo dnf install redis
  macOS:          brew install redis"

    redis-cli ping &>/dev/null || error "Redis is not running on localhost:6379.
Start Redis and retry:
  Debian/Ubuntu:  sudo systemctl start redis
  RHEL/Fedora:    sudo systemctl start redis
  macOS:          brew services start redis"

    info "  Redis ............... OK"
}

# ── Virtual Environment ───────────────────────────────────────────────────
_setup_venv() {
    local rebuild=${1:-false}

    if [[ "${rebuild}" == "true" ]] && [[ -d "${VENV_DIR}" ]]; then
        info "Removing existing virtual environment..."
        rm -rf "${VENV_DIR}"
    fi

    if [[ ! -f "${VENV_DIR}/bin/python" ]]; then
        info "Creating virtual environment..."
        python3 -m venv "${VENV_DIR}"
    else
        info "Reusing existing virtual environment."
    fi
}

# ── Package Installation ──────────────────────────────────────────────────
_pip_install() {
    local proxy=$1
    shift  # remaining args are the package(s) / flags passed to pip install

    local pip_out
    if [[ -n "${proxy}" ]]; then
        pip_out=$("${VENV_DIR}/bin/pip" install --proxy "${proxy}" \
            --index-url https://pypi.python.org/simple/ \
            "$@" 2>&1)
    else
        pip_out=$("${VENV_DIR}/bin/pip" install "$@" 2>&1)
    fi
    # Filter noise but don't mask pip's exit code (checked above via $())
    echo "${pip_out}" | grep -v "already satisfied" || true
}

_git_clone() {
    local url=$1
    local dest=$2
    local proxy=${3:-}

    if [[ -n "${proxy}" ]]; then
        git -c http.proxy="${proxy}" clone "${url}" "${dest}"
    else
        git clone "${url}" "${dest}"
    fi
}

_clone_and_install() {
    local name=$1
    local url=$2
    local proxy=${3:-}
    local dest="${QUICKRUN_DIR}/${name}"

    if [[ ! -d "${dest}" ]]; then
        info "Cloning ${name}..."
        _git_clone "${url}" "${dest}" "${proxy}"
    fi

    info "Installing ${name}..."
    cd "${dest}" || exit 1
    _pip_install "${proxy}" "."
    cd "${PROJECT_DIR}" || exit 1
}

_install_dependencies() {
    local proxy=${1:-}
    local include_nvidia=${2:-false}

    info "Installing dependencies..."

    _clone_and_install sev_pytools    https://github.com/TEE-Attestation/sev_pytools.git    "${proxy}"
    _clone_and_install tdx_pytools    https://github.com/TEE-Attestation/tdx_pytools.git    "${proxy}"

    if [[ "${include_nvidia}" == "true" ]]; then
        _clone_and_install nvidia_pytools https://github.com/TEE-Attestation/nvidia_pytools.git "${proxy}"
    fi

    # Install project requirements after pytools so they are already in place
    _pip_install "${proxy}" -r "${PROJECT_DIR}/requirements.txt"

    info "  Dependencies installed."
}

# ── Configuration Generation ──────────────────────────────────────────────
_generate_api_keys() {
    printf '%s' "$(openssl rand -hex 32)" > "${QUICKRUN_DIR}/TAS_API_KEY.txt"
    printf '%s' "$(openssl rand -hex 32)" > "${QUICKRUN_DIR}/TAS_MANAGEMENT_API_KEY.txt"
    info "API keys written to ${QUICKRUN_DIR}/"
}

_generate_configs() {
    local port=$1

    # KBM Mock config — always uses SQLite for local secret storage
    cat > "${QUICKRUN_DIR}/kbm_mock_config.yaml" << 'YAML'
backend: sqlite
db_path: kbm_db/kbm_mock_secrets.db
strict: false
YAML

    # TAS server config
    cat > "${QUICKRUN_DIR}/tas_config.yaml" << 'YAML'
SERVER_BIND_HOST: "0.0.0.0"
SERVER_PORT: PLACEHOLDER_PORT
TAS_ENFORCE_SIGNED_POLICIES: false
TAS_REDIS_PERSISTENCE: false
TAS:
  logging:
    level: "INFO"
    file: "./tas.log"
YAML
    sed -i "s/PLACEHOLDER_PORT/${port}/g" "${QUICKRUN_DIR}/tas_config.yaml"
}

_generate_tls_certificate() {
    local bind_host=${1:-127.0.0.1}
    info "Generating TLS CA and server certificate..."

    # Step 1: CA key + self-signed CA cert
    openssl req -x509 -newkey rsa:2048 \
        -keyout "${QUICKRUN_DIR}/tas_ca_key.pem" \
        -out    "${QUICKRUN_DIR}/tas_ca_cert.pem" \
        -days 365 -nodes -subj "/CN=TAS-QuickRun-CA" \
        -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" \
        &>/dev/null

    # Step 2: Server key + CSR
    openssl req -newkey rsa:2048 \
        -keyout "${QUICKRUN_DIR}/tas_key.pem" \
        -out    "${QUICKRUN_DIR}/tas_server.csr" \
        -nodes -subj "/CN=${HOSTNAME}" \
        &>/dev/null

    # Step 3: Build SAN — always include localhost; add $HOSTNAME and the
    # bind host if they are not 0.0.0.0 (bind-all) or already covered.
    local san="DNS:localhost,DNS:127.0.0.1,IP:127.0.0.1,DNS:${HOSTNAME}"
    if [[ "${bind_host}" != "0.0.0.0" && "${bind_host}" != "127.0.0.1" && "${bind_host}" != "localhost" ]]; then
        # Determine whether it looks like an IP address or a hostname
        if [[ "${bind_host}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            san="${san},IP:${bind_host}"
        else
            san="${san},DNS:${bind_host}"
        fi
    else
        # bind-all: include every non-loopback IP currently assigned to this host
        while IFS= read -r _ip; do
            [[ "$_ip" == "127.0.0.1" ]] && continue
            san="${san},IP:${_ip}"
        done < <(hostname -I | tr ' ' '\n' | grep -v '^$')
    fi

    # Step 4: Sign the server CSR with the CA
    local ext_file; ext_file=$(mktemp)
    printf 'subjectAltName=%s\nbasicConstraints=critical,CA:FALSE\n' "${san}" > "${ext_file}"
    openssl x509 -req \
        -in     "${QUICKRUN_DIR}/tas_server.csr" \
        -CA     "${QUICKRUN_DIR}/tas_ca_cert.pem" \
        -CAkey  "${QUICKRUN_DIR}/tas_ca_key.pem" \
        -CAcreateserial \
        -out    "${QUICKRUN_DIR}/tas_cert.pem" \
        -days 30 -sha256 -extfile "${ext_file}" \
        &>/dev/null
    rm -f "${ext_file}" "${QUICKRUN_DIR}/tas_server.csr" "${QUICKRUN_DIR}/tas_ca_cert.srl"

    info "  CA cert:     ${QUICKRUN_DIR}/tas_ca_cert.pem"
    info "  Server cert: ${QUICKRUN_DIR}/tas_cert.pem"
    info "  Server key:  ${QUICKRUN_DIR}/tas_key.pem"
}

# ── Build State Persistence ───────────────────────────────────────────────
# Saves choices made during build so 'run' can restore them as defaults.
_save_setup_conf() {
    cat > "${BUILD_CONF}" << EOF
port=$1
host=$2
use_tls=$3
EOF
}

_load_setup_conf() {
    # shellcheck source=/dev/null
    [[ -f "${BUILD_CONF}" ]] && source "${BUILD_CONF}" || true
}

# ── Service Installation ───────────────────────────────────────────────────
_install_service() {
    local host=$1
    local port=$2
    local use_tls=$3

    # Requires root — write access to /etc/systemd/system/
    [[ "${EUID}" -eq 0 ]] || error "Installing a systemd service requires root.
Run with sudo:
  sudo bash ./quickrun.sh run --run-as-service"

    # Run as root — avoids permission issues with certs/keys in a dev environment
    local service_user="root"
    local service_group="root"

    local api_key management_api_key
    api_key=$(cat "${QUICKRUN_DIR}/TAS_API_KEY.txt")
    management_api_key=$(cat "${QUICKRUN_DIR}/TAS_MANAGEMENT_API_KEY.txt")

    # Build the ExecStart line
    local exec_start="${VENV_DIR}/bin/python3 -m flask run --host=${host} --port=${port}"
    if [[ "${use_tls}" == "true" ]]; then
        exec_start="${exec_start} --cert=${QUICKRUN_DIR}/tas_cert.pem --key=${QUICKRUN_DIR}/tas_key.pem"
    fi

    # Optional TLS environment block (empty string when TLS is off)
    local tls_env=""
    if [[ "${use_tls}" == "true" ]]; then
        tls_env="Environment=TAS_CERT_FILE=${QUICKRUN_DIR}/tas_cert.pem
Environment=TAS_KEY_FILE=${QUICKRUN_DIR}/tas_key.pem"
    fi

    info "Writing ${SERVICE_FILE}..."
    cat > "${SERVICE_FILE}" << EOF
[Unit]
Description=TAS (TEE Attestation Service) Quick-Run Server
After=network.target redis.service
Requires=redis.service

[Service]
Type=simple
User=${service_user}
Group=${service_group}
WorkingDirectory=${PROJECT_DIR}
Environment=PATH=${VENV_DIR}/bin:/usr/local/bin:/usr/bin:/bin
Environment=PYTHONPATH=${PROJECT_DIR}
Environment=FLASK_APP=${PROJECT_DIR}/app.py
Environment=TAS_API_KEY=${api_key}
Environment=TAS_MANAGEMENT_API_KEY=${management_api_key}
Environment=TAS_KBM_PLUGIN=tas_kbm_mock
Environment=TAS_KBM_CONFIG_FILE=${QUICKRUN_DIR}/kbm_mock_config.yaml
Environment=TAS_CONFIG_FILE=${QUICKRUN_DIR}/tas_config.yaml
Environment=TAS_ENFORCE_SIGNED_POLICIES=false
Environment=TAS_REDIS_HOST=localhost
Environment=TAS_REDIS_PORT=6379
Environment=TAS_REDIS_PERSISTENCE=false
${tls_env}
ExecStart=${exec_start}
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=${SERVICE_NAME}

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable "${SERVICE_NAME}.service"
    systemctl restart "${SERVICE_NAME}.service"

    local scheme; [[ "${use_tls}" == "true" ]] && scheme="https" || scheme="http"
    info ""
    info "=========================================================="
    info "  TAS Quick-Run Service"
    info "=========================================================="
    info "  URL              ${scheme}://${host}:${port}"
    info "  Service          ${SERVICE_NAME}.service"
    info "  User             ${service_user}"
    info "  TLS              ${use_tls}"
    info "=========================================================="
    info ""
    info "Service management:"
    info "  systemctl status  ${SERVICE_NAME}"
    info "  systemctl stop    ${SERVICE_NAME}"
    info "  systemctl start   ${SERVICE_NAME}"
    info "  journalctl -u ${SERVICE_NAME} -f"
    if [[ "${use_tls}" == "true" ]]; then
        info ""
        info "TLS CA cert (pass to --tls-ca-cert / --cacert):"
        info "  ${QUICKRUN_DIR}/tas_ca_cert.pem"
    fi
    info ""
    info "Example curl:"
    info "  curl -k -H \"X-API-KEY: \$(cat ${QUICKRUN_DIR}/TAS_API_KEY.txt)\" ${scheme}://${host}:${port}/version"
    info "  curl -k -H \"X-MANAGEMENT-API-KEY: \$(cat ${QUICKRUN_DIR}/TAS_MANAGEMENT_API_KEY.txt)\" ${scheme}://${host}:${port}/management/policy/v0/list"
    info ""
    info "To remove the service and all artifacts:"
    info "  sudo bash ./quickrun.sh uninstall"
}

# ── BUILD Command ─────────────────────────────────────────────────────────
cmd_build() {
    local proxy=""
    local rebuild_venv=false
    local include_nvidia=false
    local port=5000
    local host="127.0.0.1"
    local use_tls=false

    local _args=()
    for _a in "$@"; do
        [[ "${_a}" == --*=* ]] && _args+=("${_a%%=*}" "${_a#*=}") || _args+=("${_a}")
    done
    set -- "${_args[@]}"

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --host)
                [[ -z "${2:-}" ]] && { echo "Error: --host requires a value." >&2; exit 1; }
                host="$2"; shift 2 ;;
            --port)
                [[ -z "${2:-}" ]] && { echo "Error: --port requires a value." >&2; exit 1; }
                port="$2"; shift 2 ;;
            --proxy)
                [[ -z "${2:-}" ]] && { echo "Error: --proxy requires a value." >&2; exit 1; }
                proxy="$2"; shift 2 ;;
            --tls)            use_tls=true;        shift ;;
            --build-env)      rebuild_venv=true;   shift ;;
            --include-nvidia) include_nvidia=true; shift ;;
            --help|-h)        show_help; exit 0 ;;
            *) echo "Unknown option: $1" >&2; echo "Run with --help for usage." >&2; exit 1 ;;
        esac
    done

    if [[ "${EUID}" -eq 0 && -n "${SUDO_USER:-}" ]]; then
        echo ""
        echo "[TAS] WARNING: build is meant to be run as a regular user — sudo is not needed."
        echo "[TAS]          If you continue, you will also need sudo for 'run --run-as-service'"
        echo "[TAS]          and 'uninstall' (since files will be owned by root)."
        echo ""
        read -rp "[TAS] Continue running build with sudo? [y/N]: " _sudo_confirm
        echo ""
        [[ "${_sudo_confirm}" =~ ^[Yy]([Ee][Ss])?$ ]] || { echo "[TAS] Aborted."; exit 1; }
    fi

    _check_prerequisites
    mkdir -p "${QUICKRUN_DIR}"
    _setup_venv "${rebuild_venv}"
    _install_dependencies "${proxy}" "${include_nvidia}"
    _generate_api_keys
    _generate_configs "${port}"
    [[ "${use_tls}" == "true" ]] && _generate_tls_certificate "${host}"
    _save_setup_conf "${port}" "${host}" "${use_tls}"

    info ""
    info "Build complete. Start the server with:"
    info "  bash ./quickrun.sh run"
}

# ── RUN Command ───────────────────────────────────────────────────────────
cmd_run() {
    # Load defaults from setup, then allow per-run flag overrides below
    local port=5000
    local host="127.0.0.1"
    local use_tls=false
    local run_as_service=false
    _load_setup_conf

    local _args=()
    for _a in "$@"; do
        [[ "${_a}" == --*=* ]] && _args+=("${_a%%=*}" "${_a#*=}") || _args+=("${_a}")
    done
    set -- "${_args[@]}"

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --host)           [[ -z "${2:-}" ]] && { echo "Error: --host requires a value." >&2; exit 1; }
                              host="$2"; shift 2 ;;
            --port)           [[ -z "${2:-}" ]] && { echo "Error: --port requires a value." >&2; exit 1; }
                              port="$2"; shift 2 ;;
            --tls)            use_tls=true; shift ;;
            --run-as-service) run_as_service=true; shift ;;
            --help|-h)        show_help; exit 0 ;;
            *) echo "Unknown option: $1" >&2; echo "Run with --help for usage." >&2; exit 1 ;;
        esac
    done

    # Guard: ensure setup has been run
    [[ -f "${VENV_DIR}/bin/python"          ]] || error "No virtual environment found. Run build first:
  bash ./quickrun.sh build"
    [[ -f "${QUICKRUN_DIR}/TAS_API_KEY.txt" ]] || error "No configuration found. Run build first:
  bash ./quickrun.sh build"

    # Guard: TLS requires certs to have been generated during setup
    if [[ "${use_tls}" == "true" ]]; then
        [[ -f "${QUICKRUN_DIR}/tas_cert.pem" && -f "${QUICKRUN_DIR}/tas_key.pem" ]] || \
            error "TLS was not configured during build. Re-run build with --tls:
  bash ./quickrun.sh build --tls"
    fi

    _check_redis

    # ── Install as a systemd service ──────────────────────────────────────
    if [[ "${run_as_service}" == "true" ]]; then
        _install_service "${host}" "${port}" "${use_tls}"
        return
    fi

    # ── Interactive foreground run ─────────────────────────────────────────

    # Activate the venv
    # shellcheck source=/dev/null
    source "${VENV_DIR}/bin/activate" || error "Failed to activate virtual environment. Try re-running build:
  bash ./quickrun.sh build --build-env"

    # Export environment for TAS
    export TAS_API_KEY;            TAS_API_KEY=$(cat "${QUICKRUN_DIR}/TAS_API_KEY.txt")
    export TAS_MANAGEMENT_API_KEY; TAS_MANAGEMENT_API_KEY=$(cat "${QUICKRUN_DIR}/TAS_MANAGEMENT_API_KEY.txt")
    export TAS_KBM_PLUGIN="tas_kbm_mock"
    export TAS_KBM_CONFIG_FILE="${QUICKRUN_DIR}/kbm_mock_config.yaml"
    export TAS_CONFIG_FILE="${QUICKRUN_DIR}/tas_config.yaml"
    export TAS_ENFORCE_SIGNED_POLICIES="false"
    export FLASK_APP="${PROJECT_DIR}/app.py"
    export TAS_REDIS_HOST="localhost"
    export TAS_REDIS_PORT="6379"
    export TAS_REDIS_PERSISTENCE="false"

    if [[ "${use_tls}" == "true" ]]; then
        export TAS_CERT_FILE="${QUICKRUN_DIR}/tas_cert.pem"
        export TAS_KEY_FILE="${QUICKRUN_DIR}/tas_key.pem"
    fi

    # Startup banner
    local scheme; [[ "${use_tls}" == "true" ]] && scheme="https" || scheme="http"
    info ""
    info "=========================================================="
    info "  TAS Quick-Run Server"
    info "=========================================================="
    info "  URL              ${scheme}://${host}:${port}"
    info "  API Key          $(head -c 20 "${QUICKRUN_DIR}/TAS_API_KEY.txt")…"
    info "  Management Key   $(head -c 20 "${QUICKRUN_DIR}/TAS_MANAGEMENT_API_KEY.txt")…"
    info "  KBM Plugin       tas_kbm_mock (SQLite)"
    info "  TLS              ${use_tls}"
    info "=========================================================="
    info ""
    info "API key files:"
    info "  cat ${QUICKRUN_DIR}/TAS_API_KEY.txt"
    info "  cat ${QUICKRUN_DIR}/TAS_MANAGEMENT_API_KEY.txt"
    if [[ "${use_tls}" == "true" ]]; then
        info ""
        info "TLS CA cert (pass to --tls-ca-cert / --cacert):"
        info "  ${QUICKRUN_DIR}/tas_ca_cert.pem"
    fi
    info ""
    info "Example curl:"
    info "  curl -k -H \"X-API-KEY: \$(cat ${QUICKRUN_DIR}/TAS_API_KEY.txt)\" ${scheme}://${host}:${port}/version"
    info "  curl -k -H \"X-MANAGEMENT-API-KEY: \$(cat ${QUICKRUN_DIR}/TAS_MANAGEMENT_API_KEY.txt)\" ${scheme}://${host}:${port}/management/policy/v0/list"
    info ""
    info "Press Ctrl+C to stop."
    info "=========================================================="
    info ""

    cd "${PROJECT_DIR}" || exit 1
    if [[ "${use_tls}" == "true" ]]; then
        python3 -m flask run --host="${host}" --port="${port}" \
            --cert="${TAS_CERT_FILE}" --key="${TAS_KEY_FILE}"
    else
        python3 -m flask run --host="${host}" --port="${port}"
    fi
}

# ── UNINSTALL Command ─────────────────────────────────────────────────────
cmd_uninstall() {
    # Handle --help before doing anything destructive
    for _a in "$@"; do
        case "${_a}" in --help|-h) show_help; exit 0 ;; esac
    done

    info "Removing TAS quick-run artifacts..."

    # Remove systemd service if present
    if [[ -f "${SERVICE_FILE}" ]]; then
        if [[ "${EUID}" -eq 0 ]]; then
            info "Stopping and disabling ${SERVICE_NAME}.service..."
            systemctl stop    "${SERVICE_NAME}.service" 2>/dev/null || true
            systemctl disable "${SERVICE_NAME}.service" 2>/dev/null || true
            rm -f "${SERVICE_FILE}"
            systemctl daemon-reload
            info "  ${SERVICE_FILE} removed."
        else
            error "Service file exists at ${SERVICE_FILE}. Run uninstall with sudo to remove it:
  sudo bash ./quickrun.sh uninstall"
        fi
    fi

    if [[ -d "${QUICKRUN_DIR}" ]]; then
        rm -rf "${QUICKRUN_DIR}"
        info "  ${QUICKRUN_DIR} removed."
    else
        info "  Nothing to remove (${QUICKRUN_DIR} not found)."
    fi
    info "Done."
}

# ── Entry Point ───────────────────────────────────────────────────────────
main() {
    [[ $# -eq 0 ]] && { show_help; exit 1; }

    local command="$1"; shift
    case "${command}" in
        build)          cmd_build     "$@" ;;
        run)            cmd_run       "$@" ;;
        uninstall)      cmd_uninstall "$@" ;;
        --help|-h|help) show_help ;;
        *) echo "Unknown command: ${command}" >&2
           echo "Run with --help for usage." >&2
           exit 1 ;;
    esac
}

main "$@"
