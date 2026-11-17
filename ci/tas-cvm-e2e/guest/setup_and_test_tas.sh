#!/usr/bin/env bash
#
# TEE Attestation Service - CVM E2E Guest Test
#
# Copyright 2026 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# This file is part of the TEE Attestation Service.
#
# Bootstrap an Ubuntu minimal CVM and run a full end-to-end TAS attestation test:
#   1. Install OS build dependencies and the Rust toolchain.
#   2. Clone the TAS server and supporting repositories.
#   3. Build the TAS tools and install the server environment.
#   4. Generate API keys, policy signing keys, and local configuration.
#   5. Start the TAS server, write a random mock secret, create a policy.
#   6. Run tas_agent and verify the released secret matches.
#
# Prints "E2E ATTESTATION TEST PASSED" and exits 0 on success; prints a
# clear error message and exits 1 if any step fails.
#
# Requires a real SEV-SNP or TDX guest with configfs/tsm evidence support.
# Run without sudo: bash setup_and_test_tas.sh (sudo is used internally).
set -Eeuo pipefail

# Require an unprivileged caller so files created by the script remain owned
# by that user; individual privileged operations are run through sudo.
if [[ $EUID -eq 0 ]]; then
  echo "Run without sudo: bash $0 (sudo is used only where needed)." >&2
  exit 1
fi
if ! command -v sudo >/dev/null 2>&1; then
  echo "This script must run as a non-root user with sudo installed and configured." >&2
  exit 1
fi

STACK_DIR="${TAS_STACK_DIR:-$HOME}"
# Keep all inputs overridable so the bootstrap can target forks and custom
# guest configurations without editing the script.
TAS_BRANCH="${TAS_BRANCH:-main}"
TAS_REPO_URL="${TAS_REPO_URL:-https://github.com/LeonStansfield/tas.git}"
TAS_COMMIT="${TAS_COMMIT:-}"
TOOL_BUILD_DIR="${TAS_TOOL_BUILD_DIR:-$STACK_DIR/.tas-tool-build}"
TOOL_SOURCE_DIR="$TOOL_BUILD_DIR/src"
TOOL_BIN_DIR="$TOOL_BUILD_DIR/bin"
RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}"
CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
CONFIG_DIR="${TAS_DEV_CONFIG_DIR:-$HOME/.config/tas-dev}"
SERVER_HOST="${TAS_SERVER_HOST:-127.0.0.1}"
TAS_PORT="${TAS_PORT:-5000}"
RUN_ID="$(date +%Y%m%d-%H%M%S)-$$"
# The mock secret writer and policy create are create-only, so each test run
# uses fresh IDs unless the caller overrides them.
POLICY_ID="${TAS_POLICY_ID:-tas-e2e-policy-$RUN_ID}"
KEY_ID="${TAS_KEY_ID:-tas-e2e-key-$RUN_ID}"
DEV_SEV_MIN_TEE_SVN="${TAS_DEV_SEV_MIN_TEE_SVN:-0}"
DEV_SEV_TSME_ENABLED="${TAS_DEV_SEV_TSME_ENABLED:-false}"
DEV_TDX_PLATFORM_TCB="${TAS_DEV_TDX_PLATFORM_TCB:-up-to-date}"
DEV_TDX_MODULE_TCB="${TAS_DEV_TDX_MODULE_TCB:-up-to-date}"
LOG_DIR="$CONFIG_DIR/logs"
SERVER_LOG="$LOG_DIR/tas-server-$RUN_ID.log"
AGENT_OUT="$LOG_DIR/tas-agent-$RUN_ID.out"
AGENT_LOG="$LOG_DIR/tas-agent-$RUN_ID.log"
SERVER_PID=""
TEST_PASSED=0

if [[ ! "$TAS_REPO_URL" =~ ^https://github\.com/[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*(\.git)?$ ]]; then
  echo "TAS_REPO_URL must be an HTTPS URL for a GitHub repository." >&2
  exit 1
fi
if [[ ! "$TAS_COMMIT" =~ ^[0-9a-f]{40}$ ]]; then
  echo "TAS_COMMIT must be the 40-character commit SHA to test." >&2
  exit 1
fi

if [[ ! "$DEV_SEV_MIN_TEE_SVN" =~ ^[0-9]{1,3}$ ]] ||
  (( DEV_SEV_MIN_TEE_SVN > 255 )); then
  echo "TAS_DEV_SEV_MIN_TEE_SVN must be an integer from 0 to 255." >&2
  exit 1
fi
# Validate this boolean before passing it to the policy CLI.
case "$DEV_SEV_TSME_ENABLED" in
  true|false) ;;
  *)
    echo "TAS_DEV_SEV_TSME_ENABLED must be true or false." >&2
    exit 1
    ;;
esac

fail() {
  FAIL_REPORTED=1
  echo >&2
  echo "E2E ATTESTATION TEST FAILED: $*" >&2
  if [[ -s "$SERVER_LOG" ]]; then
    echo "--- last TAS server log lines ($SERVER_LOG) ---" >&2
    tail -n 20 "$SERVER_LOG" >&2 || true
  fi
  if [[ -s "$AGENT_LOG" ]]; then
    echo "--- last tas_agent log lines ($AGENT_LOG) ---" >&2
    tail -n 20 "$AGENT_LOG" >&2 || true
  fi
  exit 1
}

# Convert otherwise-unhandled command failures into diagnostics with relevant
# server/agent logs; explicit fail() calls retain their more specific message.
on_error() {
  local line=$1 cmd=$2
  fail "command failed at line $line: $cmd"
}
trap 'on_error "$LINENO" "$BASH_COMMAND"' ERR

cleanup() {
  # Only the main shell performs cleanup (forked children inherit this trap).
  [[ "${BASHPID:-$$}" == "$$" ]] || return 0
  if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  if [[ $TEST_PASSED -ne 1 && -z ${FAIL_REPORTED:-} ]]; then
    echo "E2E ATTESTATION TEST FAILED: script exited before completing." >&2
  fi
}
trap cleanup EXIT

echo "==> Checking OS image dependencies"
for dependency in sudo; do
  command -v "$dependency" >/dev/null 2>&1 ||
    fail "required dependency '$dependency' is missing."
done
sudo apt-get update
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
  ca-certificates curl git build-essential pkg-config libssl-dev \
  python3 python3-venv python3-pip python3-dev redis-server openssl kmod
for dependency in curl git python3 redis-server redis-cli openssl; do
  command -v "$dependency" >/dev/null 2>&1 ||
    fail "required dependency '$dependency' is unavailable after installation."
done
RUSTUP_INSTALLER="$(mktemp)"
curl --proto '=https' --tlsv1.2 -fsS https://sh.rustup.rs -o "$RUSTUP_INSTALLER"
sh "$RUSTUP_INSTALLER" -y --profile minimal --default-toolchain stable ||
  fail "installing the stable Rust toolchain failed."
rm -f "$RUSTUP_INSTALLER"
export RUSTUP_HOME CARGO_HOME
export PATH="$CARGO_HOME/bin:$PATH"
command -v cargo >/dev/null 2>&1 || fail "Rust cargo is unavailable after toolchain installation."
sudo systemctl start redis-server
redis-cli ping | grep -qx PONG || fail "Redis is not responding to PING."

echo "==> Detecting CVM type"
# Prefer an explicit type override; otherwise infer the confidential guest
# technology from the virtual CPU vendor.
CVM_TYPE="${TAS_CVM_TYPE:-}"
if [[ -z "$CVM_TYPE" ]]; then
  vendor="$(awk -F': *' '/^vendor_id/{print $2; exit}' /proc/cpuinfo)"
  case "$vendor" in
    AuthenticAMD) CVM_TYPE=SEV ;;
    GenuineIntel) CVM_TYPE=TDX ;;
    *) fail "unknown CPU vendor '$vendor'; set TAS_CVM_TYPE=SEV or TAS_CVM_TYPE=TDX." ;;
  esac
fi
PROCESSOR_FAMILY=""
if [[ "$CVM_TYPE" == SEV ]]; then
  PROCESSOR_FAMILY=genoa
fi
# The agent collects evidence through configfs/tsm; load the guest driver and
# verify the interface exists before spending time on the rest of the setup.
if [[ "$CVM_TYPE" == SEV ]]; then
  sudo modprobe sev-guest 2>/dev/null || true
else
  sudo modprobe tdx-guest 2>/dev/null || true
fi
if ! mountpoint -q /sys/kernel/config; then
  sudo mount -t configfs configfs /sys/kernel/config ||
    fail "could not mount configfs at /sys/kernel/config."
fi
if [[ ! -d /sys/kernel/config/tsm/report ]]; then
  fail "configfs/tsm evidence support is unavailable (/sys/kernel/config/tsm/report missing). This test requires a real $CVM_TYPE guest."
fi
echo "Detected CVM type: $CVM_TYPE"

echo "==> Preparing repositories"
mkdir -p "$STACK_DIR"
# Refresh the server checkout for every run so a requested branch never
# silently reuses stale source from a previous test.
if [[ -d "$STACK_DIR/tas/.git" ]]; then
  git -C "$STACK_DIR/tas" remote set-url origin "$TAS_REPO_URL"
  git -C "$STACK_DIR/tas" fetch --depth 1 origin "$TAS_COMMIT"
  git -C "$STACK_DIR/tas" checkout --detach --force FETCH_HEAD
else
  git init "$STACK_DIR/tas"
  git -C "$STACK_DIR/tas" remote add origin "$TAS_REPO_URL"
  git -C "$STACK_DIR/tas" fetch --depth 1 origin "$TAS_COMMIT"
  git -C "$STACK_DIR/tas" checkout --detach FETCH_HEAD
fi
for repo in sev_pytools tdx_pytools; do
  url="https://github.com/TEE-Attestation/$repo.git"
  # Test the current default-branch commit, and record it so the log shows
  # exactly which helper code ran.
  helper_head="$(git ls-remote "$url" HEAD | awk '{print $1}')"
  [[ "$helper_head" =~ ^[0-9a-f]{40}$ ]] || fail "could not resolve the default branch of $repo."
  if [[ ! -d "$STACK_DIR/$repo/.git" ]]; then
    git init "$STACK_DIR/$repo"
    git -C "$STACK_DIR/$repo" remote add origin "$url"
  else
    git -C "$STACK_DIR/$repo" remote set-url origin "$url"
  fi
  git -C "$STACK_DIR/$repo" fetch --depth 1 origin "$helper_head"
  git -C "$STACK_DIR/$repo" checkout --detach --force FETCH_HEAD
  echo "Helper source: $repo ($helper_head)"
done
for repo in tas_agent tas_policy_cli; do
  url="https://github.com/TEE-Attestation/$repo.git"
  source="$TOOL_SOURCE_DIR/$repo"
  mkdir -p "$TOOL_SOURCE_DIR" "$TOOL_BIN_DIR"
  rm -rf -- "$source"
  git clone --depth 1 "$url" "$source"
  cargo build --manifest-path "$source/Cargo.toml" --release ||
    fail "building $repo from its current default branch failed."
  binary="tas_agent"
  [[ "$repo" == tas_policy_cli ]] && binary="tas-policy"
  install -m 0755 "$source/target/release/$binary" "$TOOL_BIN_DIR/$binary"
  echo "Built $repo ($(git -C "$source" rev-parse HEAD))"
done
TAS_COMMIT="$(git -C "$STACK_DIR/tas" rev-parse HEAD)"
echo "TAS server source: $TAS_REPO_URL ($TAS_BRANCH, commit $TAS_COMMIT)"
echo "Rust toolchain: $(rustc --version); $(cargo --version)"

echo "==> Building the TAS server environment"
# Use a dedicated virtual environment and install the local TEE helper
# packages in editable mode alongside the server's pinned requirements.
python3 -m venv "$STACK_DIR/tas/.venv"
"$STACK_DIR/tas/.venv/bin/pip" install --upgrade pip
"$STACK_DIR/tas/.venv/bin/pip" install \
  -e "$STACK_DIR/sev_pytools" -e "$STACK_DIR/tdx_pytools" \
  -r "$STACK_DIR/tas/requirements.txt"

echo "==> Generating keys and configuration"
# Restrict newly created credentials to the invoking user.
umask 077
mkdir -p "$CONFIG_DIR/secrets" "$CONFIG_DIR/policy-trust" "$CONFIG_DIR/kbm_db" "$LOG_DIR"
for key in TAS_API_KEY TAS_MANAGEMENT_API_KEY; do
  if [[ ! -s "$CONFIG_DIR/secrets/$key" ]]; then
    openssl rand -hex 32 > "$CONFIG_DIR/secrets/$key"
  fi
done
if [[ ! -s "$CONFIG_DIR/secrets/policy-signing-key.pem" ]]; then
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 \
    -out "$CONFIG_DIR/secrets/policy-signing-key.pem"
fi
openssl pkey -in "$CONFIG_DIR/secrets/policy-signing-key.pem" -pubout \
  -out "$CONFIG_DIR/policy-trust/bootstrap-policy-key.pem"

# Keep local configuration and secrets outside the editable checkouts. The
# small Python block writes the mock KBM and agent configs with quoted values.
"$STACK_DIR/tas/.venv/bin/python" - "$CONFIG_DIR" "$SERVER_HOST" "$TAS_PORT" "$POLICY_ID" <<'PY'
import pathlib
import sys
import json
import yaml

config = pathlib.Path(sys.argv[1])
host, port, policy = sys.argv[2:]
(config / "kbm_mock_config.yaml").write_text(yaml.safe_dump({
    "strict": True,
    "backend": "sqlite",
    "db_path": str(config / "kbm_db/kbm_mock_secrets.db"),
}))
(config / "agent.toml").write_text(
    f"server_uri = {json.dumps(f'http://{host}:{port}')}\n"
    f"api_key = {json.dumps(str(config / 'secrets/TAS_API_KEY'))}\n"
    f"policy_id = {json.dumps(policy)}\n"
)
PY
# Save the resolved settings and credentials as a reusable shell environment
# file, then load it for the server and CLI commands below.
{
  printf 'export TAS_STACK_DIR=%q\n' "$STACK_DIR"
  printf 'export TAS_BRANCH=%q\n' "$TAS_BRANCH"
  printf 'export TAS_REPO_URL=%q\n' "$TAS_REPO_URL"
  printf 'export TAS_DEV_CONFIG_DIR=%q\n' "$CONFIG_DIR"
  printf 'export TAS_POLICY_ID=%q\n' "$POLICY_ID"
  printf 'export TAS_KEY_ID=%q\n' "$KEY_ID"
  printf 'export TAS_DEV_SEV_MIN_TEE_SVN=%q\n' "$DEV_SEV_MIN_TEE_SVN"
  printf 'export TAS_DEV_SEV_TSME_ENABLED=%q\n' "$DEV_SEV_TSME_ENABLED"
  printf 'export TAS_SERVER_HOST=%q\n' "$SERVER_HOST"
  printf 'export TAS_PORT=%q\n' "$TAS_PORT"
  printf 'export TAS_API_KEY=%q\n' "$(< "$CONFIG_DIR/secrets/TAS_API_KEY")"
  printf 'export TAS_MANAGEMENT_API_KEY=%q\n' "$(< "$CONFIG_DIR/secrets/TAS_MANAGEMENT_API_KEY")"
  printf 'export FLASK_TAS_POLICY_TRUST=%q\n' "$CONFIG_DIR/policy-trust"
  printf 'export TAS_KBM_CONFIG_FILE=%q\n' "$CONFIG_DIR/kbm_mock_config.yaml"
  printf 'export TAS_CONFIG_FILE=%q\n' "$STACK_DIR/tas/config/tas_config.yaml"
  printf 'export TAS_KBM_PLUGIN=tas_kbm_mock\n'
  printf 'export TAS_REDIS_HOST=127.0.0.1\nexport TAS_REDIS_PORT=6379\n'
  printf 'export FLASK_SERVER_BIND_HOST=127.0.0.1\n'
  printf 'export FLASK_SERVER_PORT=%q\n' "$TAS_PORT"
} > "$CONFIG_DIR/env.sh"
# shellcheck disable=SC1091
source "$CONFIG_DIR/env.sh"

echo "==> Starting the TAS server"
# Run the server in the background with separate logs so startup failures can
# report useful diagnostics without mixing them into terminal output.
(
  trap - ERR EXIT
  cd "$STACK_DIR/tas"
  exec .venv/bin/python app.py
) > "$SERVER_LOG" 2>&1 &
SERVER_PID=$!
server_ready=0
# Poll the authenticated version endpoint while also detecting early process
# exit; do not begin creating test data until the API is ready.
for _ in $(seq 1 60); do
  if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    fail "the TAS server exited during startup."
  fi
  if curl -fsS -H "X-API-KEY: $TAS_API_KEY" \
      "http://$SERVER_HOST:$TAS_PORT/version" >/dev/null 2>&1; then
    server_ready=1
    break
  fi
  sleep 1
done
[[ $server_ready -eq 1 ]] || fail "the TAS server did not become ready within 60 seconds."
echo "TAS server is up (pid $SERVER_PID)."

echo "==> Running the end-to-end attestation test"
# Store a fresh random secret under the test key ID; the policy below grants
# access only to an attested guest satisfying the selected CVM requirements.
TEST_SECRET="$(openssl rand -hex 32)"
printf '%s' "$TEST_SECRET" | "$STACK_DIR/tas/.venv/bin/python" \
  "$STACK_DIR/tas/scripts/kbm_mock_secret_writer.py" \
  --config "$TAS_KBM_CONFIG_FILE" --key-id "$KEY_ID" --secret - ||
  fail "writing the mock test secret failed (key ID: $KEY_ID)."

if [[ "$CVM_TYPE" == SEV ]]; then
  # SEV policies bind the minimum TEE SVN and TSME state.
  "$TOOL_BIN_DIR/tas-policy" create \
    --policy-id "$POLICY_ID" --cvm-type SEV --processor-family "$PROCESSOR_FAMILY" \
    --min-tee-svn "$DEV_SEV_MIN_TEE_SVN" \
    --tsme-enabled "$DEV_SEV_TSME_ENABLED" \
    --key-id "$KEY_ID" --signing-key "$CONFIG_DIR/secrets/policy-signing-key.pem" \
    --tas-host "$SERVER_HOST" --tas-port "$TAS_PORT" \
    --api-key-file "$CONFIG_DIR/secrets/TAS_MANAGEMENT_API_KEY" --no-tls ||
    fail "creating the SEV test policy failed (policy ID: $POLICY_ID)."
else
  # TDX policies use the requested platform and module TCB levels.
  "$TOOL_BIN_DIR/tas-policy" create \
    --policy-id "$POLICY_ID" --cvm-type TDX --tcb-only \
    --platform-tcb "$DEV_TDX_PLATFORM_TCB" --tdx-module-tcb "$DEV_TDX_MODULE_TCB" \
    --key-id "$KEY_ID" --signing-key "$CONFIG_DIR/secrets/policy-signing-key.pem" \
    --tas-host "$SERVER_HOST" --tas-port "$TAS_PORT" \
    --api-key-file "$CONFIG_DIR/secrets/TAS_MANAGEMENT_API_KEY" --no-tls ||
    fail "creating the TDX test policy failed (policy ID: $POLICY_ID)."
fi

echo "Running tas_agent (requires sudo for TEE evidence collection)..."
# The agent requires elevated access to read hardware-backed guest evidence;
# its output is captured separately from diagnostics for exact secret checking.
sudo -v || fail "sudo authentication failed; tas_agent needs root to collect TEE evidence."
# shellcheck disable=SC2024  # output files should be owned by the invoking user
if ! sudo "$TOOL_BIN_DIR/tas_agent" \
    -c "$CONFIG_DIR/agent.toml" --policy-id "$POLICY_ID" \
    > "$AGENT_OUT" 2> "$AGENT_LOG"; then
  fail "tas_agent failed to attest and fetch the secret (see $AGENT_LOG)."
fi

RELEASED_SECRET="$(< "$AGENT_OUT")"
# Treat any difference, including unexpected output, as a failed end-to-end
# check rather than merely trusting a successful agent exit code.
if [[ "$RELEASED_SECRET" != "$TEST_SECRET" ]]; then
  fail "attestation succeeded but the released secret does not match the stored test secret."
fi
rm -f "$AGENT_OUT"

TEST_PASSED=1
cat <<EOF

E2E ATTESTATION TEST PASSED
CVM type: $CVM_TYPE (processor family: $PROCESSOR_FAMILY)
Policy ID: $POLICY_ID
Key ID: $KEY_ID
The TAS server verified this CVM's TEE evidence and released the test secret,
and the secret returned by tas_agent matched the value stored in the mock KBM.

Repositories: $STACK_DIR/{tas,sev_pytools,tdx_pytools}
TAS source: $TAS_REPO_URL ($TAS_BRANCH, commit $TAS_COMMIT)
Helper source: sev_pytools ($(git -C "$STACK_DIR/sev_pytools" rev-parse HEAD)), tdx_pytools ($(git -C "$STACK_DIR/tdx_pytools" rev-parse HEAD))
Built tools: $TOOL_BIN_DIR/{tas_agent,tas-policy}
Environment: $CONFIG_DIR/env.sh
Agent config: $CONFIG_DIR/agent.toml
Server log: $SERVER_LOG
The TAS server started for this test has been stopped. Test secrets and
policies are create-only: each run uses fresh IDs unless TAS_KEY_ID /
TAS_POLICY_ID are set.
EOF
