#!/usr/bin/env bash
#
# TEE Attestation Service - CVM E2E Runner
#
# Copyright 2026 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# This file is part of the TEE Attestation Service.
#
# This script provisions a Confidential VM, runs the TAS attestation test, and
# destroys the resources when the run finishes.

set -Eeuo pipefail
umask 077

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
TF_ROOT="$ROOT_DIR/terraform/cvm"
SCRIPT_PATH="$ROOT_DIR/guest/setup_and_test_tas.sh"
LOG_DIR="$ROOT_DIR/logs"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$-${RANDOM}${RANDOM}"
WORKSPACE="tas-e2e-$RUN_ID"
TF_VARS_FILE="${TF_VARS_FILE:-$TF_ROOT/terraform.tfvars}"
REMOTE_SCRIPT="/tmp/setup_and_test_tas-$RUN_ID.sh"
TAS_REPO_URL="${TAS_REPO_URL:-}"
TAS_BRANCH="${TAS_BRANCH:-}"
TAS_COMMIT="${TAS_COMMIT:-}"
TAS_VM_MAX_RUNTIME_MINUTES="${TAS_VM_MAX_RUNTIME_MINUTES:-180}"
# Covers the longest VM lifetime (240 minutes), so keys stay valid for the whole run.
SSH_KEY_EXPIRE_AFTER="4h"
SSH_LOG="$LOG_DIR/ssh-$RUN_ID.log"
TEST_LOG="$LOG_DIR/test-$RUN_ID.log"
APPLY_LOG="$LOG_DIR/apply-$RUN_ID.log"
DESTROY_LOG="$LOG_DIR/destroy-$RUN_ID.log"
WORKSPACE_CREATED=0
APPLY_STARTED=0
DESTROYED=0
PLAN_FILE=

mkdir -p "$LOG_DIR"

die() {
  echo "ERROR: $*" >&2
  exit 1
}

for command in terraform gcloud git jq timeout; do
  command -v "$command" >/dev/null 2>&1 ||
    die "required command '$command' was not found in PATH."
done
[[ -n "$TAS_REPO_URL" ]] || die "set TAS_REPO_URL to the repository containing the TAS branch to test."
[[ "$TAS_REPO_URL" =~ ^https://github\.com/[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*(\.git)?$ ]] ||
  die "TAS_REPO_URL must be an HTTPS URL for a GitHub repository (https://github.com/OWNER/REPO[.git])."
[[ -n "$TAS_BRANCH" ]] || die "set TAS_BRANCH to the TAS branch this test should exercise."
[[ "$TAS_COMMIT" =~ ^[0-9a-f]{40}$ ]] || die "set TAS_COMMIT to the 40-character commit SHA to test."
[[ "$TAS_VM_MAX_RUNTIME_MINUTES" =~ ^[0-9]+$ ]] &&
  (( TAS_VM_MAX_RUNTIME_MINUTES >= 30 && TAS_VM_MAX_RUNTIME_MINUTES <= 240 )) ||
  die "TAS_VM_MAX_RUNTIME_MINUTES must be an integer from 30 to 240."
TF_VAR_ARGS=()
if [[ -f "$TF_VARS_FILE" ]]; then
  if [[ "$TF_VARS_FILE" != /* ]]; then
    TF_VARS_FILE="$(cd -- "$(dirname -- "$TF_VARS_FILE")" && pwd)/$(basename -- "$TF_VARS_FILE")"
  fi
  TF_VAR_ARGS=(-var-file="$TF_VARS_FILE")
elif [[ -z "${TF_VAR_project_id:-}" ]]; then
  die "set TF_VAR_project_id or provide a Terraform variable file via TF_VARS_FILE."
fi
[[ -f "$SCRIPT_PATH" ]] || die "test script not found: $SCRIPT_PATH"
[[ -d "$TF_ROOT" ]] || die "Terraform root not found: $TF_ROOT"

tf() {
  terraform -chdir="$TF_ROOT" "$@"
}

bash "$ROOT_DIR/check.sh"
tf init -input=false

cleanup() {
  local exit_code=$?
  trap - EXIT INT TERM

  if [[ -n "$PLAN_FILE" ]]; then
    rm -f -- "$PLAN_FILE"
  fi

  if [[ $WORKSPACE_CREATED -eq 1 ]]; then
    if [[ $APPLY_STARTED -eq 1 ]]; then
      echo "==> Destroying resources in Terraform workspace $WORKSPACE"
      if tf destroy -auto-approve -input=false "${TF_VAR_ARGS[@]}" >"$DESTROY_LOG" 2>&1; then
        DESTROYED=1
        echo "CVM resources destroyed."
      else
        echo "ERROR: terraform destroy failed in workspace '$WORKSPACE'." >&2
        echo "CVM to check: $INSTANCE_NAME (project: $PROJECT_ID, zone: $ZONE)." >&2
        tail -n 40 "$DESTROY_LOG" |
          sed -E 's#(ssh-rsa|ssh-ed25519|ecdsa-[A-Za-z0-9-]+)[[:space:]]+[A-Za-z0-9+/=]+#[REDACTED SSH PUBLIC KEY]#g' >&2
        if [[ -n "${GITHUB_ENV:-}" ]]; then
          echo "The workflow will attempt direct GCP cleanup; local Terraform state does not survive the runner." >&2
        elif [[ -f "$TF_VARS_FILE" ]]; then
          echo "Run: terraform -chdir='$TF_ROOT' workspace select '$WORKSPACE' && terraform -chdir='$TF_ROOT' destroy -var-file='$TF_VARS_FILE'" >&2
        else
          echo "Set TF_VAR_project_id, then run: terraform -chdir='$TF_ROOT' workspace select '$WORKSPACE' && terraform -chdir='$TF_ROOT' destroy" >&2
        fi
        exit_code=1
      fi
    else
      DESTROYED=1
    fi
  fi

  if [[ $WORKSPACE_CREATED -eq 1 && $DESTROYED -eq 1 ]]; then
    tf workspace select default || exit_code=1
    if ! tf workspace delete "$WORKSPACE"; then
      echo "ERROR: resources were destroyed, but workspace '$WORKSPACE' could not be deleted." >&2
      exit_code=1
    fi
  fi

  if [[ -s "$SSH_LOG" ]]; then
    echo "SSH connection log: $SSH_LOG"
  fi
  if [[ -s "$TEST_LOG" ]]; then
    echo "Remote test log: $TEST_LOG"
  fi
  exit "$exit_code"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

tf workspace new "$WORKSPACE"
WORKSPACE_CREATED=1

echo "==> Planning the CVM (Terraform workspace: $WORKSPACE)"
export TF_VAR_vm_max_runtime_minutes="$TAS_VM_MAX_RUNTIME_MINUTES"
PLAN_FILE="$(mktemp)"
tf plan -input=false -out="$PLAN_FILE" "${TF_VAR_ARGS[@]}"
# Record the target before apply, including overrides from Terraform variable files.
target="$(tf show -json "$PLAN_FILE" | jq -er '
  .planned_values.outputs
  | [.instance_name.value, .project_id.value, .zone.value]
  | if all(.[]; type == "string" and test("^[a-z][a-z0-9-]+$"))
    then @tsv else error("invalid planned CVM identity") end
')"
IFS=$'\t' read -r INSTANCE_NAME PROJECT_ID ZONE <<< "$target"
if [[ -n "${GITHUB_ENV:-}" ]]; then
  printf 'TAS_E2E_INSTANCE=%s\nTAS_E2E_PROJECT=%s\nTAS_E2E_ZONE=%s\n' \
    "$INSTANCE_NAME" "$PROJECT_ID" "$ZONE" >> "$GITHUB_ENV"
fi

echo "==> Creating $INSTANCE_NAME (project: $PROJECT_ID, zone: $ZONE)"
APPLY_STARTED=1
if ! tf apply -input=false "$PLAN_FILE" >"$APPLY_LOG" 2>&1; then
  echo "ERROR: terraform apply failed. Recent diagnostics:" >&2
  tail -n 40 "$APPLY_LOG" |
    sed -E 's#(ssh-rsa|ssh-ed25519|ecdsa-[A-Za-z0-9-]+)[[:space:]]+[A-Za-z0-9+/=]+#[REDACTED SSH PUBLIC KEY]#g' >&2
  exit 1
fi
echo "CVM provisioning completed."

echo "==> Waiting for gcloud SSH access to $INSTANCE_NAME"
connected=0
ssh_deadline=$((SECONDS + 360))
while (( SECONDS < ssh_deadline )); do
  remaining=$((ssh_deadline - SECONDS))
  if timeout -k 5s "$((remaining < 15 ? remaining : 15))s" gcloud compute ssh "$INSTANCE_NAME" \
      --project="$PROJECT_ID" --zone="$ZONE" --tunnel-through-iap --quiet \
      --ssh-key-expire-after="$SSH_KEY_EXPIRE_AFTER" \
      --ssh-flag="-o ConnectTimeout=10" \
      --command="true" >"$SSH_LOG" 2>&1; then
    connected=1
    break
  fi
  remaining=$((ssh_deadline - SECONDS))
  if (( remaining > 0 )); then
    echo "SSH not ready; retrying shortly."
    sleep "$((remaining < 10 ? remaining : 10))"
  fi
done
if [[ $connected -ne 1 ]]; then
  echo "ERROR: could not connect through IAP after 6 minutes; see $SSH_LOG." >&2
  echo "Check the caller's IAP tunnel IAM permission and the VM firewall rule for IAP TCP 22." >&2
  echo "Inspect with: gcloud compute ssh '$INSTANCE_NAME' --project='$PROJECT_ID' --zone='$ZONE' --tunnel-through-iap --troubleshoot" >&2
  die "IAP SSH connectivity failed."
fi

echo "==> Copying the TAS test script to the CVM"
timeout -k 10s 2m gcloud compute scp "$SCRIPT_PATH" "$INSTANCE_NAME:$REMOTE_SCRIPT" \
  --project="$PROJECT_ID" --zone="$ZONE" --tunnel-through-iap --quiet \
  --ssh-key-expire-after="$SSH_KEY_EXPIRE_AFTER"

echo "==> Running the TAS end-to-end test"
printf -v REMOTE_TEST_ENV 'TAS_REPO_URL=%q TAS_BRANCH=%q TAS_COMMIT=%q' \
  "$TAS_REPO_URL" "$TAS_BRANCH" "$TAS_COMMIT"
echo "TAS server source: $TAS_REPO_URL ($TAS_BRANCH, commit $TAS_COMMIT)"
timeout -k 15s 65m gcloud compute ssh "$INSTANCE_NAME" \
  --project="$PROJECT_ID" --zone="$ZONE" --tunnel-through-iap --quiet \
  --ssh-key-expire-after="$SSH_KEY_EXPIRE_AFTER" \
  --ssh-flag="-o ServerAliveInterval=30" --ssh-flag="-o ServerAliveCountMax=4" \
  --command="env $REMOTE_TEST_ENV bash '$REMOTE_SCRIPT'" 2>&1 | tee "$TEST_LOG"

echo "==> TAS end-to-end test passed"
