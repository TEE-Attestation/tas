#!/usr/bin/env bash
#
# TEE Attestation Service - CVM E2E CI Validation Script
#
# Copyright 2026 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# This file is part of the TEE Attestation Service.
#
# This script syntax-checks the E2E shell scripts and validates the Terraform
# configuration without provisioning cloud resources.

set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
TF_ROOT="$ROOT_DIR/terraform/cvm"

[[ -d "$TF_ROOT" ]] || {
  echo "Terraform root not found: $TF_ROOT" >&2
  exit 1
}

cd "$TF_ROOT"
for script in "$ROOT_DIR/run.sh" "$ROOT_DIR/check.sh" "$ROOT_DIR/guest/setup_and_test_tas.sh"; do
  bash -n "$script"
done
command -v terraform >/dev/null 2>&1 || {
  echo "terraform is required for Terraform formatting and validation checks." >&2
  exit 127
}
terraform fmt -check -recursive
terraform init -backend=false -input=false -lockfile=readonly
terraform validate
