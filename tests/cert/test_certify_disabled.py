#
# TEE Attestation Service - Certificate Feature Flag Tests
#
# Copyright 2026 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# This file is part of the TEE Attestation Service.
#
# Verifies that certificate issuance is disabled by default (TAS_CERT_ENABLED
# defaults to False). The app module registers blueprints and initializes the
# cert provider at import time, so the disabled path is exercised in a clean
# subprocess to avoid mutating the shared app singleton used by other tests.

import os
import subprocess
import sys

from tas.config import BaseConfig

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_cert_disabled_by_default_in_base_config():
    """The feature flag defaults to off in the base configuration."""
    assert BaseConfig.TAS_CERT_ENABLED is False


def test_certify_route_absent_and_plugin_skipped_when_disabled():
    """With TAS_CERT_ENABLED unset, the certify route is not registered and the
    cert provider is not initialized."""
    snippet = (
        "import app as a;"
        "client = a.app.test_client();"
        "resp = client.post('/alphav1/certify', json={}, "
        "headers={'X-API-Key': 'a' * 64});"
        "assert resp.status_code == 404, resp.status_code;"
        "assert 'cert' not in a.app.blueprints, list(a.app.blueprints);"
        "assert 'cert_client' not in a.app.extensions;"
        "print('OK')"
    )

    env = dict(os.environ)
    env["PYTHONPATH"] = REPO_ROOT
    env["TAS_API_KEY"] = "a" * 64
    env["TAS_MANAGEMENT_API_KEY"] = "b" * 64
    env.pop("TAS_CERT_ENABLED", None)

    result = subprocess.run(
        [sys.executable, "-c", snippet],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, f"stdout={result.stdout!r}\nstderr={result.stderr!r}"
    assert "OK" in result.stdout
