#
# TEE Attestation Service - Shared pytest fixtures and setup.
#
# Copyright 2026 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# This file is part of the TEE Attestation Service.
#

"""Pytest bootstrap shared by the test suite.

The policy trust store (``certs/policy``) ships without any public key, so a
fresh checkout or CI runner has an empty trust store. Tests that import the
full application trigger ``load_configuration`` at import time, which raises
``RuntimeError: No valid trusted keys loaded`` when the store is empty. This
module provisions an ephemeral public key before any test module is imported
so those tests can start. It is a no-op when a key is already present.
"""

from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

_POLICY_DIR = Path(__file__).resolve().parent.parent / "certs" / "policy"
_TEST_KEY = _POLICY_DIR / "ci-test-key-pub.pem"
_KEY_GLOBS = ("*.pem", "*.crt", "*.cer", "*.pub")


def _ensure_trusted_policy_key() -> None:
    """Write an ephemeral trusted public key if the trust store has none."""
    if not _POLICY_DIR.is_dir():
        return
    existing = [f for pattern in _KEY_GLOBS for f in _POLICY_DIR.glob(pattern)]
    if existing:
        return
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    _TEST_KEY.write_bytes(
        key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )


_ensure_trusted_policy_key()
