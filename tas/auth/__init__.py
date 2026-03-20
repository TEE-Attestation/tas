#
# TEE Attestation Service - Authentication Package
#
# Copyright 2026 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# This file is part of the TEE Attestation Service.
#
# This package provides authentication for TAS API routes,
# split by role (client vs management) with pluggable mechanisms.
#

from .client_auth import authenticate_request, init_client_auth
from .management_auth import authenticate_management_request, init_management_auth

__all__ = [
    "authenticate_request",
    "authenticate_management_request",
    "init_client_auth",
    "init_management_auth",
]
