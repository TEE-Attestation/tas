#
# TEE Attestation Service - Base Authenticator
#
# Copyright 2026 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# This file is part of the TEE Attestation Service.
#
# Abstract base class for all authentication mechanisms.
#

from abc import ABC, abstractmethod


class BaseAuthenticator(ABC):
    """Abstract base for authentication mechanisms.

    Subclasses implement a specific mechanism (API key, JWT, mTLS, etc.).
    Each returns a tuple of (success: bool, error_response | None).
    """

    @abstractmethod
    def authenticate(self, request):
        """Authenticate an incoming request.

        Args:
            request: The Flask request object.

        Returns:
            (True, None) on success.
            (False, (response, status_code)) on failure.
        """
        raise NotImplementedError
